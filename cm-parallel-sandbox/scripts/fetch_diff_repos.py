#!/usr/bin/env python3
"""Mines diff-mode cases into config/repos_with_diff.tsv.

For every repos.tsv repo, walks the first-parent ancestors pinned_ref~k
(k = 1, 2, ...) and computes code-only diff stats against pinned_ref with
container/scripts/diff_stats.py. The walk stops at the first k with more than
--max-files changed code files, at k = --max-k, or at the root commit. For each
size band (S 1-3, M 4-15, L 16-49, XL 50-150 changed code files) it picks the
largest evaluated k that falls in the band; bands with no such k are skipped.
Repos in XL_OVERFLOW (or --xl-overflow) use the stop k as XL when none fits.

Mirrors are blobless, depth-limited fetches of pinned_ref under --cache-dir
(blobs needed by numstat are fetched on demand). Walk results are cached next
to each mirror, keyed by pinned_ref and the cm scan filters, so re-runs only
redo repos whose inputs changed.

pinned_ref defaults to the repos.tsv ref resolved to a commit SHA. If the
output TSV already exists, its per-repo pinned_ref is reused (so hand edits
stick) unless --reresolve is given. A ref that doesn't exist upstream fails
that repo with a message to fix it in the input sheet (config/repos.tsv).

Usage:
  scripts/fetch_diff_repos.py [--repos ID ...] [--jobs 8] [--reresolve]
"""

import argparse
import concurrent.futures
import csv
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "diff_stats", ROOT / "container" / "scripts" / "diff_stats.py")
diff_stats = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diff_stats)

DEFAULT_CACHE = pathlib.Path.home() / ".cache" / "cm-diff-mining"
BANDS = (("S", 1, 3), ("M", 4, 15), ("L", 16, 49), ("XL", 50, 150))
META_COLS = ("name", "git_url", "language", "build_system", "domain",
             "size_bucket", "approx_loc", "split", "notes")
COLUMNS = ("repo_id", "name", "git_url", "pinned_ref", "diff_ref", "diff_bucket",
           "language", "build_system", "domain", "size_bucket", "approx_loc",
           "split", "notes", "source_repo_id", "evidence")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
WALK_VERSION = 1
DEFAULT_MAX_K = 500
# Repos whose walk fills no band below the stop point (e.g. a long run of
# code-free commits followed by a huge merge). With approval, the stop k (the
# first k with more than --max-files changed code files) becomes their XL case.
XL_OVERFLOW = frozenset({"o09-benchmarkjava"})


def git(repo, *args, check=True):
  return subprocess.run(["git", "-C", str(repo), *args], check=check,
                        capture_output=True, text=True).stdout.strip()


def read_tsv(path):
  with open(path, newline="", encoding="utf-8") as f:
    text = f.read().replace("\r\n", "\n")
  return list(csv.DictReader(text.splitlines(), delimiter="\t"))


def write_tsv(path, rows):
  with open(path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=COLUMNS, delimiter="\t",
                       lineterminator="\n", quoting=csv.QUOTE_NONE,
                       escapechar="\\")
    w.writeheader()
    for r in rows:
      w.writerow({c: r.get(c, "") for c in COLUMNS})


def case_id(source_repo_id, pinned_ref, diff_ref):
  return f"{source_repo_id}--{pinned_ref[:7]}-{diff_ref[:7]}"


def band_of(changed_files):
  for name, lo, hi in BANDS:
    if lo <= changed_files <= hi:
      return name
  return None


def retry(fn, *args, attempts=4, delay=15, fatal=None, **kwargs):
  """Retries network-bound git calls (GitHub drops bursts of connections).

  `fatal(exc)` returning True re-raises at once (e.g. a ref that doesn't exist).
  """
  for i in range(attempts):
    try:
      return fn(*args, **kwargs)
    except subprocess.CalledProcessError as e:
      if i == attempts - 1 or (fatal and fatal(e)):
        raise
      time.sleep(delay * (2 ** i))
  return None


# git's messages when the remote has no such branch/tag/commit.
MISSING_REF_RE = re.compile(
    r"couldn't find remote ref|not our ref|unadvertised object|"
    r"no such remote ref", re.IGNORECASE)


class PinnedRefNotFound(RuntimeError):
  """The pinned ref doesn't exist in the upstream repo."""


def _ref_missing(exc):
  return bool(MISSING_REF_RE.search(exc.stderr or ""))


def ensure_mirror(cache_dir, repo_id, url, ref, depth,
                  ref_source="config/repos.tsv"):
  """Blobless, depth-limited mirror of `ref`; returns (path, pinned_sha).

  Raises PinnedRefNotFound if `ref` doesn't exist upstream.
  """
  path = pathlib.Path(cache_dir) / repo_id
  if not (path / ".git").exists():
    path.mkdir(parents=True, exist_ok=True)
    # Non-bare (some setups set safe.bareRepository=explicit); never checked out.
    git(path, "init", "--quiet")
    git(path, "remote", "add", "origin", url)
    git(path, "config", "remote.origin.promisor", "true")
    git(path, "config", "remote.origin.partialclonefilter", "blob:none")
  if SHA_RE.match(ref) and _has_commit(path, ref) and _history_ok(
      path, ref, depth):
    sha = ref  # already fetched deep enough
  else:
    try:
      retry(git, path, "fetch", "--quiet", "--filter=blob:none",
            f"--depth={depth}", "origin", ref, fatal=_ref_missing)
    except subprocess.CalledProcessError as e:
      if not _ref_missing(e):
        raise
      raise PinnedRefNotFound(
          f"pinned ref '{ref}' for {repo_id} can't be found in {url}; "
          f"update {repo_id}'s ref in {ref_source} to an existing tag, "
          f"branch or commit SHA") from None
    sha = git(path, "rev-parse", "FETCH_HEAD^{commit}")
  # Keep the commit reachable for gc and for later validator runs.
  git(path, "update-ref", f"refs/mined/{sha}", sha)
  return path, sha


def shallow_commits(path):
  """Commits at the mirror's shallow boundary (their parents were not fetched)."""
  f = pathlib.Path(git(path, "rev-parse", "--absolute-git-dir")) / "shallow"
  return set(f.read_text().split()) if f.exists() else set()


def _history_ok(path, sha, depth):
  """True if `sha` has `depth` first-parent commits locally, or reaches a root."""
  chain = first_parent_chain(path, sha, depth - 1)
  return len(chain) >= depth or chain[-1] not in shallow_commits(path)


def _has_commit(path, sha):
  # GIT_NO_LAZY_FETCH: a promisor remote would otherwise fetch the commit (and
  # its whole blobless history) just to answer this check.
  return subprocess.run(["git", "-C", str(path), "cat-file", "-e",
                         f"{sha}^{{commit}}"], capture_output=True,
                        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"}
                        ).returncode == 0


def missing_objects(mirror, oids):
  """Subset of `oids` not present locally (never triggers a lazy fetch)."""
  if not oids:
    return []
  out = subprocess.run(
      ["git", "-C", str(mirror), "cat-file", "--batch-check"],
      input="\n".join(sorted(oids)) + "\n", capture_output=True, text=True,
      check=True, env={**os.environ, "GIT_NO_LAZY_FETCH": "1"}).stdout
  return [l.split()[0] for l in out.splitlines() if l.endswith(" missing")]


def prefetch_blobs(mirror, oids):
  """Fetches missing blobs in one request (as git's own promisor fetch does)."""
  missing = missing_objects(mirror, oids)
  if missing:
    retry(subprocess.run,
          ["git", "-C", str(mirror), "-c", "fetch.negotiationAlgorithm=noop",
           "fetch", "--quiet", "origin", "--no-tags", "--no-write-fetch-head",
           "--recurse-submodules=no", "--filter=blob:none", "--stdin"],
          input="\n".join(missing) + "\n", capture_output=True, text=True,
          check=True)
  return len(missing)


def first_parent_chain(mirror, pinned, max_k):
  return git(mirror, "rev-list", "--first-parent",
             f"--max-count={max_k + 1}", pinned).split()


def walk(mirror, pinned, filters, max_k, max_files, log=None, chunk=20):
  """Returns (evals, stop_reason); evals = [[k, sha, files, lines], ...].

  Works in chunks of k: first collects the code-file blob ids the chunk's
  diffs need (trees only), fetches the missing ones in one request, then runs
  diff_stats for each k.
  """
  chain = first_parent_chain(mirror, pinned, max_k)
  evals = []
  for start in range(1, len(chain), chunk):
    ks = range(start, min(start + chunk, len(chain)))
    oids = set()
    for k in ks:
      ids, n = diff_stats.raw_blob_ids(mirror, chain[k], pinned, filters)
      oids |= ids
      if n > max_files:  # likely the stop point: don't prefetch past it
        break
    fetched = prefetch_blobs(mirror, oids)
    if log:
      log(f"k={ks[0]}..{ks[-1]}: prefetched {fetched} blob(s)")
    for k in ks:
      stats, _ = retry(diff_stats.compute, mirror, filters, chain[k], pinned)
      evals.append([k, chain[k], stats["changed_files"],
                    stats["changed_lines"]])
      if stats["changed_files"] > max_files:
        return evals, f"changed_files>{max_files} at k={k}"
  if len(chain) - 1 >= max_k:
    return evals, f"k={max_k} cap"
  if chain[-1] in shallow_commits(mirror):
    return evals, f"shallow boundary at k={len(chain) - 1}"
  return evals, f"root at k={len(chain) - 1}"


def pick(evals, xl_overflow=False, max_files=150):
  """Largest evaluated k per band -> {band: [k, sha, files, lines]}.

  With xl_overflow, a missing XL band takes the walk's last evaluated k if it
  overflowed max_files (the stop point).
  """
  picks = {}
  for e in evals:
    b = band_of(e[2])
    if b and (b not in picks or e[0] > picks[b][0]):
      picks[b] = e
  if xl_overflow and "XL" not in picks and evals and evals[-1][2] > max_files:
    picks["XL"] = evals[-1]
  return picks


def mine_repo(src, pinned_hint, filters, filters_key, args,
              ref_source="config/repos.tsv"):
  rid = src["repo_id"]
  log = lambda m: print(f"[{rid}] {m}", flush=True)
  mirror, pinned = ensure_mirror(args.cache_dir, rid, src["git_url"],
                                 pinned_hint, args.max_k + 1, ref_source)
  cache = pathlib.Path(args.cache_dir) / f"{rid}.walk.json"
  key = {"version": WALK_VERSION, "pinned": pinned, "filters": filters_key,
         "max_k": args.max_k, "max_files": args.max_files}
  data = None
  if cache.exists():
    try:
      data = json.loads(cache.read_text())
    except ValueError:  # truncated by an interrupted run: recompute
      data = None
    if data and data.get("key") != key:
      data = None
  if data is None:
    log(f"walking from {pinned[:12]}")
    evals, stop = walk(mirror, pinned, filters, args.max_k, args.max_files, log)
    data = {"key": key, "evals": evals, "stop": stop}
    tmp = cache.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, cache)  # atomic: never leave a truncated cache
  picks = pick(data["evals"], rid in args.xl_overflow, args.max_files)
  rows = []
  for band, _, _ in BANDS:
    if band not in picks:
      continue
    k, sha, files, lines = picks[band]
    row = {c: src.get(c, "") for c in META_COLS}
    row.update({
        "repo_id": case_id(rid, pinned, sha), "pinned_ref": pinned,
        "diff_ref": sha, "diff_bucket": band, "source_repo_id": rid,
        "evidence": f"k={k}; changed_files={files}; changed_lines={lines}",
    })
    rows.append(row)
  log(f"{data['stop']}; evaluated={len(data['evals'])}; "
      f"bands={[r['diff_bucket'] for r in rows]}")
  return rid, rows, data["stop"]


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
  p.add_argument("--repos-tsv", default=str(ROOT / "config" / "repos.tsv"))
  p.add_argument("--config", default=str(ROOT / "config" / "cm_config.yaml"))
  p.add_argument("--out", default=str(ROOT / "config" / "repos_with_diff.tsv"))
  p.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
  p.add_argument("--repos", nargs="+", default=None,
                 help="only (re)mine these source repo ids; other rows are kept")
  p.add_argument("--jobs", type=int, default=8)
  p.add_argument("--max-k", type=int, default=DEFAULT_MAX_K)
  p.add_argument("--max-files", type=int, default=150)
  p.add_argument("--reresolve", action="store_true",
                 help="ignore pinned_ref in the existing output TSV")
  p.add_argument("--xl-overflow", action="append", default=[], metavar="ID",
                 help="also use the stop k (>--max-files) as XL for this repo "
                      f"when no XL k exists (always on for {sorted(XL_OVERFLOW)})")
  args = p.parse_args(argv)
  asked = (args.repos or []) + args.xl_overflow  # ids the caller typed
  args.xl_overflow = XL_OVERFLOW | set(args.xl_overflow)

  sources = read_tsv(args.repos_tsv)
  by_id = {s["repo_id"]: s for s in sources}
  unknown = [r for r in asked if r not in by_id]
  if unknown:
    p.error(f"unknown repo ids: {unknown}")
  existing = read_tsv(args.out) if pathlib.Path(args.out).exists() else []
  existing_by_src = {}
  for r in existing:
    existing_by_src.setdefault(r["source_repo_id"], []).append(r)

  filters = diff_stats.load_filters(args.config)
  filters_key = [list(filters[0]), list(filters[1]), sorted(filters[2])]
  targets = list(dict.fromkeys(args.repos or [s["repo_id"] for s in sources]))
  results, errors = {}, {}
  with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
    futs = {}
    for rid in targets:
      hint, source = by_id[rid]["pinned_ref"].strip(), args.repos_tsv
      prev = existing_by_src.get(rid)
      if prev and not args.reresolve:
        hint = prev[0]["pinned_ref"]
        source = f"{args.out} (pinned_ref; or pass --reresolve)"
      futs[ex.submit(mine_repo, by_id[rid], hint, filters, filters_key,
                     args, source)] = rid
    for fut in concurrent.futures.as_completed(futs):
      rid = futs[fut]
      try:
        _, rows, _ = fut.result()
        results[rid] = rows
      except Exception as e:  # pylint: disable=broad-except
        errors[rid] = str(e)
        print(f"[{rid}] ERROR: {e}", file=sys.stderr, flush=True)

  out_rows = []
  for s in sources:
    rid = s["repo_id"]
    if rid in results:
      out_rows.extend(results[rid])
    elif rid in existing_by_src:
      out_rows.extend(existing_by_src[rid])
  write_tsv(args.out, out_rows)
  print(f"wrote {len(out_rows)} rows to {args.out}")
  if errors:
    print(f"{len(errors)} repo(s) failed: {sorted(errors)}", file=sys.stderr)
    return 1
  return 0


if __name__ == "__main__":
  sys.exit(main())
