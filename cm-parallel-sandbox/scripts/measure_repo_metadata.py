#!/usr/bin/env python3
"""Measures cm-filtered file and line counts for repos.tsv repos.

For each selected repos.tsv row, fetches pinned_ref at depth 1 into --cache-dir
and counts the tracked files cm would scan, using the same filter as
container/scripts/diff_stats.py (config/cm_config.yaml scan.extensions and
scan.exclude_dirs):

  files      = tracked files kept by the filter
  test_files = kept files with "test" or "spec" in the path (cm still scans them)
  loc        = newline count over kept files no larger than 1 MiB

Use it to fill size_bucket/approx_loc when adding repos. With --check (which
needs explicit --repos, since older rows' approx_loc came from other tools) it
also fails if pinned_ref doesn't resolve to itself, approx_loc is more than
--tolerance off the measured loc, or size_bucket != size_bucket_for(loc).

Usage:
  scripts/measure_repo_metadata.py [--repos ID ...] [--json OUT]
  scripts/measure_repo_metadata.py --repos ID ... --check
"""

import argparse
import concurrent.futures
import importlib.util
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cmrun import common  # pylint: disable=g-import-not-at-top,wrong-import-position

_spec = importlib.util.spec_from_file_location(
    "diff_stats", ROOT / "container" / "scripts" / "diff_stats.py")
diff_stats = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diff_stats)

DEFAULT_CACHE = pathlib.Path.home() / ".cache" / "cm-repo-metadata"
DEFAULT_CONFIG = ROOT / "config" / "cm_config.yaml"
MAX_LOC_BYTES = 1024 * 1024
# Upper LOC bounds per size_bucket; every existing repos.tsv row fits these.
SIZE_BUCKETS = (("micro", 10_000), ("small", 50_000), ("medium", 250_000),
                ("large", 1_000_000))


def size_bucket_for(loc):
  """Returns the repos.tsv size_bucket for a line count."""
  for name, upper in SIZE_BUCKETS:
    if loc < upper:
      return name
  return "mega"


def _git(repo_dir, *args):
  return subprocess.run(["git", "-C", str(repo_dir), *args], check=True,
                        capture_output=True, timeout=600)


def fetch(repo_id, meta, cache_dir):
  """Fetches pinned_ref at depth 1; returns (repo_dir, head_sha)."""
  repo_dir = cache_dir / repo_id
  ref = meta["pinned_ref"]
  if not (repo_dir / ".git").is_dir():
    subprocess.run(["git", "init", "--quiet", str(repo_dir)], check=True,
                   capture_output=True)
  try:
    head = _git(repo_dir, "rev-parse", "HEAD").stdout.decode().strip()
  except subprocess.CalledProcessError:
    head = ""
  if not (common.is_commit_sha(ref) and head == ref):
    target = ref if common.is_commit_sha(ref) else f"refs/tags/{ref}"
    try:
      _git(repo_dir, "fetch", "--quiet", "--depth", "1", meta["git_url"], target)
    except subprocess.CalledProcessError:
      _git(repo_dir, "fetch", "--quiet", "--depth", "1", meta["git_url"], ref)
    _git(repo_dir, "reset", "--quiet", "--hard", "FETCH_HEAD")
    head = _git(repo_dir, "rev-parse", "HEAD").stdout.decode().strip()
  return repo_dir, head


def count(repo_dir, filters):
  """Returns {files, test_files, loc} for the cm-filtered tracked files."""
  out = _git(repo_dir, "ls-files", "-z").stdout.decode()
  kept = [p for p in out.split("\0") if p and diff_stats.is_counted(p, filters)]
  loc = 0
  for rel in kept:
    path = repo_dir / rel
    if path.is_file() and path.stat().st_size <= MAX_LOC_BYTES:
      loc += path.read_bytes().count(b"\n")
  tests = sum(1 for p in kept if "test" in p.lower() or "spec" in p.lower())
  return {"files": len(kept), "test_files": tests, "loc": loc}


def measure(repo_id, meta, cache_dir, filters):
  try:
    repo_dir, head = fetch(repo_id, meta, cache_dir)
    return {"repo_id": repo_id, "pinned_ref": meta["pinned_ref"], "head": head,
            **count(repo_dir, filters)}
  except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
    err = getattr(e, "stderr", b"") or b""
    return {"repo_id": repo_id, "error": f"{e} {err.decode()[-200:]}".strip()}


def check_row(meta, result, tolerance):
  """Returns a list of problems comparing a repos.tsv row with its measurement."""
  problems = []
  ref = meta["pinned_ref"]
  if common.is_commit_sha(ref) and result["head"] != ref:
    problems.append(f"HEAD {result['head']} != pinned_ref {ref}")
  want = size_bucket_for(result["loc"])
  if meta.get("size_bucket") != want:
    problems.append(f"size_bucket {meta.get('size_bucket')} != {want} "
                    f"({result['loc']} loc)")
  try:
    approx = int(meta.get("approx_loc") or 0)
  except ValueError:
    approx = 0
  loc = result["loc"]
  if loc and abs(approx - loc) > tolerance * loc:
    problems.append(f"approx_loc {approx} vs measured {loc} "
                    f"(> {tolerance:.0%} off)")
  return problems


def parse_args(argv):
  p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  p.add_argument("--repos-tsv", default=str(common.DEFAULT_REPOS_TSV))
  p.add_argument("--repos", nargs="*", help="repo_ids (default: all rows)")
  p.add_argument("--config", default=str(DEFAULT_CONFIG))
  p.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
  p.add_argument("--jobs", type=int, default=8)
  p.add_argument("--json", help="write measurements to this JSON file")
  p.add_argument("--check", action="store_true",
                 help="fail if size_bucket/approx_loc disagree with measurement")
  p.add_argument("--tolerance", type=float, default=0.25,
                 help="allowed relative approx_loc error for --check")
  return p.parse_args(argv)


def main(argv=None):
  args = parse_args(argv)
  repos = common.load_repos(pathlib.Path(args.repos_tsv))
  if args.check and not args.repos:
    sys.exit("--check needs explicit --repos")
  ids = args.repos or list(repos)
  unknown = [r for r in ids if r not in repos]
  if unknown:
    sys.exit(f"unknown repo_id(s): {', '.join(unknown)}")
  filters = diff_stats.load_filters(args.config)
  cache_dir = pathlib.Path(args.cache_dir)
  cache_dir.mkdir(parents=True, exist_ok=True)
  with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
    results = list(ex.map(lambda r: measure(r, repos[r], cache_dir, filters),
                          ids))
  failed = False
  for res in results:
    rid = res["repo_id"]
    if "error" in res:
      print(f"ERR  {rid}: {res['error']}")
      failed = True
      continue
    line = (f"{res['files']:>6d} files ({res['test_files']:>4d} test) "
            f"{res['loc']:>8d} loc  {rid}")
    problems = check_row(repos[rid], res, args.tolerance) if args.check else []
    print(("FAIL " if problems else "") + line)
    for prob in problems:
      print(f"       - {prob}")
    failed = failed or bool(problems)
  if args.json:
    pathlib.Path(args.json).write_text(json.dumps(results, indent=1) + "\n")
  return 1 if failed else 0


if __name__ == "__main__":
  sys.exit(main())
