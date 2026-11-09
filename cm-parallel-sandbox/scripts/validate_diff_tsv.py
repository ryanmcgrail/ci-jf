#!/usr/bin/env python3
"""Validates config/repos_with_diff.tsv against git and the diff_stats rule.

Static checks (every row):
  - pinned_ref and diff_ref are 40-hex commit SHAs and differ;
  - repo_id is unique, matches ^[a-z0-9][a-z0-9-]*$ and equals
    <source_repo_id>--<pinned_ref[:7]>-<diff_ref[:7]>;
  - source_repo_id exists in repos.tsv; at most 4 rows per source repo.
Git checks (every row, in the mining mirror under --cache-dir):
  - git merge-base --is-ancestor diff_ref pinned_ref;
  - diff_stats reports changed_files >= 1, and matches the row's `evidence`.

Writes a per-row report (case, band, k, changed_files, changed_lines, status)
to --report (TSV) and prints a summary. Exits 1 if any row fails.

Usage:
  scripts/validate_diff_tsv.py [--tsv config/repos_with_diff.tsv] [--report out.tsv]
"""

import argparse
import collections
import concurrent.futures
import csv
import importlib.util
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "fetch_diff_repos", ROOT / "scripts" / "fetch_diff_repos.py")
mine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mine)
diff_stats = mine.diff_stats

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
EVIDENCE_RE = re.compile(
    r"^k=(\d+); changed_files=(\d+); changed_lines=(\d+)$")
MAX_ROWS_PER_REPO = 4
REPORT_COLS = ("case", "band", "k", "changed_files", "changed_lines", "status")


def static_errors(rows, source_ids):
  """Returns {repo_id_or_row_n: [error, ...]} for manifest-level problems."""
  errs = collections.defaultdict(list)
  seen = collections.Counter(r.get("repo_id", "") for r in rows)
  per_src = collections.Counter(r.get("source_repo_id", "") for r in rows)
  for n, r in enumerate(rows, start=2):
    rid = r.get("repo_id") or f"line {n}"
    pinned, diff = r.get("pinned_ref", ""), r.get("diff_ref", "")
    src = r.get("source_repo_id", "")
    for col, val in (("pinned_ref", pinned), ("diff_ref", diff)):
      if not mine.SHA_RE.match(val or ""):
        errs[rid].append(f"{col} {val!r} is not a 40-hex SHA")
    if pinned and pinned == diff:
      errs[rid].append("diff_ref == pinned_ref")
    if not ID_RE.match(rid):
      errs[rid].append("repo_id does not match ^[a-z0-9][a-z0-9-]*$")
    if seen[rid] > 1:
      errs[rid].append("duplicate repo_id")
    if not src:
      errs[rid].append("missing source_repo_id")
    elif src not in source_ids:
      errs[rid].append(f"source_repo_id {src!r} not in repos.tsv")
    elif per_src[src] > MAX_ROWS_PER_REPO:
      errs[rid].append(f"{src} has {per_src[src]} rows (max 4)")
    if src and pinned and diff and rid != mine.case_id(src, pinned, diff):
      errs[rid].append(
          f"repo_id != {mine.case_id(src, pinned, diff)} (id/ref mismatch)")
  return errs


def git_check(row, sources, filters, cache_dir):
  """Returns (report_row, [errors])."""
  rid, src = row["repo_id"], row["source_repo_id"]
  pinned, diff = row["pinned_ref"], row["diff_ref"]
  ev = EVIDENCE_RE.match(row.get("evidence", ""))
  rep = {"case": rid, "band": row.get("diff_bucket", ""),
         "k": ev.group(1) if ev else "", "changed_files": "",
         "changed_lines": "", "status": "ok"}
  errors = []
  mirror, _ = mine.retry(mine.ensure_mirror, cache_dir, src,
                         sources[src]["git_url"], pinned, mine.DEFAULT_MAX_K + 1)
  anc = subprocess.run(["git", "-C", str(mirror), "merge-base",
                        "--is-ancestor", diff, pinned], capture_output=True)
  if anc.returncode != 0:
    errors.append(f"diff_ref is not an ancestor of pinned_ref "
                  f"(merge-base exit {anc.returncode})")
  else:
    stats, _ = mine.retry(diff_stats.compute, mirror, filters, diff, pinned)
    rep["changed_files"] = stats["changed_files"]
    rep["changed_lines"] = stats["changed_lines"]
    if stats["changed_files"] < 1:
      errors.append("changed_files == 0 (cm would report no changes)")
    if ev and (int(ev.group(2)), int(ev.group(3))) != (
        stats["changed_files"], stats["changed_lines"]):
      errors.append(f"evidence {row['evidence']!r} != computed {stats}")
  if errors:
    rep["status"] = "FAIL: " + "; ".join(errors)
  return rep, errors


def write_report(path, reports):
  with open(path, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, delimiter="\t", lineterminator="\n", restval="",
                       fieldnames=REPORT_COLS)
    w.writeheader()
    for rep in reports:
      w.writerow(rep)


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
  p.add_argument("--tsv", default=str(ROOT / "config" / "repos_with_diff.tsv"))
  p.add_argument("--repos-tsv", default=str(ROOT / "config" / "repos.tsv"))
  p.add_argument("--config", default=str(ROOT / "config" / "cm_config.yaml"))
  p.add_argument("--cache-dir", default=str(mine.DEFAULT_CACHE))
  p.add_argument("--report", default=None, help="per-row report TSV path")
  p.add_argument("--static-only", action="store_true")
  p.add_argument("--jobs", type=int, default=8)
  a = p.parse_args(argv)

  rows = mine.read_tsv(a.tsv)
  sources = {s["repo_id"]: s for s in mine.read_tsv(a.repos_tsv)}
  failures = 0
  static = static_errors(rows, sources)
  for rid, errs in static.items():
    failures += 1
    print(f"[static] {rid}: {'; '.join(errs)}", file=sys.stderr)
  if failures or a.static_only:
    if a.report:
      write_report(a.report, [
          {"case": r.get("repo_id", ""), "band": r.get("diff_bucket", ""),
           "status": ("FAIL: " + "; ".join(static[r.get("repo_id", "")])
                      if r.get("repo_id", "") in static else "static ok")}
          for r in rows])
    print(f"static: {failures} row(s) failed out of {len(rows)}")
    return 1 if failures else 0

  filters = diff_stats.load_filters(a.config)
  by_src = collections.OrderedDict()
  for r in rows:
    by_src.setdefault(r["source_repo_id"], []).append(r)

  def check_repo(src_rows):  # rows sharing a mirror run sequentially
    out = []
    for r in src_rows:
      try:
        out.append((r["repo_id"],) + git_check(r, sources, filters, a.cache_dir))
      except Exception as e:  # pylint: disable=broad-except
        out.append((r["repo_id"], {"case": r["repo_id"], "status": f"FAIL: {e}"},
                    [str(e)]))
    return out

  reports = {}
  with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
    for result in ex.map(check_repo, by_src.values()):
      for rid, rep, errs in result:
        reports[rid] = rep
        if errs:
          failures += 1
          print(f"[git] {rid}: {'; '.join(errs)}", file=sys.stderr)
  if a.report:
    write_report(a.report, [reports[r["repo_id"]] for r in rows])
  print(f"validated {len(rows)} row(s) from "
        f"{len({r['source_repo_id'] for r in rows})} repo(s); "
        f"{failures} failed")
  return 1 if failures else 0


if __name__ == "__main__":
  sys.exit(main())
