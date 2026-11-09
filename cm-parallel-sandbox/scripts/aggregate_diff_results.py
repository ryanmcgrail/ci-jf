#!/usr/bin/env python3
"""Aggregates diff-mode find results (cm-011-diff) into markdown tables.

Usage:
  scripts/aggregate_diff_results.py --tsv config/repos_with_diff.tsv \\
      [--out /tmp/agg] [--model-label MODEL] [--json OUT] [--expect IDS] \\
      BATCH=gs://<bucket>/<experiment>/<run_id> [BATCH=...]

Downloads <run>/<case>/summary.json for every case directory under each run
prefix (cached under --out/<run_id>/), then prints a per-case table, per-band
aggregates, the timed-out cases, the tokens-vs-changed_lines correlation and
the total tokens.

Every case is checked (G9): status=ok, mode=diff, cm_version, diff_workers
null, model (when --model-label is set), run_id, changed_files/changed_lines
equal to the TSV `evidence`, and total_tokens > 0. A case with
diff_timed_out=true is valid: its tokens count towards the totals, it is
listed in the timed-out table and it is left out of the medians and the
correlation. Cases that fail G9 or have no summary.json are left out of all
aggregates, listed on stderr and make the script exit 2.

--json OUT writes the per-band aggregates, the correlation and the totals so
a cross-model table can be built without downloading again. --expect IDS (a
file with one case id per line) flags expected cases that have no case
directory under any run prefix, e.g. a task that failed before uploading.
"""

import argparse
import concurrent.futures
import csv
import json
import math
import os
import statistics
import subprocess
import sys

BANDS = ["S", "M", "L", "XL"]
CM_VERSION = "0.11.0"
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FETCH_WORKERS = 16


def pct(vals, p):
  """Linear-interpolated percentile (p in [0, 1]); None for no values."""
  if not vals:
    return None
  v = sorted(vals)
  k = (len(v) - 1) * p
  lo, hi = int(k), min(int(k) + 1, len(v) - 1)
  return v[lo] + (v[hi] - v[lo]) * (k - lo)


def fmt(n):
  return "-" if n is None else f"{int(round(n)):,}"


def load_tsv(path):
  with open(path, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader((l.replace("\r", "") for l in f), delimiter="\t"))
  return {r["repo_id"]: (i, r) for i, r in enumerate(rows)}


def parse_evidence(ev):
  """'k=14; changed_files=12; changed_lines=130' -> {'k': '14', ...}."""
  out = {}
  for part in (ev or "").split(";"):
    if "=" in part:
      k, v = part.split("=", 1)
      out[k.strip()] = v.strip()
  return out


def list_cases(prefix):
  r = subprocess.run(["gcloud", "storage", "ls", prefix + "/"],
                     capture_output=True, text=True, check=True)
  return sorted(l.rstrip("/").rsplit("/", 1)[1]
                for l in r.stdout.split() if l.endswith("/"))


def fetch_one(prefix, case, path):
  if not os.path.exists(path):
    r = subprocess.run(["gcloud", "storage", "cp", f"{prefix}/{case}/summary.json",
                        path], capture_output=True, text=True)
    if r.returncode != 0:
      return None
  try:
    with open(path, encoding="utf-8") as f:
      return json.load(f)
  except (OSError, ValueError):
    return None


def fetch(prefix, out):
  """{case: summary dict or None} for every case directory under prefix."""
  d = os.path.join(out, prefix.rsplit("/", 1)[1])
  os.makedirs(d, exist_ok=True)
  cases = list_cases(prefix)
  with concurrent.futures.ThreadPoolExecutor(FETCH_WORKERS) as ex:
    futs = {c: ex.submit(fetch_one, prefix, c, os.path.join(d, c + ".json"))
            for c in cases}
  return {c: f.result() for c, f in futs.items()}


def g9_errors(s, row, run_id, model):
  """Reasons the case fails G9 (empty list when it passes)."""
  if s is None:
    return ["missing summary.json"]
  errs = []
  if row is None:
    errs.append("case not in TSV")
  expect = {"status": "ok", "mode": "diff", "cm_version": CM_VERSION,
            "run_id": run_id}
  if model:
    expect["model"] = model
  for k, v in expect.items():
    if s.get(k) != v:
      errs.append(f"{k}={s.get(k)!r} (want {v!r})")
  if "diff_workers" not in s or s["diff_workers"] is not None:
    errs.append(f"diff_workers={s.get('diff_workers', '<absent>')!r} (want None)")
  if row is not None:
    ev = parse_evidence(row.get("evidence"))
    for k in ("changed_files", "changed_lines"):
      if str(s.get(k)) != ev.get(k):
        errs.append(f"{k}={s.get(k)!r} != evidence {ev.get(k)!r}")
  if not (s.get("tokens") or {}).get("total_tokens"):
    errs.append("total_tokens=0")
  return errs


def collect(batches, tsv, out, model):
  """Rows (batch, case, band, summary, errors), in TSV order."""
  rows = []
  for spec in batches:
    batch, prefix = spec.split("=", 1)
    prefix = prefix.rstrip("/")
    run_id = prefix.rsplit("/", 1)[1]
    for case, s in fetch(prefix, out).items():
      idx, row = tsv.get(case, (None, None))
      band = (row or {}).get("diff_bucket", "?")
      rows.append((batch, case, band, s, g9_errors(s, row, run_id, model)))
  order = {c: i for c, (i, _) in tsv.items()}
  rows.sort(key=lambda r: (order.get(r[1], len(order)), r[0]))
  return rows


def total_tokens(s):
  return (s.get("tokens") or {}).get("total_tokens") or 0


def band_stats(rows, band):
  sel = [(s, e) for _, _, b, s, e in rows if band == "ALL" or b == band]
  valid = [s for s, e in sel if not e]
  done = [s for s in valid if not s.get("diff_timed_out")]
  tk = [total_tokens(s) for s in done]
  sev = {}
  for s in valid:
    for k, v in (s.get("severity_counts") or {}).items():
      sev[k] = sev.get(k, 0) + v
  return {
      "cases": len(sel),
      "valid": len(valid),
      "excluded": len(sel) - len(valid),
      "timed_out": len(valid) - len(done),
      "median_tokens": pct(tk, .5),
      "p90_tokens": pct(tk, .9),
      "median_wall_s": pct([s["wall_clock_seconds"] for s in done], .5),
      "p90_wall_s": pct([s["wall_clock_seconds"] for s in done], .9),
      "median_lines": pct([s["changed_lines"] for s in done], .5),
      "median_tokens_per_line": pct([total_tokens(s) / s["changed_lines"]
                                     for s in done if s.get("changed_lines")], .5),
      "findings": sum(s.get("findings_count") or 0 for s in valid),
      "severity_counts": sev,
      "total_tokens": sum(total_tokens(s) for s in valid),
  }


def correlation(rows):
  pts = [(s["changed_lines"], total_tokens(s)) for _, _, _, s, e in rows
         if not e and not s.get("diff_timed_out")]
  if len(pts) < 3:
    return {"n": len(pts)}
  xs, ys = zip(*pts)
  try:
    fit = statistics.linear_regression(xs, ys)
    return {
        "n": len(pts),
        "pearson_r": statistics.correlation(xs, ys),
        "loglog_r": statistics.correlation([math.log1p(x) for x in xs],
                                           [math.log1p(y) for y in ys]),
        "ols_intercept": fit.intercept,
        "ols_slope": fit.slope,
    }
  except statistics.StatisticsError:
    return {"n": len(pts)}


def sev_str(counts):
  keys = [k for k in SEVERITIES if k in counts] + sorted(set(counts) - set(SEVERITIES))
  return ", ".join(f"{counts[k]} {k}" for k in keys) or "0"


def print_report(rows, bands, corr, label):
  title = f" ({label})" if label else ""
  print(f"### Per-case results{title}\n")
  print("| Batch | Case | Band | Files | Lines | Jobs | Input tok | Output tok "
        "| Total tok | Wall s | Findings | cm exit | Timed out | Status |")
  print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
  for batch, case, band, s, errs in rows:
    if s is None:
      print(f"| {batch} | `{case}` | {band} | | | | | | | | | | | MISSING |")
      continue
    tok = s.get("tokens") or {}
    jobs = f"{s.get('diff_jobs_completed')}/{s.get('diff_jobs_total')}"
    print(f"| {batch} | `{case}` | {band} | {s.get('changed_files')} "
          f"| {s.get('changed_lines')} | {jobs} | {fmt(tok.get('input_tokens'))} "
          f"| {fmt(tok.get('output_tokens'))} | {fmt(tok.get('total_tokens'))} "
          f"| {s.get('wall_clock_seconds')} | {sev_str(s.get('severity_counts') or {})} "
          f"| {s.get('cm_exit_code')} | {'yes' if s.get('diff_timed_out') else 'no'} "
          f"| {s.get('status')}{' ⚠' if errs else ''} |")

  print("\n### Per-band aggregates\n")
  print("Medians and p90s cover valid cases that finished (not timed out); "
        "band totals include timed-out cases.\n")
  print("| Band | Cases | Excluded | Timed out | Median tok | p90 tok | Median wall s "
        "| p90 wall s | Median lines | Median tok/line | Findings | Total tok |")
  print("|---|---|---|---|---|---|---|---|---|---|---|---|")
  for band, b in bands.items():
    print(f"| {band} | {b['cases']} | {b['excluded']} | {b['timed_out']} "
          f"| {fmt(b['median_tokens'])} | {fmt(b['p90_tokens'])} "
          f"| {fmt(b['median_wall_s'])} | {fmt(b['p90_wall_s'])} "
          f"| {fmt(b['median_lines'])} | {fmt(b['median_tokens_per_line'])} "
          f"| {sev_str(b['severity_counts'])} | {fmt(b['total_tokens'])} |")

  print("\n### Timed-out cases (cm's 5-minute delta-scan ceiling)\n")
  print("| Band | Case | Files | Lines | Jobs done | Total tok | Wall s |")
  print("|---|---|---|---|---|---|---|")
  for band in BANDS:
    for _, case, b, s, errs in rows:
      if b == band and s and not errs and s.get("diff_timed_out"):
        print(f"| {band} | `{case}` | {s['changed_files']} | {s['changed_lines']} "
              f"| {s.get('diff_jobs_completed')}/{s.get('diff_jobs_total')} "
              f"| {fmt(total_tokens(s))} | {s.get('wall_clock_seconds')} |")

  if "pearson_r" in corr:
    print(f"\nTokens vs changed_lines (n={corr['n']}, excl. timeouts): "
          f"Pearson r={corr['pearson_r']:.2f}, log-log r={corr['loglog_r']:.2f}, "
          f"OLS tokens ≈ {corr['ols_intercept']:,.0f} + "
          f"{corr['ols_slope']:,.0f}·lines")
  else:
    print(f"\nTokens vs changed_lines: too few points (n={corr['n']})")
  print(f"\nTotal tokens across {bands['ALL']['valid']} valid cases "
        f"({len(rows)} listed): {bands['ALL']['total_tokens']:,}")


def main(argv=None):
  ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
  ap.add_argument("--tsv", required=True)
  ap.add_argument("--out", default="/tmp/agg", help="summary.json cache dir")
  ap.add_argument("--model-label", default="",
                  help="expected summary `model`; also labels the output")
  ap.add_argument("--json", dest="json_out", help="write per-band aggregates here")
  ap.add_argument("--expect", help="file of expected case ids, one per line")
  ap.add_argument("batches", nargs="+", metavar="BATCH=gs://.../<run_id>")
  a = ap.parse_args(argv)
  for spec in a.batches:
    if "=" not in spec or not spec.split("=", 1)[1].startswith("gs://"):
      ap.error(f"bad batch {spec!r}; want NAME=gs://<bucket>/<experiment>/<run_id>")

  tsv = load_tsv(a.tsv)
  rows = collect(a.batches, tsv, a.out, a.model_label)
  if a.expect:
    with open(a.expect, encoding="utf-8") as f:
      expected = [l.strip() for l in f if l.strip()]
    seen = {r[1] for r in rows}
    for case in expected:
      if case not in seen:
        band = tsv.get(case, (None, {}))[1].get("diff_bucket", "?")
        rows.append(("?", case, band, None, ["no case directory"]))

  bands = {band: band_stats(rows, band) for band in BANDS + ["ALL"]}
  corr = correlation(rows)
  print_report(rows, bands, corr, a.model_label)

  problems = [(case, errs) for _, case, _, _, errs in rows if errs]
  if a.json_out:
    with open(a.json_out, "w", encoding="utf-8") as f:
      json.dump({"model": a.model_label,
                 "batches": dict(s.split("=", 1) for s in a.batches),
                 "bands": bands, "correlation": corr,
                 "total_tokens": bands["ALL"]["total_tokens"],
                 "problems": {c: e for c, e in problems}}, f, indent=2)
      f.write("\n")
  if problems:
    print(f"G9 PROBLEMS ({len(problems)}):", file=sys.stderr)
    for case, errs in problems:
      print(f"  {case}: {'; '.join(errs)}", file=sys.stderr)
    return 2
  return 0


if __name__ == "__main__":
  sys.exit(main())
