#!/usr/bin/env python3
"""Builds summary.json for a find or verify task results directory.

status is "ok", "timeout" or "failed"; a verify task with any per-finding
timeout (exit 124/137) is "timeout", never "ok". Verify summaries also carry cm
status counts from post_verify_report.json plus timeout / non-zero exit
counters from findings/<id>/exit_code (VERIFY_AIRGAP.md §4).
"""

import argparse
import collections
import json
import os
import pathlib
import re
import sqlite3
import sys
import tarfile

TIMEOUT_CODES = {124, 137}
# Same line pattern cm-api-token-stats uses to find sessions in cm's logs.
ACCEPTED_SESSION_RE = re.compile(
    r"^(\S+)\s.*\bStartSession\b.*\baccepted\b.*\bsession=(Ch[\w-]+)", re.M)


def _load_json(path, default=None):
  try:
    with open(path, encoding="utf-8") as f:
      return json.load(f)
  except (OSError, ValueError):
    return default


def _items(data):
  if isinstance(data, list):
    return data
  if isinstance(data, dict):
    return data.get("findings", [])
  return []


def _tokens(stats):
  stats = stats if isinstance(stats, dict) else {}
  keys = ("input_tokens", "output_tokens", "cached_tokens", "thought_tokens",
          "tool_calls", "total_tokens", "total_turns")
  return {k: int(stats.get(k, 0) or 0) for k in keys}


def _version_at_least(version, minimum):
  try:
    return tuple(int(x) for x in version.split(".")[:2]) >= minimum
  except ValueError:
    return False


def _token_stats_status(stats):
  if isinstance(stats, dict) and stats.get("error") == "timeout":
    return "timeout"
  return "ok" if isinstance(stats, dict) and "total_tokens" in stats else "failed"


def session_counts(results_dir):
  """Sessions in the uploaded state.db vs. the archived cm session logs.

  cm can drop state.db rows under concurrent --deep workers (SQLITE_BUSY); the
  logs still record those sessions.
  """
  rd = pathlib.Path(results_dir)
  db = set()
  if (rd / "state.db").is_file():
    try:
      c = sqlite3.connect(f"file:{rd / 'state.db'}?immutable=1", uri=True)
      try:
        db = {r[0] for r in c.execute("SELECT session_id FROM sessions")}
      finally:
        c.close()
    except sqlite3.Error:
      pass
  logs = set()
  try:
    with tarfile.open(rd / "logs" / "cm_logs.tar.gz") as tf:
      for member in tf.getmembers():
        if member.isfile():
          text = tf.extractfile(member).read().decode(errors="replace")
          logs.update(m.group(2) for m in ACCEPTED_SESSION_RE.finditer(text))
  except (OSError, tarfile.TarError):
    pass
  return {"state_db": len(db), "logs": len(logs), "union": len(db | logs),
          "dropped_from_db": len(logs - db)}


def verify_details(results_dir, expected_ids):
  fdir = pathlib.Path(results_dir) / "findings"
  exit_codes = {}
  tokens = collections.Counter()
  for fid in expected_ids:
    code_file = fdir / fid / "exit_code"
    try:
      exit_codes[fid] = int(code_file.read_text().strip())
    except (OSError, ValueError):
      exit_codes[fid] = None
    tokens.update(_tokens(_load_json(fdir / fid / "token_stats.json", {})))
  report = _items(_load_json(pathlib.Path(results_dir) / "post_verify_report.json"))
  by_id = {str(f.get("finding_id") or f.get("FindingID")): f for f in report}
  status_counts = collections.Counter()
  for fid in expected_ids:
    st = str((by_id.get(fid) or {}).get("status") or "MISSING").upper()
    status_counts[st if st in ("VERIFIED", "DISMISSED") else "OTHER:" + st] += 1
  return {
      "findings_expected": len(expected_ids),
      "findings_attempted": sum(1 for c in exit_codes.values() if c is not None),
      "status_counts": dict(status_counts),
      "timeout_count": sum(1 for c in exit_codes.values() if c in TIMEOUT_CODES),
      "nonzero_exit_count": sum(1 for c in exit_codes.values() if c not in (0, None)),
      "exit_codes": exit_codes,
      "tokens": dict(tokens),
  }


def fix_details(results_dir, expected_ids):
  fdir = pathlib.Path(results_dir) / "findings"
  exit_codes = {}
  tokens = collections.Counter()
  patches_generated = 0
  patch_sizes = {}
  exploits_imported = 0

  for fid in expected_ids:
    code_file = fdir / fid / "exit_code"
    try:
      exit_codes[fid] = int(code_file.read_text().strip())
    except (OSError, ValueError):
      exit_codes[fid] = None
    tokens.update(_tokens(_load_json(fdir / fid / "token_stats.json", {})))

    patch_file = fdir / fid / "patch.diff"
    if patch_file.is_file() and patch_file.stat().st_size > 0:
      patches_generated += 1
      patch_sizes[fid] = patch_file.stat().st_size
    else:
      patch_sizes[fid] = 0

    exploit_dir = fdir / fid / "exploit"
    if exploit_dir.is_dir() and any(f.is_file() for f in exploit_dir.rglob("*")):
      exploits_imported += 1

  report = _items(_load_json(pathlib.Path(results_dir) / "post_fix_report.json"))
  by_id = {str(f.get("finding_id") or f.get("FindingID")): f for f in report}
  status_counts = collections.Counter()
  for fid in expected_ids:
    st = str((by_id.get(fid) or {}).get("status") or "MISSING").upper()
    status_counts[st if st in ("FIXED", "DISMISSED") else "OTHER:" + st] += 1

  return {
      "findings_expected": len(expected_ids),
      "findings_attempted": sum(1 for c in exit_codes.values() if c is not None),
      "patches_generated": patches_generated,
      "patch_sizes": patch_sizes,
      "exploits_imported": exploits_imported,
      "status_counts": dict(status_counts),
      "timeout_count": sum(1 for c in exit_codes.values() if c in TIMEOUT_CODES),
      "nonzero_exit_count": sum(1 for c in exit_codes.values() if c not in (0, None)),
      "exit_codes": exit_codes,
      "tokens": dict(tokens),
  }


def _int_or_none(value):
  try:
    return int(value)
  except (TypeError, ValueError):
    return None


# cm's PR delta scan lines (0.10.0/0.11.0). The scan has a hard-coded
# 5-minute ceiling; entrypoint.sh's diff_timed_out greps the same messages.
DELTA_COMPLETE_RE = re.compile(
    r"PR Delta Scan Complete: (\d+) jobs? \((\d+) succeeded, (\d+) failed\)")
DELTA_TIMEOUT_RE = re.compile(
    r"PR delta scan timed out after \S+ \((\d+)/(\d+) jobs completed\)")
DELTA_CEILING_RE = re.compile(
    r"PR Delta Scan (?:reached|terminated: reached)[^\n]*ceiling")


def diff_job_stats(log_text):
  """Parses cm's delta-scan outcome from execution.log.

  diff_timed_out is true when cm stopped at its 5-minute ceiling; job counts
  are null when cm printed none.
  """
  out = {"diff_timed_out": bool(DELTA_TIMEOUT_RE.search(log_text)
                                or DELTA_CEILING_RE.search(log_text)),
         "diff_jobs_total": None, "diff_jobs_completed": None,
         "diff_jobs_failed": None}
  if m := DELTA_COMPLETE_RE.search(log_text):
    total, ok, failed = (int(x) for x in m.groups())
    out.update(diff_jobs_total=total, diff_jobs_completed=ok + failed,
               diff_jobs_failed=failed)
  elif m := DELTA_TIMEOUT_RE.search(log_text):
    out.update(diff_jobs_completed=int(m.group(1)),
               diff_jobs_total=int(m.group(2)))
  return out


def diff_fields(results_dir, a):
  """Diff-mode-only fields; changed_* come from the task's diff_stats.json.

  cm_exit_code is cm's raw exit (its --fail-on gate or 5-minute ceiling may
  make it 1 while exit_code is 0); diff_workers is null when cm used its
  default; diff_timed_out / diff_jobs_* come from logs/execution.log.
  """
  rd = pathlib.Path(results_dir)
  stats = _load_json(rd / "diff_stats.json", {})
  stats = stats if isinstance(stats, dict) else {}
  try:
    log_text = (rd / "logs" / "execution.log").read_text(errors="replace")
  except OSError:
    log_text = ""
  return {
      "pinned_ref": a.pinned_ref,
      "diff_ref": a.diff_ref,
      "changed_files": _int_or_none(stats.get("changed_files")),
      "changed_lines": _int_or_none(stats.get("changed_lines")),
      "cm_exit_code": _int_or_none(a.cm_exit_code),
      "diff_workers": _int_or_none(a.diff_workers),
      **diff_job_stats(log_text),
  }


def build(a):
  rd = pathlib.Path(a.results_dir)
  summary = {
      "operation": a.operation, "repo_id": a.repo_id,
      "run_id": a.run_id, "experiment_id": a.experiment_id, "model": a.model,
      "mode": a.mode, "cm_version": a.cm_version, "exit_code": a.exit_code,
      "start_epoch": a.start_epoch, "end_epoch": a.end_epoch,
      "wall_clock_seconds": max(0, a.end_epoch - a.start_epoch),
  }
  if a.operation == "find":
    findings = _load_json(rd / "findings.json")
    items = _items(findings)
    stats = _load_json(rd / "cm_api_token_stats.json", {})
    tokens = _tokens(stats)
    # New fields only for cm >= 0.10.0: 0.9.0 summaries stay byte-identical.
    if _version_at_least(a.cm_version, (0, 10)):
      summary.update({
          "deep_workers": int(a.deep_workers) if a.deep_workers else None,
          "sessions": session_counts(rd),
          "token_stats_status": _token_stats_status(stats),
      })
    counted_items = [
        f for f in items
        if str(f.get("status") or "").upper() != "DISMISSED"
    ]
    summary.update({
        "findings_count": len(counted_items),
        "severity_counts": dict(collections.Counter(
            str(f.get("severity") or "").upper() for f in counted_items)),
        "tokens": tokens,
    })
    if a.mode == "diff":
      summary.update(diff_fields(rd, a))
    if a.exit_code in TIMEOUT_CODES:
      status = "timeout"
    elif a.exit_code == 0 and tokens["total_tokens"] > 0 and findings is not None:
      status = "ok"
    else:
      status = "failed"
  elif a.operation == "fix":
    ids = []
    if a.ids_file and os.path.exists(a.ids_file):
      ids = [l.strip() for l in open(a.ids_file, encoding="utf-8") if l.strip()]
    details = fix_details(rd, ids)
    summary.update(details)
    summary["severity"] = a.severity
    summary["source_find_run"] = a.from_find_run
    summary["source_verify_run"] = a.from_verify_run
    if a.source_find_mode:
      summary["source_find_mode"] = a.source_find_mode
    ok = ((rd / "post_fix_report.json").exists()
          and details["findings_attempted"] == len(ids))
    if ok and a.exit_code == 0:
      status = "timeout" if details["timeout_count"] else "ok"
    elif a.exit_code in TIMEOUT_CODES:
      status = "timeout"
    else:
      status = "failed"
  else:
    ids = []
    if a.ids_file and os.path.exists(a.ids_file):
      ids = [l.strip() for l in open(a.ids_file, encoding="utf-8") if l.strip()]
    details = verify_details(rd, ids)
    summary.update(details)
    summary["severity"] = a.severity
    summary["source_find_run"] = a.from_find_run
    if a.source_find_mode:
      summary["source_find_mode"] = a.source_find_mode
    ok = ((rd / "post_verify_report.json").exists()
          and details["findings_attempted"] == len(ids))
    # Per-finding timeouts do not change the loop exit code, so check them too.
    if ok and a.exit_code == 0:
      status = "timeout" if details["timeout_count"] else "ok"
    elif a.exit_code in TIMEOUT_CODES:
      status = "timeout"
    else:
      status = "failed"
  summary["status"] = status
  return summary


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__)
  p.add_argument("--operation", choices=["find", "verify", "fix"], required=True)
  p.add_argument("--results-dir", required=True)
  p.add_argument("--repo-id", default="")
  p.add_argument("--run-id", default="")
  p.add_argument("--experiment-id", default="")
  p.add_argument("--model", default="")
  p.add_argument("--mode", default="")
  p.add_argument("--cm-version", default="")
  p.add_argument("--severity", default="")
  p.add_argument("--from-find-run", default="")
  p.add_argument("--from-verify-run", default="")
  p.add_argument("--exit-code", type=int, default=0)
  p.add_argument("--start-epoch", type=int, default=0)
  p.add_argument("--end-epoch", type=int, default=0)
  p.add_argument("--ids-file", default="")
  p.add_argument("--deep-workers", default="")
  p.add_argument("--source-find-mode", default="")
  p.add_argument("--pinned-ref", default="")
  p.add_argument("--diff-ref", default="")
  p.add_argument("--diff-workers", default="")
  p.add_argument("--cm-exit-code", default="")
  a = p.parse_args(argv)
  summary = build(a)
  out = pathlib.Path(a.results_dir) / "summary.json"
  out.write_text(json.dumps(summary, indent=2) + "\n")
  print(f"summary: status={summary['status']}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
