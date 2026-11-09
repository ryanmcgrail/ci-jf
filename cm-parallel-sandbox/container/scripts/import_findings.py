#!/usr/bin/env python3
"""Imports a find-stage findings.json into cm's state.db for `cm verify` or `cm fix`.

Normalizes file paths to
--repo-dir, filters by --severity, --finding-ids, --verify-report, or --attempted-ids,
and upserts findings (keeping finding_id) into state.db.
Columns are introspected, so a schema already created by `cm init`
wins; missing tables are created with the cm 0.9.0 layout. Matching finding IDs
are written one per line to --ids-out, in severity order.
"""

import argparse
import datetime
import json
import os
import pathlib
import re
import shutil
import sqlite3
import sys

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SESSIONS_DDL = """CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY, operation_name TEXT NOT NULL DEFAULT '',
  session_type TEXT NOT NULL, status TEXT NOT NULL,
  pipeline_mode TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  project_root TEXT DEFAULT '', last_seq_num INTEGER DEFAULT 0)"""

FINDINGS_DDL = """CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, title TEXT,
  file_path TEXT, severity TEXT, confidence INTEGER, analysis TEXT, snippet TEXT,
  vuln_type TEXT, vuln_id TEXT, verified INTEGER DEFAULT 0, muted INTEGER DEFAULT 0,
  mute_reason TEXT, created_at TEXT NOT NULL, fingerprint TEXT DEFAULT '',
  status TEXT DEFAULT 'OPEN', source_stage TEXT DEFAULT '',
  finding_json TEXT DEFAULT '{}', updated_at TEXT DEFAULT '',
  start_line INTEGER DEFAULT 0, end_line INTEGER DEFAULT 0,
  dismiss_reason TEXT DEFAULT '', confidence_level TEXT DEFAULT '')"""

ARTIFACTS_DDL = """CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL, filename TEXT NOT NULL,
  original_path TEXT DEFAULT '', purpose TEXT DEFAULT '',
  finding_id TEXT DEFAULT '', created_at TEXT NOT NULL)"""


def _get(f, *keys, default=None):
  for k in keys:
    if f.get(k) not in (None, ""):
      return f[k]
  return default


def load_items(path):
  with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
  if data is None:
    return []
  if isinstance(data, dict):
    return list(data.get("findings", [data]))
  return list(data)


def severity_of(f):
  return str(_get(f, "severity", "Severity", default="")).upper()


def filter_by_severity(items, severities):
  wanted = {s.strip().upper() for s in severities.split(",") if s.strip()}
  out = [f for f in items if severity_of(f) in wanted]
  return sorted(out, key=lambda f: SEVERITY_ORDER.get(severity_of(f), 9))


def normalize_path(fp, repo_id, repo_dir):
  """Maps an absolute path from the find task onto repo_dir."""
  if not fp:
    return repo_dir
  rel = fp
  marker = f"/{repo_id}/"
  if marker in fp:
    rel = fp.split(marker, 1)[1]
  else:
    rel = re.sub(r"^/home/[^/]+/(workspace|repos)/[^/]+/", "", fp)
  return os.path.join(repo_dir, rel.lstrip("/"))


def _columns(conn, table):
  return [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]


def _upsert(conn, table, row):
  cols = [c for c in _columns(conn, table) if c in row]
  sql = (f"INSERT OR REPLACE INTO {table} ({', '.join(cols)}) "
         f"VALUES ({', '.join('?' for _ in cols)})")
  conn.execute(sql, [row[c] for c in cols])


def import_findings(items, db_path, repo_id, repo_dir,
                    exploits_dir=None, artifacts_root=None):
  pathlib.Path(db_path).parent.mkdir(parents=True, exist_ok=True)
  artifacts_root = pathlib.Path(
      artifacts_root or os.path.expanduser("~/.codemender/artifacts"))
  now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
  conn = sqlite3.connect(str(db_path))
  try:
    conn.execute(SESSIONS_DDL)
    conn.execute(FINDINGS_DDL)
    ids = []
    for f in items:
      fid = _get(f, "finding_id", "FindingID")
      if not fid:
        raise ValueError("finding without finding_id")

      if exploits_dir:
        edir = pathlib.Path(exploits_dir) / fid
        if edir.is_dir():
          reg_files = []
          for root, _, files in os.walk(edir):
            for fn in sorted(files):
              full_src = os.path.join(root, fn)
              if not os.path.islink(full_src) and os.path.isfile(full_src):
                rel = os.path.relpath(full_src, edir)
                reg_files.append((full_src, rel))
          if reg_files:
            conn.execute(ARTIFACTS_DDL)
            verify_sid = f"sess_verify_{fid[:8]}"
            _upsert(conn, "sessions", {
                "session_id": verify_sid,
                "operation_name": "verify",
                "session_type": "VERIFY",
                "pipeline_mode": "VERIFY",
                "status": "COMPLETED",
                "target": fid,
                "project_root": repo_dir,
                "created_at": now,
                "updated_at": now,
            })
            conn.execute("DELETE FROM artifacts WHERE session_id = ?", (verify_sid,))
            dest_session_dir = artifacts_root / verify_sid
            for full_src, rel in reg_files:
              dest_path = dest_session_dir / rel
              dest_path.parent.mkdir(parents=True, exist_ok=True)
              shutil.copy2(full_src, dest_path)
              orig_p = os.path.join(repo_dir, ".exploit", rel)
              _upsert(conn, "artifacts", {
                  "session_id": verify_sid,
                  "filename": rel,
                  "original_path": orig_p,
                  "purpose": "Exploit artifact collected from .exploit directory",
                  "finding_id": fid,
                  "created_at": now,
              })
            f["verified"] = 1
            f["status"] = "VERIFIED"

      sid = _get(f, "session_id", "SessionID", default=f"sess_import_{fid[:8]}")
      _upsert(conn, "sessions", {
          "session_id": sid, "operation_name": "find", "session_type": "FIND",
          "status": "COMPLETED", "pipeline_mode": "", "target": repo_dir,
          "project_root": repo_dir, "created_at": now, "updated_at": now})
      fp = normalize_path(_get(f, "file_path", "FilePath", default=""), repo_id,
                          repo_dir)
      start = int(_get(f, "start_line", "StartLine", default=0) or 0)
      verified_val = int(_get(f, "verified", "Verified", default=0) or 0)
      status_val = _get(f, "status", "Status", default="OPEN")
      _upsert(conn, "findings", {
          "finding_id": fid, "session_id": sid,
          "title": _get(f, "title", "Title", default=""),
          "file_path": fp, "severity": severity_of(f) or "MEDIUM",
          "confidence": _get(f, "confidence", "Confidence", default=100),
          "analysis": _get(f, "analysis", "Analysis", default=""),
          "snippet": _get(f, "snippet", "Snippet", default=""),
          "vuln_type": _get(f, "vuln_type", "VulnType", default=""),
          "vuln_id": _get(f, "vuln_id", "VulnID", default=""),
          "verified": verified_val, "muted": 0, "mute_reason": "",
          "fingerprint": _get(f, "fingerprint", "Fingerprint", default=""),
          "status": status_val, "source_stage": "find",
          "finding_json": json.dumps(f), "start_line": start,
          "end_line": int(_get(f, "end_line", "EndLine", default=start) or start),
          "dismiss_reason": _get(f, "dismiss_reason", "DismissReason", default=""),
          "confidence_level": _get(f, "confidence_level", "ConfidenceLevel",
                                   default=""),
          "created_at": now, "updated_at": now})
      ids.append(fid)
    conn.commit()
    return ids
  finally:
    conn.close()


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__)
  p.add_argument("--findings", required=True, help="find-stage findings.json")
  p.add_argument("--repo-dir", required=True)
  p.add_argument("--repo-id", required=True)
  p.add_argument("--severity", default="CRITICAL,HIGH")
  p.add_argument("--db-path",
                 default=os.path.expanduser("~/.codemender/state.db"))
  p.add_argument("--ids-out", required=True)
  p.add_argument("--filtered-out", default="",
                 help="optional path for the filtered, normalized findings JSON")
  p.add_argument("--verify-report", default="",
                 help="path to post_verify_report.json")
  p.add_argument("--attempted-ids", default="",
                 help="path to matching_finding_ids.txt from verify stage")
  p.add_argument("--only-verified", action="store_true",
                 help="keep only verified findings")
  p.add_argument("--finding-ids", default="",
                 help="comma-separated finding UUIDs or prefixes")
  p.add_argument("--exploits-dir", default="",
                 help="directory containing per-finding exploit archives")
  p.add_argument("--artifacts-root",
                 default=os.path.expanduser("~/.codemender/artifacts"),
                 help="root directory for codemender artifacts")
  a = p.parse_args(argv)

  items = load_items(a.findings)
  for item in items:
    item["status"] = "OPEN"
    item["verified"] = 0

  if a.verify_report and os.path.exists(a.verify_report):
    v_items = load_items(a.verify_report)
    by_id = {str(_get(r, "finding_id", "FindingID")): r for r in v_items}
    for item in items:
      fid = str(_get(item, "finding_id", "FindingID"))
      if fid in by_id:
        rep = by_id[fid]
        for k in ("status", "confidence", "analysis", "verified", "dismiss_reason", "confidence_level"):
          val = _get(rep, k)
          if val is not None:
            item[k] = val
        if str(_get(item, "status", default="")).upper() == "VERIFIED":
          item["verified"] = 1

  if a.attempted_ids and os.path.exists(a.attempted_ids):
    with open(a.attempted_ids, encoding="utf-8") as f:
      attempted = {line.strip() for line in f if line.strip()}
    items = [f for f in items if str(_get(f, "finding_id", "FindingID")) in attempted]

  if a.only_verified:
    items = [f for f in items if str(_get(f, "status", default="")).upper() == "VERIFIED"]
  elif a.verify_report:
    items = [f for f in items if str(_get(f, "status", default="")).upper() != "DISMISSED"]

  if a.finding_ids:
    prefixes = [p.strip() for p in a.finding_ids.split(",") if p.strip()]
    if prefixes:
      items = [f for f in items if any(str(_get(f, "finding_id", "FindingID", default="")).startswith(p) for p in prefixes)]
      items = sorted(items, key=lambda f: SEVERITY_ORDER.get(severity_of(f), 9))
    else:
      items = filter_by_severity(items, a.severity)
  else:
    items = filter_by_severity(items, a.severity)

  ids = import_findings(items, a.db_path, a.repo_id, a.repo_dir,
                        exploits_dir=a.exploits_dir, artifacts_root=a.artifacts_root)
  with open(a.ids_out, "w", encoding="utf-8") as f:
    f.write("".join(i + "\n" for i in ids))
  if a.filtered_out:
    with open(a.filtered_out, "w", encoding="utf-8") as f:
      json.dump(items, f, indent=2)
  print(f"imported {len(ids)} finding(s) matching {a.severity}")
  return 0


if __name__ == "__main__":
  sys.exit(main())
