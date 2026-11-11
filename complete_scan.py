"""Multi-pass complete scan orchestration on top of CodeMender deep scans."""

import os
import sqlite3
import tempfile
import types
from typing import Any, Dict, List, Optional

from codemender import CodeMender, ScanMode
from deduplication import dedup, remove_duplicates_in_db
from finding import Finding


def get_latest_session_finding_counts(cm: CodeMender) -> Dict[str, int]:
  """Returns the active finding count of the most recent completed per-file FIND session per target."""
  con = cm.db
  if con is None:
    return {}
  repo_real = os.path.realpath(cm.repo_dir)
  try:
    rows = con.execute(
        """
        SELECT s.target,
               (SELECT COUNT(*) FROM findings f
                WHERE f.session_id = s.session_id
                  AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED')) AS finding_count
        FROM sessions s
        WHERE s.session_type = 'FIND'
          AND s.status = 'COMPLETED'
          AND s.target != ''
          AND s.target != '.'
          AND (s.project_root = '' OR s.project_root = ? OR s.project_root = ?)
          AND NOT EXISTS (
              SELECT 1 FROM sessions c WHERE c.parent_session_id = s.session_id
          )
        ORDER BY s.updated_at ASC, s.created_at ASC, s.rowid ASC
        """,
        (cm.repo_dir, repo_real),
    ).fetchall()
  except sqlite3.Error:
    return {}
  latest_counts: Dict[str, int] = {}
  for target, count in rows:
    latest_counts[str(target)] = int(count)
  return latest_counts


def deduplicate_db_findings(cm: CodeMender) -> None:
  """Deduplicates active findings in state.db so inter-pass duplicates do not keep files active."""
  con = cm.db
  if con is None:
    return
  try:
    cur = con.execute("SELECT * FROM findings ORDER BY rowid ASC")
    col_names = [desc[0] for desc in (cur.description or [])]
    rows = cur.fetchall()
  except sqlite3.Error:
    return
  if not rows or "file_path" not in col_names:
    return
  findings = [
      Finding.from_dict(dict(zip(col_names, row)))
      for row in rows
  ]
  res = dedup([], findings, cm.repo_dir)
  if res["suppressed_duplicates"]:
    remove_duplicates_in_db(
        types.SimpleNamespace(cm=cm),
        res["suppressed_duplicates"],
    )


def run_complete_scan(
    cm: CodeMender,
    target_or_id: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
    complete_runs: int = 5,
) -> Any:
  """Runs sequential deep scans, tracking clean files, scoping follow-up passes to active files, and stopping early when converged."""
  temp_dir = cm.repo_dir if os.path.isdir(cm.repo_dir) else None
  with tempfile.NamedTemporaryFile(
      mode="w",
      suffix="",
      dir=temp_dir,
      delete=False,
      encoding="utf-8",
  ) as clean_tmp_file:
    clean_files_file = clean_tmp_file.name

  try:
    result = None
    for scan_index in range(complete_runs):
      active_files: Optional[List[str]] = None
      if scan_index > 0:
        counts = get_latest_session_finding_counts(cm)
        clean_files = sorted(t for t, c in counts.items() if c == 0)
        active_files = sorted(t for t, c in counts.items() if c > 0)
        if counts and not active_files:
          break
        with open(clean_files_file, "w", encoding="utf-8") as clean_f:
          if clean_files:
            clean_f.write("\n".join(clean_files) + "\n")
      result = cm.find(
          target_or_id=target_or_id,
          scan_mode=ScanMode.DEEP,
          extra_flags=extra_flags,
          clean_files_file=clean_files_file if scan_index > 0 else None,
          max_turns=12 if scan_index > 0 else 8,
          active_files=active_files or None,
      )
      deduplicate_db_findings(cm)
    return result
  finally:
    if os.path.exists(clean_files_file):
      os.remove(clean_files_file)

