"""Multi-pass complete scan orchestration on top of CodeMender deep scans."""

import json
import os
import re
import sqlite3
import types
import uuid
from typing import Any, Dict, Iterable, List, Optional, Set

from codemender import CodeMender, ScanMode
from deduplication import dedup, remove_duplicates_in_db
from finding import Finding

# Matches per-batch completion lines emitted by `cm find --deep`, e.g.:
#   [1/124 batches] ✅ data/static/codefixes/forgedReviewChallenge_3.ts (1m13.6s) | 14.2k tok - 0 vulnerabilities
_DEEP_BATCH_LINE_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+\S+\s+(\S+)\s+\([^)]+\)\s+\|.*-\s+\d+\s+vulnerabilit",
    re.MULTILINE,
)
# Matches per-batch failure lines emitted by `cm find --deep`, e.g.:
#   [2/12 batches] ❌ routes/auth.js — session failed
_DEEP_FAILED_BATCH_LINE_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+(?:❌|✗|FAIL)\S*\s+(\S+)",
    re.MULTILINE,
)


def _rel_target_path(
    file_path: str,
    repo_dir: str,
    repo_real: str,
    project_root: str = "",
) -> str:
  """Normalizes a session target or finding file_path to a case-preserved repo-relative path."""
  path = (file_path or "").strip()
  if not path:
    return ""
  for root in (repo_dir, repo_real, project_root):
    if not root or root == ".":
      continue
    prefix = root.rstrip("/\\") + "/"
    if path.startswith(prefix):
      return path[len(prefix) :].lstrip("./")
  return path.lstrip("./")


def _extract_batch_files_from_stdout(stdout: str) -> List[str]:
  """Extracts repo-relative file paths from `cm find --deep` batch progress lines."""
  if not stdout:
    return []
  seen: Set[str] = set()
  ordered: List[str] = []
  for match in _DEEP_BATCH_LINE_RE.finditer(stdout):
    rel_path = match.group(1).strip().lstrip("./")
    if rel_path and rel_path not in seen:
      seen.add(rel_path)
      ordered.append(rel_path)
  return ordered


def _extract_failed_batch_files_from_stdout(stdout: str) -> Set[str]:
  """Extracts repo-relative file paths from failed `cm find --deep` batch lines."""
  if not stdout:
    return set()
  return {
      match.group(1).strip().lstrip("./")
      for match in _DEEP_FAILED_BATCH_LINE_RE.finditer(stdout)
      if match.group(1).strip().lstrip("./")
  }


def get_latest_session_finding_counts(
    cm: CodeMender,
    last_pass_files: Optional[Iterable[str]] = None,
    last_pass_stdout: Optional[str] = None,
) -> Dict[str, int]:
  """Returns the active finding count of the most recent FIND session per target.

  Handles two important edge cases in `cm find --deep`:
    1. Promoted parent sessions: In every pass of N files, `cm`'s
       `finalizePrimarySession` promotes the first worker session that finishes
       (`batch [1/N]`) to be the parent session for the whole pass, overwriting
       its `sessions.target` to the repository root (`project_root`) and setting
       `parent_session_id = ''`. We attribute active findings on parent sessions
       back to their `findings.file_path`, and recover 0-finding promoted
       sessions via `last_pass_files` / `last_pass_stdout`.
    2. Failed, timed-out, or incomplete per-file sessions (`status != 'COMPLETED'`):
       Included in the query and assigned a minimum count of 1 so they remain in
       `active_files` (and out of `.cmignore`) and are retried on the next pass
       rather than being silently dropped or causing premature convergence.
  """
  con = cm.db
  if con is None:
    return {}
  repo_real = os.path.realpath(cm.repo_dir)
  try:
    session_rows = con.execute(
        """
        SELECT s.session_id,
               s.status,
               s.target,
               s.project_root,
               s.parent_session_id,
               EXISTS (
                   SELECT 1 FROM sessions c WHERE c.parent_session_id = s.session_id
               ) AS has_children,
               (SELECT COUNT(*) FROM findings f
                WHERE f.session_id = s.session_id
                  AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED')) AS finding_count
        FROM sessions s
        WHERE s.session_type = 'FIND'
          AND s.target != ''
          AND (s.project_root = '' OR s.project_root = ? OR s.project_root = ?)
        ORDER BY s.updated_at ASC, s.created_at ASC, s.rowid ASC
        """,
        (cm.repo_dir, repo_real),
    ).fetchall()
    finding_cols = {
        desc[1]
        for desc in con.execute("PRAGMA table_info(findings)").fetchall()
    }
  except sqlite3.Error:
    return {}

  has_file_path_col = "file_path" in finding_cols
  latest_counts: Dict[str, int] = {}
  latest_parent_id: Optional[str] = None
  child_targets_by_parent: Dict[str, Set[str]] = {}
  parent_finding_targets: Dict[str, Set[str]] = {}

  for (
      session_id,
      status,
      target,
      project_root,
      parent_session_id,
      has_children,
      finding_count,
  ) in session_rows:
    sid = str(session_id)
    is_completed = str(status or "").upper() == "COMPLETED"
    target_str = str(target or "")
    proj_root_str = str(project_root or "")
    parent_id_str = str(parent_session_id or "")
    is_root_target = target_str in (".", cm.repo_dir, repo_real, proj_root_str)

    if has_children or is_root_target:
      # Promoted parent/root session: its original per-file `s.target` was
      # overwritten to the repo root by `cm` (unless already restored on a
      # previous pass). Recover any active findings recorded under this
      # session_id by grouping on `findings.file_path`.
      latest_parent_id = sid
      parent_finding_targets.setdefault(sid, set())
      if not is_root_target:
        rel_target = _rel_target_path(
            target_str, cm.repo_dir, repo_real, proj_root_str
        )
        if rel_target:
          latest_counts[rel_target] = (
              int(finding_count) if is_completed else max(int(finding_count), 1)
          )
          if int(finding_count) > 0:
            parent_finding_targets[sid].add(rel_target)
      if has_file_path_col and int(finding_count) > 0:
        try:
          f_rows = con.execute(
              """
              SELECT f.file_path, COUNT(*)
              FROM findings f
              WHERE f.session_id = ?
                AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED')
                AND f.file_path IS NOT NULL
                AND f.file_path != ''
              GROUP BY f.file_path
              """,
              (sid,),
          ).fetchall()
        except sqlite3.Error:
          f_rows = []
        for raw_fp, f_cnt in f_rows:
          rel_fp = _rel_target_path(
              str(raw_fp), cm.repo_dir, repo_real, proj_root_str
          )
          if rel_fp:
            latest_counts[rel_fp] = int(f_cnt)
            parent_finding_targets[sid].add(rel_fp)
    else:
      rel_target = _rel_target_path(
          target_str, cm.repo_dir, repo_real, proj_root_str
      )
      if rel_target:
        # If the per-file session did not complete (e.g. FAILED, CANCELLED,
        # INTERRUPTED), assign a count >= 1 so the file stays in `active_files`
        # and is re-audited on the next pass.
        latest_counts[rel_target] = (
            int(finding_count) if is_completed else max(int(finding_count), 1)
        )
        if parent_id_str:
          latest_parent_id = parent_id_str
          child_targets_by_parent.setdefault(parent_id_str, set()).add(
              rel_target
          )

  failed_stdout_files = (
      _extract_failed_batch_files_from_stdout(last_pass_stdout)
      if last_pass_stdout
      else set()
  )
  for failed_file in failed_stdout_files:
    latest_counts[failed_file] = max(latest_counts.get(failed_file, 0), 1)

  # Recover the 0-finding promoted session for the most recent pass:
  # Any file known to have been audited in the latest pass (from `last_pass_files`
  # on Pass 2+ or from `[i/N batches]` stdout lines on Pass 1+) that did not
  # appear as a child session of the latest pass, did not fail, and had 0 active
  # findings on the latest parent session must have been the promoted parent
  # session with 0 findings.
  known_last_pass_files: List[str] = []
  if last_pass_files:
    known_last_pass_files.extend(
        _rel_target_path(f, cm.repo_dir, repo_real) for f in last_pass_files
    )
  if last_pass_stdout:
    known_last_pass_files.extend(
        _extract_batch_files_from_stdout(last_pass_stdout)
    )

  if known_last_pass_files:
    latest_children = (
        child_targets_by_parent.get(latest_parent_id, set())
        if latest_parent_id
        else set()
    )
    latest_parent_with_findings = (
        parent_finding_targets.get(latest_parent_id, set())
        if latest_parent_id
        else set()
    )
    unaccounted_clean: List[str] = []
    for rel_file in known_last_pass_files:
      if (
          rel_file
          and rel_file not in latest_children
          and rel_file not in latest_parent_with_findings
          and rel_file not in failed_stdout_files
      ):
        latest_counts[rel_file] = 0
        if rel_file not in unaccounted_clean:
          unaccounted_clean.append(rel_file)
    if latest_parent_id and not latest_parent_with_findings:
      promoted_target: Optional[str] = None
      if len(unaccounted_clean) == 1:
        promoted_target = unaccounted_clean[0]
      elif last_pass_stdout:
        stdout_unaccounted = [
            f
            for f in _extract_batch_files_from_stdout(last_pass_stdout)
            if f not in latest_children
            and f not in latest_parent_with_findings
            and f not in failed_stdout_files
        ]
        if len(stdout_unaccounted) == 1:
          promoted_target = stdout_unaccounted[0]
      if promoted_target:
        try:
          con.execute(
              "UPDATE sessions SET target = ? WHERE session_id = ?",
              (promoted_target, latest_parent_id),
          )
          con.commit()
        except sqlite3.Error:
          pass

  return latest_counts


def _snapshot_db_findings(cm: CodeMender) -> Dict[str, Dict[str, Any]]:
  """Captures a snapshot of existing rows in state.db findings keyed by finding_id."""
  con = cm.db
  if con is None:
    return {}
  try:
    cur = con.execute("SELECT * FROM findings ORDER BY rowid ASC")
    col_names = [desc[0] for desc in (cur.description or [])]
    rows = cur.fetchall()
  except sqlite3.Error:
    return {}
  if not rows or "finding_id" not in col_names:
    return {}
  snapshot: Dict[str, Dict[str, Any]] = {}
  for row in rows:
    row_dict = dict(zip(col_names, row))
    fid = row_dict.get("finding_id")
    if fid:
      snapshot[str(fid)] = row_dict
  return snapshot


def _reconcile_overwritten_findings(
    cm: CodeMender,
    pre_pass_rows: Dict[str, Dict[str, Any]],
) -> None:
  """Reconciles findings overwritten in-place by cm when a fingerprint collides across passes."""
  if not pre_pass_rows:
    return
  con = cm.db
  if con is None:
    return
  try:
    cur = con.execute("SELECT * FROM findings ORDER BY rowid ASC")
    col_names = [desc[0] for desc in (cur.description or [])]
    rows = cur.fetchall()
  except sqlite3.Error:
    return
  if not rows or "finding_id" not in col_names or "session_id" not in col_names:
    return

  changed = False
  for row in rows:
    cur_row = dict(zip(col_names, row))
    fid = str(cur_row.get("finding_id") or "")
    if not fid or fid not in pre_pass_rows:
      continue
    old_row = pre_pass_rows[fid]
    old_sid = old_row.get("session_id")
    cur_sid = cur_row.get("session_id")
    if not old_sid or not cur_sid or cur_sid == old_sid:
      continue

    try:
      old_sl = int(old_row.get("start_line") or 0)
    except (TypeError, ValueError):
      old_sl = 0
    try:
      old_el = max(int(old_row.get("end_line") or old_sl), old_sl)
    except (TypeError, ValueError):
      old_el = old_sl
    try:
      cur_sl = int(cur_row.get("start_line") or 0)
    except (TypeError, ValueError):
      cur_sl = 0
    try:
      cur_el = max(int(cur_row.get("end_line") or cur_sl), cur_sl)
    except (TypeError, ValueError):
      cur_el = cur_sl

    if old_sl > 0 and cur_sl > 0 and (old_el < cur_sl or cur_el < old_sl):
      # Distinct non-overlapping sinks in the same file collided on identical snippet text.
      # Re-insert the overwritten prior finding under a disambiguated finding_id.
      disambiguated_id = str(
          uuid.uuid5(uuid.NAMESPACE_DNS, f"{fid}:{old_sl}:{old_el}")
      )
      restored = dict(old_row)
      restored["finding_id"] = disambiguated_id
      if isinstance(restored.get("finding_json"), str) and restored["finding_json"]:
        try:
          fjson = json.loads(restored["finding_json"])
          if isinstance(fjson, dict):
            fjson["finding_id"] = disambiguated_id
            restored["finding_json"] = json.dumps(fjson)
        except json.JSONDecodeError:
          pass
      placeholders = ", ".join("?" * len(col_names))
      cols_sql = ", ".join(col_names)
      try:
        con.execute(
            f"INSERT OR IGNORE INTO findings ({cols_sql}) VALUES ({placeholders})",
            [restored.get(c) for c in col_names],
        )
        changed = True
      except sqlite3.Error:
        pass
    else:
      # Same vulnerability re-reported in a later pass: restore original session_id
      # so get_latest_session_finding_counts does not treat it as a new finding.
      try:
        con.execute(
            "UPDATE findings SET session_id = ? WHERE finding_id = ?",
            (old_sid, fid),
        )
        changed = True
      except sqlite3.Error:
        pass

  if changed:
    try:
      con.commit()
    except sqlite3.Error:
      pass


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
  """Runs sequential deep scans, tracking clean files in .cmignore, scoping follow-up passes to active files, and stopping early when converged."""
  cmignore_path = (
      os.path.join(cm.repo_dir, ".cmignore")
      if os.path.isdir(cm.repo_dir)
      else None
  )
  orig_cmignore: Optional[str] = None
  if cmignore_path and os.path.exists(cmignore_path):
    with open(cmignore_path, "r", encoding="utf-8") as fh:
      orig_cmignore = fh.read()

  try:
    result = None
    prev_active_files: Optional[List[str]] = None
    cleared_files: Set[str] = set()
    for scan_index in range(complete_runs):
      active_files: Optional[List[str]] = None
      if scan_index > 0:
        last_stdout = getattr(result, "stdout", "") if result is not None else ""
        counts = get_latest_session_finding_counts(
            cm,
            last_pass_files=prev_active_files,
            last_pass_stdout=last_stdout,
        )
        for cleared in cleared_files:
          counts[cleared] = 0
        cleared_files.update(t for t, c in counts.items() if c == 0)
        clean_files = sorted(t for t, c in counts.items() if c == 0)
        active_files = sorted(t for t, c in counts.items() if c > 0)
        if counts and not active_files:
          break
        if cmignore_path:
          base = orig_cmignore or ""
          if base and not base.endswith("\n"):
            base += "\n"
          extra = "".join(f"{f}\n" for f in clean_files)
          with open(cmignore_path, "w", encoding="utf-8") as clean_f:
            clean_f.write(base + extra)
      pre_pass_rows = _snapshot_db_findings(cm) if scan_index > 0 else {}
      result = cm.find(
          target_or_id=target_or_id,
          scan_mode=ScanMode.DEEP,
          extra_flags=extra_flags,
          max_turns=12 if scan_index > 0 else 8,
          active_files=active_files or None,
      )
      prev_active_files = active_files
      if scan_index > 0:
        _reconcile_overwritten_findings(cm, pre_pass_rows)
      deduplicate_db_findings(cm)
    return result
  finally:
    if cmignore_path:
      if orig_cmignore is not None:
        with open(cmignore_path, "w", encoding="utf-8") as fh:
          fh.write(orig_cmignore)
      elif os.path.exists(cmignore_path):
        os.remove(cmignore_path)

