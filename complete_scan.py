"""Multi-pass complete scan orchestration on top of CodeMender deep scans."""

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import codemender
from codemender import CodeMender, ScanMode
import covered_lines
from cwe_database import parse_cwe_id
from deduplication import (
    CWE_DB,
    deduplicate_db_findings,
    reconcile_overwritten_findings,
    snapshot_db_findings,
)
from finding import Finding

_DISCOURAGED_CWES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "discouraged_cwes.txt",
)
_SAFETY_ESCALATION_MODEL = "gemini-4-argon"
_ACTIVE_REPORT_STATUSES = frozenset({"OPEN", "VERIFIED", "REOPENED"})
_FIND_CONTEXT_FOR_FIRST_PASS = """\
# Audit Strategy
- Audit the entire target file in a single pass, reporting each distinct vulnerable endpoint, route, or function separately with at most one finding per vulnerable sink or code block (when multiple impacts share one sink, report a single finding using the most specific root-cause CWE).
- Anchor each finding directly at the sink or security defect—never on pure pass-through wrappers/callers or sinkless intra-file helpers, validators, or sanitizers (and report shared file-level auth/state defects once at their definition rather than per caller).
- Scope each snippet and line range strictly to the minimal contiguous sink lines (never the whole enclosing function, and never bridge non-contiguous lines with `...`).
- Check cross-file callers, routes, or auth helpers only when needed to verify untrusted input reachability or authentication/authorization enforcement; never blanket-skip internal services, workers, or serverless handlers that process untrusted DB, queue, storage, or RPC payloads.
- Grade directly exploitable injection (SQL/NoSQL/LDAP/OS/code/XSS/XXE/SSTI), authentication or token/signature validation bypass, missing authorization/IDOR on sensitive data or state, SSRF, unrestricted file upload, and hardcoded or cleartext credential storage as `HIGH` or `CRITICAL` when reachable without prior privileged access.
- Ignore tests, build/package manifests, developer CLI/deployment scripts, `.codemender` files, and vendored or minified third-party libraries (if the target file is third-party/vendored code, stop immediately and report 0).

# CWE Requirements
- Assign each finding exactly one specific Base/Variant/Class Weakness `CWE-<number>`—never a CWE Category, View, Pillar, Deprecated ID, code-quality metric (`CWE-1041`–`CWE-1127`), or discouraged weakness ({discouraged_cwes})."""
_FIND_CONTEXT_FOR_LATER_PASSES = f"""\
# Initial Pre-Audit Check
- First, run `grep_search` on "{{report_file}}" for this target file's repo-relative path to check its already-covered line ranges/snippets (if any).
- Never re-report a covered vulnerability (its covered/sink lines, enclosing declaration/caller, or any intra-file helper/validator/sanitizer whose caller/sink in this file is already covered, or vice versa); audit the remaining uncovered lines and report 0 if no distinct vulnerabilities remain.

{_FIND_CONTEXT_FOR_FIRST_PASS}"""


def _load_discouraged_cwes() -> str:
  """Returns the concise non-deprecated, non-Pillar discouraged security CWEs for prompt guidance."""
  if CWE_DB.prompt_discouraged_ids:
    return ", ".join(f"CWE-{cid}" for cid in CWE_DB.prompt_discouraged_ids)
  if not os.path.exists(_DISCOURAGED_CWES_PATH):
    return ""
  with open(_DISCOURAGED_CWES_PATH, "r", encoding="utf-8") as cwe_f:
    return ", ".join(cwe_f.read().split())


def _strip_dot_slash(path: str) -> str:
  """Strips leading `./` and `/` prefixes without stripping leading dots on hidden directories like `.github`."""
  p = path
  while p.startswith("./"):
    p = p[2:]
  return p.lstrip("/")


def _format_cmignore_entry(rel_path: str) -> str:
  """Formats a repo-relative path for `.cmignore` without leading `/` (`cm` matches slashless `relPath`)."""
  entry = _strip_dot_slash(rel_path)
  if entry.startswith(("#", "!")):
    entry = "\\" + entry
  if entry.endswith(" "):
    entry = entry[:-1] + "\\ "
  return entry


def _filter_cmignore_entries(
    ignored_files: Iterable[str],
    keep_files: Optional[Iterable[str]] = None,
) -> List[str]:
  """Formats sorted `.cmignore` entries while avoiding root-basename shadowing.

  `cm` matches `.cmignore` patterns containing `/` against the full repo-relative
  path, whereas patterns without `/` are matched against `filepath.Base(relPath)`
  across all subdirectories. If a root-level file (no `/`) is ignored while a
  subdirectory file with the same basename remains active, omit the root-level
  entry so the subdirectory file is still audited.
  """
  protected_basenames_lower: Set[str] = set()
  if keep_files:
    for kept in keep_files:
      norm_kept = _strip_dot_slash(str(kept or ""))
      if norm_kept:
        protected_basenames_lower.add(os.path.basename(norm_kept).lower())

  entries: List[str] = []
  for raw in sorted({_strip_dot_slash(str(f or "")) for f in ignored_files}):
    if not raw:
      continue
    if "/" not in raw and raw.lower() in protected_basenames_lower:
      continue
    entries.append(_format_cmignore_entry(raw))
  return entries


def _normalize_report_file_path(file_path: str, repo_dir: str = "") -> str:
  """Normalizes a finding file_path to a repo-relative path."""
  path = (file_path or "").strip().replace("\\", "/")
  if not path:
    return ""
  roots = []
  if repo_dir:
    for candidate in (
        repo_dir,
        os.path.abspath(repo_dir),
        os.path.realpath(repo_dir),
    ):
      norm_root = candidate.strip().replace("\\", "/").rstrip("/")
      if norm_root and norm_root != "." and norm_root not in roots:
        roots.append(norm_root)
  for root in roots:
    prefix = root + "/"
    if path.startswith(prefix):
      return _strip_dot_slash(path[len(prefix) :])
  return _strip_dot_slash(path)


def preprocess_report_for_context(
    raw_report: str,
    repo_dir: str = "",
    exclude_finding_ids: Optional[Iterable[str]] = None,
) -> str:
  """Filters a raw `cm report --format json` output to OPEN/VERIFIED/REOPENED findings with repo-relative file_path and snippet."""
  text = (raw_report or "").strip()
  if not text or text == "null":
    return "[]"
  try:
    items, _ = json.JSONDecoder().raw_decode(text)
  except json.JSONDecodeError:
    return "[]"
  if not isinstance(items, list):
    return "[]"
  excluded = {str(fid) for fid in exclude_finding_ids if fid} if exclude_finding_ids else set()
  filtered = []
  for item in items:
    if not isinstance(item, dict):
      continue
    finding = Finding.from_dict(item)
    if excluded and str(finding.finding_id or "") in excluded:
      continue
    if finding.status in _ACTIVE_REPORT_STATUSES:
      filtered.append({
          "file_path": _normalize_report_file_path(finding.file_path, repo_dir),
          "snippet": finding.snippet,
      })
  return json.dumps(filtered, indent=2)


def build_covered_lines_report(
    raw_report: str,
    repo_dir: str = "",
    exclude_finding_ids: Optional[Iterable[str]] = None,
    only_files: Optional[Iterable[str]] = None,
) -> str:
  """Precomputes a compact, `grep_search`-friendly per-file covered-lines manifest on the host."""
  text = (raw_report or "").strip()
  if not text or text == "null":
    return ""
  try:
    raw_items, _ = json.JSONDecoder().raw_decode(text)
  except json.JSONDecodeError:
    return ""
  if not isinstance(raw_items, list) or not raw_items:
    return ""

  excluded = (
      {str(fid) for fid in exclude_finding_ids if fid}
      if exclude_finding_ids
      else set()
  )
  allowed_exact: Optional[Set[str]] = None
  allowed_lower: Optional[Set[str]] = None
  if only_files is not None:
    norm_only = {
        _normalize_report_file_path(f, repo_dir)
        for f in only_files
        if f and str(f).strip()
    }
    norm_only.discard("")
    if norm_only:
      allowed_exact = norm_only
      allowed_lower = {f.lower() for f in norm_only}

  grouped: Dict[str, List[Finding]] = {}
  for item in raw_items:
    if not isinstance(item, dict):
      continue
    finding = Finding.from_dict(item)
    if excluded and str(finding.finding_id or "") in excluded:
      continue
    if finding.status not in _ACTIVE_REPORT_STATUSES:
      continue
    rel_fp = _normalize_report_file_path(finding.file_path, repo_dir)
    if not rel_fp:
      continue
    if allowed_exact is not None and allowed_lower is not None:
      if rel_fp not in allowed_exact and rel_fp.lower() not in allowed_lower:
        continue
    grouped.setdefault(rel_fp, []).append(finding)

  if not grouped:
    return ""

  out_lines: List[str] = []
  for rel_file in sorted(grouped):
    candidate_path = os.path.join(repo_dir or ".", rel_file)
    file_lines: List[str] = []
    if os.path.isfile(candidate_path):
      try:
        with open(candidate_path, "r", encoding="utf-8", errors="replace") as fh:
          file_lines = fh.read().splitlines()
      except OSError:
        file_lines = []

    raw_ranges: List[Tuple[int, int]] = []
    unresolved_previews: List[str] = []
    seen_previews: Set[str] = set()

    for finding in grouped[rel_file]:
      snip = str(finding.snippet or "")
      matched = (
          covered_lines.find_snippet_line_ranges(file_lines, snip)
          if (file_lines and snip.strip())
          else []
      )
      if matched:
        raw_ranges.append(matched[0])
      elif (finding.start_line or 0) > 0:
        sl = int(finding.start_line)
        el = max(int(finding.end_line or sl), sl)
        raw_ranges.append((sl, el))
      elif snip.strip():
        preview = covered_lines._first_meaningful_line(snip.splitlines())
        if preview and preview not in seen_previews:
          seen_previews.add(preview)
          unresolved_previews.append(preview)

    if raw_ranges:
      raw_ranges.sort(key=lambda r: (r[0], r[1]))
      merged: List[Tuple[int, int]] = []
      for sl, el in raw_ranges:
        if merged and sl <= merged[-1][1] + 1:
          merged[-1] = (merged[-1][0], max(merged[-1][1], el))
        else:
          merged.append((sl, el))
      labels = [
          f"L{sl}" if sl == el else f"L{sl}-{el}" for sl, el in merged
      ]
      prefix = f"{rel_file} | covered: "
      cur_labels: List[str] = []
      cur_len = len(prefix)
      for lbl in labels:
        sep_len = 2 if cur_labels else 0
        if cur_labels and cur_len + sep_len + len(lbl) > 160:
          out_lines.append(prefix + ", ".join(cur_labels))
          cur_labels = [lbl]
          cur_len = len(prefix) + len(lbl)
        else:
          cur_labels.append(lbl)
          cur_len += sep_len + len(lbl)
      if cur_labels:
        out_lines.append(prefix + ", ".join(cur_labels))

    for preview in unresolved_previews:
      out_lines.append(f"{rel_file} | snippet: {preview}")

  return "\n".join(out_lines)


def normalize_db_finding_cwes(
    cm: CodeMender,
    exclude_finding_ids: Optional[Iterable[str]] = None,
) -> int:
  """Remaps any discouraged/prohibited CWE IDs on active findings in `state.db` to allowed Weaknesses."""
  con = cm.db
  if con is None or not CWE_DB.discouraged_ids:
    return 0
  try:
    cur = con.execute("SELECT * FROM findings ORDER BY rowid ASC")
    col_names = [desc[0] for desc in (cur.description or [])]
    rows = cur.fetchall()
  except sqlite3.Error:
    return 0
  if not rows or "finding_id" not in col_names:
    return 0

  cols = set(col_names)
  excluded = (
      {str(fid) for fid in exclude_finding_ids if fid}
      if exclude_finding_ids
      else set()
  )
  updated = 0
  for row in rows:
    rd = dict(zip(col_names, row))
    fid = str(rd.get("finding_id") or "")
    if not fid or (excluded and fid in excluded):
      continue
    status = str(rd.get("status") or "OPEN").upper()
    if status not in _ACTIVE_REPORT_STATUSES:
      continue
    f_obj = Finding.from_dict(rd)
    cid = parse_cwe_id(f_obj)
    if cid is None or cid not in CWE_DB.discouraged_ids:
      continue
    ctx_text = " ".join(
        str(rd.get(k) or "") for k in ("title", "vuln_type", "analysis")
    )
    new_cid = CWE_DB.remap_discouraged_cwe(cid, context_text=ctx_text)
    if new_cid is None or new_cid == cid:
      continue
    new_cwe_str = f"CWE-{new_cid}"
    set_clauses: List[str] = []
    params: List[Any] = []
    if "vuln_id" in cols:
      set_clauses.append("vuln_id = ?")
      params.append(new_cwe_str)
    if "vuln_type" in cols:
      old_vt = str(rd.get("vuln_type") or "")
      vt_cid = parse_cwe_id(old_vt)
      if not old_vt.strip() or vt_cid == cid:
        set_clauses.append("vuln_type = ?")
        params.append(new_cwe_str)
    if "finding_json" in cols and rd.get("finding_json"):
      try:
        fj = json.loads(str(rd["finding_json"]))
        if isinstance(fj, dict) and fj:
          if "vuln_id" in fj:
            fj["vuln_id"] = new_cwe_str
          if "vuln_type" in fj and parse_cwe_id(str(fj.get("vuln_type") or "")) == cid:
            fj["vuln_type"] = new_cwe_str
          set_clauses.append("finding_json = ?")
          params.append(json.dumps(fj))
      except (TypeError, ValueError):
        pass
    if set_clauses:
      params.append(fid)
      try:
        con.execute(
            f"UPDATE findings SET {', '.join(set_clauses)} WHERE finding_id = ?",
            params,
        )
        updated += 1
      except sqlite3.Error:
        pass
  if updated:
    try:
      con.commit()
    except sqlite3.Error:
      pass
  return updated

# Matches per-batch completion lines emitted by `cm find --deep`, e.g.:
#   [1/124 batches] ✅ data/static/codefixes/forgedReviewChallenge_3.ts (1m13.6s) | 14.2k tok - 0 vulnerabilities
_DEEP_BATCH_LINE_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+\S+\s+(.+?)\s+\(\d[^)]*\)(?:\s+\|[^\n]*)?\s+-\s+\d+\s+vulnerabilit",
    re.MULTILINE,
)
# Matches per-batch failure lines emitted by `cm find --deep`, e.g.:
#   [2/12 batches] ❌ routes/auth.js — session failed
#   [2/12 batches] ❌ src/my dir/auth.js (10.2s): context deadline exceeded
_DEEP_FAILED_BATCH_LINE_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+(?:❌|✗|FAIL)\S*\s+(.+?)(?:\s+\(\d[^)]*\)\s*:|\s+(?:—|--|-)\s+|\s*$)",
    re.MULTILINE,
)


def _rel_target_path(
    file_path: str,
    repo_dir: str,
    repo_real: str,
    project_root: str = "",
) -> str:
  """Normalizes a session target or finding file_path to a case-preserved repo-relative path."""
  path = (file_path or "").strip().replace("\\", "/")
  if not path:
    return ""
  for root in (repo_dir, repo_real, project_root):
    if not root or root == ".":
      continue
    prefix = root.replace("\\", "/").rstrip("/") + "/"
    if path.startswith(prefix):
      return _strip_dot_slash(path[len(prefix) :])
  return _strip_dot_slash(path)


def _extract_batch_files_from_stdout(stdout: str) -> List[str]:
  """Extracts repo-relative file paths from `cm find --deep` batch progress lines."""
  if not stdout:
    return []
  seen: Set[str] = set()
  ordered: List[str] = []
  for match in _DEEP_BATCH_LINE_RE.finditer(stdout):
    rel_path = _strip_dot_slash(match.group(1).strip())
    if rel_path and rel_path not in seen:
      seen.add(rel_path)
      ordered.append(rel_path)
  return ordered


_DEEP_FAILED_SUMMARY_BLOCK_RE = re.compile(
    r"deep scan batch\(es\)\s+failed\s*\(coverage is incomplete\):\s*\n"
    r"((?:(?:\s*•\s+.+|─+|📊\s+Deep Scan Sifter Complete:.*|\s*Session:\s+\S.*|\s*Total tokens consumed:.*)\n?)+)",
    re.IGNORECASE,
)
_DEEP_FAILED_BULLET_RE = re.compile(r"^\s*•\s+(.+?)\s*$", re.MULTILINE)
_DEEP_FAILED_BATCH_WITH_REASON_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+(?:❌|✗|FAIL)\S*\s+(.+?)(?:\s+\(\d[^)]*\)\s*:\s*(.+)|\s+(?:—|--|-)\s+(.+))$",
    re.MULTILINE,
)
_DEEP_SINGLE_INCOMPLETE_FILE_RE = re.compile(
    r"deep scan incomplete:\s*1\s+of\s+\d+\s+(?:deep scan\s+)?batch\(es\)\s+failed\s*\(([^),\n]+)\)\s*:\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_failed_batch_files_from_stdout(stdout: str) -> Set[str]:
  """Extracts repo-relative file paths from failed `cm find --deep` batch lines and summary blocks."""
  if not stdout:
    return set()
  out: Set[str] = set()
  for match in _DEEP_FAILED_BATCH_LINE_RE.finditer(stdout):
    rel_path = _strip_dot_slash(match.group(1).strip())
    if rel_path:
      out.add(rel_path)
  for block_match in _DEEP_FAILED_SUMMARY_BLOCK_RE.finditer(stdout):
    for bullet_match in _DEEP_FAILED_BULLET_RE.finditer(block_match.group(1)):
      rel_path = _strip_dot_slash(bullet_match.group(1).strip())
      if rel_path:
        out.add(rel_path)
  return out


def get_latest_session_finding_counts(
    cm: CodeMender,
    last_pass_files: Optional[Iterable[str]] = None,
    last_pass_stdout: Optional[str] = None,
    critical_high_only: bool = True,
    exclude_session_ids: Optional[Set[str]] = None,
    exclude_finding_ids: Optional[Set[str]] = None,
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
  excluded_fids = {str(fid) for fid in exclude_finding_ids if fid} if exclude_finding_ids else set()
  try:
    finding_cols = {
        desc[1]
        for desc in con.execute("PRAGMA table_info(findings)").fetchall()
    }
    has_file_path_col = "file_path" in finding_cols
    has_severity_col = "severity" in finding_cols
    filter_by_severity = bool(critical_high_only and has_severity_col)
    sev_clause = (
        " AND UPPER(COALESCE(f.severity, '')) IN ('CRITICAL', 'HIGH')"
        if filter_by_severity
        else ""
    )
    fid_excl_clause = ""
    fid_excl_params: List[str] = []
    if excluded_fids and "finding_id" in finding_cols:
      sorted_fids = sorted(excluded_fids)
      placeholders = ", ".join("?" * len(sorted_fids))
      fid_excl_clause = f" AND COALESCE(f.finding_id, '') NOT IN ({placeholders})"
      fid_excl_params = sorted_fids
    session_rows = con.execute(
        f"""
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
                  AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED'){sev_clause}{fid_excl_clause}) AS finding_count,
               (SELECT COUNT(*) FROM findings f
                WHERE f.session_id = s.session_id
                  AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED'){fid_excl_clause}) AS any_finding_count
        FROM sessions s
        WHERE s.session_type = 'FIND'
          AND s.target != ''
          AND (s.project_root = '' OR s.project_root = ? OR s.project_root = ?)
        ORDER BY s.updated_at ASC,
                 CASE WHEN UPPER(COALESCE(s.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END ASC,
                 s.created_at ASC,
                 s.rowid ASC
        """,
        [*fid_excl_params, *fid_excl_params, cm.repo_dir, repo_real],
    ).fetchall()
  except sqlite3.Error:
    return {}

  latest_counts: Dict[str, int] = {}
  latest_parent_id: Optional[str] = None
  latest_parent_completed = True
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
      any_finding_count,
  ) in session_rows:
    sid = str(session_id)
    if exclude_session_ids and sid in exclude_session_ids:
      continue
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
      latest_parent_completed = is_completed
      parent_finding_targets.setdefault(sid, set())
      if not is_root_target:
        rel_target = _rel_target_path(
            target_str, cm.repo_dir, repo_real, proj_root_str
        )
        if rel_target:
          latest_counts[rel_target] = (
              int(finding_count) if is_completed else max(int(finding_count), 1)
          )
          if int(any_finding_count) > 0:
            parent_finding_targets[sid].add(rel_target)
      if has_file_path_col and int(any_finding_count) > 0:
        count_expr = (
            "SUM(CASE WHEN UPPER(COALESCE(f.severity, '')) IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END)"
            if filter_by_severity
            else "COUNT(*)"
        )
        try:
          f_rows = con.execute(
              f"""
              SELECT f.file_path, {count_expr}
              FROM findings f
              WHERE f.session_id = ?
                AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED'){fid_excl_clause}
                AND f.file_path IS NOT NULL
                AND f.file_path != ''
              GROUP BY f.file_path
              """,
              [sid, *fid_excl_params],
          ).fetchall()
        except sqlite3.Error:
          f_rows = []
        for raw_fp, f_cnt in f_rows:
          rel_fp = _rel_target_path(
              str(raw_fp), cm.repo_dir, repo_real, proj_root_str
          )
          if rel_fp:
            latest_counts[rel_fp] = int(f_cnt or 0)
            parent_finding_targets[sid].add(rel_fp)
        if is_root_target and len(parent_finding_targets[sid]) == 1:
          sole_fp = next(iter(parent_finding_targets[sid]))
          try:
            con.execute(
                "UPDATE sessions SET target = ? WHERE session_id = ?",
                (sole_fp, sid),
            )
            con.commit()
          except sqlite3.Error:
            pass
    else:
      rel_target = _rel_target_path(
          target_str, cm.repo_dir, repo_real, proj_root_str
      )
      if rel_target:
        # If the per-file session did not complete (e.g. FAILED, CANCELLED,
        # INTERRUPTED), assign a count >= 1 so the file stays in `active_files`
        # and is re-audited on the next pass (unless a COMPLETED retry in the
        # same pass supersedes it).
        latest_counts[rel_target] = (
            int(finding_count) if is_completed else max(int(finding_count), 1)
        )
        if parent_id_str:
          latest_parent_id = parent_id_str
          if is_completed:
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
        if latest_parent_id and not latest_parent_completed:
          latest_counts[rel_file] = max(latest_counts.get(rel_file, 0), 1)
        else:
          latest_counts[rel_file] = 0
          if rel_file not in unaccounted_clean:
            unaccounted_clean.append(rel_file)
    if latest_parent_id and latest_parent_completed and not latest_parent_with_findings:
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


def _snapshot_db_session_ids(cm: CodeMender) -> Set[str]:
  """Captures the set of existing session_ids in state.db sessions."""
  con = cm.db
  if con is None:
    return set()
  try:
    rows = con.execute("SELECT session_id FROM sessions").fetchall()
  except sqlite3.Error:
    return set()
  return {str(r[0]) for r in rows if r and r[0]}


def _get_unresolved_failed_targets(
    cm: CodeMender,
    exclude_session_ids: Optional[Set[str]] = None,
) -> List[str]:
  """Returns target paths whose most recent current-scan FIND session in state.db remains FAILED."""
  con = cm.db
  if con is None:
    return []
  repo_real = os.path.realpath(cm.repo_dir)
  try:
    rows = con.execute(
        """
        SELECT s.session_id,
               s.status,
               s.target,
               s.project_root,
               EXISTS (
                   SELECT 1 FROM sessions c WHERE c.parent_session_id = s.session_id
               ) AS has_children
        FROM sessions s
        WHERE s.session_type = 'FIND'
          AND s.target != ''
          AND (s.project_root = '' OR s.project_root = ? OR s.project_root = ?)
        ORDER BY s.updated_at ASC,
                 CASE WHEN UPPER(COALESCE(s.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END ASC,
                 s.created_at ASC,
                 s.rowid ASC
        """,
        (cm.repo_dir, repo_real),
    ).fetchall()
  except sqlite3.Error:
    return []

  latest_status: Dict[str, str] = {}
  latest_root_failed = False
  last_root_target = "."
  for session_id, status, target, project_root, has_children in rows:
    sid = str(session_id)
    if exclude_session_ids and sid in exclude_session_ids:
      continue
    norm_status = str(status or "").upper()
    target_str = str(target or "")
    proj_root_str = str(project_root or "")
    is_root_target = target_str in (".", cm.repo_dir, repo_real, proj_root_str)
    if has_children or is_root_target:
      latest_root_failed = norm_status == "FAILED"
      last_root_target = target_str or "."
      if not is_root_target:
        rel = _rel_target_path(target_str, cm.repo_dir, repo_real, proj_root_str)
        if rel:
          latest_status[rel] = norm_status
    else:
      if norm_status == "COMPLETED":
        latest_root_failed = False
      rel = _rel_target_path(target_str, cm.repo_dir, repo_real, proj_root_str)
      if rel:
        latest_status[rel] = norm_status

  unresolved = sorted(t for t, st in latest_status.items() if st == "FAILED")
  if not unresolved and latest_root_failed:
    unresolved.append(last_root_target)
  return unresolved


def _is_model_fallback_disabled(
    extra_flags: Iterable[str],
    env: Optional[Dict[str, str]] = None,
) -> bool:
  """Returns True if the caller explicitly disabled model fallback via CLI flag or env."""
  for flag in extra_flags:
    if flag == "--no-model-fallback" or (
        flag.startswith("--no-model-fallback=")
        and flag.split("=", 1)[1].strip().lower() not in ("false", "0", "no", "off")
    ):
      return True
  raw_env = (env or {}).get("CM_DISABLE_MODEL_FALLBACK")
  if raw_env is None:
    raw_env = os.environ.get("CM_DISABLE_MODEL_FALLBACK", "")
  return str(raw_env).strip().lower() in ("1", "true", "yes", "on")


def _extract_safety_blocked_files(
    cm: CodeMender,
    stdout: str,
    pass_pre_session_ids: Set[str],
    primary_model: str,
) -> Tuple[Set[str], bool]:
  """Identifies files blocked by safety filters (or downgraded to a non-Argon fallback model)."""
  blocked: Set[str] = set()
  text = stdout or ""

  reason_matches = list(_DEEP_FAILED_BATCH_WITH_REASON_RE.finditer(text))
  if reason_matches:
    for m in reason_matches:
      rel_path = _strip_dot_slash(m.group(1).strip())
      reason = (m.group(2) or m.group(3) or "").strip()
      if rel_path and codemender._SAFETY_BLOCK_ERROR.search(reason):
        blocked.add(rel_path)
  elif codemender._SAFETY_BLOCK_ERROR.search(text):
    blocked.update(_extract_failed_batch_files_from_stdout(text))
    for sm in _DEEP_SINGLE_INCOMPLETE_FILE_RE.finditer(text):
      rel_path = _strip_dot_slash(sm.group(1).strip())
      reason = sm.group(2).strip()
      if rel_path and codemender._SAFETY_BLOCK_ERROR.search(reason):
        blocked.add(rel_path)

  con = cm.db
  if con is not None:
    repo_real = os.path.realpath(cm.repo_dir)
    try:
      session_cols = {
          desc[1]
          for desc in con.execute("PRAGMA table_info(sessions)").fetchall()
      }
      if "model" in session_cols:
        rows = con.execute(
            """
            SELECT session_id, target, project_root, model
            FROM sessions
            WHERE session_type = 'FIND'
              AND target != ''
              AND (project_root = '' OR project_root = ? OR project_root = ?)
            """,
            (cm.repo_dir, repo_real),
        ).fetchall()
        primary_low = primary_model.strip().lower()
        for sid, target, project_root, mdl in rows:
          if str(sid) in pass_pre_session_ids:
            continue
          mdl_low = str(mdl or "").strip().lower()
          if (
              not mdl_low
              or mdl_low == primary_low
              or mdl_low.startswith(("gemini-4-argon", "gemini-4-carbon"))
          ):
            continue
          target_str = str(target or "")
          proj_root_str = str(project_root or "")
          if target_str not in (".", cm.repo_dir, repo_real, proj_root_str):
            rel = _rel_target_path(target_str, cm.repo_dir, repo_real, proj_root_str)
            if rel:
              blocked.add(rel)
    except sqlite3.Error:
      pass

  all_batches_safety_blocked = bool(
      not blocked
      and codemender._DEEP_ALL_BATCHES_FAILED.search(text)
      and codemender._SAFETY_BLOCK_ERROR.search(text)
  )
  return blocked, all_batches_safety_blocked


def _active_preexisting_finding_ids(
    cm: CodeMender,
    pre_scan_finding_ids: Set[str],
    pre_scan_session_ids: Set[str],
) -> Set[str]:
  """Returns preexisting finding_ids that have not been re-found by a current-scan session."""
  if not pre_scan_finding_ids:
    return set()
  con = cm.db
  if con is None:
    return set(pre_scan_finding_ids)
  try:
    cur = con.execute("SELECT * FROM findings")
    col_names = [desc[0] for desc in (cur.description or [])]
    rows = cur.fetchall()
  except sqlite3.Error:
    return set(pre_scan_finding_ids)
  if "finding_id" not in col_names or "session_id" not in col_names:
    return set(pre_scan_finding_ids)
  still_preexisting: Set[str] = set()
  for row in rows:
    rd = dict(zip(col_names, row))
    fid = str(rd.get("finding_id") or "")
    sid = str(rd.get("session_id") or "")
    if fid in pre_scan_finding_ids and (not sid or sid in pre_scan_session_ids):
      still_preexisting.add(fid)
  return still_preexisting


# Extensionless, slashless filename so `cm find` neither discovers it as a source
# file nor interprets a double-quoted mention in `--context` as a target file
# scope filter (never wrap it in backticks in `--context`, as `cm` checks all
# `` `...` `` spans via `os.Stat` against the repo root).
_PASS_REPORT_REL_PATH = "_cm_pass_report"
_WORKSPACE_BACKUPS_DIR = "workspace_backups"


def _workspace_backup_path(repo_dir: str, cm_dir: str) -> str:
  """Returns the path in `CM_HOME` storing crash-recovery metadata for `repo_dir`."""
  real_repo = os.path.realpath(repo_dir)
  digest = hashlib.sha256(real_repo.encode("utf-8")).hexdigest()[:24]
  return os.path.join(cm_dir, _WORKSPACE_BACKUPS_DIR, f"{digest}.json")


def _atomic_write_text(path: str, content: str) -> None:
  """Writes `content` atomically via a sibling `.tmp` file."""
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  tmp_path = f"{path}.tmp"
  with open(tmp_path, "w", encoding="utf-8") as fh:
    fh.write(content)
  os.replace(tmp_path, path)


def _safe_remove(path: str) -> None:
  try:
    if os.path.exists(path):
      os.remove(path)
  except OSError:
    pass


def restore_interrupted_workspace(
    repo_dir: Optional[str],
    cm_dir: Optional[str] = None,
) -> None:
  """Restores `.cmignore` and removes temporary complete-scan scratch files left by SIGTERM/SIGKILL."""
  if not repo_dir or not os.path.isdir(repo_dir):
    return
  resolved_cm_dir = cm_dir or codemender.resolve_cm_home()
  report_path = os.path.join(repo_dir, *_PASS_REPORT_REL_PATH.split("/"))
  backup_path = _workspace_backup_path(repo_dir, resolved_cm_dir)
  _safe_remove(report_path)
  _safe_remove(f"{report_path}.tmp")
  _safe_remove(f"{backup_path}.tmp")
  if not os.path.exists(backup_path):
    return
  try:
    with open(backup_path, "r", encoding="utf-8") as fh:
      backup = json.load(fh)
  except (OSError, json.JSONDecodeError):
    _safe_remove(backup_path)
    return

  cmignore_path = os.path.join(repo_dir, ".cmignore")
  if backup.get("existed"):
    orig_content = str(backup.get("content") or "")
    current_content: Optional[str] = None
    if os.path.exists(cmignore_path):
      try:
        with open(cmignore_path, "r", encoding="utf-8") as fh:
          current_content = fh.read()
      except OSError:
        current_content = None
    if current_content != orig_content:
      _atomic_write_text(cmignore_path, orig_content)
  else:
    _safe_remove(cmignore_path)

  _safe_remove(backup_path)


def run_complete_scan(
    cm: CodeMender,
    target_or_id: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
    complete_runs: int = 5,
    critical_high_only: bool = True,
    context: Optional[str] = None,
) -> Any:
  """Runs sequential deep scans, tracking clean files in .cmignore, scoping follow-up passes to active files, and stopping early when converged."""
  has_repo_dir = os.path.isdir(cm.repo_dir)
  cm_dir = codemender.resolve_cm_home(cm.env)
  cmignore_path: Optional[str] = None
  orig_cmignore: Optional[str] = None
  if has_repo_dir:
    restore_interrupted_workspace(cm.repo_dir, cm_dir=cm_dir)
    cmignore_path = os.path.join(cm.repo_dir, ".cmignore")
    cmignore_existed = os.path.exists(cmignore_path)
    if cmignore_existed:
      with open(cmignore_path, "r", encoding="utf-8") as fh:
        orig_cmignore = fh.read()
    backup_path = _workspace_backup_path(cm.repo_dir, cm_dir)
    _atomic_write_text(
        backup_path,
        json.dumps({
            "repo_dir": os.path.realpath(cm.repo_dir),
            "existed": cmignore_existed,
            "content": orig_cmignore or "",
        }),
    )

  with codemender.handle_termination_signals():
    try:
      result = None
      prev_active_files: Optional[List[str]] = None
      cleared_files: Set[str] = set()
      pre_scan_session_ids = _snapshot_db_session_ids(cm)
      pre_scan_finding_ids = set(snapshot_db_findings(cm).keys())
      excluded_finding_ids = set(pre_scan_finding_ids)
      discouraged_cwes = _load_discouraged_cwes()
      cleaned_extra_flags, extra_contexts = codemender._extract_context_flags(
          extra_flags
      )
      flags_without_model, primary_model = codemender._extract_model_flag(
          cleaned_extra_flags,
          default_model="gemini-4-hydrogen",
      )
      enable_argon_escalation = (
          not primary_model.lower().startswith(
              ("gemini-4-argon", "gemini-4-carbon")
          )
          and not _is_model_fallback_disabled(cleaned_extra_flags, cm.env)
      )
      user_contexts: List[str] = []
      if context and context.strip():
        user_contexts.append(context.strip())
      user_contexts.extend(c.strip() for c in extra_contexts if c and c.strip())
      additional_context = "\n\n".join(user_contexts)

      all_discovered_files: Set[str] = set()
      escalated_files: Set[str] = set()
      escalate_entire_repo = False

      def _write_cmignore(
          ignored_files: Iterable[str],
          keep_files: Optional[Iterable[str]] = None,
      ) -> None:
        if not cmignore_path:
          return
        base = orig_cmignore or ""
        if base and not base.endswith("\n"):
          base += "\n"
        entries = _filter_cmignore_entries(ignored_files, keep_files=keep_files)
        extra = "".join(f"{entry}\n" for entry in entries)
        _atomic_write_text(cmignore_path, base + extra)

      def _fetch_covered_report(only_files: Optional[Iterable[str]]) -> str:
        report_cmd = codemender.build_cm_command(
            cm.cm_binary,
            "report",
            extra_flags=["--format", "json"],
        )
        report_res = codemender.run_command(
            report_cmd,
            cwd=cm.repo_dir,
            env=codemender.resolve_subprocess_env(cm.env),
            check=False,
        )
        return build_covered_lines_report(
            getattr(report_res, "stdout", "") or "",
            repo_dir=cm.repo_dir,
            exclude_finding_ids=excluded_finding_ids or None,
            only_files=only_files,
        )

      def _execute_pass(
          *,
          has_prior_state: bool,
          covered_report: str,
          pass_flags: List[str],
          max_turns: int,
          allow_partial_failure: bool,
          allow_all_batches_failed: bool,
          allow_safety_block_failure: bool = False,
          model_override: Optional[str] = None,
          env_overrides: Optional[Dict[str, str]] = None,
      ) -> Any:
        nonlocal excluded_finding_ids
        report_file: Optional[str] = None
        pass_error: Optional[RuntimeError] = None
        pass_result = None
        report_text = covered_report or "No preexisting findings.\n"
        try:
          if has_prior_state:
            if has_repo_dir:
              report_file = os.path.join(
                  cm.repo_dir, *_PASS_REPORT_REL_PATH.split("/")
              )
              _atomic_write_text(report_file, report_text)
              report_ref = _PASS_REPORT_REL_PATH
            else:
              with tempfile.NamedTemporaryFile(
                  mode="w",
                  suffix="",
                  delete=False,
                  encoding="utf-8",
              ) as tmp_file:
                tmp_file.write(report_text)
                report_file = tmp_file.name
                report_ref = report_file
            pass_context = _FIND_CONTEXT_FOR_LATER_PASSES.format(
                report_file=report_ref,
                discouraged_cwes=discouraged_cwes,
            )
          else:
            pass_context = _FIND_CONTEXT_FOR_FIRST_PASS.format(
                discouraged_cwes=discouraged_cwes,
            )
          if additional_context:
            pass_context = (
                f"{pass_context}\n\n# Additional Context\n{additional_context}"
            )
          pre_pass_rows = snapshot_db_findings(cm)
          find_kwargs: Dict[str, Any] = {
              "target_or_id": target_or_id,
              "scan_mode": ScanMode.DEEP,
              "extra_flags": pass_flags or None,
              "max_turns": max_turns,
              "context": pass_context,
              "allow_partial_failure": allow_partial_failure,
              "allow_all_batches_failed": allow_all_batches_failed,
              "allow_safety_block_failure": allow_safety_block_failure,
              "env_overrides": env_overrides,
          }
          if model_override is not None:
            find_kwargs["model"] = model_override
          try:
            pass_result = cm.find(**find_kwargs)
          except RuntimeError as exc:
            pass_error = exc
        finally:
          if report_file is not None:
            _safe_remove(report_file)
            _safe_remove(f"{report_file}.tmp")
        reconcile_overwritten_findings(
            cm,
            pre_pass_rows,
            pre_scan_session_ids=pre_scan_session_ids,
            pre_scan_finding_ids=pre_scan_finding_ids,
        )
        excluded_finding_ids = _active_preexisting_finding_ids(
            cm, pre_scan_finding_ids, pre_scan_session_ids
        )
        normalize_db_finding_cwes(
            cm, exclude_finding_ids=excluded_finding_ids or None
        )
        deduplicate_db_findings(cm, exclude_finding_ids=excluded_finding_ids or None)
        if pass_error is not None:
          raise pass_error
        return pass_result

      primary_env_overrides = (
          {"CM_DISABLE_MODEL_FALLBACK": "true"} if enable_argon_escalation else None
      )
      for scan_index in range(complete_runs):
        active_files: Optional[List[str]] = None
        covered_report = ""
        has_prior_state = False
        if scan_index > 0:
          last_stdout = getattr(result, "stdout", "") if result is not None else ""
          counts = get_latest_session_finding_counts(
              cm,
              last_pass_files=prev_active_files,
              last_pass_stdout=last_stdout,
              critical_high_only=critical_high_only,
              exclude_session_ids=pre_scan_session_ids or None,
              exclude_finding_ids=excluded_finding_ids or None,
          )
          all_discovered_files.update(counts.keys())
          for cleared in cleared_files:
            counts[cleared] = 0
          cleared_files.update(
              t for t, c in counts.items() if c == 0 and t not in escalated_files
          )
          clean_files = sorted(
              t for t, c in counts.items() if c == 0 and t not in escalated_files
          )
          active_files = sorted(
              t for t, c in counts.items() if c > 0 and t not in escalated_files
          )
          if counts and not active_files:
            break
          _write_cmignore(
              set(clean_files) | escalated_files,
              keep_files=active_files,
          )
          covered_report = _fetch_covered_report(active_files or None)
          has_prior_state = bool(covered_report) or bool(active_files)

        pass_pre_sessions = _snapshot_db_session_ids(cm)
        is_non_final_pass = scan_index < complete_runs - 1
        result = _execute_pass(
            has_prior_state=has_prior_state,
            covered_report=covered_report,
            pass_flags=list(cleaned_extra_flags),
            max_turns=8,
            allow_partial_failure=is_non_final_pass,
            allow_all_batches_failed=(scan_index > 0 and has_prior_state),
            allow_safety_block_failure=enable_argon_escalation,
            env_overrides=primary_env_overrides,
        )
        prev_active_files = active_files
        if enable_argon_escalation:
          new_blocked, all_safety_blocked = _extract_safety_blocked_files(
              cm,
              getattr(result, "stdout", "") or "",
              pass_pre_sessions,
              primary_model,
          )
          if new_blocked:
            escalated_files.update(new_blocked)
            cleared_files.difference_update(new_blocked)
          elif scan_index == 0 and all_safety_blocked:
            escalate_entire_repo = True
            break

      if enable_argon_escalation and (escalated_files or escalate_entire_repo):
        if result is not None and not escalate_entire_repo:
          last_stdout = getattr(result, "stdout", "") or ""
          counts = get_latest_session_finding_counts(
              cm,
              last_pass_files=prev_active_files,
              last_pass_stdout=last_stdout,
              critical_high_only=critical_high_only,
              exclude_session_ids=pre_scan_session_ids or None,
              exclude_finding_ids=excluded_finding_ids or None,
          )
          all_discovered_files.update(counts.keys())
          cleared_files.update(
              t for t, c in counts.items() if c == 0 and t not in escalated_files
          )

        argon_cleared_files: Set[str] = set()
        argon_prev_active: Optional[List[str]] = None
        for argon_index in range(complete_runs):
          argon_active: Optional[List[str]] = None
          covered_report = ""
          has_prior_state = False
          if escalate_entire_repo:
            if argon_index > 0:
              last_stdout = getattr(result, "stdout", "") or ""
              argon_counts = get_latest_session_finding_counts(
                  cm,
                  last_pass_files=argon_prev_active,
                  last_pass_stdout=last_stdout,
                  critical_high_only=critical_high_only,
                  exclude_session_ids=pre_scan_session_ids or None,
                  exclude_finding_ids=excluded_finding_ids or None,
              )
              for cleared in argon_cleared_files:
                argon_counts[cleared] = 0
              argon_cleared_files.update(
                  t for t, c in argon_counts.items() if c == 0
              )
              argon_clean = sorted(t for t, c in argon_counts.items() if c == 0)
              argon_active = sorted(t for t, c in argon_counts.items() if c > 0)
              if argon_counts and not argon_active:
                break
              _write_cmignore(argon_clean, keep_files=argon_active)
              covered_report = _fetch_covered_report(argon_active or None)
              has_prior_state = bool(covered_report) or bool(argon_active)
            else:
              _write_cmignore([])
          else:
            if argon_index > 0:
              last_stdout = getattr(result, "stdout", "") or ""
              argon_counts = get_latest_session_finding_counts(
                  cm,
                  last_pass_files=argon_prev_active,
                  last_pass_stdout=last_stdout,
                  critical_high_only=critical_high_only,
                  exclude_session_ids=pre_scan_session_ids or None,
                  exclude_finding_ids=excluded_finding_ids or None,
              )
              all_discovered_files.update(argon_counts.keys())
              argon_cleared_files.update(
                  f for f in escalated_files if argon_counts.get(f, 1) == 0
              )
            argon_active = sorted(escalated_files - argon_cleared_files)
            if not argon_active:
              break
            ignored_for_argon = (
                (all_discovered_files - set(argon_active))
                | cleared_files
                | argon_cleared_files
            )
            _write_cmignore(ignored_for_argon, keep_files=argon_active)
            covered_report = _fetch_covered_report(argon_active)
            has_prior_state = bool(covered_report) or (argon_index > 0)

          is_non_final_argon = argon_index < complete_runs - 1
          result = _execute_pass(
              has_prior_state=has_prior_state,
              covered_report=covered_report,
              pass_flags=list(flags_without_model),
              max_turns=8,
              allow_partial_failure=is_non_final_argon,
              allow_all_batches_failed=(argon_index > 0 and is_non_final_argon),
              model_override=_SAFETY_ESCALATION_MODEL,
          )
          argon_prev_active = argon_active
        prev_active_files = argon_prev_active

      if result is not None:
        final_stdout = getattr(result, "stdout", "") or ""
        get_latest_session_finding_counts(
            cm,
            last_pass_files=prev_active_files,
            last_pass_stdout=final_stdout,
            critical_high_only=critical_high_only,
            exclude_session_ids=pre_scan_session_ids or None,
            exclude_finding_ids=excluded_finding_ids or None,
        )
        unresolved_failed = set(
            _get_unresolved_failed_targets(
                cm, exclude_session_ids=pre_scan_session_ids or None
            )
        )
        if getattr(result, "returncode", 0) != 0:
          unresolved_failed.update(
              _extract_failed_batch_files_from_stdout(final_stdout)
          )
        if unresolved_failed:
          failed_list = ", ".join(sorted(unresolved_failed))
          raise RuntimeError(
              "cm find failed with exit code 1: deep scan incomplete"
              f" (unresolved failed batch(es): {failed_list})"
          )
      return result
    finally:
      if has_repo_dir:
        restore_interrupted_workspace(cm.repo_dir, cm_dir=cm_dir)

