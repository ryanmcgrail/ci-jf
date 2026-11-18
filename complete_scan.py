"""Multi-pass complete scan orchestration on top of CodeMender deep scans."""

import hashlib
import json
import os
import re
import sqlite3
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set

import codemender
from codemender import CodeMender, ScanMode
from deduplication import (
    deduplicate_db_findings,
    reconcile_overwritten_findings,
    snapshot_db_findings,
)
from finding import Finding

_DISCOURAGED_CWES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "discouraged_cwes.txt",
)
_COVERED_LINES_SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "covered_lines.py",
)
_ACTIVE_REPORT_STATUSES = frozenset({"OPEN", "VERIFIED", "REOPENED"})
_CRITICAL_HIGH_AUDIT_BULLET = (
    "- Audit the entire target file top to bottom and report all distinct"
    " vulnerabilities in a single pass (at most one finding per code block/line"
    " range), focusing on the most critical security issues (CRITICAL and HIGH"
    " severity)."
)
_DEFAULT_AUDIT_BULLET = (
    "- Audit the entire target file top to bottom and report all distinct"
    " vulnerabilities in a single pass (at most one finding per code block/line"
    " range)."
)
_FIND_CONTEXT_FOR_FIRST_PASS = f"""\
# Audit Strategy
{_DEFAULT_AUDIT_BULLET}
- Report each distinct vulnerable route, endpoint, or function separately rather than grouping multiple endpoints into one finding, except:
  - For intra-file helpers/validators/sanitizers or pure pass-through controller-to-service wrappers (adding no auth, validation, or sink logic), report the vulnerability once at the function/block where the sink or security defect resides—never on a pass-through caller/wrapper or an ineffective/disabled intra-file validator/sanitizer lacking the sink.
  - When multiple routes in one file share the exact same client-side boolean/state check, report it once at its definition rather than per route (still report routes with distinct auth flaws, such as missing admin checks or exposed hidden routes, separately).
- Scope each snippet and line range strictly to the minimal contiguous sink lines (never the whole enclosing function, and never bridge non-contiguous lines with `...`).
- Batch cross-file `grep_search`/`read_file` lookups after collecting all candidate issues in the target file (at most 2-3 turns; never read `node_modules`). Inspect cross-file consumers before concluding 0 vulnerabilities on files that generate/encode tokens, state, or cookies, and inspect repo-local security/auth helper definitions (e.g., `security.*`) before assuming they enforce auth, role authorization, or ownership.
- Before reporting missing auth or untrusted event/request input on a handler, controller, or cloud/serverless function, check repository-wide routing and deployment/IaC manifests (including at the repository root, e.g., route tables, OpenAPI, CloudFormation/SAM/Serverless/Terraform) to confirm how it is deployed and triggered; skip dead/undeployed handlers, internal-only functions lacking an external route/trigger or untrusted data source, and platform-triggered functions whose configured schema prevents attacker-controlled attributes.
- Ignore tests, package manifests, vendor/dependency directories, `.codemender` files, and vendored/minified third-party libraries (if the target file is vendored third-party code, stop immediately and report 0).

# Vulnerabilities to Report
- **Secrets, Crypto & Helpers:** Report hardcoded secrets/passwords/API keys/salts/keys, weak cryptographic/hashing/encoding primitives, unescaped query/filter builders, and insecure token/key processors directly where defined rather than deferring to callers or consumers.
- **Frontend:**
  - DOM XSS and unsafe sinks (`innerHTML`, `outerHTML`, `document.write`, `bypassSecurityTrust*`, `dangerouslySetInnerHTML`, `v-html`, `eval`), open redirects, and unvalidated `postMessage`/URL handling.
  - Client-side-only auth, authorization, or rate-limit/CAPTCHA checks (`localStorage`/`sessionStorage`, unverified JWT decoding, client-side credential/OAuth password derivation or verification, or mutating auth state before server confirmation).
  - Privileged/account routes missing guards or using only client-decodable state, obfuscated/hidden route matchers, and exposed debug/sandbox/unreleased routes.
  - Credentials/tokens sent in URL query parameters (e.g., `GET` requests) or secrets exposed in client code or storage.
- **Backend:**
  - Injection (SQL, NoSQL, command, template, XXE, XPath), SSRF, unsafe deserialization, prototype pollution, ReDoS on untrusted input, and path traversal/static file serving without canonical path containment or null-byte filtering (e.g., checking only `.includes('/')` or `..`).
  - Missing/bypassable auth on endpoints or file/log/key servers, IDOR, mass assignment, privilege escalation (trusting client-supplied user IDs, roles, prices, or wallet addresses without server-side session/signature verification), and CSRF on state-changing endpoints.
  - Serializing DB/ORM records into JWTs, sessions, or responses without stripping all sensitive schema fields (e.g., password hashes, TOTP secrets, security answers, even if another field was cleared), and cleartext DB storage of auth secrets/keys.
  - Unbounded per-request resource allocation (e.g., persistent WebSocket/network providers or event listeners without cleanup/rate limiting), permissive CORS/headers, and error/stack-trace/metrics/directory disclosure.

# CWE Requirements
- Assign each finding exactly one `CWE-<number>` ID, and never use these discouraged/prohibited CWEs: {{discouraged_cwes}}"""
_FIND_CONTEXT_FOR_LATER_PASSES = f"""\
# Initial Pre-Audit Check
- First, run `python3 {_COVERED_LINES_SCRIPT_PATH} {{report_file}} "<file>"` (using the target file's repo-relative path) to list already-covered lines and snippets; use `run_command` strictly for this single check (never invoke `node`, `sh`, or other commands, or query other files).
- Never re-report a covered vulnerability (its covered/sink lines, enclosing declaration/caller, or any intra-file helper/validator/sanitizer whose caller/sink in this file is already covered, or vice versa); audit the remaining uncovered lines and report 0 if no distinct vulnerabilities remain.

{_FIND_CONTEXT_FOR_FIRST_PASS}"""


def _load_discouraged_cwes() -> str:
  """Loads the discouraged CWE IDs from discouraged_cwes.txt as a comma-separated string."""
  if not os.path.exists(_DISCOURAGED_CWES_PATH):
    return ""
  with open(_DISCOURAGED_CWES_PATH, "r", encoding="utf-8") as cwe_f:
    return ", ".join(cwe_f.read().split())


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
      return path[len(prefix) :].lstrip("./")
  return path.lstrip("./")


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


_SCRATCH_DIR_NAME = ".codemender"
_PASS_REPORT_REL_PATH = f"{_SCRATCH_DIR_NAME}/.cm_pass_report.json"
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
  if backup.get("created_scratch_dir"):
    try:
      os.rmdir(os.path.join(repo_dir, _SCRATCH_DIR_NAME))
    except OSError:
      pass


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
    scratch_dir = os.path.join(cm.repo_dir, _SCRATCH_DIR_NAME)
    created_scratch_dir = not os.path.exists(scratch_dir)
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
            "created_scratch_dir": created_scratch_dir,
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
      for scan_index in range(complete_runs):
        active_files: Optional[List[str]] = None
        preprocessed_report = "[]"
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
            _atomic_write_text(cmignore_path, base + extra)
          report_cmd = codemender.build_cm_command(
              cm.cm_binary,
              "report",
              extra_flags=["--format", "json"],
          )
          report_res = codemender.run_command(
              report_cmd,
              cwd=cm.repo_dir,
              env=cm.env,
              check=False,
          )
          preprocessed_report = preprocess_report_for_context(
              getattr(report_res, "stdout", "") or "",
              repo_dir=cm.repo_dir,
              exclude_finding_ids=excluded_finding_ids or None,
          )
          has_prior_state = (preprocessed_report != "[]") or bool(active_files)

        report_file: Optional[str] = None
        pass_extra_flags = list(extra_flags) if extra_flags else []
        try:
          if has_prior_state:
            if has_repo_dir:
              report_file = os.path.join(
                  cm.repo_dir, *_PASS_REPORT_REL_PATH.split("/")
              )
              _atomic_write_text(report_file, preprocessed_report)
              report_ref = _PASS_REPORT_REL_PATH
            else:
              with tempfile.NamedTemporaryFile(
                  mode="w",
                  suffix=".json",
                  delete=False,
                  encoding="utf-8",
              ) as tmp_file:
                tmp_file.write(preprocessed_report)
                report_file = tmp_file.name
                report_ref = report_file
            pass_context = _FIND_CONTEXT_FOR_LATER_PASSES.format(
                report_file=report_ref,
                discouraged_cwes=discouraged_cwes,
            )
            if not codemender._has_flag(pass_extra_flags, "--enable-bash"):
              pass_extra_flags.append("--enable-bash")
          else:
            pass_context = _FIND_CONTEXT_FOR_FIRST_PASS.format(
                discouraged_cwes=discouraged_cwes,
            )
          if critical_high_only:
            pass_context = pass_context.replace(
                _DEFAULT_AUDIT_BULLET,
                _CRITICAL_HIGH_AUDIT_BULLET,
                1,
            )
          if context and context.strip():
            pass_context = f"{pass_context}\n\n{context.strip()}"
          pre_pass_rows = snapshot_db_findings(cm)
          result = cm.find(
              target_or_id=target_or_id,
              scan_mode=ScanMode.DEEP,
              extra_flags=pass_extra_flags or None,
              max_turns=12 if scan_index > 0 else 8,
              context=pass_context,
          )
        finally:
          if report_file is not None:
            _safe_remove(report_file)
            _safe_remove(f"{report_file}.tmp")
        prev_active_files = active_files
        reconcile_overwritten_findings(
            cm,
            pre_pass_rows,
            pre_scan_session_ids=pre_scan_session_ids,
            pre_scan_finding_ids=pre_scan_finding_ids,
        )
        excluded_finding_ids = _active_preexisting_finding_ids(
            cm, pre_scan_finding_ids, pre_scan_session_ids
        )
        deduplicate_db_findings(cm, exclude_finding_ids=excluded_finding_ids or None)
      return result
    finally:
      if has_repo_dir:
        restore_interrupted_workspace(cm.repo_dir, cm_dir=cm_dir)

