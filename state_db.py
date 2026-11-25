"""SQLite `state.db` session and finding queries, reconciliation, and consolidation."""

from datetime import datetime, timezone
import json
import os
import re
import sqlite3
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
import uuid

import codemender
from codemender import CodeMender
from cwe_database import parse_cwe_id
from deduplication import (
    ACTIVE,
    CWE_DB,
    RESOLVED,
    as_int,
    dedup,
    higher_severity,
    is_duplicate,
    norm_rel_path,
    severity_rank,
    status_of,
    strip_dot_slash,
)
from finding import Finding

ACTIVE_REPORT_STATUSES = frozenset({"OPEN", "VERIFIED", "REOPENED"})
CM_TWIN_REASONS = (
    "Duplicate un-fingerprinted streamed entry",
    "Duplicate finding entry",
)

# Matches per-batch completion lines emitted by `cm find --deep`
_DEEP_BATCH_LINE_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+\S+\s+(.+?)\s+\(\d[^)]*\)(?:\s+\|[^\n]*)?\s+-\s+\d+\s+vulnerabilit",
    re.MULTILINE,
)
# Matches per-batch failure lines emitted by `cm find --deep`
_DEEP_FAILED_BATCH_LINE_RE = re.compile(
    r"^\[\d+/\d+\s+batches\]\s+(?:❌|✗|FAIL)\S*\s+(.+?)(?:\s+\(\d[^)]*\)\s*:|\s+(?:—|--|-)\s+|\s*$)",
    re.MULTILINE,
)
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


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unwrap_db(cm_or_ctx: Any) -> Optional[sqlite3.Connection]:
    if isinstance(cm_or_ctx, sqlite3.Connection):
        return cm_or_ctx
    target = getattr(cm_or_ctx, "cm", cm_or_ctx)
    return getattr(target, "db", None)


def _fetch_rows(
    con: Optional[sqlite3.Connection],
    table: str = "findings",
    order_by_rowid: bool = True,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    if con is None:
        return [], []
    order_sql = " ORDER BY rowid ASC" if order_by_rowid else ""
    try:
        cur = con.execute(f"SELECT * FROM {table}{order_sql}")
        col_names = [desc[0] for desc in (cur.description or [])]
        rows = cur.fetchall()
    except sqlite3.Error:
        return [], []
    if not rows:
        return col_names, []
    return col_names, [dict(zip(col_names, row)) for row in rows]


def _safe_commit(con: sqlite3.Connection) -> None:
    try:
        con.commit()
    except sqlite3.Error:
        pass


def _extract_row_severity(row: Dict[str, Any]) -> str:
    sev = str(row.get("severity") or "").strip().upper()
    if sev:
        return sev
    raw_json = row.get("finding_json")
    if isinstance(raw_json, str) and raw_json.strip():
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                return str(parsed.get("severity") or "").strip().upper()
        except json.JSONDecodeError:
            pass
    return ""


def _patch_finding_json(
    raw_json: Any,
    mutator: Optional[Callable[[Dict[str, Any]], None]] = None,
    **updates: Any,
) -> Any:
    if not isinstance(raw_json, str) or not raw_json.strip():
        return raw_json
    try:
        parsed = json.loads(raw_json)
    except (TypeError, ValueError):
        return raw_json
    if not isinstance(parsed, dict) or not parsed:
        return raw_json
    if mutator is not None:
        mutator(parsed)
    if updates:
        parsed.update(updates)
    return json.dumps(parsed)


def _rel_db_path(
    file_path: str,
    repo_dir: str,
    repo_real: str,
    project_root: str = "",
) -> str:
    return norm_rel_path(
        file_path,
        repo_dir,
        case_sensitive=True,
        extra_roots=(repo_real, project_root),
    )


# ─── findings table operations ───────────────────────────────────────────────


def upgrade_finding_severity_in_db(
    con: sqlite3.Connection,
    cols: set,
    finding_id: Any,
    candidate_severity: Any,
) -> bool:
    """Upgrades a finding's severity in state.db only if candidate_severity is strictly higher."""
    fid = str(finding_id or "").strip()
    cand = str(candidate_severity or "").strip().upper()
    if not fid or not cand or "severity" not in cols or severity_rank(cand) >= 99:
        return False
    has_fjson = "finding_json" in cols
    select_cols = "severity, finding_json" if has_fjson else "severity"
    row = con.execute(f"SELECT {select_cols} FROM findings WHERE finding_id=?", (fid,)).fetchone()
    if row is None:
        return False
    row_dict: Dict[str, Any] = {"severity": row[0]}
    if has_fjson:
        row_dict["finding_json"] = row[1]
    if severity_rank(cand) >= severity_rank(_extract_row_severity(row_dict)):
        return False
    sets = ["severity=?"]
    params: List[Any] = [cand]
    if has_fjson:
        updated_fjson = _patch_finding_json(row[1], severity=cand)
        if updated_fjson != row[1]:
            sets.append("finding_json=?")
            params.append(updated_fjson)
    params.append(fid)
    con.execute(f"UPDATE findings SET {', '.join(sets)} WHERE finding_id=?", params)
    return True


def remove_duplicates_in_db(
    cm_or_ctx: Any,
    dups: List[Finding],
) -> Optional[Tuple[int, int]]:
    """Drops duplicate rows from CodeMender's state.db (or marks patch-referenced ones DISMISSED)."""
    con = _unwrap_db(cm_or_ctx)
    if con is None:
        return None
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")} if "findings" in tables else set()
        if "finding_id" not in cols or "status" not in cols:
            return None
        refs = (
            " OR ".join(
                f"finding_id IN (SELECT finding_id FROM {t} WHERE finding_id IS NOT NULL)"
                for t in ("patches", "artifacts")
                if t in tables
            )
            or "0"
        )
        removed = marked = 0
        now = _now_rfc3339()
        for d in dups:
            if d.duplicate_of and d.severity:
                upgrade_finding_severity_in_db(con, cols, d.duplicate_of, d.severity)
            fid = d.finding_id
            cur = con.execute(f"DELETE FROM findings WHERE finding_id=? AND NOT ({refs})", (fid,))
            if cur.rowcount:
                removed += cur.rowcount
                continue
            sets, args = ["status='DISMISSED'"], []
            if "dismiss_reason" in cols:
                sets.append("dismiss_reason=?")
                args.append(f"cm-ci: duplicate of {d.duplicate_of}")
            if "updated_at" in cols:
                sets.append("updated_at=?")
                args.append(now)
            marked += con.execute(
                f"UPDATE findings SET {', '.join(sets)} WHERE finding_id=? AND status<>'DISMISSED'",
                args + [fid],
            ).rowcount
        if "dismiss_reason" in cols:
            q = ",".join("?" * len(CM_TWIN_REASONS))
            removed += con.execute(
                f"DELETE FROM findings WHERE status='DISMISSED' AND dismiss_reason IN ({q}) AND NOT ({refs})",
                CM_TWIN_REASONS,
            ).rowcount
        con.commit()
        return removed, marked
    except sqlite3.Error as e:
        print(f"cm-ci: warning — could not update state.db: {e}", file=sys.stderr)
        return None


def snapshot_db_findings(
    cm: Any,
    exclude_finding_ids: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Captures a snapshot of existing rows in state.db findings keyed by finding_id."""
    col_names, row_dicts = _fetch_rows(_unwrap_db(cm), "findings")
    if not row_dicts or "finding_id" not in col_names:
        return {}
    snapshot: Dict[str, Dict[str, Any]] = {}
    for row_dict in row_dicts:
        fid = row_dict.get("finding_id")
        if fid:
            fid_str = str(fid)
            if exclude_finding_ids and fid_str in exclude_finding_ids:
                continue
            snapshot[fid_str] = row_dict
    return snapshot


def reconcile_overwritten_findings(
    cm: Any,
    pre_pass_rows: Dict[str, Dict[str, Any]],
    pre_scan_session_ids: Optional[Set[str]] = None,
    pre_scan_finding_ids: Optional[Set[str]] = None,
    restore_session_id: bool = True,
) -> None:
    """Reconciles findings overwritten in-place by cm, disambiguating disjoint collisions and preserving severities."""
    if not pre_pass_rows:
        return
    con = _unwrap_db(cm)
    col_names, row_dicts = _fetch_rows(con, "findings")
    if con is None or not row_dicts or "finding_id" not in col_names:
        return

    has_session_col = "session_id" in col_names
    changed = False
    for cur_row in row_dicts:
        fid = str(cur_row.get("finding_id") or "")
        if not fid or fid not in pre_pass_rows:
            continue
        old_row = pre_pass_rows[fid]
        old_sid = old_row.get("session_id") if has_session_col else None
        cur_sid = cur_row.get("session_id") if has_session_col else None
        old_sev = _extract_row_severity(old_row)
        cur_sev = _extract_row_severity(cur_row)
        best_sev = higher_severity(old_sev, cur_sev) or ""
        sid_changed = bool(old_sid and cur_sid and cur_sid != old_sid)
        sev_decreased = bool(best_sev and severity_rank(best_sev) < severity_rank(cur_sev))
        if not sid_changed and not sev_decreased:
            continue

        old_sl = as_int(old_row.get("start_line"))
        old_el = max(as_int(old_row.get("end_line"), old_sl), old_sl)
        cur_sl = as_int(cur_row.get("start_line"))
        cur_el = max(as_int(cur_row.get("end_line"), cur_sl), cur_sl)

        if sid_changed and old_sl > 0 and cur_sl > 0 and (old_el < cur_sl or cur_el < old_sl):
            disambiguated_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{fid}:{old_sl}:{old_el}"))
            restored = dict(old_row)
            restored["finding_id"] = disambiguated_id
            if restored.get("fingerprint"):
                restored["fingerprint"] = f"{restored['fingerprint']}:{old_sl}:{old_el}"
            if "finding_json" in restored:
                restored["finding_json"] = _patch_finding_json(
                    restored.get("finding_json"),
                    finding_id=disambiguated_id,
                )
            placeholders = ", ".join("?" * len(col_names))
            cols_sql = ", ".join(col_names)
            try:
                con.execute(
                    f"INSERT OR IGNORE INTO findings ({cols_sql}) VALUES ({placeholders})",
                    [restored.get(c) for c in col_names],
                )
                if (
                    pre_scan_finding_ids is not None
                    and fid in pre_scan_finding_ids
                    and pre_scan_session_ids
                    and str(old_sid) in pre_scan_session_ids
                ):
                    pre_scan_finding_ids.add(disambiguated_id)
                changed = True
            except sqlite3.Error:
                pass
        else:
            should_restore_sid = (
                sid_changed
                and restore_session_id
                and not (pre_scan_session_ids and str(old_sid) in pre_scan_session_ids)
            )
            set_clauses: List[str] = []
            params: List[Any] = []
            if should_restore_sid:
                set_clauses.append("session_id = ?")
                params.append(old_sid)
            if "severity" in col_names and best_sev and (should_restore_sid or sev_decreased):
                set_clauses.append("severity = ?")
                params.append(best_sev)
                if "finding_json" in col_names:
                    set_clauses.append("finding_json = ?")
                    params.append(_patch_finding_json(cur_row.get("finding_json"), severity=best_sev))
            if not set_clauses:
                continue
            params.append(fid)
            try:
                con.execute(
                    f"UPDATE findings SET {', '.join(set_clauses)} WHERE finding_id = ?",
                    params,
                )
                changed = True
            except sqlite3.Error:
                pass

    if changed:
        _safe_commit(con)


def deduplicate_db_findings(
    cm: Any,
    exclude_finding_ids: Optional[Set[str]] = None,
) -> None:
    """Deduplicates active current-scan findings in state.db via `dedup()`, syncing monotonic severities."""
    con = _unwrap_db(cm)
    col_list, all_row_dicts = _fetch_rows(con, "findings")
    cols = set(col_list)
    if con is None or not all_row_dicts or "file_path" not in cols:
        return

    preexisting_findings: List[Finding] = []
    if exclude_finding_ids:
        preexisting_findings = [
            Finding.from_dict(rd)
            for rd in all_row_dicts
            if str(rd.get("finding_id") or "") in exclude_finding_ids
        ]
        row_dicts = [
            rd for rd in all_row_dicts
            if str(rd.get("finding_id") or "") not in exclude_finding_ids
        ]
    else:
        row_dicts = all_row_dicts

    active_current = [
        f for f in (Finding.from_dict(rd) for rd in row_dicts) if status_of(f) in ACTIVE
    ]
    upgraded_any = False
    if preexisting_findings and active_current:
        prior_candidates = [
            pf for pf in preexisting_findings if status_of(pf) in (ACTIVE | RESOLVED)
        ]
        for idx, cur_f in enumerate(active_current):
            for p_pre in prior_candidates:
                if not is_duplicate(p_pre, cur_f, cm.repo_dir, allow_line_shift=False):
                    continue
                best = higher_severity(p_pre.severity, cur_f.severity)
                if not best:
                    continue
                if severity_rank(best) < severity_rank(cur_f.severity):
                    active_current[idx] = Finding(cur_f.to_dict(), severity=best)
                    cur_f = active_current[idx]
                    upgraded_any |= upgrade_finding_severity_in_db(con, cols, cur_f.finding_id, best)
                upgraded_any |= upgrade_finding_severity_in_db(con, cols, p_pre.finding_id, best)

    res = dedup([], active_current, cm.repo_dir, allow_line_shift=False)
    if res["suppressed_duplicates"]:
        remove_duplicates_in_db(cm, res["suppressed_duplicates"])
    elif upgraded_any:
        _safe_commit(con)


def normalize_db_finding_cwes(
    cm: CodeMender,
    exclude_finding_ids: Optional[Iterable[str]] = None,
) -> int:
    """Remaps any discouraged/prohibited CWE IDs on active findings in `state.db` to allowed Weaknesses."""
    con = _unwrap_db(cm)
    if con is None or not CWE_DB.discouraged_ids:
        return 0
    col_names, row_dicts = _fetch_rows(con, "findings")
    if not row_dicts or "finding_id" not in col_names:
        return 0

    cols = set(col_names)
    excluded = {str(fid) for fid in exclude_finding_ids if fid} if exclude_finding_ids else set()
    updated = 0
    for rd in row_dicts:
        fid = str(rd.get("finding_id") or "")
        if not fid or (excluded and fid in excluded):
            continue
        if str(rd.get("status") or "OPEN").upper() not in ACTIVE_REPORT_STATUSES:
            continue
        cid = parse_cwe_id(Finding.from_dict(rd))
        if cid is None or cid not in CWE_DB.discouraged_ids:
            continue
        ctx_text = " ".join(str(rd.get(k) or "") for k in ("title", "vuln_type", "analysis"))
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
            if not old_vt.strip() or parse_cwe_id(old_vt) == cid:
                set_clauses.append("vuln_type = ?")
                params.append(new_cwe_str)
        if "finding_json" in cols and rd.get("finding_json"):
            def _mutate_cwe(fj: Dict[str, Any], _cid: int = cid, _new: str = new_cwe_str) -> None:
                if "vuln_id" in fj:
                    fj["vuln_id"] = _new
                if "vuln_type" in fj and parse_cwe_id(str(fj.get("vuln_type") or "")) == _cid:
                    fj["vuln_type"] = _new

            patched = _patch_finding_json(rd["finding_json"], mutator=_mutate_cwe)
            if patched != rd["finding_json"]:
                set_clauses.append("finding_json = ?")
                params.append(patched)
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
        _safe_commit(con)
    return updated


def active_preexisting_finding_ids(
    cm: CodeMender,
    pre_scan_finding_ids: Set[str],
    pre_scan_session_ids: Set[str],
) -> Set[str]:
    """Returns preexisting finding_ids that have not been re-found by a current-scan session."""
    if not pre_scan_finding_ids:
        return set()
    con = _unwrap_db(cm)
    if con is None:
        return set(pre_scan_finding_ids)
    col_names, row_dicts = _fetch_rows(con, "findings", order_by_rowid=False)
    if not col_names or "finding_id" not in col_names or "session_id" not in col_names:
        return set(pre_scan_finding_ids)
    return {
        str(rd.get("finding_id") or "")
        for rd in row_dicts
        if str(rd.get("finding_id") or "") in pre_scan_finding_ids
        and (
            not str(rd.get("session_id") or "")
            or str(rd.get("session_id") or "") in pre_scan_session_ids
        )
    }


# ─── sessions table & batch stdout operations ────────────────────────────────


def extract_batch_files_from_stdout(stdout: str) -> List[str]:
    """Extracts repo-relative file paths from `cm find --deep` batch progress lines."""
    if not stdout:
        return []
    seen: Set[str] = set()
    ordered: List[str] = []
    for match in _DEEP_BATCH_LINE_RE.finditer(stdout):
        rel_path = strip_dot_slash(match.group(1).strip())
        if rel_path and rel_path not in seen:
            seen.add(rel_path)
            ordered.append(rel_path)
    return ordered


def extract_failed_batch_files_from_stdout(stdout: str) -> Set[str]:
    """Extracts repo-relative file paths from failed `cm find --deep` batch lines and summary blocks."""
    if not stdout:
        return set()
    out: Set[str] = set()
    for match in _DEEP_FAILED_BATCH_LINE_RE.finditer(stdout):
        rel_path = strip_dot_slash(match.group(1).strip())
        if rel_path:
            out.add(rel_path)
    for block_match in _DEEP_FAILED_SUMMARY_BLOCK_RE.finditer(stdout):
        for bullet_match in _DEEP_FAILED_BULLET_RE.finditer(block_match.group(1)):
            rel_path = strip_dot_slash(bullet_match.group(1).strip())
            if rel_path:
                out.add(rel_path)
    return out


def snapshot_db_session_ids(cm: CodeMender) -> Set[str]:
    """Captures the set of existing session_ids in state.db sessions."""
    con = _unwrap_db(cm)
    if con is None:
        return set()
    try:
        rows = con.execute("SELECT session_id FROM sessions").fetchall()
    except sqlite3.Error:
        return set()
    return {str(r[0]) for r in rows if r and r[0]}


def inspect_find_sessions(
    cm: CodeMender,
    last_pass_files: Optional[Iterable[str]] = None,
    last_pass_stdout: Optional[str] = None,
    critical_high_only: bool = True,
    exclude_session_ids: Optional[Set[str]] = None,
    exclude_finding_ids: Optional[Set[str]] = None,
) -> Tuple[Dict[str, int], List[str]]:
    """Queries `sessions` once to compute `(latest_finding_counts, unresolved_failed_targets)`.

    Recovers promoted parent sessions (attributing findings by `file_path` and restoring
    `sessions.target` for 0-finding or single-file promoted sessions) and assigns count >= 1
    to non-`COMPLETED` per-file sessions so they remain active for retry.
    """
    con = _unwrap_db(cm)
    if con is None:
        return {}, []
    repo_real = os.path.realpath(cm.repo_dir)
    excluded_fids = {str(fid) for fid in exclude_finding_ids if fid} if exclude_finding_ids else set()
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finding_cols = (
            {desc[1] for desc in con.execute("PRAGMA table_info(findings)").fetchall()}
            if "findings" in tables
            else set()
        )
        has_findings_table = "findings" in tables
        has_file_path_col = "file_path" in finding_cols
        filter_by_severity = bool(critical_high_only and "severity" in finding_cols)
        sev_clause = (
            " AND UPPER(COALESCE(f.severity, '')) IN ('CRITICAL', 'HIGH')"
            if filter_by_severity
            else ""
        )
        fid_excl_clause = ""
        fid_excl_params: List[str] = []
        if has_findings_table and excluded_fids and "finding_id" in finding_cols:
            sorted_fids = sorted(excluded_fids)
            placeholders = ", ".join("?" * len(sorted_fids))
            fid_excl_clause = f" AND COALESCE(f.finding_id, '') NOT IN ({placeholders})"
            fid_excl_params = sorted_fids

        if has_findings_table:
            count_select = (
                f"(SELECT COUNT(*) FROM findings f WHERE f.session_id = s.session_id"
                f" AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED'){sev_clause}{fid_excl_clause}) AS finding_count,"
                f" (SELECT COUNT(*) FROM findings f WHERE f.session_id = s.session_id"
                f" AND f.status IN ('OPEN', 'VERIFIED', 'REOPENED'){fid_excl_clause}) AS any_finding_count"
            )
            query_params = [*fid_excl_params, *fid_excl_params, cm.repo_dir, repo_real]
        else:
            count_select = "0 AS finding_count, 0 AS any_finding_count"
            query_params = [cm.repo_dir, repo_real]

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
                   {count_select}
            FROM sessions s
            WHERE s.session_type = 'FIND'
              AND s.target != ''
              AND (s.project_root = '' OR s.project_root = ? OR s.project_root = ?)
            ORDER BY s.updated_at ASC,
                     CASE WHEN UPPER(COALESCE(s.status, '')) = 'COMPLETED' THEN 1 ELSE 0 END ASC,
                     s.created_at ASC,
                     s.rowid ASC
            """,
            query_params,
        ).fetchall()
    except sqlite3.Error:
        return {}, []

    latest_counts: Dict[str, int] = {}
    latest_status: Dict[str, str] = {}
    latest_root_failed = False
    last_root_target = "."
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
        norm_status = str(status or "").upper()
        is_completed = norm_status == "COMPLETED"
        target_str = str(target or "")
        proj_root_str = str(project_root or "")
        parent_id_str = str(parent_session_id or "")
        is_root_target = target_str in (".", cm.repo_dir, repo_real, proj_root_str)

        if has_children or is_root_target:
            latest_parent_id = sid
            latest_parent_completed = is_completed
            latest_root_failed = norm_status == "FAILED"
            last_root_target = target_str or "."
            parent_finding_targets.setdefault(sid, set())
            if not is_root_target:
                rel_target = _rel_db_path(target_str, cm.repo_dir, repo_real, proj_root_str)
                if rel_target:
                    latest_status[rel_target] = norm_status
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
                    rel_fp = _rel_db_path(str(raw_fp), cm.repo_dir, repo_real, proj_root_str)
                    if rel_fp:
                        latest_counts[rel_fp] = int(f_cnt or 0)
                        parent_finding_targets[sid].add(rel_fp)
                if is_root_target and len(parent_finding_targets[sid]) == 1:
                    sole_fp = next(iter(parent_finding_targets[sid]))
                    latest_status[sole_fp] = norm_status
                    try:
                        con.execute(
                            "UPDATE sessions SET target = ? WHERE session_id = ?",
                            (sole_fp, sid),
                        )
                        con.commit()
                    except sqlite3.Error:
                        pass
        else:
            if is_completed:
                latest_root_failed = False
            rel_target = _rel_db_path(target_str, cm.repo_dir, repo_real, proj_root_str)
            if rel_target:
                latest_status[rel_target] = norm_status
                latest_counts[rel_target] = (
                    int(finding_count) if is_completed else max(int(finding_count), 1)
                )
                if parent_id_str:
                    latest_parent_id = parent_id_str
                    if is_completed:
                        child_targets_by_parent.setdefault(parent_id_str, set()).add(rel_target)

    failed_stdout_files = (
        extract_failed_batch_files_from_stdout(last_pass_stdout)
        if last_pass_stdout
        else set()
    )
    for failed_file in failed_stdout_files:
        latest_counts[failed_file] = max(latest_counts.get(failed_file, 0), 1)

    known_last_pass_files: List[str] = []
    if last_pass_files:
        known_last_pass_files.extend(
            _rel_db_path(f, cm.repo_dir, repo_real) for f in last_pass_files
        )
    if last_pass_stdout:
        known_last_pass_files.extend(extract_batch_files_from_stdout(last_pass_stdout))

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
                    for f in extract_batch_files_from_stdout(last_pass_stdout)
                    if f not in latest_children
                    and f not in latest_parent_with_findings
                    and f not in failed_stdout_files
                ]
                if len(stdout_unaccounted) == 1:
                    promoted_target = stdout_unaccounted[0]
            if promoted_target:
                try:
                    cur = con.execute(
                        "UPDATE sessions SET target = ? WHERE session_id = ?",
                        (promoted_target, latest_parent_id),
                    )
                    if cur.rowcount:
                        latest_status[promoted_target] = "COMPLETED"
                    con.commit()
                except sqlite3.Error:
                    pass

    unresolved_failed = sorted(t for t, st in latest_status.items() if st == "FAILED")
    if not unresolved_failed and latest_root_failed:
        unresolved_failed.append(last_root_target)

    return latest_counts, unresolved_failed


def get_latest_session_finding_counts(
    cm: CodeMender,
    last_pass_files: Optional[Iterable[str]] = None,
    last_pass_stdout: Optional[str] = None,
    critical_high_only: bool = True,
    exclude_session_ids: Optional[Set[str]] = None,
    exclude_finding_ids: Optional[Set[str]] = None,
) -> Dict[str, int]:
    """Returns the active finding count of the most recent FIND session per target."""
    counts, _ = inspect_find_sessions(
        cm,
        last_pass_files=last_pass_files,
        last_pass_stdout=last_pass_stdout,
        critical_high_only=critical_high_only,
        exclude_session_ids=exclude_session_ids,
        exclude_finding_ids=exclude_finding_ids,
    )
    return counts


def extract_safety_blocked_files(
    cm: CodeMender,
    stdout: str,
    pass_pre_session_ids: Set[str],
    primary_model: str,
) -> Tuple[Set[str], bool]:
    """Identifies files blocked by safety filters (or downgraded to a non-Argon/Carbon fallback model)."""
    blocked: Set[str] = set()
    text = stdout or ""

    reason_matches = list(_DEEP_FAILED_BATCH_WITH_REASON_RE.finditer(text))
    if reason_matches:
        for m in reason_matches:
            rel_path = strip_dot_slash(m.group(1).strip())
            reason = (m.group(2) or m.group(3) or "").strip()
            if rel_path and codemender._SAFETY_BLOCK_ERROR.search(reason):
                blocked.add(rel_path)
    elif codemender._SAFETY_BLOCK_ERROR.search(text):
        blocked.update(extract_failed_batch_files_from_stdout(text))
        for sm in _DEEP_SINGLE_INCOMPLETE_FILE_RE.finditer(text):
            rel_path = strip_dot_slash(sm.group(1).strip())
            reason = sm.group(2).strip()
            if rel_path and codemender._SAFETY_BLOCK_ERROR.search(reason):
                blocked.add(rel_path)

    con = _unwrap_db(cm)
    if con is not None:
        repo_real = os.path.realpath(cm.repo_dir)
        try:
            session_cols = {
                desc[1] for desc in con.execute("PRAGMA table_info(sessions)").fetchall()
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
                        rel = _rel_db_path(target_str, cm.repo_dir, repo_real, proj_root_str)
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
