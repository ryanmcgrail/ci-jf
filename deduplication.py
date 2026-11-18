"""Deduplication helpers and state.db consolidation for CodeMender findings."""

from datetime import datetime, timezone
import json
import re
import sqlite3
import sys
import types
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from cwe_database import load_cwe_database, parse_cwe_id
from finding import Finding

CWE_DB = load_cwe_database()
GITHUB_MARKER_RE = re.compile(r"<!--\s*cm-dedup:v1:(\{.*?\})\s*-->", re.DOTALL)
ACTIVE = {"OPEN", "REOPENED", "VERIFIED", ""}
RESOLVED = {"FIXED", "CLOSED"}
CRITICAL_HIGH_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
SEVERITY_RANK = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "INFORMATIONAL": 4,
}
CM_TWIN_REASONS = (
    "Duplicate un-fingerprinted streamed entry",
    "Duplicate finding entry",
)  # cm's own in-run dedup markers


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_rel_path(file_path: str, repo_root: str = "") -> str:
    p = (file_path or "").strip().replace("\\", "/")
    if not p:
        return ""
    if repo_root:
        root = repo_root.strip().replace("\\", "/").rstrip("/") + "/"
        if p.startswith(root):
            return p[len(root):].lstrip("./").lower()
    return p.lstrip("./").lower()


def code_lines(snippet: str) -> set:
    raw = (snippet or "").replace("\\r\\n", "\n").replace("\\n", "\n").splitlines()
    return {
        re.sub(r"\s+", " ", ln.strip())
        for ln in raw
        if len(ln.strip()) >= 20 and not ln.strip().startswith(("//", "#", "/*", "*"))
    }


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v or default)
    except (TypeError, ValueError):
        return default


def has_disjoint_positive_lines(a: Finding, b: Finding) -> bool:
    """Returns True when both findings have positive line numbers and their ranges do not overlap."""
    sla = _int(a.start_line)
    ela = max(_int(a.end_line, sla), sla)
    slb = _int(b.start_line)
    elb = max(_int(b.end_line, slb), slb)
    return sla > 0 and slb > 0 and (ela < slb or elb < sla)


def is_duplicate(
    a: Finding,
    b: Finding,
    repo_root: str = "",
    allow_line_shift: bool = True,
) -> bool:
    fa = norm_rel_path(a.file_path or "", repo_root)
    fb = norm_rel_path(b.file_path or "", repo_root)
    if not fa or fa != fb or CWE_DB.find_parent(a, b) is None:
        return False
    sla = _int(a.start_line)
    ela = max(_int(a.end_line, sla), sla)
    slb = _int(b.start_line)
    elb = max(_int(b.end_line, slb), slb)
    if sla > 0 and slb > 0 and sla <= elb and slb <= ela:
        return True
    if not allow_line_shift and sla > 0 and slb > 0:
        return False
    la = set(a.raw_lines or code_lines(a.snippet or ""))
    lb = set(b.raw_lines or code_lines(b.snippet or ""))
    return bool(la and lb and (la <= lb or lb <= la))


def make_github_marker(f: Finding, repo_root: str = "") -> str:
    cwe_id = parse_cwe_id(f)
    vuln_type = f"CWE-{cwe_id}" if cwe_id is not None else str(f.vuln_type or f.vuln_id or "UNKNOWN")
    payload = {
        "file_path": norm_rel_path(f.file_path or "", repo_root),
        "vuln_type": vuln_type,
        "start_line": _int(f.start_line),
        "end_line": _int(f.end_line),
        "raw_lines": sorted(code_lines(f.snippet or "")),
    }
    return f"<!-- cm-dedup:v1:{json.dumps(payload, separators=(',', ':'))} -->"


def unpack_findings(data: Any) -> List[Finding]:
    """cm report JSON (array or {findings: []}) or `gh issue list --json` output → findings."""
    if data is None:
        return []
    items = (
        data
        if isinstance(data, list)
        else next((data.get(k) for k in ("findings", "results", "items") if isinstance(data.get(k), list)), [])
    )
    out: List[Finding] = []
    for it in items or []:
        if isinstance(it, Finding):
            out.append(it)
            continue
        if not isinstance(it, dict):
            continue
        if "body" in it and "file_path" not in it:
            m = GITHUB_MARKER_RE.search(it.get("body") or "")
            if m:
                parsed = json.loads(m.group(1))
                parsed["gh_issue_number"] = it.get("number")
                parsed["state"] = it.get("state")
                out.append(Finding.from_dict(parsed))
        else:
            out.append(Finding.from_dict(it))
    return out


def load_findings(path: str) -> List[Finding]:
    with open(path, encoding="utf-8") as fh:
        return unpack_findings(json.load(fh))


def status_of(f: Finding) -> str:
    return str(f.status or "OPEN").upper()


def severity_rank(severity: Any) -> int:
    return SEVERITY_RANK.get(str(severity or "").strip().upper(), 99)


def higher_severity(sev_a: Any, sev_b: Any) -> Optional[str]:
    """Returns whichever severity is higher (e.g. HIGH over MEDIUM), never downgrading."""
    norm_a = str(sev_a or "").strip().upper()
    norm_b = str(sev_b or "").strip().upper()
    rank_a = severity_rank(norm_a)
    rank_b = severity_rank(norm_b)
    if rank_b < rank_a:
        return norm_b or None
    if rank_a < 99:
        return norm_a
    return norm_a or norm_b or None


def dup_id(m: Finding) -> Any:
    return m.finding_id or m.gh_issue_number or m.file_path


def _upgrade_list_entry_severity(items: List[Finding], target: Finding, new_sev: str) -> None:
    target_key = dup_id(target)
    for idx, item in enumerate(items):
        if item is target or (target_key and dup_id(item) == target_key):
            if severity_rank(new_sev) < severity_rank(item.severity):
                items[idx] = Finding(item.to_dict(), severity=new_sev)


def dedup(
    existing: List[Finding],
    current: List[Finding],
    repo_root: str,
    allow_line_shift: bool = True,
) -> Dict[str, List[Finding]]:
    """Partition `current` against `existing`. A match on an active entry → suppressed
    duplicate; a match only on a FIXED/CLOSED entry → reopened (regression, not noise).
    Preference among several matches: ACTIVE > FIXED/CLOSED > DISMISSED, so a dismissed
    twin never hides a regression of a fixed finding. Severities can only increase over time.
    Cross-run comparisons (`existing` vs `current`) tolerate shifted line numbers when
    `allow_line_shift=True`, whereas intra-`current` comparisons within the same scan
    snapshot keep disjoint positive line ranges distinct."""
    pool: List[Finding] = []
    res: Dict[str, List[Finding]] = {"findings": [], "reopened": [], "suppressed_duplicates": []}
    for ex in existing:
        if status_of(ex) in ACTIVE:
            m_idx = next(
                (
                    idx
                    for idx, p in enumerate(pool)
                    if status_of(p) in ACTIVE
                    and is_duplicate(p, ex, repo_root, allow_line_shift=allow_line_shift)
                ),
                None,
            )
            if m_idx is not None:
                m = pool[m_idx]
                best = higher_severity(m.severity, ex.severity)
                if best and severity_rank(best) < severity_rank(m.severity):
                    pool[m_idx] = Finding(m.to_dict(), severity=best)
                marker = make_github_marker(ex, repo_root)
                res["suppressed_duplicates"].append(
                    Finding(ex.to_dict(), github_marker=marker, duplicate_of=dup_id(m))
                )
                continue
        pool.append(ex)
    existing_pool_len = len(pool)
    for cur in current:
        matches = [
            p
            for idx, p in enumerate(pool)
            if is_duplicate(
                p,
                cur,
                repo_root,
                allow_line_shift=(allow_line_shift if idx < existing_pool_len else False),
            )
        ]
        m = (
            next((p for p in matches if status_of(p) in ACTIVE), None)
            or next((p for p in matches if status_of(p) in RESOLVED), None)
            or (matches[0] if matches else None)
        )
        marker = make_github_marker(cur, repo_root)
        if m is None:
            e = Finding(cur.to_dict(), github_marker=marker)
            res["findings"].append(e)
            pool.append(e)
        elif status_of(m) in RESOLVED:
            best_sev = cur.severity
            for p in matches:
                best_sev = higher_severity(p.severity, best_sev)
            reopened_kwargs: Dict[str, Any] = {
                "github_marker": marker,
                "duplicate_of": dup_id(m),
            }
            if best_sev:
                reopened_kwargs["severity"] = best_sev
            e = Finding(cur.to_dict(), **reopened_kwargs)
            res["reopened"].append(e)
            pool.append(e)
        else:
            best_sev = m.severity
            for p in matches:
                best_sev = higher_severity(p.severity, best_sev)
            best_sev = higher_severity(best_sev, cur.severity)
            if best_sev and severity_rank(best_sev) < severity_rank(m.severity):
                _upgrade_list_entry_severity(pool, m, best_sev)
                _upgrade_list_entry_severity(res["findings"], m, best_sev)
                _upgrade_list_entry_severity(res["reopened"], m, best_sev)
            e = Finding(cur.to_dict(), github_marker=marker, duplicate_of=dup_id(m))
            res["suppressed_duplicates"].append(e)
    return res


def is_critical_high(f: Finding) -> bool:
    return str(f.severity or "").strip().upper() in CRITICAL_HIGH_SEVERITIES


def summary_line(
    existing_n: int,
    current_n: int,
    res: Dict[str, List[Finding]],
    critical_high_only: bool = False,
) -> str:
    if critical_high_only:
        suppressed_ch = [f for f in res["suppressed_duplicates"] if is_critical_high(f)]
        new_ch = [f for f in res["findings"] if is_critical_high(f)]
        reopened_ch = [f for f in res["reopened"] if is_critical_high(f)]
        crit_n = sum(1 for f in new_ch if str(f.severity or "").strip().upper() == "CRITICAL")
        high_n = len(new_ch) - crit_n
        return (
            f"CRITICAL/HIGH Summary — Existing: {existing_n} | Current: {current_n}"
            f" | Duplicates suppressed: {len(suppressed_ch)}"
            f" | New to file: {len(new_ch)} ({crit_n} CRITICAL, {high_n} HIGH)"
            f" | Reopened: {len(reopened_ch)}"
        )
    return (
        f"Existing: {existing_n} | Current: {current_n} | Duplicates suppressed: {len(res['suppressed_duplicates'])}"
        f" | New to file: {len(res['findings'])} | Reopened: {len(res['reopened'])}"
    )


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


def _update_finding_json_str(raw_json: Any, **updates: Any) -> Any:
    if not isinstance(raw_json, str) or not raw_json.strip():
        return raw_json
    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return raw_json
    if not isinstance(parsed, dict) or not parsed:
        return raw_json
    parsed.update(updates)
    return json.dumps(parsed)


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
    cur_sev = _extract_row_severity(row_dict)
    if severity_rank(cand) >= severity_rank(cur_sev):
        return False
    sets = ["severity=?"]
    params: List[Any] = [cand]
    if has_fjson:
        updated_fjson = _update_finding_json_str(row[1], severity=cand)
        if updated_fjson != row[1]:
            sets.append("finding_json=?")
            params.append(updated_fjson)
    params.append(fid)
    con.execute(f"UPDATE findings SET {', '.join(sets)} WHERE finding_id=?", params)
    return True


def remove_duplicates_in_db(ctx: Any, dups: List[Finding]) -> Optional[Tuple[int, int]]:
    """Drop duplicate rows from CodeMender's state.db so `cm report` (which lists every
    status) shows each bug once: the cross-run duplicates found here plus the DISMISSED
    twins cm itself writes in deep mode. Rows referenced by a patch/artifact are never
    deleted — they are marked DISMISSED instead. Returns (removed, marked); None = no DB."""
    con = ctx.cm.db
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
        now = now_rfc3339()
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
    """Reconciles findings overwritten in-place by cm, disambiguating disjoint collisions and ensuring severities never decrease."""
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
    if not rows or "finding_id" not in col_names:
        return

    has_session_col = "session_id" in col_names
    changed = False
    for row in rows:
        cur_row = dict(zip(col_names, row))
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

        old_sl = _int(old_row.get("start_line"))
        old_el = max(_int(old_row.get("end_line"), old_sl), old_sl)
        cur_sl = _int(cur_row.get("start_line"))
        cur_el = max(_int(cur_row.get("end_line"), cur_sl), cur_sl)

        if sid_changed and old_sl > 0 and cur_sl > 0 and (old_el < cur_sl or cur_el < old_sl):
            disambiguated_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{fid}:{old_sl}:{old_el}"))
            restored = dict(old_row)
            restored["finding_id"] = disambiguated_id
            if restored.get("fingerprint"):
                restored["fingerprint"] = f"{restored['fingerprint']}:{old_sl}:{old_el}"
            if "finding_json" in restored:
                restored["finding_json"] = _update_finding_json_str(
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
                    params.append(
                        _update_finding_json_str(cur_row.get("finding_json"), severity=best_sev)
                    )
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
        try:
            con.commit()
        except sqlite3.Error:
            pass


def deduplicate_db_findings(
    cm: Any,
    exclude_finding_ids: Optional[Set[str]] = None,
) -> None:
    """Deduplicates active current-scan findings in state.db via `dedup()`, syncing monotonic severities."""
    con = cm.db
    if con is None:
        return
    try:
        cur = con.execute("SELECT * FROM findings ORDER BY rowid ASC")
        col_list = [desc[0] for desc in (cur.description or [])]
        rows = cur.fetchall()
    except sqlite3.Error:
        return
    cols = set(col_list)
    if not rows or "file_path" not in cols:
        return

    all_row_dicts = [dict(zip(col_list, row)) for row in rows]
    preexisting_findings: List[Finding] = []
    if exclude_finding_ids:
        preexisting_findings = [
            Finding.from_dict(rd)
            for rd in all_row_dicts
            if str(rd.get("finding_id") or "") in exclude_finding_ids
        ]
        row_dicts = [
            rd
            for rd in all_row_dicts
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
        remove_duplicates_in_db(types.SimpleNamespace(cm=cm), res["suppressed_duplicates"])
    elif upgraded_any:
        try:
            con.commit()
        except sqlite3.Error:
            pass

