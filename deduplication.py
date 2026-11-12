"""Deduplication helpers and state.db consolidation for CodeMender findings."""

from datetime import datetime, timezone
import json
import re
import sqlite3
import sys
from typing import Any, Dict, List, Optional, Tuple

from cwe_database import load_cwe_database, parse_cwe_id
from finding import Finding

CWE_DB = load_cwe_database()
GITHUB_MARKER_RE = re.compile(r"<!--\s*cm-dedup:v1:(\{.*?\})\s*-->", re.DOTALL)
ACTIVE = {"OPEN", "REOPENED", "VERIFIED", ""}
RESOLVED = {"FIXED", "CLOSED"}
CRITICAL_HIGH_SEVERITIES = frozenset({"CRITICAL", "HIGH"})
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


def is_duplicate(a: Finding, b: Finding, repo_root: str = "") -> bool:
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


def dup_id(m: Finding) -> Any:
    return m.finding_id or m.gh_issue_number or m.file_path


def dedup(existing: List[Finding], current: List[Finding], repo_root: str) -> Dict[str, List[Finding]]:
    """Partition `current` against `existing`. A match on an active entry → suppressed
    duplicate; a match only on a FIXED/CLOSED entry → reopened (regression, not noise).
    Preference among several matches: ACTIVE > FIXED/CLOSED > DISMISSED, so a dismissed
    twin never hides a regression of a fixed finding."""
    pool: List[Finding] = []
    res: Dict[str, List[Finding]] = {"findings": [], "reopened": [], "suppressed_duplicates": []}
    for ex in existing:
        if status_of(ex) in ACTIVE:
            m = next((p for p in pool if status_of(p) in ACTIVE and is_duplicate(p, ex, repo_root)), None)
            if m is not None:
                marker = make_github_marker(ex, repo_root)
                res["suppressed_duplicates"].append(
                    Finding(ex.to_dict(), github_marker=marker, duplicate_of=dup_id(m))
                )
                continue
        pool.append(ex)
    for cur in current:
        matches = [p for p in pool if is_duplicate(p, cur, repo_root)]
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
            e = Finding(cur.to_dict(), github_marker=marker, duplicate_of=dup_id(m))
            res["reopened"].append(e)
            pool.append(e)
        else:
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

