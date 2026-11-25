"""Pure in-memory deduplication, path normalization, and severity rules for findings."""

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional

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

_FS_CASE_SENSITIVE_CACHE: Dict[str, bool] = {}


def _swap_first_alpha_case(name: str) -> Optional[str]:
    for idx, ch in enumerate(name):
        swapped = ch.swapcase()
        if swapped != ch:
            return name[:idx] + swapped + name[idx + 1 :]
    return None


def _is_case_sensitive_fs(repo_root: str = "") -> bool:
    """Detects whether the filesystem hosting `repo_root` (or cwd) is case-sensitive."""
    probe_dir = repo_root if (repo_root and os.path.exists(repo_root)) else os.getcwd()
    real_dir = os.path.realpath(probe_dir)
    cached = _FS_CASE_SENSITIVE_CACHE.get(real_dir)
    if cached is not None:
        return cached

    result: Optional[bool] = None
    if os.path.isdir(real_dir):
        try:
            for entry in os.listdir(real_dir):
                swapped = _swap_first_alpha_case(entry)
                if swapped:
                    orig_p = os.path.join(real_dir, entry)
                    swap_p = os.path.join(real_dir, swapped)
                    result = not (os.path.exists(swap_p) and os.path.samefile(orig_p, swap_p))
                    break
        except OSError:
            result = None

    if result is None:
        parent = os.path.dirname(real_dir)
        base = os.path.basename(real_dir)
        swapped_base = _swap_first_alpha_case(base)
        if parent and swapped_base and os.path.exists(real_dir):
            swap_dir = os.path.join(parent, swapped_base)
            try:
                result = not (os.path.exists(swap_dir) and os.path.samefile(real_dir, swap_dir))
            except OSError:
                result = None

    if result is None:
        mod_path = os.path.abspath(__file__)
        swapped_mod = _swap_first_alpha_case(os.path.basename(mod_path))
        if swapped_mod:
            swap_mod_path = os.path.join(os.path.dirname(mod_path), swapped_mod)
            try:
                result = not (os.path.exists(swap_mod_path) and os.path.samefile(mod_path, swap_mod_path))
            except OSError:
                result = os.name != "nt"
        else:
            result = os.name != "nt"

    _FS_CASE_SENSITIVE_CACHE[real_dir] = result
    return result


def strip_dot_slash(path: str) -> str:
    """Strips leading `./` and `/` prefixes while preserving hidden directory names like `.github`."""
    p = path
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def norm_rel_path(
    file_path: str,
    repo_root: str = "",
    case_sensitive: Optional[bool] = None,
    extra_roots: Iterable[str] = (),
) -> str:
    """Normalizes `file_path` to a forward-slash repository-relative path."""
    p = (file_path or "").strip().replace("\\", "/")
    if not p:
        return ""
    is_cs = _is_case_sensitive_fs(repo_root) if case_sensitive is None else case_sensitive
    rel = p
    raw_roots = [
        r for r in (repo_root, *extra_roots)
        if r and str(r).strip() and str(r).strip() != "."
    ]
    if raw_roots:
        candidates: List[str] = []
        for r in raw_roots:
            candidates.append(r)
            if os.path.exists(r):
                candidates.extend([os.path.abspath(r), os.path.realpath(r)])
        for cand in candidates:
            root = cand.strip().replace("\\", "/").rstrip("/") + "/"
            if root == "/":
                continue
            if rel.startswith(root) or (not is_cs and rel.lower().startswith(root.lower())):
                rel = rel[len(root) :]
                break
    rel = strip_dot_slash(rel)
    return rel if is_cs else rel.lower()


def code_lines(snippet: str) -> set:
    raw = (snippet or "").replace("\\r\\n", "\n").replace("\\n", "\n").splitlines()
    return {
        re.sub(r"\s+", " ", ln.strip())
        for ln in raw
        if len(ln.strip()) >= 20 and not ln.strip().startswith(("//", "#", "/*", "*"))
    }


def as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v or default)
    except (TypeError, ValueError):
        return default


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
    sla = as_int(a.start_line)
    ela = max(as_int(a.end_line, sla), sla)
    slb = as_int(b.start_line)
    elb = max(as_int(b.end_line, slb), slb)
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
        "file_path": norm_rel_path(f.file_path or "", repo_root, case_sensitive=True),
        "vuln_type": vuln_type,
        "start_line": as_int(f.start_line),
        "end_line": as_int(f.end_line),
        "raw_lines": sorted(code_lines(f.snippet or "")),
    }
    return f"<!-- cm-dedup:v1:{json.dumps(payload, separators=(',', ':'))} -->"


def unpack_findings(data: Any) -> List[Finding]:
    """cm report JSON (array or {findings: []}) or `gh issue list --json` output -> findings."""
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
    """Partition `current` against `existing`.

    A match on an active entry -> suppressed duplicate; a match only on a FIXED/CLOSED entry
    -> reopened (regression, not noise). Preference among several matches: ACTIVE > FIXED/CLOSED
    > DISMISSED, so a dismissed twin never hides a regression of a fixed finding. Severities can
    only increase over time. Cross-run comparisons (`existing` vs `current`) tolerate shifted
    line numbers when `allow_line_shift=True`, whereas intra-`current` comparisons within the
    same scan snapshot keep disjoint positive line ranges distinct.
    """
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
