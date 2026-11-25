"""Host-precomputed covered-lines manifest builder for multi-pass complete scans."""

import json
import os
from typing import Dict, Iterable, List, Optional, Set, Tuple

import covered_lines
from deduplication import norm_rel_path
from finding import Finding
from state_db import ACTIVE_REPORT_STATUSES

# Extensionless, slashless filename so `cm find` neither discovers it as a source
# file nor interprets a double-quoted mention in `--context` as a target file
# scope filter (never wrap it in backticks in `--context`, as `cm` checks all
# `` `...` `` spans via `os.Stat` against the repo root).
PASS_REPORT_REL_PATH = "_cm_pass_report"


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

    excluded = {str(fid) for fid in exclude_finding_ids if fid} if exclude_finding_ids else set()
    allowed_exact: Optional[Set[str]] = None
    allowed_lower: Optional[Set[str]] = None
    if only_files is not None:
        norm_only = {
            norm_rel_path(str(f), repo_dir, case_sensitive=True)
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
        if finding.status not in ACTIVE_REPORT_STATUSES:
            continue
        rel_fp = norm_rel_path(finding.file_path or "", repo_dir, case_sensitive=True)
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
            labels = [f"L{sl}" if sl == el else f"L{sl}-{el}" for sl, el in merged]
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
