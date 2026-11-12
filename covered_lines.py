#!/usr/bin/env python3
"""Prints already-covered line ranges in a target file from a preprocessed findings JSON file."""

import json
import os
import re
import sys
from typing import List, Optional, Tuple


def _norm_path(path: str, repo_dir: str = "") -> str:
  p = (path or "").strip().replace("\\", "/")
  if not p:
    return ""
  if repo_dir:
    for candidate in (repo_dir, os.path.abspath(repo_dir), os.path.realpath(repo_dir)):
      root = candidate.strip().replace("\\", "/").rstrip("/")
      if root and root != "." and p.startswith(root + "/"):
        p = p[len(root) + 1 :]
        break
  while p.startswith("./"):
    p = p[2:]
  return p


def _first_meaningful_line(lines: List[str], max_len: int = 100) -> str:
  for ln in lines:
    s = re.sub(r"\s+", " ", ln.strip())
    if s and s not in ("{", "}", "(", ")", "try {"):
      return s[:max_len] + ("..." if len(s) > max_len else "")
  for ln in lines:
    s = ln.strip()
    if s:
      return s[:max_len]
  return ""


def find_snippet_line_ranges(
    file_lines: List[str],
    snippet: str,
) -> List[Tuple[int, int]]:
  """Locates all 1-based (start_line, end_line) occurrences of `snippet` inside `file_lines`."""
  raw_lines = (snippet or "").replace("\r\n", "\n").replace("\r", "\n").splitlines()
  while raw_lines and not raw_lines[0].strip():
    raw_lines.pop(0)
  while raw_lines and not raw_lines[-1].strip():
    raw_lines.pop()
  if not raw_lines or not file_lines:
    return []

  n = len(raw_lines)
  m = len(file_lines)
  matches: List[Tuple[int, int]] = []

  # 1. Exact rstrip match
  if n <= m:
    target_rstrip = [ln.rstrip() for ln in raw_lines]
    file_rstrip = [ln.rstrip() for ln in file_lines]
    for i in range(m - n + 1):
      if file_rstrip[i : i + n] == target_rstrip:
        matches.append((i + 1, i + n))
    if matches:
      return matches

    # 2. Whitespace-trimmed contiguous match
    target_strip = [re.sub(r"\s+", " ", ln.strip()) for ln in raw_lines]
    file_strip = [re.sub(r"\s+", " ", ln.strip()) for ln in file_lines]
    for i in range(m - n + 1):
      if file_strip[i : i + n] == target_strip:
        matches.append((i + 1, i + n))
    if matches:
      return matches

  # 3. Non-empty line sequence match (tolerating blank line differences)
  non_empty_snip = [re.sub(r"\s+", " ", ln.strip()) for ln in raw_lines if ln.strip()]
  if non_empty_snip:
    non_empty_file = [
        (idx + 1, re.sub(r"\s+", " ", ln.strip()))
        for idx, ln in enumerate(file_lines)
        if ln.strip()
    ]
    k = len(non_empty_snip)
    if k <= len(non_empty_file):
      for i in range(len(non_empty_file) - k + 1):
        if [x[1] for x in non_empty_file[i : i + k]] == non_empty_snip:
          matches.append((non_empty_file[i][0], non_empty_file[i + k - 1][0]))
      if matches:
        return matches

    # 4. Fallback: match first and last non-empty lines if sufficiently distinctive
    first_ln = non_empty_snip[0]
    last_ln = non_empty_snip[-1]
    if len(first_ln) >= 10:
      for idx, fln in non_empty_file:
        if fln == first_ln:
          if k == 1:
            matches.append((idx, idx))
            continue
          found_end = False
          for end_idx, efln in non_empty_file:
            if end_idx >= idx and end_idx <= idx + max(n * 2, 20) and efln == last_ln:
              matches.append((idx, end_idx))
              found_end = True
              break
          if not found_end:
            matches.append((idx, min(m, idx + n - 1)))
      if matches:
        return matches

  return []


def find_snippet_line_range(
    file_lines: List[str],
    snippet: str,
) -> Optional[Tuple[int, int]]:
  """Locates the first 1-based (start_line, end_line) of `snippet` inside `file_lines`."""
  ranges = find_snippet_line_ranges(file_lines, snippet)
  return ranges[0] if ranges else None


def summarize_covered_lines(
    report_path: str,
    target_file: str,
    repo_dir: str = ".",
) -> str:
  """Returns a compact summary of already-covered line ranges for `target_file`."""
  norm_target = _norm_path(target_file, repo_dir)
  try:
    with open(report_path, "r", encoding="utf-8") as fh:
      items = json.load(fh)
  except (OSError, json.JSONDecodeError):
    items = []
  if not isinstance(items, list):
    items = []

  matching_snippets: List[str] = []
  for item in items:
    if not isinstance(item, dict):
      continue
    fp = _norm_path(str(item.get("file_path") or ""), repo_dir)
    if fp == norm_target or fp.lower() == norm_target.lower():
      snip = str(item.get("snippet") or "")
      if snip.strip():
        matching_snippets.append(snip)

  if not matching_snippets:
    return f"No preexisting findings for {norm_target}."

  candidate_path = os.path.join(repo_dir, norm_target)
  if not os.path.isfile(candidate_path) and os.path.isfile(target_file):
    candidate_path = target_file
  file_lines: List[str] = []
  if os.path.isfile(candidate_path):
    try:
      with open(candidate_path, "r", encoding="utf-8", errors="replace") as fh:
        file_lines = fh.read().splitlines()
    except OSError:
      file_lines = []

  resolved: List[Tuple[int, int, str]] = []
  unresolved: List[str] = []
  seen_entries = set()

  for snip in matching_snippets:
    raw_lines = snip.splitlines()
    preview = _first_meaningful_line(raw_lines)
    ranges = find_snippet_line_ranges(file_lines, snip) if file_lines else []
    if ranges:
      chosen = next(
          (r for r in ranges if (r[0], r[1], preview) not in seen_entries),
          ranges[0],
      )
      key = (chosen[0], chosen[1], preview)
      if key not in seen_entries:
        seen_entries.add(key)
        resolved.append(key)
    else:
      if preview and preview not in seen_entries:
        seen_entries.add(preview)
        unresolved.append(preview)

  resolved.sort(key=lambda x: (x[0], x[1]))
  out_lines = [f"Already-covered vulnerabilities in {norm_target}:"]
  for sl, el, preview in resolved:
    line_label = f"Line {sl}" if sl == el else f"Lines {sl}-{el}"
    out_lines.append(f"- {line_label}: {preview}")
  for preview in unresolved:
    out_lines.append(f"- Snippet: {preview}")
  return "\n".join(out_lines)


def main(argv: List[str]) -> int:
  if len(argv) < 2:
    print("Usage: covered_lines.py <report_file> <target_file>", file=sys.stderr)
    return 1
  print(summarize_covered_lines(argv[0], argv[1], repo_dir=os.getcwd()))
  return 0


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
