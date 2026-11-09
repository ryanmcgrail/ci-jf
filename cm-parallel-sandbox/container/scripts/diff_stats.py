#!/usr/bin/env python3
"""Counts changed code files/lines between two commits, using cm's scan filters.

Shared by scripts/fetch_diff_repos.py (picks diff-size bands) and the container
entrypoint (diff-mode summary.json). The rule mirrors config/cm_config.yaml:

  git diff --numstat --no-renames -z <base> <head>, then
  1. drop binary files (numstat "-\t-"),
  2. keep paths ending in a scan.extensions.include suffix and not in a
     scan.extensions.exclude suffix,
  3. drop paths with any directory component in scan.exclude_dirs.

changed_files = remaining file count; changed_lines = added + deleted lines.
Submodule entries (gitlinks) never count: they have no content to scan. Symlinks
count like files, and scan.max_file_size_kb is not applied, so counts can be
slightly higher than what cm actually scans.

Usage:
  diff_stats.py --repo DIR --config cm_config.yaml --base SHA [--head REV] [--list]
prints {"changed_files": N, "changed_lines": N}, or with --list the counted
paths, one per line.
"""

import argparse
import json
import subprocess
import sys

import yaml

GITLINK = "160000"  # git tree mode of a submodule entry


def load_filters(config_path):
  """Returns (include, exclude, exclude_dirs) from a cm_config.yaml."""
  with open(config_path, encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
  scan = cfg.get("scan") or {}
  exts = scan.get("extensions") or {}
  return (tuple(exts.get("include") or ()), tuple(exts.get("exclude") or ()),
          frozenset(scan.get("exclude_dirs") or ()))


def is_counted(path, filters):
  include, exclude, exclude_dirs = filters
  if not path.endswith(include) or path.endswith(exclude):
    return False
  return not any(part in exclude_dirs for part in path.split("/")[:-1])


def parse_numstat_z(data):
  """Parses `git diff --numstat --no-renames -z` output.

  Returns [(added, deleted, path)]; added/deleted are None for binary files.
  """
  rows = []
  for rec in data.split(b"\0"):
    if not rec:
      continue
    added, deleted, path = rec.split(b"\t", 2)
    if added == b"-" and deleted == b"-":
      rows.append((None, None, path.decode("utf-8", "surrogateescape")))
    else:
      rows.append((int(added), int(deleted),
                   path.decode("utf-8", "surrogateescape")))
  return rows


def counted_rows(rows, filters):
  return [r for r in rows if r[0] is not None and is_counted(r[2], filters)]


def pathspecs(filters):
  """Git pathspecs equivalent to is_counted's path rules.

  Limiting `git diff` with these means blobs of non-code files are never read
  (so partial clones never fetch them). is_counted() is still applied to the
  output as the source of truth.
  """
  include, exclude, exclude_dirs = filters
  specs = [f":(glob)**/*{ext}" for ext in include]
  specs += [f":(glob,exclude)**/*{ext}" for ext in exclude]
  specs += [f":(glob,exclude)**/{d}/**" for d in sorted(exclude_dirs)]
  return specs


def _git_diff(repo, fmt, base, head, filters):
  # stderr is captured: partial clones print lazy blob-fetch progress there.
  proc = subprocess.run(
      ["git", "-C", str(repo), "diff", fmt, "--no-abbrev", "--no-renames", "-z",
       base, head, "--", *pathspecs(filters)],
      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  if proc.returncode != 0:
    sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
    raise subprocess.CalledProcessError(proc.returncode, proc.args,
                                        proc.stdout, proc.stderr)
  return proc.stdout


def numstat(repo, base, head, filters):
  return _git_diff(repo, "--numstat", base, head, filters)


def raw_records(repo, base, head, filters):
  """[(old_mode, new_mode, old_oid, new_oid, path)] for counted paths.

  Reads trees only, never blobs.
  """
  parts = _git_diff(repo, "--raw", base, head, filters).split(b"\0")
  recs = []
  for meta, path in zip(parts[0::2], parts[1::2]):
    if not meta:
      continue
    # ":<old mode> <new mode> <old oid> <new oid> <status>"
    old_mode, new_mode, old_oid, new_oid = meta.decode().lstrip(":").split()[:4]
    p = path.decode("utf-8", "surrogateescape")
    if is_counted(p, filters):
      recs.append((old_mode, new_mode, old_oid, new_oid, p))
  return recs


def _is_gitlink(rec):
  return GITLINK in (rec[0], rec[1])


def raw_blob_ids(repo, base, head, filters):
  """(blob ids of both sides, path count) for counted non-submodule paths.

  Binary files are included (numstat needs their content to tell), so the
  count is an upper bound on changed_files.
  """
  ids, n = set(), 0
  for rec in raw_records(repo, base, head, filters):
    if _is_gitlink(rec):
      continue
    n += 1
    ids.update(o for o in rec[2:4] if o.strip("0"))
  return ids, n


def compute(repo, filters, base, head="HEAD"):
  """Returns (stats_dict, counted_paths). Submodule entries never count."""
  gitlinks = {r[4] for r in raw_records(repo, base, head, filters)
              if _is_gitlink(r)}
  rows = [r for r in counted_rows(
      parse_numstat_z(numstat(repo, base, head, filters)), filters)
          if r[2] not in gitlinks]
  stats = {"changed_files": len(rows),
           "changed_lines": sum(a + d for a, d, _ in rows)}
  return stats, [p for _, _, p in rows]


def main(argv=None):
  p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
  p.add_argument("--repo", required=True)
  p.add_argument("--config", required=True)
  p.add_argument("--base", required=True)
  p.add_argument("--head", default="HEAD")
  p.add_argument("--list", action="store_true",
                 help="print counted paths instead of the JSON stats")
  a = p.parse_args(argv)
  stats, paths = compute(a.repo, load_filters(a.config), a.base, a.head)
  if a.list:
    out = getattr(sys.stdout, "buffer", None)
    for path in paths:
      line = path.encode("utf-8", "surrogateescape") + b"\n"
      if out is not None:
        out.write(line)
      else:  # e.g. a StringIO under test
        sys.stdout.write(line.decode("utf-8", "replace"))
    if out is not None:
      out.flush()
  else:
    print(json.dumps(stats))
  return 0


if __name__ == "__main__":
  sys.exit(main())
