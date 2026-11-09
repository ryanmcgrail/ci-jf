#!/usr/bin/env python3
"""Sequentially stages repos.tsv repos as tarballs in the payload bucket.

Each tarball is a depth-1 clone at pinned_ref (keeping .git) with a single
top-level <repo_id>/ directory. Existing tarballs are skipped unless --force.
Rows of a diff manifest (config/repos_with_diff.tsv, with a diff_ref column)
are cloned deep enough to contain diff_ref instead (see stage_one_diff).
"""

import argparse
import pathlib
import sys
import tempfile

from cmrun import common


def stage_one(runner, repo_id, meta, bucket, force, workdir):
  uri = common.repo_tarball_uri(bucket, repo_id)
  if not force and common.gcs_exists(runner, uri):
    print(f"[skip] {repo_id}: {uri} exists")
    return "skipped"
  work = pathlib.Path(workdir)
  repo_dir = work / repo_id
  tar_path = work / f"{repo_id}.tar.gz"
  print(f"[clone] {repo_id}: {meta['git_url']} @ {meta['pinned_ref']}")
  ref = meta["pinned_ref"]
  try:
    if common.is_commit_sha(ref):
      # `clone --branch` only takes branches/tags; fetch a commit at depth 1.
      runner.run(["git", "-c", "init.defaultRefFormat=files", "init", "--quiet",
                  str(repo_dir)])
      runner.run(["git", "-C", str(repo_dir), "fetch", "--quiet", "--depth", "1",
                  meta["git_url"], ref])
      runner.run(["git", "-C", str(repo_dir), "reset", "--quiet", "--hard",
                  "FETCH_HEAD"])
    else:
      runner.run(["git", "-c", "init.defaultRefFormat=files", "clone", "--quiet",
                  "--depth", "1", "--branch", ref, meta["git_url"], str(repo_dir)])
  except RuntimeError as e:
    print(f"[WARN] {repo_id}: failed to checkout pinned_ref '{ref}' from "
          f"{meta['git_url']}; update config/repos.tsv")
    raise RuntimeError(
        f"{repo_id}: pinned_ref '{ref}' not found in {meta['git_url']}; "
        f"fix config/repos.tsv ({e})") from e
  runner.run(["tar", "-czf", str(tar_path), "-C", str(work), repo_id])
  print(f"[upload] {repo_id}: {uri}")
  runner.run(["gcloud", "storage", "cp", str(tar_path), uri])
  return "uploaded"


def _git(runner, repo_dir, *args, check=True):
  return runner.run(["git", "-C", str(repo_dir), *args], check=check)


def _init(runner, repo_dir):
  runner.run(["git", "-c", "init.defaultRefFormat=files", "init", "--quiet",
              str(repo_dir)])


def _is_ancestor(runner, repo_dir, diff_ref, head):
  return _git(runner, repo_dir, "merge-base", "--is-ancestor", diff_ref, head,
              check=False).returncode == 0


def stage_one_diff(runner, repo_id, meta, bucket, force, workdir):
  """Stages a diff case: a full clone of pinned_ref deep enough for diff_ref.

  A commit-graph-only (tree:0) fetch checks that diff_ref is an ancestor of
  pinned_ref and counts N = rev-list --count diff_ref..pinned_ref; a fresh,
  non-partial depth-(N+1) fetch then holds diff_ref and the merge-base, so
  `cm find --diff=<diff_ref>` runs in merge-base mode without network. The
  tarball name embeds both SHAs, so an existing one is reused unless --force.
  """
  uri = common.repo_tarball_uri(bucket, repo_id)
  if not force and common.gcs_exists(runner, uri):
    print(f"[skip] {repo_id}: {uri} exists")
    return "skipped"
  url, pinned, diff = meta["git_url"], meta["pinned_ref"], meta["diff_ref"]
  work = pathlib.Path(workdir)
  probe, repo_dir = work / f"{repo_id}.graph", work / repo_id
  print(f"[clone] {repo_id}: {url} @ {pinned} (diff {diff})")
  _init(runner, probe)
  try:
    _git(runner, probe, "fetch", "--quiet", "--filter=tree:0", url, pinned)
  except RuntimeError as e:
    raise RuntimeError(f"{repo_id}: pinned_ref {pinned} not found in {url} "
                       f"({e})") from e
  if not _is_ancestor(runner, probe, diff, pinned):
    raise RuntimeError(f"{repo_id}: diff_ref {diff} is not an ancestor of "
                       f"pinned_ref {pinned} in {url}")
  count = _git(runner, probe, "rev-list", "--count",
               f"{diff}..{pinned}").stdout.strip()
  if not count.isdigit() or int(count) < 1:
    raise RuntimeError(f"{repo_id}: bad rev-list count {count!r} for "
                       f"{diff}..{pinned}")
  depth = int(count) + 1
  print(f"[fetch] {repo_id}: depth {depth} ({count} commit(s) in diff range)")
  _init(runner, repo_dir)
  _git(runner, repo_dir, "fetch", "--quiet", "--depth", str(depth), url, pinned)
  _git(runner, repo_dir, "reset", "--quiet", "--hard", "FETCH_HEAD")
  if (_git(runner, repo_dir, "cat-file", "-e", f"{diff}^{{commit}}",
           check=False).returncode != 0
      or not _is_ancestor(runner, repo_dir, diff, "HEAD")):
    raise RuntimeError(f"{repo_id}: depth-{depth} clone of {pinned} does not "
                       f"contain diff_ref {diff} as an ancestor")
  runner.run(["tar", "-czf", str(work / f"{repo_id}.tar.gz"), "-C", str(work),
              repo_id])
  print(f"[upload] {repo_id}: {uri}")
  runner.run(["gcloud", "storage", "cp", str(work / f"{repo_id}.tar.gz"), uri])
  return "uploaded"


def stage(runner, repo_id, meta, bucket, force, workdir):
  """Stages a diff case (row has diff_ref) or a full-scan repo."""
  fn = stage_one_diff if meta.get("diff_ref") else stage_one
  return fn(runner, repo_id, meta, bucket, force, workdir)


def main(argv=None, runner=None):
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--repos-tsv", default=str(common.DEFAULT_REPOS_TSV))
  parser.add_argument("--repos", nargs="+", default=None)
  parser.add_argument("--bucket", default=None,
                      help="payload bucket (default gs://<project>-cm-payload)")
  parser.add_argument("--project", default=None, help=argparse.SUPPRESS)
  parser.add_argument("--force", action="store_true")
  args = parser.parse_args(argv)
  runner = runner or common.Runner()
  try:
    repos = common.load_repos(args.repos_tsv)
    if common.is_diff_manifest(repos):
      common.validate_diff_repos(repos)
    targets = common.select_repos(repos, args.repos)
  except common.UsageError as e:
    parser.error(str(e))
  bucket = args.bucket or common.payload_bucket(
      args.project or common.gcloud_project(runner))
  counts = {"skipped": 0, "uploaded": 0}
  for repo_id in targets:
    with tempfile.TemporaryDirectory(prefix="cm_stage_") as tmp:
      counts[stage(runner, repo_id, repos[repo_id], bucket, args.force,
                   tmp)] += 1
  print(f"done: {counts['uploaded']} uploaded, {counts['skipped']} skipped")
  return 0


if __name__ == "__main__":
  sys.exit(main())
