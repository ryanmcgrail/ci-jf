"""Shared helpers: repos.tsv loading, naming, run ids, and an injectable Runner."""

import csv
import dataclasses
import datetime
import difflib
import pathlib
import re
import subprocess
from typing import Dict, List, Optional, Sequence

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_REPOS_TSV = REPO_ROOT / "config" / "repos.tsv"
DEFAULT_REGION = "us-central1"
FIND_JOB = "cm-find-runner"
VERIFY_JOB = "cm-verify-runner"
FIX_JOB = "cm-fix-runner"
AR_REPO = "cm-parallel-sandbox"
IMAGE_NAME = "cm-sandbox-runner"


class UsageError(Exception):
  """Raised for invalid user input (unknown repos, bad flags)."""


@dataclasses.dataclass
class Result:
  returncode: int
  stdout: str = ""
  stderr: str = ""


class Runner:
  """Thin subprocess wrapper; tests inject a fake with the same interface."""

  def run(self, args: Sequence[str], check: bool = True,
          cwd: Optional[str] = None) -> Result:
    proc = subprocess.run(list(args), capture_output=True, text=True, cwd=cwd)
    res = Result(proc.returncode, proc.stdout, proc.stderr)
    if check and proc.returncode != 0:
      raise RuntimeError(
          f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr}")
    return res


def load_repos(path=DEFAULT_REPOS_TSV) -> Dict[str, Dict[str, str]]:
  """Returns an ordered {repo_id: row} mapping from a repos.tsv manifest."""
  with open(path, newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))
  return {r["repo_id"]: r for r in rows}


def select_repos(repos: Dict[str, Dict[str, str]],
                 wanted: Optional[List[str]]) -> List[str]:
  """Validates --repos against the manifest; None selects all repos."""
  if not wanted:
    return list(repos)
  unknown = [r for r in wanted if r not in repos]
  if unknown:
    hints = []
    for u in unknown:
      close = difflib.get_close_matches(u, list(repos), n=3)
      hints.append(f"{u} (did you mean: {', '.join(close)})" if close else u)
    raise UsageError("unknown repo_id(s): " + "; ".join(hints))
  seen = []
  for r in wanted:
    if r not in seen:
      seen.append(r)
  return seen


def payload_bucket(project: str) -> str:
  return f"{project}-cm-payload"


def find_results_bucket(project: str) -> str:
  return f"{project}-cm-find-results"


def verify_results_bucket(project: str) -> str:
  return f"{project}-cm-verify-results"


def fix_results_bucket(project: str) -> str:
  return f"{project}-cm-fix-results"


def image_repo(project: str, region: str) -> str:
  return f"{region}-docker.pkg.dev/{project}/{AR_REPO}/{IMAGE_NAME}"


def repo_tarball_uri(bucket: str, repo_id: str) -> str:
  return f"gs://{strip_gs(bucket)}/repos/{repo_id}.tar.gz"


def strip_gs(bucket: str) -> str:
  return bucket[len("gs://"):].rstrip("/") if bucket.startswith("gs://") else bucket


def make_run_id(operation: str, cm_version: str, model: str,
                now: Optional[datetime.datetime] = None) -> str:
  """<YYYYMMDD_HHMMSS>_<operation>_v<cm_ver>_<model>."""
  now = now or datetime.datetime.now(datetime.timezone.utc)
  safe_model = re.sub(r"[^A-Za-z0-9.\-]", "-", model)
  return f"{now:%Y%m%d_%H%M%S}_{operation}_v{cm_version}_{safe_model}"


def gcloud_project(runner: Runner) -> str:
  res = runner.run(["gcloud", "config", "get-value", "project"], check=False)
  project = res.stdout.strip()
  if not project:
    raise UsageError("no --project given and no gcloud default project set")
  return project


def gcs_exists(runner: Runner, uri: str) -> bool:
  res = runner.run(["gcloud", "storage", "ls", uri], check=False)
  return res.returncode == 0 and uri in res.stdout


def is_commit_sha(ref):
  """True if ref is a full 40-hex git commit SHA."""
  return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)


DIFF_REQUIRED_COLUMNS = ("repo_id", "git_url", "pinned_ref", "diff_ref",
                         "source_repo_id")
CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def diff_case_id(source_repo_id: str, pinned_ref: str, diff_ref: str) -> str:
  """<source_repo_id>--<pinned_ref[:7]>-<diff_ref[:7]>."""
  return f"{source_repo_id}--{pinned_ref[:7]}-{diff_ref[:7]}"


def is_diff_manifest(repos: Dict[str, Dict[str, str]]) -> bool:
  """True when the manifest has a diff_ref column (stage() then diff-stages)."""
  return bool(repos) and "diff_ref" in next(iter(repos.values()))


def validate_diff_repos(repos: Dict[str, Dict[str, str]]) -> None:
  """Raises UsageError unless every row is a valid diff case.

  Checks the required columns, 40-hex refs, diff_ref != pinned_ref and the
  case id <-> refs match. diff_bucket is optional metadata and is ignored.
  """
  if not repos:
    raise UsageError("diff manifest has no rows")
  columns = set(next(iter(repos.values())))
  missing = [c for c in DIFF_REQUIRED_COLUMNS if c not in columns]
  if missing:
    raise UsageError(
        f"--mode diff needs a diff manifest with column(s) {', '.join(missing)}"
        " (e.g. --repos-tsv config/repos_with_diff.tsv)")
  errors = []
  for rid, row in repos.items():
    pinned, diff = row.get("pinned_ref") or "", row.get("diff_ref") or ""
    src = row.get("source_repo_id") or ""
    problems = [f"{col} {val!r} is not a 40-hex SHA"
                for col, val in (("pinned_ref", pinned), ("diff_ref", diff))
                if not is_commit_sha(val)]
    if not src:
      problems.append("missing source_repo_id")
    if pinned and pinned == diff:
      problems.append("diff_ref == pinned_ref")
    if not CASE_ID_RE.match(rid or ""):
      problems.append("repo_id does not match ^[a-z0-9][a-z0-9-]*$")
    elif src and not problems and rid != diff_case_id(src, pinned, diff):
      problems.append(f"repo_id != {diff_case_id(src, pinned, diff)}"
                      " (id/ref mismatch)")
    errors.extend(f"{rid}: {p}" for p in problems)
  if errors:
    shown = errors[:10] + ([f"... {len(errors) - 10} more"]
                           if len(errors) > 10 else [])
    raise UsageError("invalid diff manifest: " + "; ".join(shown))
