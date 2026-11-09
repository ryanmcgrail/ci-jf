#!/usr/bin/env python3
"""Orchestrates cm find / verify runs on the cm-parallel-sandbox Cloud Run jobs.

Steps: stage_cm_binary -> ensure_repos_staged -> build_tasks -> dispatch_job.
"""

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import urllib.parse
from typing import Callable, Dict, List, Optional

import stage_repos
from cmrun import common
from cmrun import pipeline

CM_ZIP = "cm-linux-amd64.zip"
DEEP_CALL_BUDGET = 900  # max concurrent model calls per deep find run (API limit: 1000)
MAX_DEEP_WORKERS = 16  # cm find --deep-workers range is 1..16
DEFAULT_DEEP_WORKERS = 8  # cm's own default
MAX_DIFF_WORKERS = 16  # cm find --diff-workers range is 1..16
DEFAULT_DIFF_WORKERS = 4  # cm's own default, used when --diff-workers is unset
DEFAULT_TOKEN_STATS_WORKERS = 8  # cm-api-token-stats' own default
ENV_DELIM = "^##^"
POLL_INTERVAL_SECONDS = 300
DEFAULT_FIX_TIMEOUT_SECONDS = 10800  # 3 hours per finding
UPLOAD_RESERVE_SECONDS = 300  # per task, for telemetry and result upload
MAX_CONTAINER_TIMEOUT_SECONDS = 604800  # Cloud Run task timeout limit (7 days)
NON_FIX_OPERATIONS = ("find", "verify", "find-verify")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _version_tuple(ver):
  parts = [int(x) for x in ver.split(".")[:2] if x.isdigit()]
  return tuple(parts) if len(parts) == 2 else (0, 0)


def findings_list(raw):
  """Returns the finding dicts of a report: a list, or {"findings": [...]}."""
  if isinstance(raw, list):
    return raw
  if isinstance(raw, dict):
    return raw.get("findings", [])
  return []


def finding_id(f):
  return str(f.get("finding_id") or f.get("FindingID") or "")


def finding_severity(f):
  return str(f.get("severity") or f.get("Severity") or "UNKNOWN").upper()


def parse_severities(severities):
  return {s.strip().upper() for s in severities.split(",") if s.strip()}


def summarize_findings(raw_findings, severities):
  """Parses findings JSON, returning (total, breakdown_dict, matching_count)."""
  items = findings_list(raw_findings)
  wanted = parse_severities(severities)
  counts = {}
  matching = 0
  for f in items:
    sev = finding_severity(f)
    counts[sev] = counts.get(sev, 0) + 1
    if sev in wanted:
      matching += 1
  return len(items), counts, matching


def format_severity_breakdown(counts):
  """Formats {SEVERITY: count} dict into a human-readable sorted string."""
  if not counts:
    return "none"
  ordered_keys = [s for s in SEVERITY_ORDER if s in counts] + [
      s for s in sorted(counts) if s not in SEVERITY_ORDER
  ]
  return ", ".join(f"{k}={counts[k]}" for k in ordered_keys)


def _build_parser():
  p = argparse.ArgumentParser(description=__doc__)
  add = p.add_argument
  add("--operation", choices=pipeline.OPERATIONS, default="find")
  add("--repos-tsv",
      help=("repos manifest (default: config/repos.tsv); --mode diff requires"
            " a diff manifest such as config/repos_with_diff.tsv"))
  add("--repos", nargs="+")
  add("--project")
  add("--region", default=common.DEFAULT_REGION)
  add("--cm-version", default="0.11.0")
  add("--model", default="gemini-3.8-flash")
  add("--mode", choices=["shallow", "deep", "diff", "complete"], default="shallow",
      help="find mode; diff runs `cm find --diff=<diff_ref>` per manifest case")
  add("--extra-cm-args", default="")
  add("--from-find-run", help="find run_id, exp/run_id, or 'latest'")
  add("--from-verify-run",
      help="fix only: verify run_id, exp/run_id, or 'latest'")
  add("--severity", help="comma-separated severities (default: CRITICAL,HIGH)")
  add("--verify-limit", type=int, help="max findings per verify task (0 = all)")
  add("--fix-limit", type=int, help="max findings per fix task (0 = all)")
  add("--include-unverified", action="store_true",
      help="fix: include unverified findings (status!=DISMISSED)")
  add("--finding-ids", nargs="+", help="filter by finding UUIDs or prefixes")
  add("--experiment-id", default="default")
  add("--run-id")
  add("--deep-workers", type=int,
      help=(f"find --mode deep: cm workers per repo (1-{MAX_DEEP_WORKERS}, default"
            f" {DEFAULT_DEEP_WORKERS}); repos x workers must be <= {DEEP_CALL_BUDGET}"))
  add("--diff-workers", type=int,
      help=(f"find --mode diff: cm --diff-workers per case (1-{MAX_DIFF_WORKERS});"
            f" unset = not passed to cm (cm default {DEFAULT_DIFF_WORKERS})"))
  add("--token-stats-workers", type=int,
      help=("concurrent sessions per cm-api-token-stats run (>= 1, default"
            f" {DEFAULT_TOKEN_STATS_WORKERS})"))
  add("--container-timeout", type=int, default=172800)
  add("--fix-timeout", type=int,
      help=("max seconds per finding in fix stage (default: 10800, 3 hours;"
            " <= container-timeout - 300)"))
  add("--wait", action="store_true")
  add("--poll-interval", type=int, default=POLL_INTERVAL_SECONDS,
      help="polling interval in seconds under --wait (default 300)")
  add("--dry-run", action="store_true")
  return p


def parse_args(argv):
  p = _build_parser()
  args = p.parse_args(argv)
  # --severity / --*-limit conflict with --finding-ids only when given explicitly.
  explicit = {flag for flag, dest in (("--severity", "severity"),
                                      ("--verify-limit", "verify_limit"),
                                      ("--fix-limit", "fix_limit"))
              if getattr(args, dest) is not None}
  _check_timeouts(p, args)
  _resolve_limit(p, args, "verify_limit", ("find", "fix", "find-fix"))
  _resolve_limit(p, args, "fix_limit", NON_FIX_OPERATIONS)
  _resolve_severity(p, args)
  _check_mode(p, args)
  _resolve_repos_tsv(p, args)
  _check_sources(p, args)
  _check_finding_ids(p, args, explicit)
  return p, args


def _check_timeouts(p, args):
  if args.poll_interval <= 0:
    p.error("--poll-interval must be > 0")
  if args.token_stats_workers is None:
    args.token_stats_workers = DEFAULT_TOKEN_STATS_WORKERS
  elif args.token_stats_workers < 1:
    p.error("--token-stats-workers must be >= 1")
  if args.container_timeout <= UPLOAD_RESERVE_SECONDS:
    p.error("--container-timeout must be > 300 (300s are reserved for telemetry/upload)")
  if args.container_timeout > MAX_CONTAINER_TIMEOUT_SECONDS:
    p.error("--container-timeout must be <= 604800 (7 days)")
  budget = args.container_timeout - UPLOAD_RESERVE_SECONDS
  if args.fix_timeout is None:
    args.fix_timeout = (max(1, budget) if budget < DEFAULT_FIX_TIMEOUT_SECONDS
                        else DEFAULT_FIX_TIMEOUT_SECONDS)
    return
  if args.operation in NON_FIX_OPERATIONS:
    p.error(f"--fix-timeout is not supported for --operation {args.operation}")
  if args.fix_timeout <= 0:
    p.error("--fix-timeout must be > 0")
  if args.fix_timeout > budget:
    p.error(
        f"--fix-timeout ({args.fix_timeout}s) cannot exceed --container-timeout"
        f" - 300 ({budget}s)"
    )


def _resolve_limit(p, args, dest, unsupported_operations):
  """Validates --verify-limit / --fix-limit; unset means 0 (no cap)."""
  flag = "--" + dest.replace("_", "-")
  value = getattr(args, dest)
  if value is None:
    setattr(args, dest, 0)
    return
  if args.operation in unsupported_operations:
    p.error(f"{flag} is not supported for --operation {args.operation}")
  if value < 0:
    p.error(f"{flag} must be >= 0")


def _resolve_severity(p, args):
  if args.severity is None:
    args.severity = "CRITICAL,HIGH"
    return
  if args.operation == "find":
    p.error("--severity is not supported for --operation find")
  args.severity = ",".join(
      s.strip().upper() for s in args.severity.split(",") if s.strip())


def _check_mode(p, args):
  extra = re.split(r"[\s,=]+", args.extra_cm_args)
  if "--deep-workers" in extra:
    p.error("--extra-cm-args cannot contain --deep-workers; use --deep-workers")
  if "--diff-workers" in extra:
    p.error("--extra-cm-args cannot contain --diff-workers; use --diff-workers")
  if args.mode != "diff" and args.diff_workers is not None:
    p.error("--diff-workers requires --mode diff")
  if args.mode == "diff":
    _check_diff_mode(p, args, extra)
    return
  if args.mode not in ("deep", "complete"):
    if args.deep_workers is not None:
      p.error("--deep-workers requires --mode deep")
    return
  if args.operation in ("verify", "fix", "verify-fix"):
    p.error(f"--mode {args.mode} is not supported for --operation {args.operation}")
  if _version_tuple(args.cm_version) < (0, 10):
    p.error(
        f"--mode {args.mode} requires --cm-version >= 0.10.0 (got {args.cm_version};"
        " cm < 0.10.0 has no --deep flag)"
    )
  if args.deep_workers is None:
    args.deep_workers = DEFAULT_DEEP_WORKERS
  elif not 1 <= args.deep_workers <= MAX_DEEP_WORKERS:
    p.error(f"--deep-workers must be between 1 and {MAX_DEEP_WORKERS}")


def _check_diff_mode(p, args, extra):
  for flag in ("--diff", "--staged", "--deep"):
    if flag in extra:
      p.error(f"--extra-cm-args cannot contain {flag} with --mode diff")
  if args.deep_workers is not None:
    p.error("--deep-workers requires --mode deep")
  if args.operation in ("verify", "fix", "verify-fix"):
    p.error(f"--mode diff is not supported for --operation {args.operation}")
  if _version_tuple(args.cm_version) < (0, 10):
    p.error(f"--mode diff requires --cm-version >= 0.10.0 (got {args.cm_version})")
  if args.diff_workers is not None and not 1 <= args.diff_workers <= MAX_DIFF_WORKERS:
    p.error(f"--diff-workers must be between 1 and {MAX_DIFF_WORKERS}")


def _resolve_repos_tsv(p, args):
  if args.repos_tsv is not None:
    return
  if args.mode == "diff":
    p.error("--mode diff requires an explicit --repos-tsv (a diff manifest such"
            " as config/repos_with_diff.tsv)")
  args.repos_tsv = str(common.DEFAULT_REPOS_TSV)


def effective_diff_workers(args):
  """cm's --diff-workers for a diff find: the flag, else cm's default."""
  return args.diff_workers or DEFAULT_DIFF_WORKERS


def check_call_budget(args, total):
  """Raises UsageError if a deep/complete/diff find would exceed DEEP_CALL_BUDGET calls."""
  if args.mode in ("deep", "complete"):
    workers, unit, flag = args.deep_workers, "repo(s)", "--deep-workers"
  elif args.mode == "diff":
    workers, unit, flag = effective_diff_workers(args), "case(s)", "--diff-workers"
  else:
    return
  calls = total * workers
  if calls <= DEEP_CALL_BUDGET:
    return
  hints = ([f"{flag} {DEEP_CALL_BUDGET // total}"]
           if total <= DEEP_CALL_BUDGET else [])
  hints.append(f"at most {DEEP_CALL_BUDGET // workers} {unit} via --repos")
  raise common.UsageError(
      f"{args.mode} find would run {total} {unit} x {workers} worker(s) = "
      f"{calls} concurrent model calls, over the budget of {DEEP_CALL_BUDGET}; "
      f"rerun with {' or '.join(hints)}")


check_deep_budget = check_call_budget  # pre-diff-mode name


def _check_sources(p, args):
  op = args.operation
  first = pipeline.stages(op)[0]
  if first == "verify" and not args.from_find_run:
    p.error(f"--from-find-run is required for --operation {op}")
  if first == "find" and args.from_find_run:
    p.error(f"--from-find-run is not supported for --operation {op}")
  if op != "fix" and args.from_verify_run:
    p.error(f"--from-verify-run is not supported for --operation {op}")
  if op == "fix":
    if not args.from_find_run and not args.from_verify_run:
      p.error("--operation fix requires either --from-verify-run or --from-find-run")
    if args.from_find_run and args.from_verify_run:
      p.error("--from-find-run and --from-verify-run are mutually exclusive for --operation fix")
  if args.include_unverified:
    if op in ("find", "verify", "find-verify", "find-fix"):
      p.error(f"--include-unverified is not supported for --operation {op}")
    elif op == "fix" and args.from_find_run:
      p.error("--include-unverified is only supported when fixing from a verify run")


def _check_finding_ids(p, args, explicit):
  if not args.finding_ids:
    return
  if args.operation == "find":
    p.error("--finding-ids is not supported for --operation find")
  for flag in ("--severity", "--verify-limit", "--fix-limit"):
    if flag in explicit:
      p.error(f"{flag} cannot be used with --finding-ids")
  ids = [x.strip() for item in args.finding_ids for x in item.split(",")
         if x.strip()]
  args.finding_ids = ids or None


def sha256_file(path):
  h = hashlib.sha256()
  with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
      h.update(chunk)
  return h.hexdigest()


class CmDownloadError(RuntimeError):
  """gcloud could not fetch the cm zip (bad credentials, no access, bad version)."""


def stage_cm_binary(runner, payload, cm_version, dry_run, log):
  """Caches the cm zip (+ .sha256 sidecar) in the payload bucket; returns sha."""
  zip_uri = f"gs://{payload}/bin/cm/{cm_version}/{CM_ZIP}"
  sha_uri = zip_uri + ".sha256"
  if common.gcs_exists(runner, zip_uri):
    res = runner.run(["gcloud", "storage", "cat", sha_uri], check=False)
    sha = res.stdout.strip().split()[0] if res.returncode == 0 and res.stdout.strip() else ""
    if re.fullmatch(r"[0-9a-f]{64}", sha):
      log(f"[stage] cm {cm_version}: cached {zip_uri} sha256={sha}")
      return sha
    reason = "invalid" if sha else "missing"
    log(f"[stage] cm {cm_version}: {zip_uri} exists but sidecar {reason}; re-staging")
  download = ["gcloud", "artifacts", "generic", "download", "--project=cmoc-prod",
              "--location=us", "--repository=codemender-cli-production",
              "--package=cm", f"--version={cm_version}", f"--name={CM_ZIP}"]
  if dry_run:
    log("[dry-run] would run: " + " ".join(download + ["--destination=<tmp>"]))
    log(f"[dry-run] would upload to {zip_uri} and {sha_uri}")
    return "<sha256-of-downloaded-zip>"
  log(f"[stage] cm {cm_version}: downloading from Artifact Registry and uploading to {zip_uri}...")
  with tempfile.TemporaryDirectory(prefix="cm_zip_") as tmp:
    try:
      runner.run(download + [f"--destination={tmp}"])
    except RuntimeError as e:
      detail = [l for l in str(e).splitlines() if l.strip()][-1]
      raise CmDownloadError(
          f"failed to download cm {cm_version} from Artifact Registry "
          "(cmoc-prod/codemender-cli-production); check --cm-version, "
          "gcloud credentials (`gcloud auth login`) and repository access: "
          f"{detail}") from e
    zip_path = pathlib.Path(tmp) / CM_ZIP
    sha = sha256_file(zip_path)
    sha_path = pathlib.Path(tmp) / (CM_ZIP + ".sha256")
    sha_path.write_text(f"{sha}  {CM_ZIP}\n")
    runner.run(["gcloud", "storage", "cp", str(zip_path), zip_uri])
    runner.run(["gcloud", "storage", "cp", str(sha_path), sha_uri])
  log(f"[stage] cm {cm_version}: staged {zip_uri} sha256={sha}")
  return sha


def ensure_repos_staged(runner, payload, repos, targets, dry_run, log):
  """Stages any repo tarball missing from gs://<payload>/repos/."""
  res = runner.run(["gcloud", "storage", "ls",
                    f"gs://{common.strip_gs(payload)}/repos/"], check=False)
  staged = {line.strip() for line in res.stdout.splitlines() if line.strip()
            } if res.returncode == 0 else set()
  missing = [r for r in targets if common.repo_tarball_uri(payload, r) not in staged]
  cached_count = len(targets) - len(missing)
  if not missing:
    log(f"[stage] repos: all {len(targets)} tarball(s) cached ({cached_count}/{len(targets)})")
    return
  if dry_run:
    log(f"[dry-run] repos: {cached_count}/{len(targets)} cached; would stage {len(missing)} missing: {' '.join(missing)}")
    return
  log(f"[stage] repos: {cached_count}/{len(targets)} cached; staging {len(missing)} missing tarball(s): {', '.join(missing)}")
  for r in missing:
    with tempfile.TemporaryDirectory(prefix="cm_stage_") as tmp:
      stage_repos.stage(runner, r, repos[r], payload, False, tmp)
  log(f"[stage] repos: staged {len(missing)} tarball(s) ({len(targets)}/{len(targets)} ready)")


def _gcs_ls(runner, uri):
  return runner.run(["gcloud", "storage", "ls", uri], check=False)


def _child_names(stdout, prefix):
  """First path segment under `prefix` of each listed object."""
  return {line[len(prefix):].split("/", 1)[0]
          for line in stdout.splitlines()
          if line.startswith(prefix) and "/" in line[len(prefix):]}


def _resolve_run(runner, bucket, spec, default_exp, stage):
  """Returns (source_experiment, run_id) for a --from-<stage>-run value.

  'latest' / '<exp>/latest' pick the run whose newest summary.json was created
  last (ties break on run id); '<exp>/<run>' must exist; a bare run id is
  searched across experiments.
  """
  if spec == "latest" or spec.endswith("/latest"):
    exp = spec.split("/", 1)[0] if "/" in spec else default_exp
    prefix = f"gs://{bucket}/{exp}/"
    res = runner.run(["gcloud", "storage", "ls", "-l",
                      f"{prefix}*/*/summary.json"], check=False)
    newest = {}  # run_id -> newest creation time (ISO-8601 sorts by time)
    for line in res.stdout.splitlines():
      parts = line.split()
      if len(parts) == 3 and parts[2].startswith(prefix):
        run_id = parts[2][len(prefix):].split("/", 1)[0]
        newest[run_id] = max(newest.get(run_id, ""), parts[1])
    if res.returncode != 0 or not newest:
      raise common.UsageError(f"no {stage} runs found under {prefix}")
    return exp, max(newest, key=lambda r: (newest[r], r))
  if "/" in spec:
    exp, run_id = spec.split("/", 1)
    run_id = run_id.strip("/")
    if _gcs_ls(runner, f"gs://{bucket}/{exp}/{run_id}/").returncode != 0:
      raise common.UsageError(
          f"{stage} run '{exp}/{run_id}' not found under gs://{bucket}/")
    return exp, run_id
  root = f"gs://{bucket}/"
  res = _gcs_ls(runner, f"{root}*/{spec}/")
  exps = sorted(_child_names(res.stdout, root) - {"selftest"})
  if res.returncode != 0 or not exps:
    raise common.UsageError(f"{stage} run '{spec}' not found under {root}*/")
  if len(exps) > 1:
    raise common.UsageError(
        f"{stage} run '{spec}' exists in several experiments {exps}; "
        f"pass --from-{stage}-run <experiment_id>/<run_id>")
  return exps[0], spec


def resolve_find_run(runner, find_bucket, from_find_run, default_exp="default"):
  """Returns (source_experiment, find_run_id)."""
  return _resolve_run(runner, find_bucket, from_find_run, default_exp, "find")


def resolve_verify_run(runner, verify_bucket, from_verify_run, default_exp="default"):
  """Returns (source_experiment, verify_run_id)."""
  return _resolve_run(runner, verify_bucket, from_verify_run, default_exp,
                      "verify")


@dataclasses.dataclass
class _Tally:
  """Running totals across repos for the per-phase `[summary]` line."""
  findings: int = 0
  matching: int = 0
  counts: Dict[str, int] = dataclasses.field(default_factory=dict)


def _cat_json(runner, uri):
  """Returns the parsed JSON object at `uri`, or None if it is not valid JSON."""
  res = runner.run(["gcloud", "storage", "cat", uri], check=False)
  try:
    return json.loads(res.stdout or "null")
  except json.JSONDecodeError:
    return None


def _repo_task(repos, repo_id, **fields):
  row = repos[repo_id]
  return {
      "repo_id": repo_id,
      "language": row.get("language", ""),
      "git_url": row["git_url"],
      "pinned_ref": row["pinned_ref"],
      **({"diff_ref": row["diff_ref"]} if row.get("diff_ref") else {}),
      **fields,
  }


def _limit_note(n, limit, flag):
  if limit and limit < n:
    return f" (capped to {min(n, limit)} by --{flag}={limit})"
  return ""


def _capped(n, limit):
  return min(n, limit) if limit else n


def _matches_ids(fid, prefixes):
  return any(fid.startswith(p) for p in prefixes)


def _ids_desc(finding_ids):
  return f"matching finding ID(s) {','.join(finding_ids)}"


def _match_desc(args):
  return _ids_desc(args.finding_ids) if args.finding_ids else f"matching {args.severity}"


def build_tasks(
    args,
    runner,
    repos,
    targets,
    find_bucket,
    log,
    project=None,
    verify_bucket=None,
):
  """Returns (tasks, source) for one phase; `source` names the upstream run."""
  if args.operation == "find":
    return _find_tasks(repos, targets, log), None
  if args.operation == "verify":
    return _verify_tasks(args, runner, repos, targets, find_bucket, log)
  if args.operation == "fix" and args.from_verify_run:
    v_bucket = verify_bucket or (
        common.verify_results_bucket(project) if project else "")
    return _fix_tasks_from_verify(args, runner, repos, targets, v_bucket, log)
  if args.operation == "fix" and args.from_find_run:
    return _fix_tasks_from_find(args, runner, repos, targets, find_bucket, log)
  return [], None


def _find_tasks(repos, targets, log):
  tasks = [_repo_task(repos, r) for r in targets]
  log(f"[stage] manifest: {len(tasks)} find task(s) across {len(targets)} repo(s)")
  return tasks


def _tasks_from_find_run(args, runner, repos, targets, find_bucket, log,
                         stage, limit, skip_message):
  """Builds verify/fix tasks from each repo's findings.json in a find run.

  Returns (tasks, tally, source). `skip_message(repo_id, desc, total,
  breakdown)` renders the stage-specific line for repos with no match.
  """
  src_exp, find_run = resolve_find_run(
      runner, find_bucket, args.from_find_run, args.experiment_id)
  res = _gcs_ls(runner, f"gs://{find_bucket}/{src_exp}/{find_run}/*/findings.json")
  tasks, tally = [], _Tally()
  desc = _match_desc(args)
  for uri in sorted(res.stdout.split()):
    repo_id = uri.split("/")[-2]
    if repo_id not in targets:
      continue
    raw = _cat_json(runner, uri)
    total, counts, n = summarize_findings(raw, args.severity)
    tally.findings += total
    for sev, count in counts.items():
      tally.counts[sev] = tally.counts.get(sev, 0) + count
    breakdown = format_severity_breakdown(counts)
    if args.finding_ids:
      n = sum(1 for f in findings_list(raw)
              if _matches_ids(finding_id(f), args.finding_ids))
    if n == 0:
      log(skip_message(repo_id, desc, total, breakdown))
      continue
    log(f"[summary] {repo_id}: {total} finding(s) ({breakdown}); {n} {desc}"
        f"{_limit_note(n, limit, stage + '-limit')}")
    tally.matching += _capped(n, limit)
    tasks.append(_repo_task(
        repos, repo_id, findings_gcs_uri=uri, source_stage="find",
        severity=args.severity, matching_findings=_capped(n, limit)))
  return tasks, tally, {"source_experiment": src_exp, "find_run_id": find_run}


def _find_run_summary(source, tally, desc, n_tasks, n_targets, stage):
  return (
      f"[summary] findings from {source['source_experiment']}/"
      f"{source['find_run_id']}: {tally.findings} total"
      f" ({format_severity_breakdown(tally.counts)}); {tally.matching} {desc}"
      f" across {n_tasks}/{n_targets} repo(s) queued for {stage}")


def _verify_tasks(args, runner, repos, targets, find_bucket, log):
  def skip_message(repo_id, desc, total, breakdown):
    what = desc if args.finding_ids else f"{args.severity} findings"
    return f"[verify] skip {repo_id}: no {what} ({total} total: {breakdown})"

  tasks, tally, source = _tasks_from_find_run(
      args, runner, repos, targets, find_bucket, log,
      "verify", args.verify_limit, skip_message)
  log(_find_run_summary(source, tally, _match_desc(args), len(tasks),
                        len(targets), "verify"))
  return tasks, source


def _fix_tasks_from_find(args, runner, repos, targets, find_bucket, log):
  def skip_message(repo_id, desc, total, breakdown):
    return f"[fix] skip {repo_id}: no {desc} findings ({total} total: {breakdown})"

  tasks, tally, source = _tasks_from_find_run(
      args, runner, repos, targets, find_bucket, log,
      "fix", args.fix_limit, skip_message)
  log(_find_run_summary(source, tally, "matching", len(tasks), len(targets),
                        "fix"))
  return tasks, source


def _verify_run_repo_uris(runner, run_prefix):
  """Per-repo marker objects of a verify run: ids files, else reports."""
  for marker in ("matching_finding_ids.txt", "post_verify_report.json"):
    res = _gcs_ls(runner, f"{run_prefix}*/{marker}")
    uris = res.stdout.split() if res.returncode == 0 else []
    if uris:
      return uris
  return []


def _verify_candidates(runner, repo_prefix):
  """Returns [(finding_id, finding, verify_status)] attempted by verify."""
  ids = runner.run(["gcloud", "storage", "cat",
                    f"{repo_prefix}matching_finding_ids.txt"], check=False)
  attempted = [line.strip() for line in ids.stdout.splitlines() if line.strip()]
  report = findings_list(_cat_json(runner, f"{repo_prefix}post_verify_report.json"))
  status_by_id = {}
  for r in report:
    fid = finding_id(r)
    if fid:
      status_by_id[fid] = str(r.get("status") or "").upper()
  if not attempted and report:
    attempted = list(status_by_id)
  if not attempted:
    return []
  source = findings_list(_cat_json(runner, f"{repo_prefix}source_findings.json"))
  by_id = {finding_id(f): f for f in source}
  candidates = []
  for fid in attempted:
    f = by_id.get(fid) or {"finding_id": fid, "severity": "UNKNOWN"}
    status = status_by_id.get(fid, str(f.get("status") or "OPEN").upper())
    candidates.append((fid, f, status))
  return candidates


def _select_fix_ids(args, candidates):
  if args.finding_ids:
    return [fid for fid, _, _ in candidates
            if _matches_ids(fid, args.finding_ids)]
  wanted = parse_severities(args.severity)

  def eligible(status):
    if args.include_unverified:
      return status != "DISMISSED"
    return status == "VERIFIED"

  return [fid for fid, f, status in candidates
          if finding_severity(f) in wanted and eligible(status)]


def _fix_tasks_from_verify(args, runner, repos, targets, v_bucket, log):
  src_exp, verify_run = resolve_verify_run(
      runner, v_bucket, args.from_verify_run, args.experiment_id)
  run_prefix = f"gs://{v_bucket}/{src_exp}/{verify_run}/"
  status = "non-dismissed" if args.include_unverified else "verified"
  desc = _match_desc(args)
  tasks, attempted_total, matching_total = [], 0, 0
  for uri in sorted(_verify_run_repo_uris(runner, run_prefix)):
    repo_id = uri.split("/")[-2]
    if repo_id not in targets:
      continue
    repo_prefix = f"{run_prefix}{repo_id}/"
    candidates = _verify_candidates(runner, repo_prefix)
    if not candidates:
      log(f"[fix] skip {repo_id}: no attempted findings found in verify run")
      continue
    n, total = len(_select_fix_ids(args, candidates)), len(candidates)
    attempted_total += total
    if n == 0:
      log(f"[fix] skip {repo_id}: no {status} findings {desc} ({total}"
          " attempted in verify)")
      continue
    log(f"[summary] {repo_id}: {total} finding(s) attempted; {n} {status} {desc}"
        f"{_limit_note(n, args.fix_limit, 'fix-limit')}")
    matching_total += _capped(n, args.fix_limit)
    tasks.append(_repo_task(
        repos, repo_id,
        findings_gcs_uri=f"{repo_prefix}source_findings.json",
        verify_report_gcs_uri=f"{repo_prefix}post_verify_report.json",
        verify_ids_gcs_uri=f"{repo_prefix}matching_finding_ids.txt",
        verify_repo_prefix=repo_prefix,
        source_stage="verify",
        severity=args.severity,
        matching_findings=_capped(n, args.fix_limit)))
  log(f"[summary] candidates from {src_exp}/{verify_run}: {attempted_total}"
      f" attempted; {matching_total} matching across"
      f" {len(tasks)}/{len(targets)} repo(s) queued for fix")
  return tasks, {"source_experiment": src_exp, "verify_run_id": verify_run}


def _cloud_logging_info(stdout, project, region, job, name):
  """Returns (read_cmd, log_uri) for an execution."""
  cmd_filter = (
      f'resource.type="cloud_run_job" AND '
      f'resource.labels.job_name="{job}" AND '
      f'resource.labels.location="{region}" AND '
      f'labels."run.googleapis.com/execution_name"="{name}"'
  )
  read_cmd = f"gcloud logging read '{cmd_filter}' --project={project} --limit=50"
  try:
    log_uri = (json.loads(stdout or "{}").get("status") or {}).get("logUri")
  except (ValueError, AttributeError):
    log_uri = None
  if not log_uri:
    filter_query = (
        f'resource.type="cloud_run_job"\n'
        f'resource.labels.job_name="{job}"\n'
        f'resource.labels.location="{region}"\n'
        f'labels."run.googleapis.com/execution_name"="{name}"'
    )
    encoded = urllib.parse.quote(filter_query)
    log_uri = f"https://console.cloud.google.com/logs/viewer?project={project}&advancedFilter={encoded}"
  return read_cmd, log_uri


def is_interactive_tty(log_fn=print, stdout=sys.stdout):
  """Returns True only when output is to an interactive terminal supporting cursor movement."""
  if log_fn is not print:
    return False
  if not getattr(stdout, "isatty", lambda: False)():
    return False
  term = os.environ.get("TERM", "")
  if not term or term.lower() == "dumb":
    return False
  if os.environ.get("CI"):
    return False
  return True


MAX_POLL_ERRORS = 5


def _describe_execution(stdout, total):
  """Returns (task_count, running, succeeded, failed, completed_condition)."""
  try:
    data = json.loads(stdout or "{}")
  except json.JSONDecodeError:
    data = {}
  status = data.get("status") or {}
  spec = data.get("spec") or {}
  conditions = status.get("conditions") or []
  completed = next((c for c in conditions if c.get("type") == "Completed"), None)
  return (int(spec.get("taskCount") or total),
          int(status.get("runningCount") or 0),
          int(status.get("succeededCount") or 0),
          int(status.get("failedCount") or 0),
          completed or {})


def _finish_execution(completed, job, name, elapsed, task_count, succeeded,
                      failed, log):
  """Logs the final summary; returns 0 on success, raises RuntimeError otherwise."""
  if str(completed.get("status")) == "True":
    msg = completed.get("message") or "Execution completed successfully."
    log(f"[summary] {name}: Completed=True ({succeeded}/{task_count} succeeded, {failed} failed) "
        f"in {elapsed} (exit_code=0) — {msg}")
    return 0
  reason = completed.get("reason") or "Failed"
  msg = completed.get("message") or "Execution failed."
  log(f"[summary] {name}: Completed=False [{reason}] ({succeeded} succeeded, {failed} failed / {task_count} total) "
      f"in {elapsed} (exit_code=1) — {msg}")
  raise RuntimeError(f"{job} execution {name} failed ({reason}): {msg}")


def wait_for_execution(runner, project, region, job, name, total, log,
                       poll_interval=POLL_INTERVAL_SECONDS, sleep=time.sleep,
                       clock=time.monotonic, is_tty=None):
  """Polls `gcloud run jobs executions describe` until the execution finishes."""
  start_t = clock()
  last_status_line = ""
  tty = is_tty if is_tty is not None else is_interactive_tty(log)
  consecutive_errors = 0
  while True:
    res = runner.run(["gcloud", "run", "jobs", "executions", "describe", name,
                      f"--project={project}", f"--region={region}", "--format=json"],
                     check=False)
    if res.returncode != 0:
      consecutive_errors += 1
      if consecutive_errors >= MAX_POLL_ERRORS:
        raise RuntimeError(
            f"failed to poll execution {name} ({res.returncode}): {res.stderr.strip()}")
      sleep(poll_interval)
      continue
    consecutive_errors = 0
    task_count, running, succeeded, failed, completed = _describe_execution(
        res.stdout, total)
    mm, ss = divmod(max(0, int(clock() - start_t)), 60)
    status_line = (f"[progress] [{mm:02d}:{ss:02d}] {name}: "
                   f"{running} running, {succeeded} succeeded, {failed} failed / {task_count} total")
    if tty:
      sys.stdout.write(f"\r\033[K{status_line}")
      sys.stdout.flush()
    elif status_line != last_status_line:
      log(status_line)
      last_status_line = status_line
    if str(completed.get("status") or "") in ("True", "False"):
      if tty:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
      return _finish_execution(completed, job, name, f"{mm:02d}:{ss:02d}",
                               task_count, succeeded, failed, log)
    sleep(poll_interval)


@dataclasses.dataclass
class RunContext:
  """Per-invocation dependencies shared by every phase of a pipeline."""
  runner: common.Runner
  repos: Dict[str, Dict[str, str]]
  targets: List[str]
  project: str
  payload: str
  find_bucket: str
  cm_sha: str
  log: Callable[[str], None]
  sleep: Callable[[float], None] = time.sleep
  clock: Callable[[], float] = time.monotonic
  poll_interval: int = POLL_INTERVAL_SECONDS
  is_tty: Optional[bool] = None


def build_job_env(args, run_id, cm_sha, source):
  """Env vars sent to every job execution (all keys, whatever the stage)."""
  source = source or {}
  find_run = source.get("find_run_id", "")
  verify_run = source.get("verify_run_id", "")
  env = {
      "EXPERIMENT_ID": args.experiment_id,
      "RUN_ID": run_id,
      "CM_VERSION": args.cm_version,
      "EXPECTED_CM_SHA256": cm_sha,
      "MODEL": args.model,
      "MODE": args.mode,
      "DEEP_WORKERS": "" if args.deep_workers is None else str(args.deep_workers),
      "SEVERITY": args.severity,
      "VERIFY_LIMIT": str(args.verify_limit),
      "FIX_LIMIT": str(args.fix_limit),
      "FIX_FINDING_TIMEOUT": str(args.fix_timeout),
      "FROM_FIND_RUN": find_run,
      "SOURCE_FIND_EXPERIMENT": source.get("source_experiment", "") if find_run else "",
      "FROM_VERIFY_RUN": verify_run,
      "SOURCE_VERIFY_EXPERIMENT": (
          source.get("source_experiment", "") if verify_run else ""),
      "INCLUDE_UNVERIFIED": "1" if args.include_unverified else "0",
      "FINDING_IDS": ",".join(args.finding_ids) if args.finding_ids else "",
      "EXTRA_CM_ARGS": args.extra_cm_args,
      "JOB_TIMEOUT": str(args.container_timeout),
      "TOKEN_STATS_WORKERS": str(args.token_stats_workers),
  }
  if args.diff_workers is not None:  # unset: cm uses its own default
    env["DIFF_WORKERS"] = str(args.diff_workers)
  return env


def job_commands(args, job, project, total, env):
  """Returns the `jobs execute` gcloud argv for a phase.

  Parallelism is never written: execute cannot override it per run, and the
  shared job template must stay unset (deploy.sh fails on drift).
  """
  # ENV_DELIM lets values contain commas (SEVERITY, FINDING_IDS).
  env_arg = ENV_DELIM + "##".join(f"{k}={v}" for k, v in env.items())
  return ["gcloud", "run", "jobs", "execute", job,
          f"--region={args.region}", f"--project={project}",
          f"--tasks={total}", f"--task-timeout={args.container_timeout}s",
          f"--update-env-vars={env_arg}", "--async", "--format=json"]


def _upload_run_files(runner, run_prefix, tasks, manifest):
  with tempfile.TemporaryDirectory(prefix="cm_run_") as tmp:
    for name, obj in (("tasks.json", tasks), ("run_manifest.json", manifest)):
      path = pathlib.Path(tmp) / name
      path.write_text(json.dumps(obj, indent=2) + "\n")
      runner.run(["gcloud", "storage", "cp", str(path), f"{run_prefix}/{name}"])


def dispatch_job(args, ctx, job, run_id, tasks, manifest, source):
  """Uploads tasks.json + run_manifest.json and starts the job execution."""
  total = len(tasks)
  env = build_job_env(args, run_id, ctx.cm_sha, source)
  execute = job_commands(args, job, ctx.project, total, env)
  run_prefix = f"gs://{ctx.payload}/runs/{args.experiment_id}/{run_id}"
  if common.gcs_exists(ctx.runner, f"{run_prefix}/tasks.json"):
    raise common.UsageError(
        f"run {run_id} already exists in experiment '{args.experiment_id}' "
        f"({run_prefix}/tasks.json present); specify a different --run-id"
    )
  manifest.update({
      "total_tasks": total,
      "env": env,
      "commands": {"execute": execute},
  })
  if args.dry_run:
    ctx.log("[dry-run] tasks.json:\n" + json.dumps(tasks, indent=2))
    ctx.log(f"[dry-run] would upload {run_prefix}/tasks.json and run_manifest.json")
    ctx.log("[dry-run] " + " ".join(execute))
    return
  _upload_run_files(ctx.runner, run_prefix, tasks, manifest)
  ctx.log(f"[stage] manifest: uploaded {run_prefix}/tasks.json and run_manifest.json"
          f" ({total} task(s), {len(manifest.get('repos', []))} repo(s))")
  res = ctx.runner.run(execute)
  deep = ""
  if args.operation == "find" and args.mode in ("deep", "complete"):
    deep = (f", deep workers {args.deep_workers}/task"
            f" ({total * args.deep_workers}/{DEEP_CALL_BUDGET} calls)")
  elif args.operation == "find" and args.mode == "diff":
    workers = effective_diff_workers(args)
    default = "" if args.diff_workers else " (cm default)"
    deep = (f", diff workers {workers}/task{default}"
            f" ({total * workers}/{DEEP_CALL_BUDGET} calls)")
  ctx.log(f"[dispatch] {job}: {total} task(s){deep}")
  _follow_execution(args, ctx, job, run_id, res.stdout, total)


def _follow_execution(args, ctx, job, run_id, execute_stdout, total):
  """Logs how to inspect the execution and, under --wait, polls it."""
  name = _execution_name(execute_stdout)
  if not name:
    ctx.log(f"warning: could not parse execution name from `{job}` execute output")
    if args.wait:
      raise RuntimeError(
          f"cannot wait on {job} run {run_id}: execution name could not be parsed")
    return
  ctx.log(f"execution={name}")
  ctx.log(f"status: gcloud run jobs executions describe {name} "
          f"--project={ctx.project} --region={args.region}")
  read_cmd, log_uri = _cloud_logging_info(
      execute_stdout, ctx.project, args.region, job, name)
  ctx.log(f"logs: {read_cmd}")
  ctx.log(f"console: {log_uri}")
  if args.wait:
    wait_for_execution(ctx.runner, ctx.project, args.region, job, name, total,
                       ctx.log, poll_interval=ctx.poll_interval,
                       sleep=ctx.sleep, clock=ctx.clock, is_tty=ctx.is_tty)


def _execution_name(stdout):
  """Returns metadata.name from `gcloud run jobs execute --format=json`."""
  try:
    return str(
        (json.loads(stdout or "{}").get("metadata") or {}).get("name") or ""
    )
  except (ValueError, AttributeError):
    return ""


def source_find_mode(runner, payload, source):
  """Mode of the find run behind `source`, read from its run manifest(s)."""
  run = source.get("find_run_id") or source.get("verify_run_id")
  manifest = _cat_json(runner, f"gs://{payload}/runs/"
                       f"{source['source_experiment']}/{run}/run_manifest.json")
  if not isinstance(manifest, dict):
    return None
  return manifest.get("mode" if "find_run_id" in source else "source_find_mode")


def _run_manifest(args, ctx, job, run_id, results_prefix, source, tasks,
                  find_mode):
  return {
      "run_id": run_id,
      "experiment_id": args.experiment_id,
      "operation": args.operation,
      "project": ctx.project,
      "region": args.region,
      "job": job,
      "results_prefix": results_prefix,
      "cm_version": args.cm_version,
      "cm_sha256": ctx.cm_sha,
      "model": args.model,
      "mode": args.mode,
      "deep_workers": args.deep_workers,
      "deep_call_budget": DEEP_CALL_BUDGET,
      **({"diff_workers": args.diff_workers} if args.mode == "diff" else {}),
      "token_stats_workers": args.token_stats_workers,
      "severity": args.severity,
      "timeout": args.container_timeout,
      "verify_limit": args.verify_limit,
      "fix_limit": args.fix_limit,
      "fix_timeout": args.fix_timeout,
      "include_unverified": args.include_unverified,
      "finding_ids": args.finding_ids,
      "extra_cm_args": args.extra_cm_args,
      "source_find": source if (source and "find_run_id" in source) else None,
      "source_verify": source if (source and "verify_run_id" in source) else None,
      **({"source_find_mode": find_mode} if source else {}),
      "repos": sorted({t["repo_id"] for t in tasks}),
  }


def _run_phase(args, ctx):
  """Builds and dispatches one find/verify/fix phase; returns (rc, run_id)."""
  phase = pipeline.PHASES[args.operation]
  run_id = args.run_id or common.make_run_id(
      args.operation, args.cm_version, args.model)
  tasks, source = build_tasks(
      args, ctx.runner, ctx.repos, ctx.targets, ctx.find_bucket, ctx.log,
      project=ctx.project,
      verify_bucket=common.verify_results_bucket(ctx.project))
  if not tasks:
    ctx.log(phase.no_tasks_error)
    return 2, run_id
  find_mode = None
  if source:
    find_mode = source_find_mode(ctx.runner, ctx.payload, source)
    # Keyed right after repo_id so existing task fields keep their layout.
    tasks = [{"repo_id": t["repo_id"], "source_find_mode": find_mode or "", **t}
             for t in tasks]
  results_prefix = (f"gs://{phase.results_bucket(ctx.project)}/"
                    f"{args.experiment_id}/{run_id}/")
  manifest = _run_manifest(args, ctx, phase.job, run_id, results_prefix,
                           source, tasks, find_mode)
  ctx.log(f"run_id={run_id}")
  ctx.log(f"results={results_prefix}")
  try:
    dispatch_job(args, ctx, phase.job, run_id, tasks, manifest, source)
  except RuntimeError as e:
    ctx.log(f"error: {phase.job} run {run_id} failed: {str(e).splitlines()[0]}")
    return 1, run_id
  return 0, run_id


def run_pipeline(args, ctx):
  """Runs each phase of args.operation in order; returns the exit code.

  A non-final phase that fails, finds nothing, or is a dry run stops the
  pipeline and logs how to continue from it.
  """
  last = len(pipeline.stages(args.operation)) - 1
  run_id = ""
  for index in range(last + 1):
    rc, run_id = _run_phase(pipeline.phase_args(args, index, run_id), ctx)
    if index == last:
      return rc
    if rc != 0 or args.dry_run:
      hint = pipeline.stop_hint(args, index, run_id, rc)
      if hint:
        ctx.log(hint)
      return rc
    ctx.log(pipeline.transition_message(args, index, run_id))


def _prepare(args, runner, log, **clock_deps):
  """Resolves repos and buckets and stages cm + repo tarballs."""
  repos = common.load_repos(args.repos_tsv)
  # Any diff manifest is validated, not just --mode diff: stage() diff-stages
  # every row with a diff_ref (e.g. standalone verify/fix of a diff find run).
  if args.mode == "diff" or common.is_diff_manifest(repos):
    common.validate_diff_repos(repos)
  targets = common.select_repos(repos, args.repos)
  check_call_budget(args, len(targets))
  project = args.project or common.gcloud_project(runner)
  payload = common.payload_bucket(project)
  find_bucket = common.find_results_bucket(project)
  cm_sha = stage_cm_binary(runner, payload, args.cm_version, args.dry_run, log)
  ensure_repos_staged(runner, payload, repos, targets, args.dry_run, log)
  return RunContext(runner, repos, targets, project, payload, find_bucket,
                    cm_sha, log, **clock_deps)


def main(
    argv=None,
    runner=None,
    log=print,
    sleep=time.sleep,
    clock=time.monotonic,
    poll_interval=None,
    is_tty=None,
):
  parser, args = parse_args(argv)
  if poll_interval is None:
    poll_interval = args.poll_interval
  runner = runner or common.Runner()
  try:
    ctx = _prepare(args, runner, log, sleep=sleep, clock=clock,
                   poll_interval=poll_interval, is_tty=is_tty)
    return run_pipeline(args, ctx)
  except common.UsageError as e:
    parser.error(str(e))
  except CmDownloadError as e:
    log(f"error: {e}")
    return 1


if __name__ == "__main__":
  sys.exit(main())

