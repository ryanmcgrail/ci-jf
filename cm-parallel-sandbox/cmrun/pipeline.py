"""Operation pipelines: the phases each --operation runs and how they chain.

A chained operation such as `find-verify-fix` runs its phases in order; every
phase after the first consumes the previous phase's run through
`--from-<previous>-run <experiment_id>/<run_id>`.
"""

import argparse
import copy
import dataclasses
from typing import Callable, Dict, Optional, Tuple

from cmrun import common

OPERATIONS = (
    "find",
    "verify",
    "find-verify",
    "fix",
    "verify-fix",
    "find-fix",
    "find-verify-fix",
)


@dataclasses.dataclass(frozen=True)
class Phase:
  """A single Cloud Run job stage."""
  job: str
  results_bucket: Callable[[str], str]
  no_tasks_error: str


PHASES: Dict[str, Phase] = {
    "find": Phase(common.FIND_JOB, common.find_results_bucket,
                  "error: no tasks to run"),
    "verify": Phase(
        common.VERIFY_JOB, common.verify_results_bucket,
        "error: no tasks to run (verify: no findings matched --severity)"),
    "fix": Phase(common.FIX_JOB, common.fix_results_bucket,
                 "error: no tasks to run (fix: no findings matched criteria)"),
}


def stages(operation: str) -> Tuple[str, ...]:
  """Phase names of an operation, e.g. 'find-fix' -> ('find', 'fix')."""
  return tuple(operation.split("-"))


def _source_flag(stage: str) -> str:
  return f"--from-{stage}-run"


def phase_args(args: argparse.Namespace, index: int,
               prev_run_id: str = "") -> argparse.Namespace:
  """Returns a copy of `args` configured for phase `index` of the pipeline."""
  names = stages(args.operation)
  phase = copy.copy(args)
  phase.operation = names[index]
  if index + 1 < len(names):
    phase.wait = True  # later phases need this phase's results.
  if index > 0:
    source = f"{args.experiment_id}/{prev_run_id}"
    if names[index - 1] == "find":
      phase.from_find_run, phase.from_verify_run = source, None
    else:
      phase.from_find_run, phase.from_verify_run = None, source
    phase.run_id = f"{args.run_id}_{names[index]}" if args.run_id else None
    # --mode deep/diff are find options; later phases run cm verify/fix as usual.
    phase.mode, phase.deep_workers, phase.diff_workers = "shallow", None, None
  return phase


def dry_run_hint(args: argparse.Namespace, index: int, run_id: str) -> str:
  names = stages(args.operation)
  return (f"[dry-run] would then run {names[index + 1]}"
          f" {_source_flag(names[index])} {args.experiment_id}/{run_id}")


def resume_hint(args: argparse.Namespace, index: int, run_id: str) -> str:
  names = stages(args.operation)
  rest = "-".join(names[index + 1:])
  return (f"{rest} skipped; inspect {names[index]} results, then resume with: "
          f"--operation {rest} {_source_flag(names[index])}"
          f" {args.experiment_id}/{run_id}")


def stop_hint(args: argparse.Namespace, index: int, run_id: str,
              rc: int) -> Optional[str]:
  """What to log when a non-final phase stops the pipeline early."""
  if args.dry_run:
    return dry_run_hint(args, index, run_id)
  if rc == 1:
    return resume_hint(args, index, run_id)
  return None  # rc 2 (no tasks) already logged its own error.


def transition_message(args: argparse.Namespace, index: int, run_id: str) -> str:
  names = stages(args.operation)
  return (f"[phase] {names[index]} phase ({run_id}) complete; transitioning to"
          f" {names[index + 1]} ({_source_flag(names[index])}"
          f" {args.experiment_id}/{run_id})")
