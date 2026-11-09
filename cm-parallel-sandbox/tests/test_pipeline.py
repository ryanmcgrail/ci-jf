"""Tests for cmrun/pipeline.py (pure phase chaining logic)."""

import argparse
import unittest

from cmrun import common
from cmrun import pipeline


def ns(operation, **kw):
  base = dict(operation=operation, experiment_id="exp", run_id=None,
              wait=False, from_find_run=None, from_verify_run=None)
  base.update(kw)
  return argparse.Namespace(**base)


class StagesTest(unittest.TestCase):

  def test_every_operation_maps_to_known_phases(self):
    for op in pipeline.OPERATIONS:
      with self.subTest(op):
        self.assertTrue(set(pipeline.stages(op)) <= set(pipeline.PHASES))
    self.assertEqual(pipeline.stages("find-verify-fix"),
                     ("find", "verify", "fix"))

  def test_phase_jobs_and_buckets(self):
    self.assertEqual(pipeline.PHASES["verify"].job, common.VERIFY_JOB)
    self.assertEqual(pipeline.PHASES["fix"].results_bucket("p"),
                     "p-cm-fix-results")


class PhaseArgsTest(unittest.TestCase):

  def test_single_phase_is_unchanged_copy(self):
    args = ns("verify", from_find_run="exp/F", run_id="R")
    got = pipeline.phase_args(args, 0)
    self.assertIsNot(got, args)
    self.assertEqual(vars(got), vars(args))

  def test_non_final_phases_force_wait(self):
    args = ns("find-verify-fix", run_id="R")
    self.assertTrue(pipeline.phase_args(args, 0).wait)
    self.assertTrue(pipeline.phase_args(args, 1, "F").wait)
    self.assertFalse(pipeline.phase_args(args, 2, "V").wait)
    self.assertFalse(args.wait)

  def test_chained_sources_and_run_ids(self):
    args = ns("find-verify-fix", run_id="R")
    verify = pipeline.phase_args(args, 1, "F")
    self.assertEqual((verify.operation, verify.from_find_run,
                      verify.from_verify_run, verify.run_id),
                     ("verify", "exp/F", None, "R_verify"))
    fix = pipeline.phase_args(args, 2, "V")
    self.assertEqual((fix.operation, fix.from_find_run, fix.from_verify_run,
                      fix.run_id), ("fix", None, "exp/V", "R_fix"))

  def test_verify_fix_clears_find_source_for_fix(self):
    args = ns("verify-fix", from_find_run="exp/F")
    first = pipeline.phase_args(args, 0)
    self.assertEqual(first.from_find_run, "exp/F")
    fix = pipeline.phase_args(args, 1, "V")
    self.assertEqual((fix.from_find_run, fix.from_verify_run, fix.run_id),
                     (None, "exp/V", None))

  def test_find_fix_uses_find_source(self):
    fix = pipeline.phase_args(ns("find-fix"), 1, "F")
    self.assertEqual((fix.from_find_run, fix.from_verify_run),
                     ("exp/F", None))


class MessagesTest(unittest.TestCase):

  def test_hints(self):
    args = ns("find-verify-fix")
    self.assertEqual(pipeline.dry_run_hint(args, 0, "F"),
                     "[dry-run] would then run verify --from-find-run exp/F")
    self.assertEqual(
        pipeline.resume_hint(args, 0, "F"),
        "verify-fix skipped; inspect find results, then resume with: "
        "--operation verify-fix --from-find-run exp/F")
    self.assertEqual(
        pipeline.resume_hint(args, 1, "V"),
        "fix skipped; inspect verify results, then resume with: "
        "--operation fix --from-verify-run exp/V")
    self.assertEqual(
        pipeline.transition_message(args, 1, "V"),
        "[phase] verify phase (V) complete; transitioning to fix"
        " (--from-verify-run exp/V)")

  def test_stop_hint(self):
    self.assertIn("would then run fix",
                  pipeline.stop_hint(ns("verify-fix", dry_run=True), 0, "V", 2))
    self.assertIn("resume with", pipeline.stop_hint(ns("find-fix", dry_run=False),
                                                    0, "F", 1))
    self.assertIsNone(pipeline.stop_hint(ns("find-fix", dry_run=False), 0, "F", 2))


if __name__ == "__main__":
  unittest.main()
