"""Tests for cmrun.common."""

import datetime
import unittest

from cmrun import common


class CommonTest(unittest.TestCase):

  def setUp(self):
    self.repos = common.load_repos()

  def test_load_repos(self):
    self.assertEqual(len(self.repos), 88)
    self.assertEqual(self.repos["o04-vampi"]["pinned_ref"], "f16052dce83f05847133ec98f01c5193a41de7d8")

  def test_select_all_when_none(self):
    self.assertEqual(common.select_repos(self.repos, None), list(self.repos))

  def test_select_subset_dedupes_and_keeps_order(self):
    self.assertEqual(
        common.select_repos(self.repos, ["o04-vampi", "p01-flask", "o04-vampi"]),
        ["o04-vampi", "p01-flask"])

  def test_unknown_repo_lists_close_matches(self):
    with self.assertRaises(common.UsageError) as cm:
      common.select_repos(self.repos, ["o04-vamp"])
    self.assertIn("o04-vampi", str(cm.exception))

  def test_naming(self):
    self.assertEqual(common.FIX_JOB, "cm-fix-runner")
    self.assertEqual(common.payload_bucket("p"), "p-cm-payload")
    self.assertEqual(common.find_results_bucket("p"), "p-cm-find-results")
    self.assertEqual(common.verify_results_bucket("p"), "p-cm-verify-results")
    self.assertEqual(common.fix_results_bucket("p"), "p-cm-fix-results")
    self.assertEqual(common.repo_tarball_uri("gs://b/", "r"),
                     "gs://b/repos/r.tar.gz")
    self.assertEqual(common.image_repo("p", "us-central1"),
                     "us-central1-docker.pkg.dev/p/cm-parallel-sandbox/cm-sandbox-runner")

  def test_run_id_format(self):
    now = datetime.datetime(2026, 9, 26, 12, 0, 0)
    self.assertEqual(
        common.make_run_id("find", "0.9.0", "gemini-3.8-flash", now),
        "20260926_120000_find_v0.9.0_gemini-3.8-flash")
    self.assertRegex(common.make_run_id("verify", "0.9.0", "m"),
                     r"^\d{8}_\d{6}_verify_v0\.9\.0_m$")


if __name__ == "__main__":
  unittest.main()
