"""container/entrypoint.sh with MODE=diff (stub cm; GCS emulated).

The staged tarball is a pinned_ref checkout with history back to diff_ref, as
stage_repos.stage_one_diff builds it. Commits use fixed dates so SHAs, and so
the golden, are deterministic.
"""

import json
import os
import subprocess
import tarfile
import unittest

from tests.golden_util import assert_golden
from tests.test_entrypoint import FIND, PAYLOAD, REPO
from tests.test_entrypoint_golden import GoldenBase

GIT_ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
               GIT_AUTHOR_DATE="2024-01-01T00:00:00Z",
               GIT_COMMITTER_DATE="2024-01-01T00:00:00Z")
HIGH_REPORT = [{"finding_id": "f-high", "severity": "HIGH", "status": "OPEN"}]


class DiffEntrypointTest(GoldenBase):

  def _git(self, *args):
    return subprocess.run(["git", "-C", str(self.src), *args], check=True,
                          env=GIT_ENV, capture_output=True,
                          text=True).stdout.strip()

  def _commit(self, files, msg):
    for name, text in files.items():
      path = self.src / name
      path.parent.mkdir(parents=True, exist_ok=True)
      path.write_text(text)
    self._git("add", "-A")
    self._git("commit", "-qm", msg)
    return self._git("rev-parse", "HEAD")

  def _stage_repo_tarball(self):
    self.src = self.tmp / "src" / REPO
    self.src.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(self.src)],
                   check=True)
    self.base = self._commit({"app.py": "print('vampi')\n"}, "base")
    self._commit({"README.md": "docs\n"}, "docs")
    self.pinned = self._commit(
        {"app.py": "print('vampi')\nprint('v2')\n", "api/views.py": "x = 1\n",
         "vendor/lib.py": "y = 2\n"}, "change")
    tgz = self.tmp / "repo.tar.gz"
    with tarfile.open(tgz, "w:gz") as tf:
      tf.add(self.src, arcname=REPO)
    self.put(f"gs://{PAYLOAD}/repos/{REPO}.tar.gz", tgz.read_bytes())

  def diff_task(self, **kw):
    return self.task(pinned_ref=self.pinned, diff_ref=self.base, **kw)

  def run_diff(self, run_id="D", task=None, env=None):
    self.stage_tasks(run_id, [task or self.diff_task()])
    extra = {"MODE": "diff", "CM_STUB_REPORT": str(self.report)}
    extra.update(env or {})
    p = self.run_ep("find", run_id, cm_version="0.10.0", extra_env=extra)
    out = self.results(FIND, run_id)
    summary_path = out / "summary.json"
    summary = (json.loads(summary_path.read_text())
               if summary_path.exists() else None)
    return p, out, summary

  def setUp(self):
    super().setUp()
    self.report = self.tmp / "diff_report.json"
    self.report.write_text(json.dumps(HIGH_REPORT))

  def test_gate_trip_with_findings_is_success_golden(self):
    p, out, s = self.run_diff()
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(self.cm_calls("find")[0]["argv"],
                     ["find", f"--diff={self.base}", ".", "--model",
                      "gemini-3.8-flash", "-y", "--bypass-warning"])
    self.assertIn("gate tripped; counted as success", p.stderr)
    self.assertEqual((s["status"], s["exit_code"], s["cm_exit_code"]),
                     ("ok", 0, 1))
    self.assertEqual((s["mode"], s["pinned_ref"], s["diff_ref"]),
                     ("diff", self.pinned, self.base))
    # app.py and api/views.py count; README.md and vendor/ do not.
    self.assertEqual((s["changed_files"], s["changed_lines"]), (2, 2))
    self.assertIsNone(s["diff_workers"])
    self.assertEqual(
        {k: s[k] for k in ("diff_timed_out", "diff_jobs_total",
                           "diff_jobs_completed", "diff_jobs_failed")},
        {"diff_timed_out": False, "diff_jobs_total": 1,
         "diff_jobs_completed": 1, "diff_jobs_failed": 0})
    self.assertEqual((out / "diff_files.txt").read_text(),
                     "api/views.py\napp.py\n")
    self.assertIn(f"merge-base({self.base})",
                  (out / "logs" / "execution.log").read_text())
    assert_golden(self, "ep_find_diff_v0_10.txt", self.snapshot(p, out))

  def test_exit_1_without_findings_fails(self):
    self.report.write_text("[]")
    p, _, s = self.run_diff(env={"CM_STUB_DIFF_EXIT": "1"})
    self.assertEqual(p.returncode, 1, p.stderr)
    self.assertEqual((s["status"], s["exit_code"], s["cm_exit_code"]),
                     ("failed", 1, 1))

  def test_ceiling_timeout_without_findings_is_success(self):
    self.report.write_text("[]")
    p, _, s = self.run_diff(env={"CM_STUB_DIFF_TIMEOUT": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertIn("5-minute PR delta scan ceiling; counted as success",
                  p.stderr)
    self.assertEqual(
        {k: s[k] for k in ("status", "exit_code", "cm_exit_code",
                           "diff_timed_out", "diff_jobs_completed",
                           "diff_jobs_total", "diff_jobs_failed")},
        {"status": "ok", "exit_code": 0, "cm_exit_code": 1,
         "diff_timed_out": True, "diff_jobs_completed": 3,
         "diff_jobs_total": 4, "diff_jobs_failed": None})

  def test_exit_2_fails_even_with_findings(self):
    p, _, s = self.run_diff(env={"CM_STUB_DIFF_EXIT": "2"})
    self.assertEqual(p.returncode, 2, p.stderr)
    self.assertEqual((s["status"], s["exit_code"], s["cm_exit_code"]),
                     ("failed", 2, 2))

  def test_clean_exit_records_zero(self):
    self.report.write_text("[]")
    p, _, s = self.run_diff()
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual((s["status"], s["cm_exit_code"]), ("ok", 0))

  def test_fail_on_in_extra_args_is_passed_through(self):
    p, _, s = self.run_diff(env={"EXTRA_CM_ARGS": "--fail-on CRITICAL"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(self.cm_calls("find")[0]["argv"][-2:],
                     ["--fail-on", "CRITICAL"])
    self.assertEqual(s["cm_exit_code"], 0)

  def test_diff_workers_set_is_passed(self):
    p, _, s = self.run_diff(env={"DIFF_WORKERS": "2"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(self.cm_calls("find")[0]["argv"][1:4],
                     [f"--diff={self.base}", "--diff-workers", "2"])
    self.assertEqual(s["diff_workers"], 2)

  def test_diff_token_stats_limit_and_workers(self):
    p, out, s = self.run_diff(env={"TOKEN_STATS_WORKERS": "8"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertIn("cm-api-token-stats (limit 780s, workers 8)", p.stderr)
    argv = json.loads((out / "cm_api_token_stats.json").read_text())["argv"]
    self.assertEqual(argv[argv.index("--workers") + 1], "8")
    self.assertEqual(s["token_stats_status"], "ok")

  def test_diff_workers_unset_is_not_passed(self):
    self.run_diff()
    self.assertNotIn("--diff-workers", self.cm_calls("find")[0]["argv"])

  def test_invalid_diff_workers_dies(self):
    for value in ("0", "17", "x"):
      with self.subTest(value=value):
        p, _, _ = self.run_diff(run_id=f"W{value}",
                                env={"DIFF_WORKERS": value})
        self.assertEqual(p.returncode, 1)
        self.assertIn("FATAL: DIFF_WORKERS must be empty or 1-16", p.stderr)

  def test_non_ancestor_diff_ref_dies(self):
    side = self._git("commit-tree", "-m", "orphan",
                     self._git("rev-parse", "HEAD^{tree}"))
    p, out, _ = self.run_diff(task=self.task(pinned_ref=self.pinned,
                                             diff_ref=side))
    self.assertEqual(p.returncode, 1)
    self.assertIn(f"FATAL: diff_ref {side} is not an ancestor of HEAD",
                  p.stderr)
    self.assertEqual(self.cm_calls("find"), [])
    self.assertFalse(out.exists())

  def test_head_mismatch_dies(self):
    p, _, _ = self.run_diff(task=self.task(pinned_ref=self.base,
                                           diff_ref=self.base))
    self.assertEqual(p.returncode, 1)
    self.assertIn(f"FATAL: checkout HEAD '{self.pinned}' != pinned_ref",
                  p.stderr)

  def test_missing_refs_die(self):
    p, _, _ = self.run_diff(task=self.task(pinned_ref=self.pinned))
    self.assertEqual(p.returncode, 1)
    self.assertIn("FATAL: diff task has no 40-hex diff_ref", p.stderr)

  def test_timeout_is_not_remapped(self):
    p, _, s = self.run_diff(env={"CM_STUB_DIFF_EXIT": "124"})
    self.assertEqual(p.returncode, 124)
    self.assertEqual((s["status"], s["cm_exit_code"]), ("timeout", 124))

  def test_shallow_find_has_no_diff_fields(self):
    self.stage_tasks("S", [self.task()])
    p = self.run_ep("find", "S", cm_version="0.10.0",
                    extra_env={"DIFF_WORKERS": "2"})
    self.assertEqual(p.returncode, 0, p.stderr)
    s = json.loads((self.results(FIND, "S") / "summary.json").read_text())
    for key in ("pinned_ref", "diff_ref", "changed_files", "cm_exit_code",
                "diff_workers", "diff_timed_out", "diff_jobs_total"):
      self.assertNotIn(key, s)
    self.assertNotIn("--diff-workers", self.cm_calls("find")[0]["argv"])


if __name__ == "__main__":
  unittest.main()
