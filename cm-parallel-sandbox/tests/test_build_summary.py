"""Tests for container/scripts/build_summary.py."""

import importlib.util
import json
import io
import pathlib
import sqlite3
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "build_summary", ROOT / "container" / "scripts" / "build_summary.py")
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)


def run(rd, *argv):
  bs.main(["--results-dir", str(rd), *argv])
  return json.loads((rd / "summary.json").read_text())


class FindSummaryTest(unittest.TestCase):

  def setUp(self):
    self.rd = pathlib.Path(tempfile.mkdtemp())
    (self.rd / "findings.json").write_text(json.dumps(
        [{"severity": "HIGH"}, {"severity": "CRITICAL"}, {"severity": "HIGH"}]))

  def test_ok(self):
    (self.rd / "cm_api_token_stats.json").write_text('{"total_tokens": 10}')
    s = run(self.rd, "--operation", "find", "--exit-code", "0")
    self.assertEqual(s["status"], "ok")
    self.assertEqual(s["findings_count"], 3)
    self.assertEqual(s["severity_counts"], {"HIGH": 2, "CRITICAL": 1})
    self.assertNotIn("repeat", s)

  def test_zero_tokens_fails(self):
    (self.rd / "cm_api_token_stats.json").write_text('{"total_tokens": 0}')
    self.assertEqual(run(self.rd, "--operation", "find")["status"], "failed")

  def test_timeout(self):
    (self.rd / "cm_api_token_stats.json").write_text('{"total_tokens": 5}')
    s = run(self.rd, "--operation", "find", "--exit-code", "124")
    self.assertEqual(s["status"], "timeout")

  def test_excludes_dismissed_findings(self):
    (self.rd / "findings.json").write_text(json.dumps([
        {"severity": "HIGH", "status": "OPEN"},
        {"severity": "CRITICAL", "status": "OPEN"},
        {"severity": "HIGH", "status": "DISMISSED", "dismiss_reason": "Duplicate un-fingerprinted streamed entry"},
        {"severity": "CRITICAL", "status": "DISMISSED"},
        {"severity": "MEDIUM"},
    ]))
    (self.rd / "cm_api_token_stats.json").write_text('{"total_tokens": 10}')
    s = run(self.rd, "--operation", "find", "--exit-code", "0")
    self.assertEqual(s["status"], "ok")
    self.assertEqual(s["findings_count"], 3)
    self.assertEqual(s["severity_counts"], {"HIGH": 1, "CRITICAL": 1, "MEDIUM": 1})


class Cm010FindSummaryTest(unittest.TestCase):

  def setUp(self):
    self.rd = pathlib.Path(tempfile.mkdtemp())
    (self.rd / "findings.json").write_text("[]")

  def _find(self, *extra):
    return run(self.rd, "--operation", "find", "--cm-version", "0.10.0",
               "--mode", "deep", *extra)

  def test_sum_01_sessions_and_deep_workers(self):
    c = sqlite3.connect(self.rd / "state.db")
    c.execute("CREATE TABLE sessions (session_id TEXT, session_type TEXT,"
              " created_at TEXT)")
    c.executemany("INSERT INTO sessions VALUES (?, 'SCAN', '')",
                  [("ChStubSession0001",), ("ChStubSession0002",)])
    c.commit()
    c.close()
    (self.rd / "logs").mkdir()
    with tarfile.open(self.rd / "logs" / "cm_logs.tar.gz", "w:gz") as tf:
      log = "".join(
          f"2026-09-28T00:00:0{i}Z [DEBUG] StartSession \u2713 accepted: "
          f"operation={sid} session={sid}\n"
          for i, sid in enumerate(("ChStubSession0001", "ChStubSession0003",
                                   "ChStubSession0001")))
      log += "2026-09-28T00:00:09Z [DEBUG] WaitOperation #1: request=x\n"
      for name, data in (("20260928T000000Z_pending.log", log.encode()),
                         ("20260928T000500Z_pending.log", b"")):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    (self.rd / "cm_api_token_stats.json").write_text('{"total_tokens": 3}')
    s = self._find("--deep-workers", "8")
    self.assertEqual(s["deep_workers"], 8)
    self.assertEqual(s["sessions"], {"state_db": 2, "logs": 2, "union": 3,
                                     "dropped_from_db": 1})

  def test_sum_02_token_stats_status(self):
    ts = self.rd / "cm_api_token_stats.json"
    ts.write_text('{"total_tokens": 3}')
    s = self._find()
    self.assertEqual((s["token_stats_status"], s["status"]), ("ok", "ok"))
    ts.write_text('{"error": "timeout"}')
    s = self._find()
    self.assertEqual((s["token_stats_status"], s["status"]),
                     ("timeout", "failed"))
    ts.unlink()
    s = self._find()
    self.assertEqual((s["token_stats_status"], s["status"]),
                     ("failed", "failed"))
    self.assertNotIn("token_stats_status",
                     run(self.rd, "--operation", "find",
                         "--cm-version", "0.9.0"))


class VerifySummaryTest(unittest.TestCase):

  def setUp(self):
    self.rd = pathlib.Path(tempfile.mkdtemp())
    self.ids = ["a", "b", "c", "d"]
    (self.rd / "ids.txt").write_text("\n".join(self.ids) + "\n")
    for fid, code in zip(self.ids, [0, 124, 137, 1]):
      d = self.rd / "findings" / fid
      d.mkdir(parents=True)
      (d / "exit_code").write_text(f"{code}\n")
      (d / "token_stats.json").write_text('{"total_tokens": 7}')
    (self.rd / "post_verify_report.json").write_text(json.dumps([
        {"finding_id": "a", "status": "VERIFIED"},
        {"finding_id": "b", "status": "DISMISSED"},
        {"finding_id": "c", "status": "OPEN"}]))

  def test_counts(self):
    s = run(self.rd, "--operation", "verify", "--ids-file",
            str(self.rd / "ids.txt"))
    self.assertEqual(s["status_counts"],
                     {"VERIFIED": 1, "DISMISSED": 1, "OTHER:OPEN": 1,
                      "OTHER:MISSING": 1})
    self.assertEqual(s["timeout_count"], 2)
    self.assertEqual(s["nonzero_exit_count"], 3)
    self.assertEqual(s["tokens"]["total_tokens"], 28)
    self.assertEqual(s["status"], "timeout")
    self.assertNotIn("repeat", s)

  def test_ok_without_per_finding_timeouts(self):
    for fid in ("b", "c"):
      (self.rd / "findings" / fid / "exit_code").write_text("0\n")
    s = run(self.rd, "--operation", "verify", "--ids-file",
            str(self.rd / "ids.txt"))
    self.assertEqual(s["timeout_count"], 0)
    self.assertEqual(s["nonzero_exit_count"], 1)
    self.assertEqual(s["status"], "ok")

  def test_missing_exit_code_fails(self):
    (self.rd / "findings" / "d" / "exit_code").write_text("deadline\n")
    s = run(self.rd, "--operation", "verify", "--ids-file",
            str(self.rd / "ids.txt"), "--exit-code", "124")
    self.assertEqual(s["status"], "timeout")
    self.assertEqual(s["findings_attempted"], 3)


class FixSummaryTest(unittest.TestCase):

  def setUp(self):
    self.rd = pathlib.Path(tempfile.mkdtemp())
    self.ids = ["a", "b", "c"]
    (self.rd / "ids.txt").write_text("\n".join(self.ids) + "\n")
    for fid in self.ids:
      d = self.rd / "findings" / fid
      d.mkdir(parents=True)
      (d / "exit_code").write_text("0\n")
      (d / "token_stats.json").write_text('{"total_tokens": 10}')

    (self.rd / "findings" / "a" / "patch.diff").write_text("diff a\n")
    (self.rd / "findings" / "b" / "patch.diff").write_text("diff b\n")
    (self.rd / "findings" / "c" / "patch.diff").write_text("")

    exp_a = self.rd / "findings" / "a" / "exploit"
    exp_a.mkdir(parents=True)
    (exp_a / "exploit.sh").write_text("#!/bin/bash\n")
    exp_b = self.rd / "findings" / "b" / "exploit"
    exp_b.mkdir(parents=True)
    (exp_b / "exploit.sh").write_text("#!/bin/bash\n")

    (self.rd / "post_fix_report.json").write_text(json.dumps([
        {"finding_id": "a", "status": "FIXED"},
        {"finding_id": "b", "status": "DISMISSED"},
        {"finding_id": "c", "status": "OPEN"},
    ]))

  def test_fix_summary_ok_with_patches_and_exploits(self):
    s = run(self.rd, "--operation", "fix",
            "--ids-file", str(self.rd / "ids.txt"),
            "--from-find-run", "find_run_1",
            "--from-verify-run", "verify_run_1",
            "--severity", "CRITICAL,HIGH")
    self.assertEqual(s["status"], "ok")
    self.assertEqual(s["patches_generated"], 2)
    self.assertEqual(s["patch_sizes"]["a"], len("diff a\n"))
    self.assertEqual(s["patch_sizes"]["b"], len("diff b\n"))
    self.assertEqual(s["patch_sizes"]["c"], 0)
    self.assertEqual(s["exploits_imported"], 2)
    self.assertEqual(s["status_counts"], {
        "FIXED": 1,
        "DISMISSED": 1,
        "OTHER:OPEN": 1,
    })
    self.assertEqual(s["source_find_run"], "find_run_1")
    self.assertEqual(s["source_verify_run"], "verify_run_1")
    self.assertEqual(s["severity"], "CRITICAL,HIGH")
    self.assertEqual(s["findings_expected"], 3)
    self.assertEqual(s["findings_attempted"], 3)
    self.assertEqual(s["timeout_count"], 0)
    self.assertEqual(s["tokens"]["total_tokens"], 30)

  def test_fix_summary_timeout_and_failed(self):
    (self.rd / "findings" / "b" / "exit_code").write_text("124\n")
    s = run(self.rd, "--operation", "fix",
            "--ids-file", str(self.rd / "ids.txt"))
    self.assertEqual(s["status"], "timeout")
    self.assertEqual(s["timeout_count"], 1)

    (self.rd / "post_fix_report.json").unlink()
    s = run(self.rd, "--operation", "fix",
            "--ids-file", str(self.rd / "ids.txt"))
    self.assertEqual(s["status"], "failed")


class DiffSummaryTest(unittest.TestCase):

  def setUp(self):
    self.rd = pathlib.Path(tempfile.mkdtemp())
    (self.rd / "findings.json").write_text(json.dumps(
        [{"severity": "HIGH"}, {"severity": "LOW", "status": "DISMISSED"}]))
    (self.rd / "cm_api_token_stats.json").write_text('{"total_tokens": 10}')
    (self.rd / "diff_stats.json").write_text(
        '{"changed_files": 3, "changed_lines": 40}')
    self.base = ["--operation", "find", "--mode", "diff", "--cm-version",
                 "0.10.0", "--pinned-ref", "a" * 40, "--diff-ref", "b" * 40]

  def test_diff_fields(self):
    s = run(self.rd, *self.base, "--cm-exit-code", "1", "--exit-code", "0")
    self.assertEqual(
        {k: s[k] for k in ("pinned_ref", "diff_ref", "changed_files",
                           "changed_lines", "cm_exit_code", "diff_workers")},
        {"pinned_ref": "a" * 40, "diff_ref": "b" * 40, "changed_files": 3,
         "changed_lines": 40, "cm_exit_code": 1, "diff_workers": None})
    self.assertEqual((s["status"], s["findings_count"]), ("ok", 1))
    self.assertNotIn("diff_bucket", s)

  def test_diff_workers_set(self):
    s = run(self.rd, *self.base, "--diff-workers", "2", "--cm-exit-code", "0")
    self.assertEqual(s["diff_workers"], 2)

  def test_missing_diff_stats_is_null(self):
    (self.rd / "diff_stats.json").unlink()
    s = run(self.rd, *self.base, "--cm-exit-code", "0")
    self.assertIsNone(s["changed_files"])
    self.assertIsNone(s["changed_lines"])

  def test_failed_exit_keeps_raw_code(self):
    s = run(self.rd, *self.base, "--cm-exit-code", "2", "--exit-code", "2")
    self.assertEqual((s["status"], s["cm_exit_code"]), ("failed", 2))

  def _log(self, text):
    (self.rd / "logs").mkdir(exist_ok=True)
    (self.rd / "logs" / "execution.log").write_text(text)

  def test_job_stats_from_complete_line(self):
    self._log("  PR Delta Scan Complete: 4 jobs (3 succeeded, 1 failed) in 10s\n")
    s = run(self.rd, *self.base, "--cm-exit-code", "0")
    self.assertEqual(
        (s["diff_timed_out"], s["diff_jobs_total"], s["diff_jobs_completed"],
         s["diff_jobs_failed"]), (False, 4, 4, 1))

  def test_job_stats_from_ceiling_timeout(self):
    self._log("  PR Delta Scan reached maximum 5-minute ceiling (5m0s). "
              "Cancelling active sessions...\n"
              "Error: PR delta scan timed out after 5m0s (3/4 jobs completed): "
              "context deadline exceeded\n")
    s = run(self.rd, *self.base, "--cm-exit-code", "1")
    self.assertEqual(
        (s["diff_timed_out"], s["diff_jobs_total"], s["diff_jobs_completed"],
         s["diff_jobs_failed"]), (True, 4, 3, None))

  def test_ceiling_message_alone_marks_timeout(self):
    self._log("  PR Delta Scan terminated: reached the 5-minute maximum "
              "ceiling (5m0s).\n")
    s = run(self.rd, *self.base, "--cm-exit-code", "1")
    self.assertTrue(s["diff_timed_out"])
    self.assertIsNone(s["diff_jobs_total"])

  def test_missing_log_has_null_job_stats(self):
    s = run(self.rd, *self.base, "--cm-exit-code", "0")
    self.assertEqual((s["diff_timed_out"], s["diff_jobs_total"]), (False, None))

  def test_other_modes_have_no_diff_fields(self):
    for mode in ("shallow", "deep"):
      with self.subTest(mode=mode):
        s = run(self.rd, "--operation", "find", "--mode", mode, "--cm-version",
                "0.10.0", "--pinned-ref", "a" * 40, "--cm-exit-code", "1")
        for key in ("pinned_ref", "diff_ref", "changed_files", "changed_lines",
                    "cm_exit_code", "diff_workers", "diff_timed_out",
                    "diff_jobs_total"):
          self.assertNotIn(key, s)


if __name__ == "__main__":
  unittest.main()
