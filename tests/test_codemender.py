"""Unit tests for codemender.py."""

import io
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import codemender
from codemender import CodeMender


class CodeMenderTests(unittest.TestCase):

  def test_is_ci_gate_exit_blocking(self):
    stdout = "CI Gate Failure: 2 blocking finding(s) detected."
    self.assertTrue(codemender.is_ci_gate_exit(1, stdout))

  def test_is_ci_gate_exit_truncated(self):
    stdout = "CI Gate Failure: 2 blocking finding(s) detected. CI Gate Failure: Impact expansion truncated"
    self.assertFalse(codemender.is_ci_gate_exit(1, stdout))

  def test_is_ci_gate_exit_success(self):
    stdout = "CI Gate Failure: 2 blocking finding"
    self.assertFalse(codemender.is_ci_gate_exit(0, stdout))

  def test_build_cm_command_find(self):
    cmd = codemender.build_cm_command(
        cm_binary="/usr/bin/cm",
        action="find",
        target_or_id="/tmp/repo",
    )
    self.assertEqual(cmd, ["/usr/bin/cm", "find", "/tmp/repo"])

  def test_build_cm_command_requires_target(self):
    with self.assertRaises(ValueError):
      codemender.build_cm_command(cm_binary="cm", action="find", target_or_id=None)

  def test_init_defaults(self):
    cm = CodeMender()
    self.assertEqual(cm.cm_binary, "cm")
    self.assertEqual(cm.repo_dir, ".")
    self.assertIsNone(cm.env)

  def test_init_custom(self):
    cm = CodeMender(
        cm_binary="/custom/cm",
        repo_dir="/custom/repo",
        env={"CUSTOM_VAR": "val"},
    )
    self.assertEqual(cm.cm_binary, "/custom/cm")
    self.assertEqual(cm.repo_dir, "/custom/repo")
    self.assertEqual(cm.env, {"CUSTOM_VAR": "val"})

  def test_find_defaults_to_repo_dir(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc_find = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc_find) as mock_run:
      res = cm.find()
      self.assertEqual(mock_run.call_count, 1)
      args, kwargs = mock_run.call_args_list[0]
      cmd = args[0]
      self.assertEqual(
          cmd,
          [
              "cm",
              "find",
              "/tmp/test_repo",
              "--deep",
              "--deep-workers=16",
              "--model=gemini-4-argon",
              "--bypass-warning",
              "--deep-max-turns",
              "8",
          ],
      )
      self.assertNotIn("--context", cmd)
      self.assertEqual(kwargs.get("cwd"), "/tmp/test_repo")
      self.assertEqual(res, proc_find)

  def test_find_custom_target(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      cm.find(target_or_id="/tmp/other_target")
      args, _ = mock_run.call_args_list[0]
      cmd = args[0]
      self.assertEqual(cmd[2], "/tmp/other_target")

  def test_find_scan_modes_omit_context_unless_supplied(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      cm.find(scan_mode=codemender.ScanMode.QUICK)
      cm.find(scan_mode=codemender.ScanMode.DIFF)
      cm.find(scan_mode=codemender.ScanMode.DEEP)
      cm.find(
          scan_mode=codemender.ScanMode.QUICK,
          extra_flags=["--context", "Quick guidance"],
      )
      cm.find(
          scan_mode=codemender.ScanMode.DIFF,
          extra_flags=["-c", "Diff guidance"],
      )
      cm.find(
          scan_mode=codemender.ScanMode.DEEP,
          extra_flags=["--context=Deep guidance"],
      )

    self.assertEqual(
        mock_run.call_args_list[0].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--quick",
            "--model=gemini-4-argon",
            "--bypass-warning",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[1].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--diff",
            "--model=gemini-4-argon",
            "--bypass-warning",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[2].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--deep",
            "--deep-workers=16",
            "--model=gemini-4-argon",
            "--bypass-warning",
            "--deep-max-turns",
            "8",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[3].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--quick",
            "--model=gemini-4-argon",
            "--bypass-warning",
            "--context",
            "Quick guidance",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[4].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--diff",
            "--model=gemini-4-argon",
            "--bypass-warning",
            "--context",
            "Diff guidance",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[5].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--deep",
            "--deep-workers=16",
            "--model=gemini-4-argon",
            "--bypass-warning",
            "--deep-max-turns",
            "8",
            "--context",
            "Deep guidance",
        ],
    )

  def test_find_handles_ci_gate_exit(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(
        returncode=1,
        stdout="CI Gate Failure: 2 blocking finding(s) detected.",
    )
    with patch("codemender.run_command", return_value=proc):
      cm.find()

  def test_find_raises_on_fatal_error(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=2, stdout="Fatal error")
    with patch("codemender.run_command", return_value=proc):
      with self.assertRaises(RuntimeError):
        cm.find()

  def test_find_runs_gcloud_adc_login_and_retries_on_reauth_error(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc_reauth = types.SimpleNamespace(
        returncode=1,
        stdout="",
        stderr='Error: retrieving access token: oauth2: "invalid_grant" "reauth related error (invalid_rapt)"',
    )
    proc_gcloud = types.SimpleNamespace(returncode=0, stdout="Credentials saved", stderr="")
    proc_success = types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
    with patch(
        "codemender.run_command",
        side_effect=[proc_reauth, proc_gcloud, proc_success],
    ) as mock_run:
      res = cm.find(scan_mode=codemender.ScanMode.QUICK)
    self.assertEqual(res, proc_success)
    self.assertEqual(mock_run.call_count, 3)
    self.assertEqual(
        mock_run.call_args_list[0].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--quick",
            "--model=gemini-4-argon",
            "--bypass-warning",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[1].args[0],
        ["gcloud", "auth", "application-default", "login"],
    )
    self.assertEqual(
        mock_run.call_args_list[2].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--quick",
            "--model=gemini-4-argon",
            "--bypass-warning",
        ],
    )

  def test_list_findings(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    raw = json.dumps([{"finding_id": "cm-99"}])
    proc = types.SimpleNamespace(returncode=0, stdout=raw)
    with patch("codemender.run_command", return_value=proc):
      findings = cm.list_findings()
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0].finding_id, "cm-99")

  def test_db_returns_none_when_state_db_missing(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      cm = CodeMender(env={"CM_HOME": tmpdir})
      self.assertIsNone(cm.db)

  def test_db_returns_sqlite_connection_when_state_db_exists(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      db_path = os.path.join(tmpdir, "state.db")
      con = sqlite3.connect(db_path)
      con.execute("CREATE TABLE findings (finding_id TEXT)")
      con.commit()
      con.close()

      cm = CodeMender(env={"CM_HOME": tmpdir})
      self.assertIsInstance(cm.db, sqlite3.Connection)
      tables = {
          r[0]
          for r in cm.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
      }
      self.assertIn("findings", tables)

  def test_run_command_prints_to_console_when_stdout_redirected(self):
    fake_stdout = io.StringIO()
    fake_stderr = io.StringIO()
    with patch.object(sys, "stdout", fake_stdout), patch.object(
        sys, "stderr", fake_stderr
    ):
      res = codemender.run_command(
          [sys.executable, "-c", 'print("hello from cm find")'],
          print_to_stdout=True,
      )
    self.assertEqual(res.stdout, "hello from cm find\n")
    self.assertEqual(fake_stdout.getvalue(), "hello from cm find\n")
    self.assertEqual(fake_stderr.getvalue(), "hello from cm find\n")

  def test_find_deduplicates_extra_flags_and_merges_custom_context(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      cm.find(
          context="Base context",
          extra_flags=[
              "--deep-workers=8",
              "--deep-max-turns=14",
              "--bypass-warning",
              "--context",
              "Focus on payment handlers",
              "-c=Check webhook signatures",
          ],
      )
      cm.find(
          scan_mode=codemender.ScanMode.DIFF,
          extra_flags=["--diff=origin/main", "--model", "gemini-2.5-pro"],
      )

    deep_cmd = mock_run.call_args_list[0].args[0]
    self.assertEqual(
        [f for f in deep_cmd if f.startswith("--deep-workers")],
        ["--deep-workers=8"],
    )
    self.assertEqual(
        [f for f in deep_cmd if f.startswith("--deep-max-turns")],
        ["--deep-max-turns=14"],
    )
    self.assertEqual(deep_cmd.count("--bypass-warning"), 1)
    self.assertEqual(deep_cmd.count("--context"), 1)
    self.assertNotIn("-c", deep_cmd)
    ctx_val = deep_cmd[deep_cmd.index("--context") + 1]
    self.assertEqual(
        ctx_val,
        "Base context\n\nFocus on payment handlers\n\nCheck webhook signatures",
    )

    diff_cmd = mock_run.call_args_list[1].args[0]
    self.assertEqual(
        [f for f in diff_cmd if f == "--diff" or f.startswith("--diff=")],
        ["--diff=origin/main"],
    )
    self.assertEqual(
        [f for f in diff_cmd if f == "--model" or f.startswith("--model=")],
        ["--model"],
    )
    self.assertNotIn("--deep-max-turns", diff_cmd)
    self.assertNotIn("--context", diff_cmd)


if __name__ == "__main__":
  unittest.main()
