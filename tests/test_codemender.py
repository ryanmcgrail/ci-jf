"""Unit tests for codemender.py."""

import io
import json
import os
import signal
import sqlite3
import sys
import tempfile
import threading
import time
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
              "--model=gemini-4-hydrogen",
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
            "--model=gemini-4-hydrogen",
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
            "--model=gemini-4-hydrogen",
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
            "--model=gemini-4-hydrogen",
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
            "--model=gemini-4-hydrogen",
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
            "--model=gemini-4-hydrogen",
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
            "--model=gemini-4-hydrogen",
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

  def test_find_runs_gcloud_adc_login_and_retries_on_reauth_error_when_interactive(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc_reauth = types.SimpleNamespace(
        returncode=1,
        stdout="",
        stderr='Error: retrieving access token: oauth2: "invalid_grant" "reauth related error (invalid_rapt)"',
    )
    proc_gcloud = types.SimpleNamespace(returncode=0, stdout="Credentials saved", stderr="")
    proc_success = types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
    tty_stdin = types.SimpleNamespace(isatty=lambda: True)
    with (
        patch.object(sys, "stdin", tty_stdin),
        patch(
            "codemender.run_command",
            side_effect=[proc_reauth, proc_gcloud, proc_success],
        ) as mock_run,
    ):
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
            "--model=gemini-4-hydrogen",
            "--bypass-warning",
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[1].args[0],
        ["gcloud", "auth", "application-default", "login"],
    )
    self.assertTrue(mock_run.call_args_list[1].kwargs.get("interactive"))
    self.assertEqual(
        mock_run.call_args_list[2].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--quick",
            "--model=gemini-4-hydrogen",
            "--bypass-warning",
        ],
    )

  def test_find_skips_gcloud_adc_login_and_raises_in_headless_ci(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc_reauth = types.SimpleNamespace(
        returncode=1,
        stdout="",
        stderr='Error: retrieving access token: oauth2: "invalid_grant" "reauth related error (invalid_rapt)"',
    )
    headless_stdin = types.SimpleNamespace(isatty=lambda: False)
    with (
        patch.object(sys, "stdin", headless_stdin),
        patch("codemender.run_command", return_value=proc_reauth) as mock_run,
    ):
      with self.assertRaises(RuntimeError) as ctx:
        cm.find(scan_mode=codemender.ScanMode.QUICK)
    self.assertEqual(mock_run.call_count, 1)
    self.assertIn("exit code 1", str(ctx.exception))
    self.assertIn("Application Default Credentials", str(ctx.exception))

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

  def test_run_command_does_not_duplicate_output_to_stderr_when_non_tty(self):
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
    self.assertEqual(fake_stderr.getvalue(), "")

  def test_run_command_terminates_child_and_runs_finally_on_sigterm(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      pid_file = os.path.join(tmpdir, "child.pid")
      cleanup_ran = False

      def send_sigterm_once_child_starts():
        deadline = time.monotonic() + 5.0
        while not os.path.exists(pid_file) and time.monotonic() < deadline:
          time.sleep(0.02)
        time.sleep(0.05)
        os.kill(os.getpid(), signal.SIGTERM)

      sender = threading.Thread(target=send_sigterm_once_child_starts, daemon=True)
      sender.start()
      with self.assertRaises(SystemExit) as exit_ctx:
        try:
          codemender.run_command(
              [
                  sys.executable,
                  "-c",
                  (
                      "import os, sys, time;"
                      f" open({pid_file!r}, 'w').write(str(os.getpid()));"
                      " print('started', flush=True);"
                      " time.sleep(60)"
                  ),
              ],
              check=False,
          )
        finally:
          cleanup_ran = True
      sender.join(timeout=2.0)

      self.assertTrue(cleanup_ran)
      self.assertEqual(exit_ctx.exception.code, 128 + signal.SIGTERM)
      with open(pid_file, "r", encoding="utf-8") as fh:
        child_pid = int(fh.read().strip())
      # Child process must already be terminated and reaped by run_command's finally block
      with self.assertRaises(ProcessLookupError):
        os.kill(child_pid, 0)

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

  def test_subprocess_env_defaults_stall_detection_on_unless_overridden(self):
    proc_find = types.SimpleNamespace(returncode=0, stdout="Success")
    proc_report = types.SimpleNamespace(returncode=0, stdout="[]")

    with patch.dict(os.environ, {}, clear=False):
      os.environ.pop("CM_STALL_DETECTION", None)
      cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
      with patch("codemender.run_command", side_effect=[proc_find, proc_report]) as mock_run:
        cm.find()
        cm.list_findings()
      self.assertIsNone(cm.env)
      self.assertEqual(mock_run.call_args_list[0].kwargs["env"]["CM_STALL_DETECTION"], "on")
      self.assertEqual(mock_run.call_args_list[1].kwargs["env"]["CM_STALL_DETECTION"], "on")

    # Empty string in os.environ still defaults to "on"
    with patch.dict(os.environ, {"CM_STALL_DETECTION": "  "}, clear=False):
      cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
      with patch("codemender.run_command", return_value=proc_find) as mock_run:
        cm.find()
      self.assertEqual(mock_run.call_args.kwargs["env"]["CM_STALL_DETECTION"], "on")

    # User override in os.environ is respected
    with patch.dict(os.environ, {"CM_STALL_DETECTION": "off"}, clear=False):
      cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
      with patch("codemender.run_command", return_value=proc_find) as mock_run:
        cm.find()
      self.assertEqual(mock_run.call_args.kwargs["env"]["CM_STALL_DETECTION"], "off")

    # Explicit CodeMender(env=...) override takes precedence over os.environ
    with patch.dict(os.environ, {"CM_STALL_DETECTION": "on"}, clear=False):
      cm = CodeMender(
          cm_binary="cm",
          repo_dir="/tmp/test_repo",
          env={"CM_STALL_DETECTION": "off", "CM_HOME": "/tmp/custom_cm"},
      )
      with patch("codemender.run_command", return_value=proc_find) as mock_run:
        cm.find()
      self.assertEqual(mock_run.call_args.kwargs["env"]["CM_STALL_DETECTION"], "off")
      self.assertEqual(mock_run.call_args.kwargs["env"]["CM_HOME"], "/tmp/custom_cm")

  def test_is_partial_deep_scan_failure_and_find_flag(self):
    partial_stdout = (
        "Error: deep scan incomplete: 1 of 7 batch(es) failed"
        " (Update/VLAUpdate.cs): The prompt is blocked due to safety\n"
    )
    all_failed_stdout = "Error: all 2 deep scan batch(es) failed: timeout\n"

    self.assertTrue(codemender.is_partial_deep_scan_failure(1, partial_stdout))
    self.assertTrue(codemender.is_partial_deep_scan_failure(2, partial_stdout))
    self.assertFalse(codemender.is_partial_deep_scan_failure(3, partial_stdout))
    self.assertTrue(codemender.is_safety_block_failure(1, partial_stdout))
    self.assertTrue(codemender.is_safety_block_failure(2, partial_stdout))
    self.assertFalse(codemender.is_safety_block_failure(3, partial_stdout))
    self.assertFalse(codemender.is_partial_deep_scan_failure(1, all_failed_stdout))
    self.assertTrue(
        codemender.is_partial_deep_scan_failure(
            2, all_failed_stdout, allow_all_batches_failed=True
        )
    )

    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc_partial = types.SimpleNamespace(returncode=1, stdout=partial_stdout, stderr="")
    with patch("codemender.run_command", return_value=proc_partial):
      with self.assertRaises(RuntimeError):
        cm.find()
      res = cm.find(allow_partial_failure=True)
      self.assertEqual(res.returncode, 1)

    proc_all_failed = types.SimpleNamespace(returncode=1, stdout=all_failed_stdout, stderr="")
    with patch("codemender.run_command", return_value=proc_all_failed):
      with self.assertRaises(RuntimeError):
        cm.find(allow_partial_failure=True)
      res_all = cm.find(allow_partial_failure=True, allow_all_batches_failed=True)
      self.assertEqual(res_all.returncode, 1)


if __name__ == "__main__":
  unittest.main()
