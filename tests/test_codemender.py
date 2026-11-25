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

  def test_get_scan_stats_uses_session_filter_deduplicates_turns_and_prices_models(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      db_path = os.path.join(tmpdir, "state.db")
      con = sqlite3.connect(db_path)
      con.execute(
          "CREATE TABLE sessions ("
          "session_id TEXT PRIMARY KEY, "
          "session_type TEXT, "
          "parent_session_id TEXT)"
      )
      con.execute("INSERT INTO sessions VALUES ('old-session', 'FIND', '')")
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo", env={"CM_HOME": tmpdir})
      before_sids = cm.snapshot_session_ids()
      self.assertEqual(before_sids, {"old-session"})

      # Simulate a 2-pass scan: Pass 1 (parent-1 + child-1) on Hydrogen, Pass 2 (parent-2) escalated to Argon
      con2 = sqlite3.connect(db_path)
      con2.executemany(
          "INSERT INTO sessions VALUES (?, 'FIND', ?)",
          [
              ("parent-1", ""),
              ("child-1", "parent-1"),
              ("parent-2", ""),
          ],
      )
      con2.commit()
      con2.close()

      new_sids = cm.new_scan_session_ids(before_session_ids=before_sids)
      # `child-1` is omitted because its parent `parent-1` is already in the new session set
      self.assertEqual(new_sids, ["parent-1", "parent-2"])

      stats_payloads = {
          "parent-1": {
              "session_id": "parent-1",
              "command_type": "find --deep",
              "total_turns": 2,
              "tool_turns": 3,
              "model": "gemini-4-hydrogen",
              "duration_seconds": 120.4,
              "turns": [
                  {
                      "turn": "parent-1",
                      "interaction_id": "parent-1",
                      "model": "gemini-4-hydrogen",
                      "input_tokens": 200_000,
                      "cached_tokens": 100_000,
                      "output_tokens": 2_000,
                      "thought_tokens": 8_000,
                      "total_tokens": 210_000,
                      "duration_seconds": 40.0,
                  },
                  {
                      "turn": "child-1",
                      "interaction_id": "child-1",
                      "model": "gemini-4-hydrogen",
                      "input_tokens": 100_000,
                      "cached_tokens": 50_000,
                      "output_tokens": 1_000,
                      "thought_tokens": 4_000,
                      "total_tokens": 105_000,
                      "duration_seconds": 115.0,
                  },
              ],
          },
          # Even if `child-1` were passed explicitly, `interaction_id` dedup prevents double-counting
          "child-1": {
              "session_id": "child-1",
              "command_type": "find --deep",
              "total_turns": 2,
              "tool_turns": 3,
              "model": "gemini-4-hydrogen",
              "duration_seconds": 120.4,
              "turns": [
                  {
                      "turn": "parent-1",
                      "interaction_id": "parent-1",
                      "model": "gemini-4-hydrogen",
                      "input_tokens": 200_000,
                      "cached_tokens": 100_000,
                      "output_tokens": 2_000,
                      "thought_tokens": 8_000,
                      "total_tokens": 210_000,
                  },
                  {
                      "turn": "child-1",
                      "interaction_id": "child-1",
                      "model": "gemini-4-hydrogen",
                      "input_tokens": 100_000,
                      "cached_tokens": 50_000,
                      "output_tokens": 1_000,
                      "thought_tokens": 4_000,
                      "total_tokens": 105_000,
                  },
              ],
          },
          "parent-2": {
              "session_id": "parent-2",
              "command_type": "find --deep",
              "total_turns": 1,
              "tool_turns": 1,
              "model": "gemini-4-argon",
              "duration_seconds": 65.0,
              "turns": [
                  {
                      "turn": "parent-2",
                      "interaction_id": "parent-2",
                      "model": "gemini-4-argon",
                      "input_tokens": 100_000,
                      "cached_tokens": 25_000,
                      "output_tokens": 1_000,
                      "thought_tokens": 4_000,
                      "total_tokens": 105_000,
                  },
              ],
          },
      }

      observed_cmds = []

      def fake_stats_run(cmd, **_kwargs):
        observed_cmds.append(cmd)
        sid = cmd[cmd.index("--session") + 1]
        return types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps(stats_payloads[sid]),
            stderr="",
        )

      with patch("codemender.run_command", side_effect=fake_stats_run):
        stats = cm.get_scan_stats(before_session_ids=before_sids)
        stats_with_dup = cm.get_scan_stats(session_ids=["parent-1", "child-1", "parent-2"])

      self.assertEqual(
          observed_cmds[:2],
          [
              ["cm", "stats", "--json", "--session", "parent-1"],
              ["cm", "stats", "--json", "--session", "parent-2"],
          ],
      )
      self.assertIsNotNone(stats)
      assert stats is not None
      assert stats_with_dup is not None
      self.assertEqual(stats.total_tokens, 420_000)
      self.assertEqual(stats_with_dup.total_tokens, 420_000)
      self.assertEqual(stats.input_tokens, 400_000)
      self.assertEqual(stats.cached_tokens, 175_000)
      self.assertEqual(stats.uncached_input_tokens, 225_000)
      self.assertEqual(stats.output_tokens, 4_000)
      self.assertEqual(stats.thought_tokens, 16_000)
      self.assertEqual(stats.llm_turns, 7)
      self.assertAlmostEqual(stats.duration_seconds, 185.4)
      self.assertEqual(stats.models, ["gemini-4-hydrogen", "gemini-4-argon"])
      # Hydrogen: 150k uncached * $1.50/1M ($0.225) + 150k cached * $0.075/1M ($0.01125) + 15k out/think * $7.50/1M ($0.1125) = $0.34875
      # Argon:    75k uncached * $4.00/1M ($0.30) + 25k cached * $0.20/1M ($0.005) + 5k out/think * $20.00/1M ($0.10) = $0.405
      # Total = $0.75375
      self.assertAlmostEqual(stats.estimated_cost_usd or 0.0, 0.75375, places=6)
      summary = stats.format_summary()
      self.assertIn("cm-ci: scan cost — ~$0.75", summary)
      self.assertIn("420.0k tokens", summary)
      self.assertIn("7 turn(s)", summary)
      self.assertIn("3m 05s", summary)
      self.assertIn("gemini-4-hydrogen, gemini-4-argon", summary)

      # Unknown custom model omits dollar estimate cleanly rather than guessing
      self.assertIsNone(
          codemender.estimate_token_cost_usd("custom-private-model", 10_000, 0, 500, 0)
      )


if __name__ == "__main__":
  unittest.main()
