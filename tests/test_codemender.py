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
    proc_report = types.SimpleNamespace(
        returncode=0,
        stdout=json.dumps([
            {
                "finding_id": "1",
                "status": "OPEN",
                "file_path": "a.py",
                "snippet": "x = 1",
                "title": "Should be omitted",
                "analysis": "Should be omitted",
            },
            {
                "finding_id": "2",
                "status": "DISMISSED",
                "file_path": "b.py",
                "snippet": "y = 2",
            },
            {
                "finding_id": "3",
                "status": "VERIFIED",
                "file_path": "c.py",
                "snippet": "z = 3",
            },
            {
                "finding_id": "4",
                "status": "REOPENED",
                "file_path": "d.py",
                "snippet": "w = 4",
            },
        ]),
    )
    proc_find = types.SimpleNamespace(returncode=0, stdout="Success")
    fake_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    fake_tmp_path = fake_tmp.name
    fake_tmp.close()
    written_report = []
    with patch("codemender.tempfile.NamedTemporaryFile") as mock_tmp, patch(
        "codemender.run_command", side_effect=[proc_report, proc_find]
    ) as mock_run:
      mock_tmp.return_value.__enter__.side_effect = [
          types.SimpleNamespace(name=fake_tmp_path, write=written_report.append),
      ]
      res = cm.find()
      self.assertEqual(mock_run.call_count, 2)
      self.assertEqual(
          mock_run.call_args_list[0].args[0],
          ["cm", "report", "--format", "json"],
      )
      self.assertEqual(
          json.loads(written_report[0]),
          [
              {"file_path": "a.py", "snippet": "x = 1"},
              {"file_path": "c.py", "snippet": "z = 3"},
              {"file_path": "d.py", "snippet": "w = 4"},
          ],
      )
      args, kwargs = mock_run.call_args_list[1]
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
              "--enable-bash",
              "--bypass-warning",
              "--deep-max-turns",
              "8",
              "--context",
              codemender._FIND_CONTEXT_FOR_LATER_PASSES.format(
                  report_file=fake_tmp_path,
                  discouraged_cwes=codemender._load_discouraged_cwes(),
              ),
          ],
      )
      self.assertEqual(kwargs.get("cwd"), "/tmp/test_repo")
      self.assertEqual(res, proc_find)
      self.assertFalse(os.path.exists(fake_tmp_path))

  def test_find_custom_target(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      cm.find(target_or_id="/tmp/other_target")
      args, _ = mock_run.call_args_list[1]
      cmd = args[0]
      self.assertEqual(cmd[2], "/tmp/other_target")

  def test_find_scan_modes(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    proc = types.SimpleNamespace(returncode=0, stdout="Success")
    with patch("codemender.run_command", return_value=proc) as mock_run:
      cm.find()
      cm.find(scan_mode=codemender.ScanMode.QUICK)
      cm.find(scan_mode=codemender.ScanMode.DEEP)
      cm.find(scan_mode=codemender.ScanMode.DIFF)

    expected_ctx = codemender._FIND_CONTEXT_FOR_FIRST_PASS.format(
        discouraged_cwes=codemender._load_discouraged_cwes(),
    )
    self.assertEqual(
        mock_run.call_args_list[1].args[0],
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
            expected_ctx,
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
            "--deep-max-turns",
            "8",
            "--context",
            expected_ctx,
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
            expected_ctx,
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[7].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--diff",
            "--model=gemini-4-argon",
            "--bypass-warning",
            "--deep-max-turns",
            "8",
            "--context",
            expected_ctx,
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
    proc_report = types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
    proc_reauth = types.SimpleNamespace(
        returncode=1,
        stdout="",
        stderr='Error: retrieving access token: oauth2: "invalid_grant" "reauth related error (invalid_rapt)"',
    )
    proc_gcloud = types.SimpleNamespace(returncode=0, stdout="Credentials saved", stderr="")
    proc_success = types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
    with patch(
        "codemender.run_command",
        side_effect=[proc_report, proc_reauth, proc_gcloud, proc_success],
    ) as mock_run:
      res = cm.find(scan_mode=codemender.ScanMode.QUICK)
    expected_ctx = codemender._FIND_CONTEXT_FOR_FIRST_PASS.format(
        discouraged_cwes=codemender._load_discouraged_cwes(),
    )
    self.assertEqual(res, proc_success)
    self.assertEqual(mock_run.call_count, 4)
    self.assertEqual(
        mock_run.call_args_list[0].args[0],
        ["cm", "report", "--format", "json"],
    )
    self.assertEqual(
        mock_run.call_args_list[1].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--quick",
            "--model=gemini-4-argon",
            "--bypass-warning",
            "--deep-max-turns",
            "8",
            "--context",
            expected_ctx,
        ],
    )
    self.assertEqual(
        mock_run.call_args_list[2].args[0],
        ["gcloud", "auth", "application-default", "login"],
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
            "--deep-max-turns",
            "8",
            "--context",
            expected_ctx,
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

  def test_preprocess_report_for_context_normalizes_repo_relative_paths(self):
    raw = json.dumps([
        {
            "finding_id": "1",
            "status": "OPEN",
            "file_path": "/home/runner/workspace/repo/routes/order.ts",
            "snippet": "sink1()",
        },
        {
            "finding_id": "2",
            "status": "OPEN",
            "file_path": "/home/runner/workspace/repo/routes/b2bOrder.ts",
            "snippet": "sink2()",
        },
        {
            "finding_id": "3",
            "status": "OPEN",
            "file_path": "./order.ts",
            "snippet": "sink3()",
        },
    ])
    out = json.loads(
        codemender.preprocess_report_for_context(
            raw, repo_dir="/home/runner/workspace/repo"
        )
    )
    self.assertEqual(
        out,
        [
            {"file_path": "routes/order.ts", "snippet": "sink1()"},
            {"file_path": "routes/b2bOrder.ts", "snippet": "sink2()"},
            {"file_path": "order.ts", "snippet": "sink3()"},
        ],
    )
    self.assertIn(
        'select(.file_path == "<file>")',
        codemender._FIND_CONTEXT_FOR_LATER_PASSES,
    )


if __name__ == "__main__":
  unittest.main()
