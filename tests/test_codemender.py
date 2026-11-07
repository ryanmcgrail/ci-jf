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
from finding import Finding


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

  def test_write_import_payload(self):
    findings = [
        Finding.from_dict({
            "file_path": "src/main.py",
            "start_line": 10,
            "end_line": 12,
            "title": "Bug",
            "analysis": "Bad code",
            "severity": "HIGH",
            "vuln_type": "Injection",
            "snippet": "code()",
            "unexpected": "ignore",
        })
    ]
    with tempfile.TemporaryDirectory() as tmpdir:
      dest = os.path.join(tmpdir, "payload.json")
      written = codemender.write_import_payload(findings, dest)
      self.assertEqual(written, dest)
      with open(dest, "r", encoding="utf-8") as f:
        loaded = json.load(f)
      self.assertEqual(len(loaded), 1)
      self.assertEqual(loaded[0]["file_path"], "src/main.py")
      self.assertNotIn("unexpected", loaded[0])

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
    fake_cwe_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    fake_cwe_tmp_path = fake_cwe_tmp.name
    fake_cwe_tmp.close()
    fake_clean_tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    fake_clean_tmp_path = fake_clean_tmp.name
    fake_clean_tmp.close()
    written_report = []
    with patch("codemender.tempfile.NamedTemporaryFile") as mock_tmp, patch(
        "codemender.run_command", side_effect=[proc_report, proc_find]
    ) as mock_run:
      mock_tmp.return_value.__enter__.side_effect = [
          types.SimpleNamespace(name=fake_tmp_path, write=written_report.append),
          types.SimpleNamespace(name=fake_cwe_tmp_path, write=lambda _: None),
          types.SimpleNamespace(name=fake_clean_tmp_path, write=lambda _: None),
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
              "--enable-bash",
              "--deep-max-turns",
              "8",
              "--context",
              codemender._FIND_CONTEXT.format(
                  report_file=fake_tmp_path,
                  discouraged_cwes_file=fake_cwe_tmp_path,
                  clean_files_file=fake_clean_tmp_path,
              ),
          ],
      )
      self.assertEqual(kwargs.get("cwd"), "/tmp/test_repo")
      self.assertEqual(res, proc_find)
      self.assertFalse(os.path.exists(fake_tmp_path))
      self.assertFalse(os.path.exists(fake_cwe_tmp_path))
      self.assertFalse(os.path.exists(fake_clean_tmp_path))

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
    fake_tmp_path = "/tmp/fake_report.json"
    with patch("codemender.tempfile.NamedTemporaryFile") as mock_tmp, patch(
        "codemender.run_command", return_value=proc
    ) as mock_run:
      mock_tmp.return_value.__enter__.return_value.name = fake_tmp_path
      cm.find()
      cm.find(scan_mode=codemender.ScanMode.QUICK)
      cm.find(scan_mode=codemender.ScanMode.DEEP)
      cm.find(scan_mode=codemender.ScanMode.DIFF)

    expected_ctx = codemender._FIND_CONTEXT.format(
        report_file=fake_tmp_path,
        discouraged_cwes_file=fake_tmp_path,
        clean_files_file=fake_tmp_path,
    )
    self.assertEqual(
        mock_run.call_args_list[1].args[0],
        [
            "cm",
            "find",
            "/tmp/test_repo",
            "--deep",
            "--enable-bash",
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
            "--enable-bash",
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
            "--enable-bash",
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
            "--enable-bash",
            "--deep-max-turns",
            "8",
            "--context",
            expected_ctx,
        ],
    )

  def test_find_complete_runs_three_deep_scans_and_tracks_clean_files(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(repo_dir)
      os.makedirs(cm_home)
      db_path = os.path.join(cm_home, "state.db")
      con = sqlite3.connect(db_path)
      con.execute(
          "CREATE TABLE sessions ("
          "session_id TEXT PRIMARY KEY, "
          "session_type TEXT, "
          "status TEXT, "
          "target TEXT, "
          "created_at TEXT, "
          "updated_at TEXT, "
          "project_root TEXT, "
          "parent_session_id TEXT)"
      )
      con.execute(
          "CREATE TABLE findings ("
          "finding_id TEXT PRIMARY KEY, "
          "session_id TEXT, "
          "status TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(
          cm_binary="cm",
          repo_dir=repo_dir,
          env={"CM_HOME": cm_home},
      )

      observed_clean_contents = []
      observed_clean_paths = []
      find_scan_num = 0

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          # Record the current contents of the clean_files_file passed in --context.
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            # Scan 0: clean.py has 0 findings, vuln.py has 1 finding, multi.py has 1 finding
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, ?, ?, ?, 'parent-0')",
                [
                    ("s0-clean", "clean.py", "t0", "t0", repo_dir),
                    ("s0-vuln", "vuln.py", "t0", "t0", repo_dir),
                    ("s0-multi", "multi.py", "t0", "t0", repo_dir),
                ],
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, ?, 'OPEN')",
                [("f0-1", "s0-vuln"), ("f0-2", "s0-multi")],
            )
          elif find_scan_num == 1:
            # Scan 1: vuln.py now has 0 new findings (uncovered lines benign), multi.py has 1 more finding
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, ?, ?, ?, 'parent-1')",
                [
                    ("s1-clean", "clean.py", "t1", "t1", repo_dir),
                    ("s1-vuln", "vuln.py", "t1", "t1", repo_dir),
                    ("s1-multi", "multi.py", "t1", "t1", repo_dir),
                ],
            )
            db_con.execute("INSERT INTO findings VALUES ('f1-1', 's1-multi', 'OPEN')")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      orig_find = cm.find

      def spy_find(*args, **kwargs):
        clean_path = kwargs.get("clean_files_file")
        if clean_path is not None:
          observed_clean_paths.append(clean_path)
          with open(clean_path, "r", encoding="utf-8") as fh:
            observed_clean_contents.append(fh.read())
        return orig_find(*args, **kwargs)

      with patch("codemender.run_command", side_effect=fake_run_command) as mock_run, patch.object(
          cm, "find", side_effect=spy_find
      ):
        res = cm.find(scan_mode=codemender.ScanMode.COMPLETE, extra_flags=["--deep-workers=16"])

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 5)
      self.assertEqual(len(observed_clean_paths), 5)
      # All 5 deep scans share the exact same temporary file tied to find_complete's lifecycle.
      self.assertEqual(len(set(observed_clean_paths)), 1)
      # Scan 0 starts empty; Scan 1 has clean.py; Scans 2-4 have both clean.py and vuln.py.
      self.assertEqual(
          observed_clean_contents,
          [
              "",
              "clean.py\n",
              "clean.py\nvuln.py\n",
              "clean.py\nvuln.py\n",
              "clean.py\nvuln.py\n",
          ],
      )
      # Temporary file is cleaned up after find_complete exits.
      self.assertFalse(os.path.exists(observed_clean_paths[0]))
      self.assertEqual(mock_run.call_count, 10)
      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      self.assertEqual(len(find_cmds), 5)
      # Pass 0 uses 8 turns and full-repo context.
      self.assertEqual(find_cmds[0][find_cmds[0].index("--deep-max-turns") + 1], "8")
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[0][find_cmds[0].index("--context") + 1],
      )
      # Pass 1 uses 12 turns and scopes to multi.py and vuln.py.
      self.assertEqual(find_cmds[1][find_cmds[1].index("--deep-max-turns") + 1], "12")
      self.assertTrue(
          find_cmds[1][find_cmds[1].index("--context") + 1].endswith(
              "Only audit these remaining files: `multi.py`, `vuln.py`."
          )
      )
      # Passes 2-4 use 12 turns and scope only to multi.py.
      for cmd in find_cmds[2:]:
        self.assertEqual(cmd[cmd.index("--deep-max-turns") + 1], "12")
        self.assertTrue(
            cmd[cmd.index("--context") + 1].endswith(
                "Only audit these remaining files: `multi.py`."
            )
        )

  def test_find_complete_early_stops_and_deduplicates_inter_pass_findings(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(repo_dir)
      os.makedirs(cm_home)
      db_path = os.path.join(cm_home, "state.db")
      con = sqlite3.connect(db_path)
      con.execute(
          "CREATE TABLE sessions ("
          "session_id TEXT PRIMARY KEY, "
          "session_type TEXT, "
          "status TEXT, "
          "target TEXT, "
          "created_at TEXT, "
          "updated_at TEXT, "
          "project_root TEXT, "
          "parent_session_id TEXT)"
      )
      con.execute(
          "CREATE TABLE findings ("
          "finding_id TEXT PRIMARY KEY, "
          "session_id TEXT, "
          "status TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(
          cm_binary="cm",
          repo_dir=repo_dir,
          env={"CM_HOME": cm_home},
      )

      find_scan_num = 0

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            # Pass 0: clean.py has 0 findings; vuln.py has 1 SQLi finding on lines 10-12.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, ?, ?, ?, 'parent-0')",
                [
                    ("s0-clean", "clean.py", "t0", "t0", repo_dir),
                    ("s0-vuln", "vuln.py", "t0", "t0", repo_dir),
                ],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-1', 's0-vuln', 'OPEN', 'vuln.py', 'CWE-89', 10, 12, 'db.query(user_input)')"
            )
          elif find_scan_num == 1:
            # Pass 1: vuln.py worker re-reports a duplicate of f0-1 on overlapping lines 10-12.
            # Inter-pass deduplication removes f1-dup right after Pass 1, leaving s1-vuln with 0 active findings,
            # which triggers early stopping before Pass 2!
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-vuln', 'FIND', 'COMPLETED', 'vuln.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f1-dup', 's1-vuln', 'OPEN', 'vuln.py', 'CWE-89', 10, 12, 'db.query(user_input)')"
            )
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        res = cm.find(scan_mode=codemender.ScanMode.COMPLETE, complete_runs=5)

      self.assertEqual(res.returncode, 0)
      # Stopped early after 2 passes instead of running all 5 passes!
      self.assertEqual(find_scan_num, 2)
      # Only the original finding f0-1 remains in state.db; f1-dup was removed.
      remaining = cm.db.execute("SELECT finding_id FROM findings").fetchall()
      self.assertEqual(remaining, [("f0-1",)])

  def test_find_complete_custom_runs(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      cm = CodeMender(cm_binary="cm", repo_dir=tmpdir)
      proc = types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
      with patch("codemender.run_command", return_value=proc) as mock_run:
        cm.find(scan_mode=codemender.ScanMode.COMPLETE, complete_runs=2)
      # 2 runs * (1 cm report + 1 cm find) = 4 calls
      self.assertEqual(mock_run.call_count, 4)

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
    fake_tmp_path = "/tmp/fake_report.json"
    with patch("codemender.tempfile.NamedTemporaryFile") as mock_tmp, patch(
        "codemender.run_command",
        side_effect=[proc_report, proc_reauth, proc_gcloud, proc_success],
    ) as mock_run:
      mock_tmp.return_value.__enter__.return_value.name = fake_tmp_path
      res = cm.find(scan_mode=codemender.ScanMode.QUICK)
    expected_ctx = codemender._FIND_CONTEXT.format(
        report_file=fake_tmp_path,
        discouraged_cwes_file=fake_tmp_path,
        clean_files_file=fake_tmp_path,
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
            "--enable-bash",
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
            "--enable-bash",
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

  def test_import_findings(self):
    cm = CodeMender(cm_binary="cm", repo_dir="/tmp/test_repo")
    before_raw = json.dumps([{"finding_id": "cm-1", "fingerprint": "fp-1"}])
    proc_before = types.SimpleNamespace(returncode=0, stdout=before_raw)
    proc_import = types.SimpleNamespace(returncode=0, stdout="Imported")
    to_import = [Finding(finding_id="f-2", fingerprint="fp-2", file_path="src/main.py", title="Bug")]

    with patch("codemender.run_command", side_effect=[proc_before, proc_import]) as mock_run:
      imported = cm.import_findings(to_import)
    self.assertEqual(imported, to_import)
    import_cmd = mock_run.call_args_list[1].args[0]
    temp_file_path = import_cmd[import_cmd.index("-f") + 1]
    self.assertFalse(os.path.exists(temp_file_path))

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


if __name__ == "__main__":
  unittest.main()
