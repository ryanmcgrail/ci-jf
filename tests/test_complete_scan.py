"""Unit tests for complete_scan.py."""

import os
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

from codemender import CodeMender
from complete_scan import (
    get_latest_session_finding_counts,
    run_complete_scan,
)


class CompleteScanTests(unittest.TestCase):

  def test_run_complete_scan_tracks_clean_and_active_files_across_passes(self):
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

      cmignore_path = os.path.join(repo_dir, ".cmignore")
      with open(cmignore_path, "w", encoding="utf-8") as fh:
        fh.write("existing_ignore/\n")

      observed_cmignore_contents = []
      find_scan_num = 0

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          if os.path.exists(cmignore_path):
            with open(cmignore_path, "r", encoding="utf-8") as fh:
              observed_cmignore_contents.append(fh.read())
          else:
            observed_cmignore_contents.append(None)
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

      with patch("codemender.run_command", side_effect=fake_run_command) as mock_run:
        res = run_complete_scan(cm, extra_flags=["--deep-workers=16"])

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 5)
      self.assertEqual(
          observed_cmignore_contents,
          [
              "existing_ignore/\n",
              "existing_ignore/\nclean.py\n",
              "existing_ignore/\nclean.py\nvuln.py\n",
              "existing_ignore/\nclean.py\nvuln.py\n",
              "existing_ignore/\nclean.py\nvuln.py\n",
          ],
      )
      self.assertEqual(
          get_latest_session_finding_counts(cm),
          {"clean.py": 0, "vuln.py": 0, "multi.py": 1},
      )
      with open(cmignore_path, "r", encoding="utf-8") as fh:
        self.assertEqual(fh.read(), "existing_ignore/\n")
      self.assertEqual(mock_run.call_count, 10)
      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      self.assertEqual(len(find_cmds), 5)
      self.assertEqual(find_cmds[0][find_cmds[0].index("--deep-max-turns") + 1], "8")
      self.assertNotIn("--enable-bash", find_cmds[0])
      self.assertNotIn(
          "# Initial Pre-Audit Check",
          find_cmds[0][find_cmds[0].index("--context") + 1],
      )
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[0][find_cmds[0].index("--context") + 1],
      )
      self.assertEqual(find_cmds[1][find_cmds[1].index("--deep-max-turns") + 1], "12")
      self.assertIn("--enable-bash", find_cmds[1])
      self.assertIn(
          "# Initial Pre-Audit Check",
          find_cmds[1][find_cmds[1].index("--context") + 1],
      )
      self.assertTrue(
          find_cmds[1][find_cmds[1].index("--context") + 1].endswith(
              "Only audit these remaining files: `multi.py`, `vuln.py`."
          )
      )
      for cmd in find_cmds[2:]:
        self.assertEqual(cmd[cmd.index("--deep-max-turns") + 1], "12")
        self.assertTrue(
            cmd[cmd.index("--context") + 1].endswith(
                "Only audit these remaining files: `multi.py`."
            )
        )

  def test_run_complete_scan_early_stops_and_deduplicates_inter_pass_findings(self):
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
        res = run_complete_scan(cm, complete_runs=5)

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 2)
      remaining = cm.db.execute("SELECT finding_id FROM findings").fetchall()
      self.assertEqual(remaining, [("f0-1",)])

  def test_run_complete_scan_custom_runs(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      cm = CodeMender(cm_binary="cm", repo_dir=tmpdir)
      proc = types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
      with patch("codemender.run_command", return_value=proc) as mock_run:
        run_complete_scan(cm, complete_runs=2)
      self.assertEqual(mock_run.call_count, 4)

  def test_promoted_parent_sessions_with_findings_and_zero_findings_converge(self):
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
      observed_cmignore = []

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          cmignore_path = os.path.join(repo_dir, ".cmignore")
          if os.path.exists(cmignore_path):
            with open(cmignore_path, "r", encoding="utf-8") as fh:
              observed_cmignore.append(fh.read())
          else:
            observed_cmignore.append(None)

          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            # Pass 1: `promoted_vuln.py` is promoted to parent-0 (target overwritten to repo_dir)
            # and has 1 finding; `child_clean.py` is a child session with 0 findings.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, ?, ?, ?, ?)",
                [
                    ("parent-0", repo_dir, "t0", "t0", repo_dir, ""),
                    ("s0-clean", "child_clean.py", "t0", "t0", repo_dir, "parent-0"),
                ],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-1', 'parent-0', 'OPEN', ?, 'CWE-79', 5, 7, 'res.send(x)')",
                (os.path.join(repo_dir, "promoted_vuln.py"),),
            )
            stdout = (
                "[1/2 batches] 🚨 promoted_vuln.py (10.0s) | 5.0k tok - 1 vulnerabilities\n"
                "[2/2 batches] ✅ child_clean.py (8.0s) | 4.0k tok - 0 vulnerabilities\n"
            )
          elif find_scan_num == 1:
            # Pass 2: Only `promoted_vuln.py` is active, so its session is the sole session
            # and is promoted to `parent-1` (target overwritten to repo_dir) with 0 new findings.
            db_con.execute(
                "INSERT INTO sessions VALUES ('parent-1', 'FIND', 'COMPLETED', ?, 't1', 't1', ?, '')",
                (repo_dir, repo_dir),
            )
            stdout = (
                "[1/1 batches] ✅ promoted_vuln.py (9.0s) | 4.5k tok - 0 vulnerabilities\n"
            )
          else:
            raise AssertionError("Should have converged after Pass 2")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command) as mock_run:
        res = run_complete_scan(cm, complete_runs=5)

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 2)
      self.assertEqual(observed_cmignore, [None, "child_clean.py\n"])
      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      self.assertEqual(len(find_cmds), 2)
      self.assertTrue(
          find_cmds[1][find_cmds[1].index("--context") + 1].endswith(
              "Only audit these remaining files: `promoted_vuln.py`."
          )
      )

  def test_failed_or_incomplete_sessions_are_retried_until_completed(self):
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
      observed_cmignore = []

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          cmignore_path = os.path.join(repo_dir, ".cmignore")
          if os.path.exists(cmignore_path):
            with open(cmignore_path, "r", encoding="utf-8") as fh:
              observed_cmignore.append(fh.read())
          else:
            observed_cmignore.append(None)

          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            # Pass 1: `clean.py` completes with 0 findings, while `flaky.py` fails (0 findings).
            # Even though no findings were reported, `flaky.py` must be retried in Pass 2.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', ?, ?, 't0', 't0', ?, 'parent-0')",
                [
                    ("s0-clean", "COMPLETED", "clean.py", repo_dir),
                    ("s0-flaky", "FAILED", "flaky.py", repo_dir),
                ],
            )
          elif find_scan_num == 1:
            # Pass 2: `flaky.py` now completes cleanly with 0 findings.
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-flaky', 'FIND', 'COMPLETED', 'flaky.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
          else:
            raise AssertionError("Should have converged after Pass 2 once flaky.py completed")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command) as mock_run:
        res = run_complete_scan(cm, complete_runs=5)

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 2)
      self.assertEqual(observed_cmignore, [None, "clean.py\n"])
      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      self.assertEqual(len(find_cmds), 2)
      self.assertTrue(
          find_cmds[1][find_cmds[1].index("--context") + 1].endswith(
              "Only audit these remaining files: `flaky.py`."
          )
      )


if __name__ == "__main__":
  unittest.main()

