"""Unit tests for complete_scan.py."""

import os
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

from codemender import CodeMender
from complete_scan import (
    get_active_files,
    get_clean_files,
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

      observed_clean_contents = []
      observed_clean_paths = []
      find_scan_num = 0

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
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
        res = run_complete_scan(cm, extra_flags=["--deep-workers=16"])

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 5)
      self.assertEqual(len(observed_clean_paths), 5)
      self.assertEqual(len(set(observed_clean_paths)), 1)
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
      self.assertEqual(get_clean_files(cm), ["clean.py", "vuln.py"])
      self.assertEqual(get_active_files(cm), ["multi.py"])
      self.assertFalse(os.path.exists(observed_clean_paths[0]))
      self.assertEqual(mock_run.call_count, 10)
      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      self.assertEqual(len(find_cmds), 5)
      self.assertEqual(find_cmds[0][find_cmds[0].index("--deep-max-turns") + 1], "8")
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[0][find_cmds[0].index("--context") + 1],
      )
      self.assertEqual(find_cmds[1][find_cmds[1].index("--deep-max-turns") + 1], "12")
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


if __name__ == "__main__":
  unittest.main()

