"""Unit tests for complete_scan.py."""

import json
import os
import signal
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch

import complete_scan
from codemender import CodeMender
from complete_scan import (
    get_latest_session_finding_counts,
    run_complete_scan,
)
from pass_report import build_covered_lines_report


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
      self.assertEqual(mock_run.call_count, 9)
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
      self.assertEqual(find_cmds[1][find_cmds[1].index("--deep-max-turns") + 1], "8")
      self.assertNotIn("--enable-bash", find_cmds[1])
      self.assertIn(
          "# Initial Pre-Audit Check",
          find_cmds[1][find_cmds[1].index("--context") + 1],
      )
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[1][find_cmds[1].index("--context") + 1],
      )
      for cmd in find_cmds[2:]:
        self.assertEqual(cmd[cmd.index("--deep-max-turns") + 1], "8")
        self.assertNotIn("--enable-bash", cmd)
        self.assertNotIn(
            "Only audit these remaining files:",
            cmd[cmd.index("--context") + 1],
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
      self.assertEqual(mock_run.call_count, 3)

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
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[1][find_cmds[1].index("--context") + 1],
      )

  def test_promoted_parent_sessions_across_three_or_more_passes_do_not_resurrect(self):
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
            # Pass 1: `clean.py` is promoted to parent-0 (0 findings);
            # `a.py` and `b.py` are child sessions with 1 finding each.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't0', 't0', ?, ?)",
                [
                    ("parent-0", repo_dir, repo_dir, ""),
                    ("s0-a", "a.py", repo_dir, "parent-0"),
                    ("s0-b", "b.py", repo_dir, "parent-0"),
                ],
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, ?, 'OPEN', ?, 'CWE-89', ?, ?, ?)",
                [
                    ("f0-a", "s0-a", "a.py", 10, 12, "sink_a()"),
                    ("f0-b", "s0-b", "b.py", 20, 22, "sink_b1()"),
                ],
            )
            stdout = (
                "[1/3 batches] ✅ clean.py (5.0s) | 3.0k tok - 0 vulnerabilities\n"
                "[2/3 batches] 🚨 a.py (6.0s) | 4.0k tok - 1 vulnerabilities\n"
                "[3/3 batches] 🚨 b.py (7.0s) | 4.0k tok - 1 vulnerabilities\n"
            )
          elif find_scan_num == 1:
            # Pass 2: `a.py` is promoted to parent-1 (0 findings);
            # `b.py` is a child session with 1 new finding.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't1', 't1', ?, ?)",
                [
                    ("parent-1", repo_dir, repo_dir, ""),
                    ("s1-b", "b.py", repo_dir, "parent-1"),
                ],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f1-b', 's1-b', 'OPEN', 'b.py', 'CWE-79', 40, 42, 'sink_b2()')"
            )
            stdout = (
                "[1/2 batches] ✅ a.py (5.0s) | 3.5k tok - 0 vulnerabilities\n"
                "[2/2 batches] 🚨 b.py (6.0s) | 4.0k tok - 1 vulnerabilities\n"
            )
          elif find_scan_num == 2:
            # Pass 3: `b.py` is promoted to parent-2 (0 findings).
            db_con.execute(
                "INSERT INTO sessions VALUES ('parent-2', 'FIND', 'COMPLETED', ?, 't2', 't2', ?, '')",
                (repo_dir, repo_dir),
            )
            stdout = (
                "[1/1 batches] ✅ b.py (5.0s) | 3.5k tok - 0 vulnerabilities\n"
            )
          else:
            raise AssertionError("Should have converged after Pass 3 without resurrecting a.py or b.py")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        res = run_complete_scan(cm, complete_runs=5)

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 3)
      self.assertEqual(
          observed_cmignore,
          [None, "clean.py\n", "a.py\nclean.py\n"],
      )
      self.assertEqual(
          get_latest_session_finding_counts(cm),
          {"clean.py": 0, "a.py": 0, "b.py": 0},
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
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[1][find_cmds[1].index("--context") + 1],
      )

  def test_overwritten_findings_reconcile_same_sink_and_disjoint_sink_collisions(self):
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
            # Pass 1:
            # - `same_sink.py` has finding `fid-same` at line 10.
            # - `hashing.java` has finding `fid-prng` at line 53 (getMd5).
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't0', 't0', ?, 'parent-0')",
                [
                    ("s0-same", "same_sink.py", repo_dir),
                    ("s0-hash", "hashing.java", repo_dir),
                ],
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, ?, 'OPEN', ?, 'CWE-338', ?, ?, ?)",
                [
                    ("fid-same", "s0-same", "same_sink.py", 10, 12, "String x = new Random().nextInt();"),
                    ("fid-prng", "s0-hash", "hashing.java", 53, 53, "String secret = SECRETS[new Random().nextInt(SECRETS.length)];"),
                ],
            )
          elif find_scan_num == 1:
            # Pass 2:
            # - `same_sink.py` re-reports `fid-same` at the same line 10..12,
            #   and cm overwrites `session_id` to `s1-same` in-place.
            # - `hashing.java` reports `getSha256` at line 71..71 with the identical snippet,
            #   and cm overwrites `fid-prng` in-place (`start_line=71, session_id=s1-hash`).
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't1', 't1', ?, 'parent-1')",
                [
                    ("s1-same", "same_sink.py", repo_dir),
                    ("s1-hash", "hashing.java", repo_dir),
                ],
            )
            db_con.execute(
                "UPDATE findings SET session_id = 's1-same' WHERE finding_id = 'fid-same'"
            )
            db_con.execute(
                "UPDATE findings SET session_id = 's1-hash', start_line = 71, end_line = 71 WHERE finding_id = 'fid-prng'"
            )
          elif find_scan_num == 2:
            # Pass 3: `same_sink.py` must ALREADY be cleared (0 new findings in Pass 2),
            # while `hashing.java` runs once more and reports 0 new findings.
            db_con.execute(
                "INSERT INTO sessions VALUES ('s2-hash', 'FIND', 'COMPLETED', 'hashing.java', 't2', 't2', ?, 'parent-2')",
                (repo_dir,),
            )
          else:
            raise AssertionError("Should have converged after Pass 3")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        run_complete_scan(cm, complete_runs=5)

      self.assertEqual(find_scan_num, 3)
      rows = cm.db.execute(
          "SELECT finding_id, session_id, file_path, start_line, end_line FROM findings ORDER BY file_path, start_line"
      ).fetchall()
      self.assertEqual(len(rows), 3)
      self.assertEqual(rows[0][2:], ("hashing.java", 53, 53))
      self.assertEqual(rows[0][1], "s0-hash")
      self.assertEqual(rows[1], ("fid-prng", "s1-hash", "hashing.java", 71, 71))
      self.assertEqual(rows[2], ("fid-same", "s0-same", "same_sink.py", 10, 12))

  def test_critical_high_only_skips_files_with_only_medium_or_low_findings(self):
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
          "severity TEXT, "
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
            # Pass 1:
            # - `med_only.py` (promoted parent) has 1 MEDIUM finding -> should get count 0 under critical_high_only=True.
            # - `low_only.py` has 1 LOW finding -> should get count 0 under critical_high_only=True.
            # - `high_vuln.py` has 1 HIGH finding -> should get count 1 and run in Pass 2.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't0', 't0', ?, ?)",
                [
                    ("parent-0", repo_dir, repo_dir, ""),
                    ("s0-low", "low_only.py", repo_dir, "parent-0"),
                    ("s0-high", "high_vuln.py", repo_dir, "parent-0"),
                ],
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, ?, 'OPEN', ?, ?, 'CWE-79', ?, ?, ?)",
                [
                    ("f0-med", "parent-0", "MEDIUM", "med_only.py", 10, 12, "med_sink()"),
                    ("f0-low", "s0-low", "LOW", "low_only.py", 20, 22, "low_sink()"),
                    ("f0-high", "s0-high", "HIGH", "high_vuln.py", 30, 32, "high_sink()"),
                ],
            )
          elif find_scan_num == 1:
            # Pass 2: `high_vuln.py` runs and only finds 1 MEDIUM issue -> should now get count 0 and stop.
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-high', 'FIND', 'COMPLETED', 'high_vuln.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f1-med', 's1-high', 'OPEN', 'MEDIUM', 'high_vuln.py', 'CWE-209', 45, 47, 'err_sink()')"
            )
          else:
            raise AssertionError("Should have converged after Pass 2 when no CRITICAL/HIGH findings were found")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command) as mock_run:
        run_complete_scan(cm, complete_runs=5, critical_high_only=True)

      self.assertEqual(find_scan_num, 2)
      self.assertEqual(
          observed_cmignore,
          [None, "low_only.py\nmed_only.py\n"],
      )
      self.assertEqual(
          get_latest_session_finding_counts(cm, critical_high_only=True),
          {"med_only.py": 0, "low_only.py": 0, "high_vuln.py": 0},
      )
      self.assertEqual(
          get_latest_session_finding_counts(cm, critical_high_only=False),
          {"med_only.py": 1, "low_only.py": 1, "high_vuln.py": 1},
      )
      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      for cmd in find_cmds:
        self.assertNotIn(
            "focusing on the most critical security issues",
            cmd[cmd.index("--context") + 1],
        )

  def test_inter_pass_duplicates_upgrade_severity_without_downgrading_or_keeping_file_active(self):
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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT, "
          "finding_json TEXT)"
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
            # Pass 1: `sqli.java` has:
            # - `f0-crit` (CRITICAL, line 10..12) so the file stays active for Pass 2
            # - `f0-wobble` (MEDIUM, line 50..55)
            db_con.execute(
                "INSERT INTO sessions VALUES ('s0-sqli', 'FIND', 'COMPLETED', 'sqli.java', 't0', 't0', ?, 'parent-0')",
                (repo_dir,),
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, 's0-sqli', 'OPEN', ?, 'sqli.java', 'CWE-89', ?, ?, ?, ?)",
                [
                    ("f0-crit", "CRITICAL", 10, 12, "stmt.execute(q1)", '{"finding_id":"f0-crit","severity":"CRITICAL"}'),
                    ("f0-wobble", "MEDIUM", 50, 55, "stmt.execute(q2)", '{"finding_id":"f0-wobble","severity":"MEDIUM"}'),
                ],
            )
          elif find_scan_num == 1:
            # Pass 2: `sqli.java` re-reports `f0-wobble` as a new row `f1-wobble-dup` with HIGH severity,
            # and overwrites `f0-crit` in-place with HIGH severity (attempting a downgrade from CRITICAL).
            # Neither should count as a new finding in Pass 2, and severities should end up CRITICAL and HIGH.
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-sqli', 'FIND', 'COMPLETED', 'sqli.java', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f1-wobble-dup', 's1-sqli', 'OPEN', 'HIGH', 'sqli.java', 'CWE-89', 51, 54, 'stmt.execute(q2)', '{\"finding_id\":\"f1-wobble-dup\",\"severity\":\"HIGH\"}')"
            )
            db_con.execute(
                "UPDATE findings SET session_id = 's1-sqli', severity = 'HIGH', finding_json = '{\"finding_id\":\"f0-crit\",\"severity\":\"HIGH\"}' WHERE finding_id = 'f0-crit'"
            )
          else:
            raise AssertionError("Should have converged after Pass 2 because Pass 2 only had duplicates")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        run_complete_scan(cm, complete_runs=5, critical_high_only=True)

      self.assertEqual(find_scan_num, 2)
      rows = cm.db.execute(
          "SELECT finding_id, session_id, severity, finding_json FROM findings ORDER BY finding_id"
      ).fetchall()
      self.assertEqual(
          rows,
          [
              ("f0-crit", "s0-sqli", "CRITICAL", '{"finding_id": "f0-crit", "severity": "CRITICAL"}'),
              ("f0-wobble", "s0-sqli", "HIGH", '{"finding_id": "f0-wobble", "severity": "HIGH"}'),
          ],
      )

  def test_internal_cm_retry_promoted_to_parent_clears_failed_first_attempt(self):
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
          "severity TEXT, "
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
            # Pass 1: `users.controller.ts` has 1 HIGH finding.
            db_con.execute(
                "INSERT INTO sessions VALUES ('parent-0', 'FIND', 'COMPLETED', ?, 't0', 't0', ?, '')",
                (repo_dir, repo_dir),
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-1', 'parent-0', 'OPEN', 'HIGH', 'users.controller.ts', 'CWE-306', 10, 20, 'sink()')"
            )
            stdout = "[1/1 batches] 🚨 users.controller.ts (10.0s) | 5.0k tok - 1 vulnerabilities\n"
          elif find_scan_num == 1:
            # Pass 2: `users.controller.ts` fails on attempt 1 (`s1-failed`, attached as child of `parent-1`),
            # and cm's internal retry (`parent-1`) succeeds with 0 new findings and is promoted to parent.
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', ?, ?, 't1', 't1', ?, ?)",
                [
                    ("s1-failed", "FAILED", "users.controller.ts", repo_dir, "parent-1"),
                    ("parent-1", "COMPLETED", repo_dir, repo_dir, ""),
                ],
            )
            stdout = "[1/1 batches] ✅ users.controller.ts (12.0s) | 6.0k tok - 0 vulnerabilities\n"
          else:
            raise AssertionError("Should have converged after Pass 2 once internal retry completed with 0 findings")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        run_complete_scan(cm, complete_runs=5, critical_high_only=True)

      self.assertEqual(find_scan_num, 2)
      self.assertEqual(
          get_latest_session_finding_counts(cm, critical_high_only=True),
          {"users.controller.ts": 0},
      )

  def test_preexisting_sessions_and_findings_are_excluded_from_current_complete_scan(self):
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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      # Preexisting session and finding from a previous scan
      con.execute(
          "INSERT INTO sessions VALUES ('s-old', 'FIND', 'COMPLETED', 'legacy.py', 't-old', 't-old', ?, 'parent-old')",
          (repo_dir,),
      )
      con.execute(
          "INSERT INTO findings VALUES ('f-old', 's-old', 'OPEN', 'HIGH', 'legacy.py', 'CWE-89', 5, 8, 'old_sink()')"
      )
      con.commit()
      con.close()

      cm = CodeMender(
          cm_binary="cm",
          repo_dir=repo_dir,
          env={"CM_HOME": cm_home},
      )

      find_scan_num = 0
      pass2_report_payloads = []

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          db_con = sqlite3.connect(db_path)
          cur = db_con.execute(
              "SELECT finding_id, session_id, status, severity, file_path, vuln_type, start_line, end_line, snippet FROM findings"
          )
          cols = [d[0] for d in cur.description]
          items = [dict(zip(cols, r)) for r in cur.fetchall()]
          db_con.close()
          import json as _json
          return types.SimpleNamespace(returncode=0, stdout=_json.dumps(items), stderr="")
        if cmd[:2] == ["cm", "find"]:
          ctx_arg = cmd[cmd.index("--context") + 1]
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            # Pass 1 must NOT use later-pass context even though f-old is in state.db
            self.assertNotIn("--enable-bash", cmd)
            self.assertNotIn("# Initial Pre-Audit Check", ctx_arg)
            db_con.execute(
                "INSERT INTO sessions VALUES ('s0-cur', 'FIND', 'COMPLETED', 'app.py', 't0', 't0', ?, 'parent-0')",
                (repo_dir,),
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-cur', 's0-cur', 'OPEN', 'HIGH', 'app.py', 'CWE-79', 10, 12, 'cur_sink()')"
            )
          elif find_scan_num == 1:
            self.assertNotIn("--enable-bash", cmd)
            self.assertIn("# Initial Pre-Audit Check", ctx_arg)
            report_path = os.path.join(
                repo_dir, *complete_scan._PASS_REPORT_REL_PATH.split("/")
            )
            if os.path.exists(report_path):
              with open(report_path, "r", encoding="utf-8") as fh:
                pass2_report_payloads.append(fh.read())
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-cur', 'FIND', 'COMPLETED', 'app.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
          else:
            raise AssertionError("Should have converged after Pass 2")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        run_complete_scan(cm, complete_runs=5, critical_high_only=True)

      self.assertEqual(find_scan_num, 2)
      self.assertEqual(
          pass2_report_payloads,
          ["app.py | covered: L10-12"],
      )

  def test_preexisting_findings_can_only_increase_severity_never_decrease(self):
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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.execute(
          "INSERT INTO sessions VALUES ('s-prior', 'FIND', 'COMPLETED', 'auth.py', 't-prior', 't-prior', ?, 'parent-prior')",
          (repo_dir,),
      )
      con.executemany(
          "INSERT INTO findings VALUES (?, 's-prior', 'OPEN', ?, 'auth.py', ?, ?, ?, ?)",
          [
              ("f-prior-high", "HIGH", "CWE-89", 10, 15, "sql_sink()"),
              ("f-prior-med", "MEDIUM", "CWE-78", 30, 35, "cmd_sink()"),
              ("f-prior-crit", "CRITICAL", "CWE-94", 50, 55, "eval_sink()"),
          ],
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
            db_con.execute(
                "INSERT INTO sessions VALUES ('s0-auth', 'FIND', 'COMPLETED', 'auth.py', 't0', 't0', ?, 'parent-0')",
                (repo_dir,),
            )
            # 1) Overwrite `f-prior-high` in-place on Pass 1 with MEDIUM -> must stay HIGH
            db_con.execute(
                "UPDATE findings SET session_id = 's0-auth', severity = 'MEDIUM' WHERE finding_id = 'f-prior-high'"
            )
            # 2) Overwrite `f-prior-med` in-place on Pass 1 with HIGH -> must upgrade to HIGH
            db_con.execute(
                "UPDATE findings SET session_id = 's0-auth', severity = 'HIGH' WHERE finding_id = 'f-prior-med'"
            )
            # 3) New finding_id duplicating `f-prior-crit` (CRITICAL) rated LOW -> must upgrade to CRITICAL
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-new-dup', 's0-auth', 'OPEN', 'LOW', 'auth.py', 'CWE-94', 51, 54, 'eval_sink()')"
            )
          elif find_scan_num == 1:
            # Pass 2 finds 0 new vulnerabilities (attempts another downgrade on f-prior-med to LOW)
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-auth', 'FIND', 'COMPLETED', 'auth.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
            db_con.execute(
                "UPDATE findings SET session_id = 's1-auth', severity = 'LOW' WHERE finding_id = 'f-prior-med'"
            )
          else:
            raise AssertionError("Should have converged after Pass 2")
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        run_complete_scan(cm, complete_runs=5, critical_high_only=True)

      self.assertEqual(find_scan_num, 2)
      sevs = dict(
          cm.db.execute("SELECT finding_id, severity FROM findings").fetchall()
      )
      self.assertEqual(sevs["f-prior-high"], "HIGH")
      self.assertEqual(sevs["f-prior-med"], "HIGH")
      self.assertEqual(sevs["f-prior-crit"], "CRITICAL")
      self.assertEqual(sevs["f0-new-dup"], "CRITICAL")

  def test_build_covered_lines_report_filters_statuses_and_normalizes_paths(self):
    raw = json.dumps([
        {
            "finding_id": "1",
            "status": "OPEN",
            "file_path": "/home/runner/workspace/repo/routes/order.ts",
            "start_line": 12,
            "end_line": 14,
            "snippet": "sink1()",
        },
        {
            "finding_id": "2",
            "status": "DISMISSED",
            "file_path": "/home/runner/workspace/repo/routes/b2bOrder.ts",
            "start_line": 20,
            "end_line": 22,
            "snippet": "dismissed_sink()",
        },
        {
            "finding_id": "3",
            "status": "VERIFIED",
            "file_path": "/home/runner/workspace/repo/routes/b2bOrder.ts",
            "start_line": 30,
            "end_line": 30,
            "snippet": "sink2()",
        },
        {
            "finding_id": "4",
            "status": "REOPENED",
            "file_path": "./order.ts",
            "snippet": "sink3()",
        },
    ])
    manifest = build_covered_lines_report(raw, repo_dir="/home/runner/workspace/repo")
    self.assertEqual(
        manifest.splitlines(),
        [
            "order.ts | snippet: sink3()",
            "routes/b2bOrder.ts | covered: L30",
            "routes/order.ts | covered: L12-14",
        ],
    )
    self.assertIn(
        'run `grep_search` on "{report_file}"',
        complete_scan._FIND_CONTEXT_FOR_LATER_PASSES,
    )
    self.assertNotIn(
        "`{report_file}`",
        complete_scan._FIND_CONTEXT_FOR_LATER_PASSES,
    )
    self.assertNotIn(
        "covered_lines.py",
        complete_scan._FIND_CONTEXT_FOR_LATER_PASSES,
    )

  def test_batch_line_regexes_support_file_paths_with_spaces_and_parentheses(self):
    stdout = (
        "[1/4 batches] ✅ src/my folder/clean file.py (5.0s) | 3.0k tok - 0 vulnerabilities\n"
        "[2/4 batches] 🚨 app/(admin)/user settings.tsx (8.2s) - 2 vulnerabilities\n"
        "[3/4 batches] ❌ src/my folder/flaky handler.js — session failed\n"
        "[4/4 batches] ❌ routes/slow route.ts (10.5s): context deadline exceeded\n"
    )
    self.assertEqual(
        complete_scan._extract_batch_files_from_stdout(stdout),
        ["src/my folder/clean file.py", "app/(admin)/user settings.tsx"],
    )
    self.assertEqual(
        complete_scan._extract_failed_batch_files_from_stdout(stdout),
        {"src/my folder/flaky handler.js", "routes/slow route.ts"},
    )

  def test_complete_scan_critical_high_only_keeps_pass_context_unbiased(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      cm = CodeMender(cm_binary="cm", repo_dir=tmpdir)
      proc = types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
      with patch("codemender.run_command", return_value=proc) as mock_run:
        run_complete_scan(cm, complete_runs=1, critical_high_only=True)
        run_complete_scan(cm, complete_runs=1, critical_high_only=False)

    ch_cmd = mock_run.call_args_list[0].args[0]
    ch_ctx = ch_cmd[ch_cmd.index("--context") + 1]
    all_cmd = mock_run.call_args_list[1].args[0]
    all_ctx = all_cmd[all_cmd.index("--context") + 1]
    self.assertEqual(ch_ctx, all_ctx)
    self.assertNotIn("focusing on the most critical security issues", ch_ctx)

  def test_complete_scan_context_uses_concise_principle_based_invariants(self):
    self.assertIn("# Audit Strategy", complete_scan._FIND_CONTEXT_FOR_FIRST_PASS)
    self.assertIn("# CWE Requirements", complete_scan._FIND_CONTEXT_FOR_FIRST_PASS)
    self.assertNotIn(
        "# Vulnerabilities to Report", complete_scan._FIND_CONTEXT_FOR_FIRST_PASS
    )
    self.assertIn(
        "most specific root-cause CWE",
        complete_scan._FIND_CONTEXT_FOR_FIRST_PASS,
    )
    self.assertIn(
        "never on pure pass-through wrappers/callers or sinkless intra-file helpers",
        complete_scan._FIND_CONTEXT_FOR_FIRST_PASS,
    )
    self.assertIn(
        "minimal contiguous sink lines",
        complete_scan._FIND_CONTEXT_FOR_FIRST_PASS,
    )
    self.assertIn(
        "never blanket-skip internal services, workers, or serverless handlers",
        complete_scan._FIND_CONTEXT_FOR_FIRST_PASS,
    )
    self.assertIn(
        "as `HIGH` or `CRITICAL` when reachable without prior privileged access",
        complete_scan._FIND_CONTEXT_FOR_FIRST_PASS,
    )
    self.assertIn(
        "third-party/vendored code, stop immediately and report 0",
        complete_scan._FIND_CONTEXT_FOR_FIRST_PASS,
    )
    self.assertNotIn("dead/undeployed handlers", complete_scan._FIND_CONTEXT_FOR_FIRST_PASS)
    self.assertNotIn("wallet addresses", complete_scan._FIND_CONTEXT_FOR_FIRST_PASS)
    self.assertIn(
        "intra-file helper/validator/sanitizer whose caller/sink in this file is already covered",
        complete_scan._FIND_CONTEXT_FOR_LATER_PASSES,
    )

  def test_run_complete_scan_appends_user_context_directly_after_pass_prompts(self):
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
          "severity TEXT, "
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
      observed_report_files = []

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(
              returncode=0,
              stdout=json.dumps([{
                  "finding_id": "f0-1",
                  "status": "OPEN",
                  "file_path": os.path.join(repo_dir, "vuln.py"),
                  "snippet": "sink()",
              }]),
              stderr="",
          )
        if cmd[:2] == ["cm", "find"]:
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            db_con.execute(
                "INSERT INTO sessions VALUES ('s0-vuln', 'FIND', 'COMPLETED', 'vuln.py', 't0', 't0', ?, 'parent-0')",
                (repo_dir,),
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-1', 's0-vuln', 'OPEN', 'HIGH', 'vuln.py', 'CWE-89', 10, 12, 'sink()')"
            )
          elif find_scan_num == 1:
            # Verify preprocessed report is stored at the deterministic scratch path (not tmpXXXXXX in repo root)
            ctx_val = cmd[cmd.index("--context") + 1]
            expected_path = os.path.join(
                repo_dir, *complete_scan._PASS_REPORT_REL_PATH.split("/")
            )
            if os.path.exists(expected_path) and complete_scan._PASS_REPORT_REL_PATH in ctx_val:
              observed_report_files.append(expected_path)
            self.assertEqual(
                [n for n in os.listdir(repo_dir) if n.startswith("tmp")],
                [],
            )
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-vuln', 'FIND', 'COMPLETED', 'vuln.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command) as mock_run:
        run_complete_scan(
            cm,
            extra_flags=["--context", "Custom user guidance"],
            complete_runs=2,
            critical_high_only=False,
        )

      find_cmds = [
          call.args[0]
          for call in mock_run.call_args_list
          if call.args[0][:2] == ["cm", "find"]
      ]
      self.assertEqual(len(find_cmds), 2)
      cwes = complete_scan._load_discouraged_cwes()

      expected_pass1 = (
          complete_scan._FIND_CONTEXT_FOR_FIRST_PASS.format(discouraged_cwes=cwes)
          + "\n\n# Additional Context\nCustom user guidance"
      )
      self.assertEqual(find_cmds[0].count("--context"), 1)
      self.assertEqual(
          find_cmds[0][find_cmds[0].index("--context") + 1],
          expected_pass1,
      )

      self.assertEqual(len(observed_report_files), 1)
      report_ref = complete_scan._PASS_REPORT_REL_PATH
      self.assertFalse(os.path.exists(observed_report_files[0]))
      self.assertEqual(os.listdir(repo_dir), [])
      expected_pass2 = (
          complete_scan._FIND_CONTEXT_FOR_LATER_PASSES.format(
              report_file=report_ref,
              discouraged_cwes=cwes,
          )
          + "\n\n# Additional Context\nCustom user guidance"
      )
      self.assertEqual(find_cmds[1].count("--context"), 1)
      self.assertEqual(
          find_cmds[1][find_cmds[1].index("--context") + 1],
          expected_pass2,
      )

      direct_proc = types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
      with patch("codemender.run_command", return_value=direct_proc) as mock_direct:
        run_complete_scan(
            cm,
            complete_runs=1,
            critical_high_only=False,
            context="Direct user guidance",
        )
      direct_cmd = mock_direct.call_args.args[0]
      self.assertEqual(
          direct_cmd[direct_cmd.index("--context") + 1],
          complete_scan._FIND_CONTEXT_FOR_FIRST_PASS.format(discouraged_cwes=cwes)
          + "\n\n# Additional Context\nDirect user guidance",
      )

  def test_run_complete_scan_restores_workspace_on_sigterm(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(repo_dir)
      os.makedirs(cm_home)
      cmignore_path = os.path.join(repo_dir, ".cmignore")
      with open(cmignore_path, "w", encoding="utf-8") as fh:
        fh.write("vendor/\n")

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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      find_scan_num = 0
      mutated_during_pass2 = False
      report_existed_during_pass2 = False

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num, mutated_during_pass2, report_existed_during_pass2
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(
              returncode=0,
              stdout=json.dumps([{
                  "finding_id": "f0-1",
                  "status": "OPEN",
                  "file_path": "vuln.py",
                  "snippet": "sink()",
              }]),
              stderr="",
          )
        if cmd[:2] == ["cm", "find"]:
          if find_scan_num == 0:
            db_con = sqlite3.connect(db_path)
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't0', 't0', ?, 'parent-0')",
                [("s0-clean", "clean.py", repo_dir), ("s0-vuln", "vuln.py", repo_dir)],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-1', 's0-vuln', 'OPEN', 'HIGH', 'vuln.py', 'CWE-89', 1, 2, 'sink()')"
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          # Pass 2: verify `.cmignore` and `_cm_pass_report` are active, then send real SIGTERM
          with open(cmignore_path, "r", encoding="utf-8") as fh:
            mutated_during_pass2 = "clean.py\n" in fh.read()
          report_existed_during_pass2 = os.path.exists(
              os.path.join(repo_dir, *complete_scan._PASS_REPORT_REL_PATH.split("/"))
          )
          os.kill(os.getpid(), signal.SIGTERM)
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        with self.assertRaises(SystemExit) as exit_ctx:
          run_complete_scan(cm, complete_runs=3)

      self.assertEqual(exit_ctx.exception.code, 128 + signal.SIGTERM)
      self.assertTrue(mutated_during_pass2)
      self.assertTrue(report_existed_during_pass2)
      with open(cmignore_path, "r", encoding="utf-8") as fh:
        self.assertEqual(fh.read(), "vendor/\n")
      self.assertFalse(
          os.path.exists(os.path.join(repo_dir, complete_scan._PASS_REPORT_REL_PATH))
      )
      self.assertFalse(
          os.path.exists(complete_scan._workspace_backup_path(repo_dir, cm_home))
      )

  def test_sigkill_crash_heals_workspace_on_recovery_without_vcs(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(repo_dir)
      os.makedirs(cm_home)

      # Simulate state left behind on disk if SIGKILL strikes mid-Pass-2 (no `.cmignore` existed originally)
      complete_scan._atomic_write_text(
          complete_scan._workspace_backup_path(repo_dir, cm_home),
          json.dumps({
              "repo_dir": os.path.realpath(repo_dir),
              "existed": False,
              "content": "",
          }),
      )
      complete_scan._atomic_write_text(os.path.join(repo_dir, ".cmignore"), "clean.py\n")
      complete_scan._atomic_write_text(
          os.path.join(repo_dir, complete_scan._PASS_REPORT_REL_PATH),
          "[]",
      )

      # Recovery heals `.cmignore` and removes scratch artifacts from both `repo_dir` and `CM_HOME`
      complete_scan.restore_interrupted_workspace(repo_dir, cm_dir=cm_home)
      self.assertFalse(os.path.exists(os.path.join(repo_dir, ".cmignore")))
      self.assertFalse(
          os.path.exists(os.path.join(repo_dir, complete_scan._PASS_REPORT_REL_PATH))
      )
      self.assertFalse(
          os.path.exists(complete_scan._workspace_backup_path(repo_dir, cm_home))
      )

  def test_format_and_filter_cmignore_entries_without_slash_or_root_shadowing(self):
    self.assertEqual(complete_scan._format_cmignore_entry("index.php"), "index.php")
    self.assertEqual(complete_scan._format_cmignore_entry("./src/clean.py"), "src/clean.py")
    self.assertEqual(complete_scan._format_cmignore_entry("/src/clean.py"), "src/clean.py")
    self.assertEqual(
        complete_scan._format_cmignore_entry(".github/workflows/ci.yml"),
        ".github/workflows/ci.yml",
    )
    self.assertEqual(complete_scan._format_cmignore_entry("#hash.py"), "\\#hash.py")
    self.assertEqual(complete_scan._format_cmignore_entry("!bang.py"), "\\!bang.py")
    self.assertEqual(
        complete_scan._format_cmignore_entry("my dir/trailing space.py "),
        "my dir/trailing space.py\\ ",
    )
    self.assertEqual(
        complete_scan._filter_cmignore_entries(
            ["index.php", "vulnerabilities/cmdi/index.php", "logout.php"],
            keep_files=["vulnerabilities/fi/index.php"],
        ),
        ["logout.php", "vulnerabilities/cmdi/index.php"],
    )

  def test_partial_batch_failure_retried_in_pass2_and_succeeds(self):
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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      find_scan_num = 0
      observed_cmignore = []

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        self.assertEqual(kwargs.get("env", {}).get("CM_STALL_DETECTION"), "on")
        if cmd[:2] == ["cm", "report"]:
          db_con = sqlite3.connect(db_path)
          rows = db_con.execute(
              "SELECT finding_id, status, file_path, snippet FROM findings"
          ).fetchall()
          db_con.close()
          payload = [
              {"finding_id": r[0], "status": r[1], "file_path": r[2], "snippet": r[3]}
              for r in rows
          ]
          return types.SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")
        if cmd[:2] == ["cm", "find"]:
          cmignore_path = os.path.join(repo_dir, ".cmignore")
          observed_cmignore.append(
              open(cmignore_path, "r", encoding="utf-8").read()
              if os.path.exists(cmignore_path)
              else None
          )
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', ?, ?, 't0', 't0', ?, 'parent-0')",
                [
                    ("s0-clean", "COMPLETED", "Logout.java", repo_dir),
                    ("s0-open", "COMPLETED", "Open.java", repo_dir),
                    ("s0-reg", "FAILED", "src/Register.java", repo_dir),
                ],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-open', 's0-open', 'OPEN', 'HIGH', 'Open.java', 'CWE-601', 10, 12, 'redirect()')"
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            stdout = (
                "[1/3 batches] ✅ Logout.java (10.0s) | 5.0k tok - 0 vulnerabilities\n"
                "[2/3 batches] 🚨 Open.java (12.0s) | 8.0k tok - 1 vulnerabilities\n"
                "[3/3 batches] ❌ src/Register.java (15.0s): [permission_denied] The caller does not have permission\n"
                "⚠️ 1 of 3 deep scan batch(es) failed (coverage is incomplete):\n"
                "     • src/Register.java\n"
                "Error: deep scan incomplete: 1 of 3 batch(es) failed (src/Register.java): [permission_denied]\n"
            )
            return types.SimpleNamespace(returncode=1, stdout=stdout, stderr="")
          if find_scan_num == 1:
            # Pass 2 retries Open.java (0 new findings) and src/Register.java (succeeds with 1 finding)
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't1', 't1', ?, 'parent-1')",
                [
                    ("s1-open", "Open.java", repo_dir),
                    ("s1-reg", "src/Register.java", repo_dir),
                ],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f1-reg', 's1-reg', 'OPEN', 'CRITICAL', 'src/Register.java', 'CWE-89', 20, 24, 'stmt.execute()')"
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          if find_scan_num == 2:
            # Pass 3 converges src/Register.java cleanly with 0 new findings
            db_con.execute(
                "INSERT INTO sessions VALUES ('s2-reg', 'FIND', 'COMPLETED', 'src/Register.java', 't2', 't2', ?, 'parent-2')",
                (repo_dir,),
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          raise AssertionError("Should have converged after Pass 3")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        res = run_complete_scan(cm, complete_runs=5)

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 3)
      self.assertEqual(
          observed_cmignore,
          [None, "Logout.java\n", "Logout.java\nOpen.java\n"],
      )
      self.assertEqual(
          get_latest_session_finding_counts(cm),
          {"Logout.java": 0, "Open.java": 0, "src/Register.java": 0},
      )

  def test_partial_batch_failure_tolerates_single_remaining_batch_failure_on_intermediate_pass(self):
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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      find_scan_num = 0

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', ?, ?, 't0', 't0', ?, 'parent-0')",
                [
                    ("s0-clean", "COMPLETED", "clean.py", repo_dir),
                    ("s0-flaky", "FAILED", "flaky.py", repo_dir),
                ],
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            return types.SimpleNamespace(
                returncode=1,
                stdout="Error: deep scan incomplete: 1 of 2 batch(es) failed (flaky.py): timeout\n",
                stderr="",
            )
          if find_scan_num == 1:
            # Pass 2 only scans flaky.py (1 batch total) and fails transiently as promoted parent
            db_con.execute(
                "INSERT INTO sessions VALUES ('parent-1', 'FIND', 'FAILED', ?, 't1', 't1', ?, '')",
                (repo_dir, repo_dir),
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            return types.SimpleNamespace(
                returncode=1,
                stdout="Error: all 1 deep scan batch(es) failed: transient error\n",
                stderr="",
            )
          if find_scan_num == 2:
            # Pass 3 (final pass) succeeds cleanly on flaky.py
            db_con.execute(
                "INSERT INTO sessions VALUES ('s2-flaky', 'FIND', 'COMPLETED', 'flaky.py', 't2', 't2', ?, 'parent-2')",
                (repo_dir,),
            )
            db_con.commit()
            db_con.close()
            find_scan_num += 1
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          raise AssertionError("Unexpected pass")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        res = run_complete_scan(cm, complete_runs=3)

      self.assertEqual(res.returncode, 0)
      self.assertEqual(find_scan_num, 3)

  def test_partial_batch_failure_raises_if_batch_remains_failed_after_final_pass(self):
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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      find_scan_num = 0

      def fake_persistent_failure(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', ?, ?, 't0', 't0', ?, 'parent-0')",
                [
                    ("s0-clean", "COMPLETED", "clean.py", repo_dir),
                    ("s0-broken", "FAILED", "broken.py", repo_dir),
                ],
            )
            stdout = "Error: deep scan incomplete: 1 of 2 batch(es) failed (broken.py): safety\n"
          else:
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-broken', 'FIND', 'FAILED', 'broken.py', 't1', 't1', ?, 'parent-1')",
                (repo_dir,),
            )
            stdout = "Error: all 1 deep scan batch(es) failed: safety\n"
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=1, stdout=stdout, stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_persistent_failure):
        with self.assertRaises(RuntimeError) as err_ctx:
          run_complete_scan(cm, complete_runs=2)

      self.assertEqual(find_scan_num, 2)
      self.assertIn("exit code 1", str(err_ctx.exception))
      self.assertFalse(os.path.exists(os.path.join(repo_dir, ".cmignore")))

      # Also verify unresolved FAILED session in state.db fails even if final pass returned 0
      find_scan_num_db = 0

      def fake_unretried_db_failure(cmd, **kwargs):
        nonlocal find_scan_num_db
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          db_con = sqlite3.connect(db_path)
          if find_scan_num_db == 0:
            db_con.execute(
                "INSERT INTO sessions VALUES ('s2-still-broken', 'FIND', 'FAILED', 'still_broken.py', 't2', 't2', ?, 'parent-2')",
                (repo_dir,),
            )
            db_con.commit()
            db_con.close()
            find_scan_num_db += 1
            return types.SimpleNamespace(
                returncode=1,
                stdout="Error: deep scan incomplete: 1 of 2 batch(es) failed (still_broken.py): err\n",
                stderr="",
            )
          db_con.close()
          find_scan_num_db += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_unretried_db_failure):
        with self.assertRaises(RuntimeError) as db_err_ctx:
          run_complete_scan(cm, complete_runs=2)

      self.assertEqual(find_scan_num_db, 2)
      self.assertIn("exit code 1", str(db_err_ctx.exception))
      self.assertIn("still_broken.py", str(db_err_ctx.exception))

  def test_host_precomputed_covered_lines_manifest_resolves_line_ranges_without_enable_bash(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(os.path.join(repo_dir, "src"))
      os.makedirs(cm_home)
      with open(os.path.join(repo_dir, "src", "auth.py"), "w", encoding="utf-8") as fh:
        fh.write(
            "\n".join([
                "import sqlite3",
                "",
                "def login(user):",
                '    query = f"SELECT * FROM users WHERE name = \'{user}\'"',
                "    return sqlite3.connect('db').execute(query)",
                "",
                "def run_diag(host):",
                "    return os.system('ping ' + host)",
            ])
            + "\n"
        )
      with open(os.path.join(repo_dir, "src", "other.py"), "w", encoding="utf-8") as fh:
        fh.write("def dump(x):\n    return eval(x)\n")

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
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      find_scan_num = 0
      observed_reports = []

      def fake_run_command(cmd, **kwargs):
        nonlocal find_scan_num
        if cmd[:2] == ["cm", "report"]:
          db_con = sqlite3.connect(db_path)
          rows = db_con.execute(
              "SELECT finding_id, status, file_path, snippet FROM findings"
          ).fetchall()
          db_con.close()
          return types.SimpleNamespace(
              returncode=0,
              stdout=json.dumps([
                  {"finding_id": r[0], "status": r[1], "file_path": r[2], "snippet": r[3]}
                  for r in rows
              ]),
              stderr="",
          )
        if cmd[:2] == ["cm", "find"]:
          self.assertNotIn("--enable-bash", cmd)
          report_path = os.path.join(repo_dir, complete_scan._PASS_REPORT_REL_PATH)
          if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as fh:
              observed_reports.append(fh.read())
          db_con = sqlite3.connect(db_path)
          if find_scan_num == 0:
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't0', 't0', ?, 'parent-0')",
                [("s0-auth", "src/auth.py", repo_dir), ("s0-other", "src/other.py", repo_dir)],
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, ?, 'OPEN', 'HIGH', ?, ?, ?, ?, ?)",
                [
                    (
                        "f0-auth",
                        "s0-auth",
                        "src/auth.py",
                        "CWE-89",
                        4,
                        5,
                        '    query = f"SELECT * FROM users WHERE name = \'{user}\'"\n    return sqlite3.connect(\'db\').execute(query)',
                    ),
                    ("f0-other", "s0-other", "src/other.py", "CWE-94", 2, 2, "    return eval(x)"),
                ],
            )
          elif find_scan_num == 1:
            # src/other.py converges (0 new findings); src/auth.py finds 2nd vulnerability on line 8
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't1', 't1', ?, 'parent-1')",
                [("s1-auth", "src/auth.py", repo_dir), ("s1-other", "src/other.py", repo_dir)],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f1-auth', 's1-auth', 'OPEN', 'CRITICAL', 'src/auth.py', 'CWE-78', 8, 8, \"    return os.system('ping ' + host)\")"
            )
          elif find_scan_num == 2:
            db_con.execute(
                "INSERT INTO sessions VALUES ('s2-auth', 'FIND', 'COMPLETED', 'src/auth.py', 't2', 't2', ?, 'parent-2')",
                (repo_dir,),
            )
          db_con.commit()
          db_con.close()
          find_scan_num += 1
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        run_complete_scan(cm, complete_runs=5)

      self.assertEqual(find_scan_num, 3)
      self.assertEqual(len(observed_reports), 2)
      # Pass 2 report has both active files as compact grep-friendly single lines
      self.assertEqual(
          observed_reports[0],
          "src/auth.py | covered: L4-5\nsrc/other.py | covered: L2",
      )
      # Pass 3 report scopes strictly to remaining active file (`src/auth.py`), omitting converged `src/other.py`
      self.assertEqual(
          observed_reports[1],
          "src/auth.py | covered: L4-5, L8",
      )
      self.assertNotIn("src/other.py", observed_reports[1])

  def test_safety_blocked_files_escalate_to_argon_with_scoped_cmignore(self):
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
          "parent_session_id TEXT, "
          "model TEXT)"
      )
      con.execute(
          "CREATE TABLE findings ("
          "finding_id TEXT PRIMARY KEY, "
          "session_id TEXT, "
          "status TEXT, "
          "severity TEXT, "
          "file_path TEXT, "
          "vuln_type TEXT, "
          "start_line INTEGER, "
          "end_line INTEGER, "
          "snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      recorded_passes = []

      def fake_run_command(cmd, **kwargs):
        if cmd[:2] == ["cm", "report"]:
          db_con = sqlite3.connect(db_path)
          rows = db_con.execute(
              "SELECT finding_id, status, file_path, snippet FROM findings"
          ).fetchall()
          db_con.close()
          return types.SimpleNamespace(
              returncode=0,
              stdout=json.dumps([
                  {"finding_id": r[0], "status": r[1], "file_path": r[2], "snippet": r[3]}
                  for r in rows
              ]),
              stderr="",
          )
        if cmd[:2] == ["cm", "find"]:
          cmignore_path = os.path.join(repo_dir, ".cmignore")
          cmignore_txt = (
              open(cmignore_path, "r", encoding="utf-8").read()
              if os.path.exists(cmignore_path)
              else None
          )
          env_passed = kwargs.get("env") or {}
          model_flags = [
              f for f in cmd if f == "--model" or f.startswith("--model=")
          ]
          if model_flags == ["--model"]:
            model_val = cmd[cmd.index("--model") + 1]
          else:
            model_val = model_flags[0].split("=", 1)[1]
          pass_idx = len(recorded_passes)
          recorded_passes.append({
              "model": model_val,
              "disable_fallback": env_passed.get("CM_DISABLE_MODEL_FALLBACK"),
              "cmignore": cmignore_txt,
              "max_turns": cmd[cmd.index("--deep-max-turns") + 1],
          })

          db_con = sqlite3.connect(db_path)
          if pass_idx == 0:
            # Hydrogen Pass 1: clean.cs (0), Controller.cs (1 HIGH), Update/VLAUpdate.cs (FAILED safety)
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', ?, ?, 't0', 't0', ?, 'parent-0', 'gemini-4-hydrogen')",
                [
                    ("s0-clean", "COMPLETED", "clean.cs", repo_dir),
                    ("s0-ctrl", "COMPLETED", "Controller.cs", repo_dir),
                    ("s0-upd", "FAILED", "Update/VLAUpdate.cs", repo_dir),
                ],
            )
            db_con.execute(
                "INSERT INTO findings VALUES ('f0-ctrl', 's0-ctrl', 'OPEN', 'HIGH', 'Controller.cs', 'CWE-787', 10, 15, 'stackalloc char[16]')"
            )
            db_con.commit()
            db_con.close()
            stdout = (
                "[1/3 batches] ✅ clean.cs (5.0s) - 0 vulnerabilities\n"
                "[2/3 batches] ❌ Update/VLAUpdate.cs (8.0s): The prompt is blocked due to safety\n"
                "[3/3 batches] 🚨 Controller.cs (12.0s) - 1 vulnerabilities\n"
                "Error: deep scan incomplete: 1 of 3 batch(es) failed (Update/VLAUpdate.cs): The prompt is blocked due to safety\n"
            )
            return types.SimpleNamespace(returncode=2, stdout=stdout, stderr="")
          if pass_idx == 1:
            # Hydrogen Pass 2: Controller.cs converges (Update/VLAUpdate.cs is in .cmignore)
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-ctrl', 'FIND', 'COMPLETED', 'Controller.cs', 't1', 't1', ?, 'parent-1', 'gemini-4-hydrogen')",
                (repo_dir,),
            )
            db_con.commit()
            db_con.close()
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          if pass_idx == 2:
            # Argon Pass 1 on Update/VLAUpdate.cs ONLY: finds both CWE-94 and CWE-494
            db_con.execute(
                "INSERT INTO sessions VALUES ('s2-upd-argon', 'FIND', 'COMPLETED', 'Update/VLAUpdate.cs', 't2', 't2', ?, 'parent-2', 'gemini-4-argon')",
                (repo_dir,),
            )
            db_con.executemany(
                "INSERT INTO findings VALUES (?, 's2-upd-argon', 'OPEN', 'CRITICAL', 'Update/VLAUpdate.cs', ?, ?, ?, ?)",
                [
                    ("f2-cwe94", "CWE-94", 28, 92, "VirtualAlloc(...)"),
                    ("f2-cwe494", "CWE-494", 94, 109, "ExtractPayloadFromFile(...)"),
                ],
            )
            db_con.commit()
            db_con.close()
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          if pass_idx == 3:
            # Argon Pass 2 on Update/VLAUpdate.cs ONLY: converges with 0 new findings
            db_con.execute(
                "INSERT INTO sessions VALUES ('s3-upd-argon', 'FIND', 'COMPLETED', 'Update/VLAUpdate.cs', 't3', 't3', ?, 'parent-3', 'gemini-4-argon')",
                (repo_dir,),
            )
            db_con.commit()
            db_con.close()
            return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
          raise AssertionError(f"Unexpected pass {pass_idx}")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_run_command):
        res = run_complete_scan(
            cm,
            extra_flags=["--model", "gemini-4-hydrogen"],
            complete_runs=5,
        )

      self.assertEqual(res.returncode, 0)
      self.assertEqual(
          recorded_passes,
          [
              {
                  "model": "gemini-4-hydrogen",
                  "disable_fallback": "true",
                  "cmignore": None,
                  "max_turns": "8",
              },
              {
                  "model": "gemini-4-hydrogen",
                  "disable_fallback": "true",
                  "cmignore": "Update/VLAUpdate.cs\nclean.cs\n",
                  "max_turns": "8",
              },
              {
                  "model": "gemini-4-argon",
                  "disable_fallback": None,
                  "cmignore": "Controller.cs\nclean.cs\n",
                  "max_turns": "8",
              },
              {
                  "model": "gemini-4-argon",
                  "disable_fallback": None,
                  "cmignore": "Controller.cs\nclean.cs\n",
                  "max_turns": "8",
              },
          ],
      )

  def test_single_file_safety_block_and_db_fallback_escalate_and_opt_out_respected(self):
    # 1) Single-file repo hitting `all 1 deep scan batch(es) failed: ... blocked due to safety`
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(repo_dir)
      os.makedirs(cm_home)
      db_path = os.path.join(cm_home, "state.db")
      con = sqlite3.connect(db_path)
      con.execute(
          "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, session_type TEXT, status TEXT, target TEXT, created_at TEXT, updated_at TEXT, project_root TEXT, parent_session_id TEXT, model TEXT)"
      )
      con.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, session_id TEXT, status TEXT, severity TEXT, file_path TEXT, vuln_type TEXT, start_line INTEGER, end_line INTEGER, snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      models_seen = []

      def fake_single_file(cmd, **kwargs):
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          mdl = [f.split("=", 1)[1] for f in cmd if f.startswith("--model=")][0]
          models_seen.append(mdl)
          db_con = sqlite3.connect(db_path)
          if len(models_seen) == 1:
            db_con.execute(
                "INSERT OR REPLACE INTO sessions VALUES ('s0-root', 'FIND', 'FAILED', ?, 't0', 't0', ?, '', 'gemini-4-hydrogen')",
                (repo_dir, repo_dir),
            )
            db_con.commit()
            db_con.close()
            return types.SimpleNamespace(
                returncode=2,
                stdout="Error: all 1 deep scan batch(es) failed: The prompt is blocked due to safety\n",
                stderr="",
            )
          db_con.execute(
              "INSERT INTO sessions VALUES ('s1-dsvw', 'FIND', 'COMPLETED', 'dsvw.py', 't1', 't1', ?, 'p1', 'gemini-4-argon')",
              (repo_dir,),
          )
          db_con.commit()
          db_con.close()
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_single_file):
        res = run_complete_scan(cm, complete_runs=3)
      self.assertEqual(res.returncode, 0)
      self.assertEqual(models_seen, ["gemini-4-hydrogen", "gemini-4-argon"])

      # 2) Opt-out via --no-model-fallback or primary gemini-4-carbon disables wrapper Argon escalation
      models_seen.clear()
      with patch("codemender.run_command", side_effect=fake_single_file):
        with self.assertRaises(RuntimeError):
          run_complete_scan(cm, extra_flags=["--no-model-fallback"], complete_runs=3)
      models_seen.clear()
      with patch("codemender.run_command", side_effect=fake_single_file):
        with self.assertRaises(RuntimeError):
          run_complete_scan(cm, extra_flags=["--model=gemini-4-carbon"], complete_runs=3)
      self.assertEqual(models_seen, ["gemini-4-carbon"])

    # 3) state.db fallback model (`gemini-3.8-flash-cyber`) also triggers Argon escalation
    with tempfile.TemporaryDirectory() as tmpdir:
      repo_dir = os.path.join(tmpdir, "repo")
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(repo_dir)
      os.makedirs(cm_home)
      db_path = os.path.join(cm_home, "state.db")
      con = sqlite3.connect(db_path)
      con.execute(
          "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, session_type TEXT, status TEXT, target TEXT, created_at TEXT, updated_at TEXT, project_root TEXT, parent_session_id TEXT, model TEXT)"
      )
      con.execute(
          "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, session_id TEXT, status TEXT, severity TEXT, file_path TEXT, vuln_type TEXT, start_line INTEGER, end_line INTEGER, snippet TEXT)"
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=repo_dir, env={"CM_HOME": cm_home})
      models_seen_db = []

      def fake_db_fallback(cmd, **kwargs):
        if cmd[:2] == ["cm", "report"]:
          return types.SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if cmd[:2] == ["cm", "find"]:
          mdl = [f.split("=", 1)[1] for f in cmd if f.startswith("--model=")][0]
          models_seen_db.append(mdl)
          db_con = sqlite3.connect(db_path)
          if len(models_seen_db) == 1:
            db_con.executemany(
                "INSERT INTO sessions VALUES (?, 'FIND', 'COMPLETED', ?, 't0', 't0', ?, 'p0', ?)",
                [
                    ("s0-clean", "clean.ts", repo_dir, "gemini-4-hydrogen"),
                    ("s0-fb", "mcp.tool-executor.service.ts", repo_dir, "gemini-3.8-flash-cyber"),
                ],
            )
          else:
            db_con.execute(
                "INSERT INTO sessions VALUES ('s1-argon', 'FIND', 'COMPLETED', 'mcp.tool-executor.service.ts', 't1', 't1', ?, 'p1', 'gemini-4-argon')",
                (repo_dir,),
            )
          db_con.commit()
          db_con.close()
          return types.SimpleNamespace(returncode=0, stdout="Success", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

      with patch("codemender.run_command", side_effect=fake_db_fallback):
        res_db = run_complete_scan(cm, complete_runs=3)
      self.assertEqual(res_db.returncode, 0)
      self.assertEqual(models_seen_db, ["gemini-4-hydrogen", "gemini-4-argon"])

  def test_normalize_db_finding_cwes_remaps_discouraged_findings_and_preserves_preexisting(self):
    disc_prompt = complete_scan._load_discouraged_cwes()
    self.assertLess(len(disc_prompt), 400)
    self.assertIn("CWE-287", disc_prompt)
    self.assertNotIn("CWE-1,", disc_prompt)

    with tempfile.TemporaryDirectory() as tmpdir:
      cm_home = os.path.join(tmpdir, "cm_home")
      os.makedirs(cm_home)
      db_path = os.path.join(cm_home, "state.db")
      con = sqlite3.connect(db_path)
      con.execute(
          "CREATE TABLE findings ("
          "finding_id TEXT PRIMARY KEY, "
          "status TEXT, "
          "title TEXT, "
          "analysis TEXT, "
          "vuln_type TEXT, "
          "vuln_id TEXT, "
          "finding_json TEXT)"
      )
      con.executemany(
          "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)",
          [
              (
                  "f-pre",
                  "OPEN",
                  "Preexisting discouraged finding",
                  "",
                  "CWE-287",
                  "CWE-287",
                  '{"vuln_id":"CWE-287","vuln_type":"CWE-287"}',
              ),
              (
                  "f-cur-disc",
                  "OPEN",
                  "Missing Authentication for Critical Function on /admin",
                  "Endpoint lacks authentication",
                  "CWE-287",
                  "CWE-287",
                  '{"vuln_id":"CWE-287","vuln_type":"CWE-287"}',
              ),
              (
                  "f-cur-ok",
                  "OPEN",
                  "SQL Injection in login",
                  "",
                  "SQL INJECTION",
                  "CWE-89",
                  "{}",
              ),
          ],
      )
      con.commit()
      con.close()

      cm = CodeMender(cm_binary="cm", repo_dir=tmpdir, env={"CM_HOME": cm_home})
      updated = complete_scan.normalize_db_finding_cwes(
          cm, exclude_finding_ids={"f-pre"}
      )
      self.assertEqual(updated, 1)

      check_con = sqlite3.connect(db_path)
      rows = dict(
          check_con.execute(
              "SELECT finding_id, vuln_id || '|' || vuln_type || '|' || finding_json FROM findings"
          ).fetchall()
      )
      check_con.close()
      self.assertEqual(
          rows["f-pre"],
          'CWE-287|CWE-287|{"vuln_id":"CWE-287","vuln_type":"CWE-287"}',
      )
      self.assertEqual(
          rows["f-cur-disc"],
          'CWE-306|CWE-306|{"vuln_id": "CWE-306", "vuln_type": "CWE-306"}',
      )
      self.assertEqual(rows["f-cur-ok"], "CWE-89|SQL INJECTION|{}")


if __name__ == "__main__":
  unittest.main()

