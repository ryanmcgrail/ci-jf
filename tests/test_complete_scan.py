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
      self.assertNotIn(
          "Only audit these remaining files:",
          find_cmds[1][find_cmds[1].index("--context") + 1],
      )
      for cmd in find_cmds[2:]:
        self.assertEqual(cmd[cmd.index("--deep-max-turns") + 1], "12")
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
        self.assertIn(
            "focusing on the most critical security issues (CRITICAL and HIGH severity)",
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
            self.assertIn("--enable-bash", cmd)
            self.assertIn("# Initial Pre-Audit Check", ctx_arg)
            for fname in os.listdir(repo_dir):
              if fname.startswith("tmp"):
                with open(os.path.join(repo_dir, fname), "r", encoding="utf-8") as fh:
                  import json as _json
                  pass2_report_payloads.append(_json.load(fh))
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
          [[{"file_path": "app.py", "snippet": "cur_sink()"}]],
      )


if __name__ == "__main__":
  unittest.main()

