"""Specs for the vendored upstream cm-api-token-stats (fde-security-aigis@61338ff)."""

import datetime
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "container" / "scripts" / "cm-api-token-stats"
sys.path.insert(0, str(ROOT / "container" / "scripts"))
import build_summary  # pylint: disable=g-import-not-at-top,wrong-import-position

# Re-sync with upstream on purpose (see README), then update both pins.
UPSTREAM_COMMIT = "61338fffc3fb376ca7cc4beb5e48f4bae4d4a6e4"
UPSTREAM_SHA256 = "c004be9d530d5f199a84cce44f262fd59b7e85454edc6b8bafe55c1a002fca5d"


def _load():
  loader = importlib.machinery.SourceFileLoader("cm_api_token_stats", str(SCRIPT))
  mod = importlib.util.module_from_spec(
      importlib.util.spec_from_loader(loader.name, loader))
  loader.exec_module(mod)
  return mod


class VendoredTokenStatsTest(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ts_vendor_"))
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

  def run_script(self, *args, cm_home=None):
    env = dict(os.environ, CM_HOME=str(cm_home or self.tmp / "empty"))
    return subprocess.run([sys.executable, str(SCRIPT), *args], env=env,
                          capture_output=True, text=True, timeout=30)

  def make_cm_home(self, ages):
    """0.10.0-shaped CM_HOME: one session per age (seconds), rows 0-1 dropped."""
    home = self.tmp / "cmhome"
    (home / "logs").mkdir(parents=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    c = sqlite3.connect(home / "state.db")
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE sessions (session_id TEXT PRIMARY KEY, "
              "session_type TEXT, created_at TEXT)")
    for i, age in enumerate(ages):
      sid, ts = f"ChSession{i:02d}", (now - datetime.timedelta(seconds=age)).isoformat()
      (home / "logs" / f"20260101T0000{i:02d}Z_{sid}.log").write_text(
          f"{ts} [INFO] StartSession \u2713 accepted mode=SCAN session={sid}\n")
      if i >= 2:  # SQLITE_BUSY lost the first two rows
        c.execute("INSERT INTO sessions VALUES (?, 'FIND', ?)", (sid, ts))
    c.commit()
    c.close()
    (home / "logs" / "20260101T000099Z_pending.log").write_text(
        f"{now.isoformat()} [INFO] StartSession pending session=pending\n")
    return home

  def test_vend_01_pinned_to_upstream(self):
    self.assertEqual(hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
                     UPSTREAM_SHA256, f"not upstream {UPSTREAM_COMMIT}")
    self.assertTrue(os.access(SCRIPT, os.X_OK))

  def test_vend_02_cli_surface(self):
    help_text = self.run_script("--help").stdout
    for flag in ("--json", "--since", "--project", "--session", "--limit",
                 "--workers"):
      self.assertIn(flag, help_text)
    self.assertEqual(self.run_script("--since-time", "1").returncode, 2)

  def test_vend_03_discovery_unions_db_and_logs(self):
    home = self.make_cm_home([10] * 11)
    with mock.patch.dict(os.environ, {"CM_HOME": str(home)}):
      ids = [sid for sid, _ in _load().get_candidate_sessions()]
    self.assertEqual(sorted(ids), [f"ChSession{i:02d}" for i in range(11)])

  def test_vend_04_since_cutoff(self):
    home = self.make_cm_home([10, 600, 10, 600])
    with mock.patch.dict(os.environ, {"CM_HOME": str(home)}):
      mod = _load()
      ids = [sid for sid, _ in mod.get_candidate_sessions(mod.parse_duration("30s"))]
    self.assertEqual(sorted(ids), ["ChSession00", "ChSession02"])

  def test_vend_05_empty_json_has_summary_keys(self):
    p = self.run_script("--json", "--project", "p")
    self.assertEqual(p.returncode, 0, p.stderr)
    out = json.loads(p.stdout)
    self.assertLessEqual(set(build_summary._tokens({})), set(out))

  def test_vend_06_workers_validation(self):
    p = self.run_script("--workers", "0", "--json", "--project", "p")
    self.assertEqual(p.returncode, 2, p.stderr)
    p = self.run_script("--workers", "2", "--json", "--project", "p")
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertLessEqual(set(build_summary._tokens({})), set(json.loads(p.stdout)))


if __name__ == "__main__":
  unittest.main()
