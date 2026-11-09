"""Specs for the test harness stubs (tests/stubs) and EntrypointTestBase hooks."""

import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

from tests.test_entrypoint import FIND, REPO, STUBS, EntrypointTestBase


def _journal_mode(db):
  c = sqlite3.connect(db)
  try:
    return c.execute("PRAGMA journal_mode").fetchone()[0]
  finally:
    c.close()


def _accepted(log_text):
  return set(re.findall(r"StartSession \u2713 accepted: .*session=(Ch[\w-]+)", log_text))


def _rows(db):
  c = sqlite3.connect(db)
  try:
    return c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
  finally:
    c.close()


class StubTestBase(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="stub_test_"))
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.home = self.tmp / "home"
    self.home.mkdir()
    self.cm_home = self.tmp / "cmhome"

  def run_stub(self, name, *args, **env):
    full = dict(os.environ, HOME=str(self.home), GCS_EMU=str(self.tmp / "gcs"),
                CM_STUB_LOG=str(self.tmp / "cm_calls.jsonl"))
    for k in ("CM_HOME", "CM_STUB_VERSION", "GCLOUD_STUB_REAL_AUTH"):
      full.pop(k, None)
    full.update(env)
    return subprocess.run([str(STUBS / name), *args], env=full, cwd=self.tmp,
                          capture_output=True, text=True, timeout=30)

  def find_v010(self, *args, **env):
    p = self.run_stub("cm", "find", *args, ".", CM_STUB_VERSION="0.10.0",
                      CM_HOME=str(self.cm_home), **env)
    self.assertEqual(p.returncode, 0, p.stderr)
    return p


class CmStubTest(StubTestBase):

  def test_stub_01_v090_default_is_legacy(self):
    self.assertEqual(self.run_stub("cm", "--version").stdout.strip(),
                     "cm version 0.9.0")
    p = self.run_stub("cm", "find", "--deep", "--deep-workers", "4", ".",
                      CM_HOME=str(self.cm_home))
    self.assertEqual(p.returncode, 0, p.stderr)
    db = self.home / ".codemender" / "state.db"
    self.assertFalse(self.cm_home.exists())
    self.assertNotEqual(_journal_mode(db), "wal")

  def test_stub_02_v010_cm_home_and_wal(self):
    self.find_v010()
    self.assertEqual(_journal_mode(self.cm_home / "state.db"), "wal")
    p = self.run_stub("cm", "find", ".", CM_STUB_VERSION="0.10.0")
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(_journal_mode(self.home / ".codemender" / "state.db"), "wal")

  def test_stub_03_deep_sessions_and_logs(self):
    self.find_v010("--deep", CM_STUB_DEEP_FILES="3")
    self.assertEqual(_rows(self.cm_home / "state.db"), 3)
    logs = sorted((self.cm_home / "logs").glob("*.log"))
    self.assertEqual(len(logs), 1)
    self.assertRegex(logs[0].name, r"^\d{8}T\d{6}Z_pending\.log$")
    self.assertEqual(_accepted(logs[0].read_text()),
                     {f"ChStubSession{i:04d}" for i in range(3)})

  def test_stub_04_drop_sessions(self):
    self.find_v010("--deep", CM_STUB_DEEP_FILES="5", CM_STUB_DROP_SESSIONS="2")
    self.assertEqual(_rows(self.cm_home / "state.db"), 3)
    log = next((self.cm_home / "logs").glob("*_pending.log")).read_text()
    self.assertEqual(len(_accepted(log)), 5)

  def test_stub_05_leave_wal(self):
    self.find_v010("--deep", CM_STUB_DEEP_FILES="5", CM_STUB_LEAVE_WAL="1")
    wal = self.cm_home / "state.db-wal"
    self.assertTrue(wal.is_file() and wal.stat().st_size > 0)
    copy = self.tmp / "copy" / "state.db"
    copy.parent.mkdir()
    shutil.copyfile(self.cm_home / "state.db", copy)
    try:
      rows = _rows(copy)
    except sqlite3.OperationalError:
      rows = 0
    self.assertLess(rows, 5)

  def test_stub_13_stats_json(self):
    p = self.run_stub("cm", "stats", "--json", "--since", "12s",
                      CM_STUB_VERSION="0.10.0", CM_HOME=str(self.cm_home))
    self.assertEqual(p.returncode, 0, p.stderr)
    out = json.loads(p.stdout)
    self.assertEqual((out["since"], out["total_tokens"], out["total_turns"]),
                     ("12s", 35, 4))
    self.assertIn("Session log", p.stderr)
    logs = list((self.cm_home / "logs").glob("*_stats_pending.log"))
    self.assertEqual([l.read_text() for l in logs], [""])
    p = self.run_stub("cm", "stats", "--json", CM_STUB_STATS_EXIT="3")
    self.assertEqual((p.returncode, p.stdout), (3, ""))


class HelperStubTest(StubTestBase):

  def test_stub_08_token_stats_upstream_flags(self):
    t0 = time.monotonic()
    p = self.run_stub("cm-api-token-stats", "--json", "--since", "30s",
                      "--session", "s", "--limit", "5", "--project", "p",
                      CM_HOME=str(self.cm_home), CM_STUB_TS_SLEEP="0.3")
    self.assertGreaterEqual(time.monotonic() - t0, 0.3)
    self.assertEqual(p.returncode, 0, p.stderr)
    out = json.loads(p.stdout)
    self.assertEqual(out["argv"], ["--json", "--since", "30s", "--session", "s",
                                   "--limit", "5", "--project", "p"])
    self.assertEqual(out["cm_home"], str(self.cm_home))

  def test_stub_11_token_stats_rejects_fork_flags(self):
    for flag in ("--since-time", "--discover-logs", "--log-dir"):
      with self.subTest(flag):
        p = self.run_stub("cm-api-token-stats", "--json", flag, "1")
        self.assertEqual(p.returncode, 2, flag)

  def test_stub_12_token_stats_accepts_workers(self):
    p = self.run_stub("cm-api-token-stats", "--json", "--workers", "3",
                      "--project", "p")
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(json.loads(p.stdout)["argv"],
                     ["--json", "--workers", "3", "--project", "p"])

  def test_stub_09_gcloud_adc_token_and_real_auth(self):
    adc = ("auth", "application-default", "print-access-token")
    self.assertEqual(self.run_stub("gcloud", *adc).stdout.strip(), "stub-token")
    self.assertEqual(self.run_stub("gcloud", *adc, GCLOUD_STUB_TOKEN="t2")
                     .stdout.strip(), "t2")
    real = self.tmp / "real_gcloud"
    real.write_text("#!/bin/sh\necho \"real $*\"\n")
    real.chmod(0o755)
    p = self.run_stub("gcloud", *adc, GCLOUD_STUB_REAL_AUTH=str(real))
    self.assertEqual(p.stdout.strip(), "real " + " ".join(adc))


class HarnessTest(EntrypointTestBase):

  def test_stub_10_cm_version_hook(self):
    self.stage_tasks("H", [{"repo_id": REPO, "language": "python"}])
    for version in ("0.9.0", "0.10.0"):
      with self.subTest(version):
        shutil.rmtree(self.emu / FIND, ignore_errors=True)
        shutil.rmtree(self.home / ".codemender", ignore_errors=True)
        self.cm_log.unlink(missing_ok=True)
        kw = {} if version == "0.9.0" else {"cm_version": version}
        p = self.run_ep("find", "H", **kw)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual({c["version"] for c in self.cm_calls()}, {version})
        db = self.results(FIND, "H") / "state.db"
        self.assertEqual(_journal_mode(db) == "wal", version == "0.10.0")


del EntrypointTestBase  # keep unittest from collecting the imported base twice

if __name__ == "__main__":
  unittest.main()
