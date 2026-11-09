"""End-to-end tests for container/entrypoint.sh using stub executables.

Stub `gcloud` emulates GCS over a temp dir (create-only), stub `cm` records its
argv and timing, and stub `cm-api-token-stats` returns fixed token totals. The
real container scripts and config are used via CM_OPT_DIR.
"""

import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUBS = ROOT / "tests" / "stubs"
ENTRYPOINT = ROOT / "container" / "entrypoint.sh"
FIXTURE = ROOT / "tests" / "fixtures" / "findings.json"
PAYLOAD, FIND, VERIFY, FIX = (
    "p-cm-payload", "p-cm-find-results", "p-cm-verify-results", "p-cm-fix-results"
)
REPO = "o04-vampi"


class EntrypointTestBase(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="ep_test_"))
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.emu = self.tmp / "gcs"
    self.home = self.tmp / "home"
    self.home.mkdir()
    self.bin = self.tmp / "bin"
    self.bin.mkdir()
    for s in ("gcloud", "cm-api-token-stats", "curl"):
      shutil.copy(STUBS / s, self.bin / s)
    self.opt = self.tmp / "opt"
    (self.opt / "scripts").mkdir(parents=True)
    for f in (ROOT / "container" / "scripts").iterdir():
      if f.is_file():
        shutil.copy(f, self.opt / "scripts" / f.name)
    shutil.copytree(ROOT / "config", self.opt / "config")
    self.cm_log = self.tmp / "cm_calls.jsonl"
    self.sha = self._stage_cm_zip()
    self._stage_repo_tarball()

  def gcs(self, uri):
    return self.emu / uri[len("gs://"):]

  def put(self, uri, data):
    p = self.gcs(uri)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())

  def _stage_cm_zip(self, cm_version="0.9.0"):
    z = self.tmp / "cm.zip"
    with zipfile.ZipFile(z, "w") as zf:
      info = zipfile.ZipInfo("cm")
      info.external_attr = 0o755 << 16
      zf.writestr(info, (STUBS / "cm").read_text())
    data = z.read_bytes()
    self.put(f"gs://{PAYLOAD}/bin/cm/{cm_version}/cm-linux-amd64.zip", data)
    return hashlib.sha256(data).hexdigest()

  def _stage_repo_tarball(self):
    src = self.tmp / "src" / REPO
    src.mkdir(parents=True)
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    (src / "app.py").write_text("print('vampi')\n")
    subprocess.run(["git", "-C", str(src), "add", "."], check=True)
    subprocess.run(["git", "-C", str(src), "commit", "-qm", "init"], check=True,
                   env=env)
    tgz = self.tmp / "repo.tar.gz"
    with tarfile.open(tgz, "w:gz") as tf:
      tf.add(src, arcname=REPO)
    self.put(f"gs://{PAYLOAD}/repos/{REPO}.tar.gz", tgz.read_bytes())

  def stage_tasks(self, run_id, tasks):
    self.put(f"gs://{PAYLOAD}/runs/exp/{run_id}/tasks.json", json.dumps(tasks))

  def run_ep(self, operation, run_id, sha=None, extra_env=None, timeout=120,
             cm_version="0.9.0"):
    self._stage_cm_zip(cm_version)
    env = {
        "PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.home),
        "TMPDIR": str(self.tmp), "GCS_EMU": str(self.emu),
        "CM_STUB_LOG": str(self.cm_log), "CM_OPT_DIR": str(self.opt),
        "OPERATION": operation, "CLOUD_RUN_TASK_INDEX": "0",
        "PROJECT_ID": "p", "PAYLOAD_BUCKET": PAYLOAD,
        "FIND_RESULTS_BUCKET": FIND, "VERIFY_RESULTS_BUCKET": VERIFY,
        "FIX_RESULTS_BUCKET": FIX,
        "EXPERIMENT_ID": "exp", "RUN_ID": run_id, "CM_VERSION": cm_version,
        "CM_STUB_VERSION": cm_version,
        "EXPECTED_CM_SHA256": sha or self.sha, "MODEL": "gemini-3.8-flash",
        "MODE": "shallow", "SEVERITY": "CRITICAL,HIGH", "EXTRA_CM_ARGS": "",
        "JOB_TIMEOUT": "172800", "FIX_FINDING_TIMEOUT": "10800",
    }
    env.update(extra_env or {})
    return subprocess.run(["bash", str(ENTRYPOINT)], env=env, capture_output=True,
                          text=True, timeout=timeout)

  def cm_calls(self, sub=None):
    if not self.cm_log.exists():
      return []
    calls = [json.loads(l) for l in self.cm_log.read_text().splitlines()]
    return [c for c in calls if sub is None or c["argv"][:1] == [sub]]

  def results(self, bucket, run_id):
    return self.emu / bucket / "exp" / run_id / REPO


class FindTest(EntrypointTestBase):

  def test_find_uploads_expected_files(self):
    self.stage_tasks("FR", [{"repo_id": REPO, "language": "python"}])
    self.put_report = None
    p = self.run_ep("find", "FR")
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(FIND, "FR")
    for name in ("findings.json", "state.db", "cm_api_token_stats.json",
                 "summary.json", "findings_table.txt", "logs/execution.log"):
      self.assertTrue((out / name).is_file(), name)
    self.assertEqual(json.loads((out / "findings.json").read_text()), [])
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok")
    self.assertEqual(summary["tokens"]["total_tokens"], 42)
    find = self.cm_calls("find")[0]["argv"]
    self.assertEqual(find[:2], ["find", "."])
    self.assertIn("-y", find)
    self.assertIn("--bypass-warning", find)
    self.assertTrue(self.cm_calls("find")[0]["cwd"].endswith("workspace/" + REPO))
    self.assertFalse((self.emu / VERIFY).exists())

  def test_deep_workers_flag(self):
    self.stage_tasks("FD", [{"repo_id": REPO, "language": "python"}])
    for workers, expected in (("12", ["--deep", "--deep-workers", "12"]),
                              ("", ["--deep"])):
      with self.subTest(workers=workers):
        shutil.rmtree(self.emu / FIND, ignore_errors=True)
        self.cm_log.unlink(missing_ok=True)
        p = self.run_ep("find", "FD", extra_env={"MODE": "deep",
                                                 "DEEP_WORKERS": workers})
        self.assertEqual(p.returncode, 0, p.stderr)
        find = self.cm_calls("find")[-1]["argv"]
        self.assertEqual(find[1:1 + len(expected)], expected)
        if not workers:
          self.assertNotIn("--deep-workers", find)

  def test_deep_workers_ignored_when_shallow(self):
    self.stage_tasks("FS", [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", "FS", extra_env={"DEEP_WORKERS": "12"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertNotIn("--deep-workers", self.cm_calls("find")[0]["argv"])

  def test_invalid_deep_workers_dies(self):
    self.stage_tasks("FX", [{"repo_id": REPO}])
    for value in ("abc", "0", "17", "08"):
      with self.subTest(value=value):
        p = self.run_ep("find", "FX", extra_env={"MODE": "deep",
                                                 "DEEP_WORKERS": value})
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("FATAL: DEEP_WORKERS must be empty or 1-16", p.stderr)
        self.assertEqual(self.cm_calls(), [])

  def test_sha_mismatch_aborts(self):
    self.stage_tasks("FR", [{"repo_id": REPO}])
    p = self.run_ep("find", "FR", sha="0" * 64)
    self.assertNotEqual(p.returncode, 0)
    self.assertIn("SHA-256 mismatch", p.stderr)
    self.assertFalse((self.emu / FIND).exists())
    self.assertEqual(self.cm_calls(), [])

  def test_soft_timeout_still_uploads_telemetry(self):
    self.stage_tasks("FT", [{"repo_id": REPO}])
    p = self.run_ep("find", "FT", extra_env={
        "JOB_TIMEOUT": "3", "SOFT_TIMEOUT_RESERVE": "1", "CM_STUB_SLEEP": "6"})
    self.assertEqual(p.returncode, 124, p.stderr)
    out = self.results(FIND, "FT")
    self.assertTrue((out / "cm_api_token_stats.json").is_file())
    self.assertEqual(json.loads((out / "summary.json").read_text())["status"],
                     "timeout")

  def test_results_are_create_only(self):
    self.stage_tasks("FR", [{"repo_id": REPO}])
    self.assertEqual(self.run_ep("find", "FR").returncode, 0)
    shutil.rmtree(self.home)
    self.home.mkdir()
    p = self.run_ep("find", "FR")
    self.assertNotEqual(p.returncode, 0)
    self.assertIn("upload", p.stderr)


class Cm010FindTest(EntrypointTestBase):

  def test_argv_06_critical_finding_is_ok(self):
    report = self.tmp / "report.json"
    report.write_text(json.dumps([{"finding_id": "c1", "severity": "CRITICAL"}]))
    self.stage_tasks("FC", [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", "FC", cm_version="0.10.0",
                    extra_env={"CM_STUB_REPORT": str(report)})
    self.assertEqual(p.returncode, 0, p.stderr)
    summary = json.loads((self.results(FIND, "FC") / "summary.json").read_text())
    self.assertEqual((summary["status"], summary["findings_count"]), ("ok", 1))


class StateCaptureTest(EntrypointTestBase):

  def run_deep(self, **env):
    self.stage_tasks("SC", [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", "SC", cm_version="0.10.0", extra_env=dict(
        MODE="deep", CM_STUB_DEEP_FILES="5", **env))
    self.assertEqual(p.returncode, 0, p.stderr)
    return self.results(FIND, "SC")

  def test_state_01_same_cm_home(self):
    out = self.run_deep()
    stats = json.loads((out / "cm_api_token_stats.json").read_text())
    expected = str(self.home / ".codemender")
    self.assertEqual(self.cm_calls("find")[0]["cm_home"], expected)
    self.assertEqual(stats["cm_home"], expected)

  def test_state_02_wal_rows_captured(self):
    out = self.run_deep(CM_STUB_LEAVE_WAL="1")
    c = sqlite3.connect(out / "state.db")
    self.addCleanup(c.close)
    self.assertEqual(c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 5)

  def test_state_03_no_wal_sidecars(self):
    out = self.run_deep(CM_STUB_LEAVE_WAL="1")
    self.assertEqual(sorted(p.name for p in out.glob("state.db*")), ["state.db"])

  def test_state_04_session_logs_archived(self):
    out = self.run_deep()
    with tarfile.open(out / "logs" / "cm_logs.tar.gz") as tf:
      text = "".join(tf.extractfile(m).read().decode() for m in tf.getmembers()
                     if m.isfile())
    self.assertEqual(len(set(re.findall(r"accepted: .*session=(Ch[\w-]+)", text))), 5)
    shutil.rmtree(self.home / ".codemender")
    self.stage_tasks("NL", [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", "NL")  # 0.9.0 stub writes no logs dir
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertFalse((self.results(FIND, "NL") / "logs" / "cm_logs.tar.gz").exists())


class TokenStatsLimitTest(EntrypointTestBase):

  def find(self, run_id, **env):
    self.stage_tasks(run_id, [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", run_id, cm_version="0.10.0", extra_env=env)
    self.assertEqual(p.returncode, 0, p.stderr)
    stats = self.results(FIND, run_id) / "cm_api_token_stats.json"
    return p, json.loads(stats.read_text())

  def test_tok_01_find_stats_unscoped_with_cm_home(self):
    _, stats = self.find("T1")
    self.assertNotIn("--since", stats["argv"])
    self.assertEqual(stats["cm_home"], str(self.home / ".codemender"))

  def test_tok_03_stats_timeout_still_uploads(self):
    _, stats = self.find("T3", TOKEN_STATS_TIMEOUT="1", CM_STUB_TS_SLEEP="3")
    self.assertEqual(stats, {"error": "timeout"})
    self.assertTrue((self.results(FIND, "T3") / "summary.json").is_file())

  def test_tok_04_deep_reserve(self):
    p, _ = self.find("T4", MODE="deep", JOB_TIMEOUT="2000")
    budget = int(re.search(r"soft timeout (\d+)s", p.stderr).group(1))
    self.assertIn(budget, range(2000 - 900 - 5, 2000 - 900 + 1))
    # Stats limit = reserve - 120: 2s here, 6s below.
    _, stats = self.find("T4a", MODE="deep", SOFT_TIMEOUT_RESERVE_DEEP="122",
                         CM_STUB_TS_SLEEP="4")
    self.assertEqual(stats, {"error": "timeout"})
    _, stats = self.find("T4b", MODE="deep", SOFT_TIMEOUT_RESERVE_DEEP="126",
                         CM_STUB_TS_SLEEP="4")
    self.assertNotIn("error", stats)

  def test_tok_06_workers_passed_through(self):
    _, stats = self.find("T6", TOKEN_STATS_WORKERS="3")
    argv = stats["argv"]
    self.assertEqual(argv[argv.index("--workers") + 1], "3")
    _, stats = self.find("T6e", TOKEN_STATS_WORKERS="")
    self.assertNotIn("--workers", stats["argv"])

  def test_tok_07_invalid_workers_dies(self):
    self.stage_tasks("T7", [{"repo_id": REPO}])
    for value in ("0", "abc", "08", "-1"):
      with self.subTest(value=value):
        p = self.run_ep("find", "T7", extra_env={"TOKEN_STATS_WORKERS": value})
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("FATAL: TOKEN_STATS_WORKERS must be empty or an integer >= 1",
                      p.stderr)
        self.assertEqual(self.cm_calls(), [])

  def test_tok_08_log_line(self):
    p, _ = self.find("T8")
    self.assertIn("cm-api-token-stats (limit 180s, workers default)", p.stderr)
    p, _ = self.find("T8d", MODE="deep", TOKEN_STATS_WORKERS="8")
    self.assertIn("cm-api-token-stats (limit 780s, workers 8)", p.stderr)


class CmStatsTest(EntrypointTestBase):
  """`cm stats --json` is captured next to cm-api-token-stats, best-effort."""

  def find(self, run_id, **env):
    self.stage_tasks(run_id, [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", run_id, cm_version="0.10.0", extra_env=env)
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(FIND, run_id)
    return p, out, json.loads((out / "cm_stats.json").read_text())

  def test_cms_01_find_uploads_cm_stats(self):
    _, out, stats = self.find("CS1")
    self.assertEqual(stats["total_tokens"], 35)
    self.assertEqual(stats["total_turns"], 4)
    self.assertRegex(stats["since"], r"^[1-9]\d*s$")
    [call] = self.cm_calls("stats")
    self.assertEqual(call["argv"][:3], ["stats", "--json", "--since"])
    self.assertIn("Session log: stub", (out / "logs" / "cm_stats.log").read_text())
    # cm stats runs right before cm-api-token-stats, after the state copy.
    self.assertTrue((out / "cm_api_token_stats.json").is_file())
    self.assertEqual(json.loads((out / "summary.json").read_text())["status"], "ok")

  def test_cms_02_pending_log_not_archived_for_find(self):
    _, out, _ = self.find("CS2")
    with tarfile.open(out / "logs" / "cm_logs.tar.gz") as tf:
      names = tf.getnames()
    self.assertTrue(names)
    self.assertFalse([n for n in names if "_stats_pending" in n], names)
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["sessions"]["logs"], 1)

  def test_cms_03_failure_is_best_effort(self):
    p, out, stats = self.find("CS3", CM_STUB_STATS_EXIT="3")
    self.assertEqual(stats, {"error": "failed", "exit_code": 3})
    self.assertIn("cm stats failed (see logs)", p.stderr)
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual((summary["status"], summary["exit_code"]), ("ok", 0))

  def test_cms_04_timeout_is_best_effort(self):
    p, out, stats = self.find("CS4", CM_STATS_TIMEOUT="1", CM_STUB_STATS_SLEEP="3")
    self.assertEqual(stats, {"error": "timeout"})
    self.assertIn("cm stats timed out after 1s", p.stderr)
    self.assertEqual(json.loads((out / "summary.json").read_text())["status"], "ok")

  def test_cms_05_invalid_timeout_dies(self):
    self.stage_tasks("CS5", [{"repo_id": REPO}])
    for value in ("0", "abc", "-1", "08"):
      with self.subTest(value=value):
        p = self.run_ep("find", "CS5", extra_env={"CM_STATS_TIMEOUT": value})
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("FATAL: CM_STATS_TIMEOUT must be an integer >= 1", p.stderr)
        self.assertEqual(self.cm_calls(), [])


class VerifyTest(EntrypointTestBase):

  def setUp(self):
    super().setUp()
    self.find_uri = f"gs://{FIND}/exp/FRUN/{REPO}/findings.json"
    self.put(self.find_uri, FIXTURE.read_bytes())
    self.ids = [f["finding_id"] for f in json.loads(FIXTURE.read_text())
                if f["severity"] in ("CRITICAL", "HIGH")]
    report = self.tmp / "report.json"
    report.write_text(json.dumps(
        [{"finding_id": i, "status": s} for i, s in
         zip(self.ids, ["VERIFIED", "DISMISSED", "OPEN"])]))
    self.report = report
    self.stage_tasks("VR", [{"repo_id": REPO, "language": "python",
                             "findings_gcs_uri": self.find_uri,
                             "severity": "CRITICAL,HIGH"}])

  def test_verify_limit_caps_findings(self):
    p = self.run_ep("verify", "VR", extra_env={
        "CM_STUB_REPORT": str(self.report), "FROM_FIND_RUN": "FRUN",
        "VERIFY_LIMIT": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual([c["argv"][1] for c in self.cm_calls("verify")], self.ids[:1])
    out = self.results(VERIFY, "VR")
    self.assertEqual(sorted(x.name for x in (out / "findings").iterdir()), self.ids[:1])
    self.assertEqual(json.loads((out / "summary.json").read_text())["findings_expected"], 1)

  def test_verify_loop_sequential_with_context(self):
    p = self.run_ep("verify", "VR", extra_env={
        "CM_STUB_REPORT": str(self.report), "FROM_FIND_RUN": "FRUN"})
    self.assertEqual(p.returncode, 0, p.stderr)
    calls = self.cm_calls("verify")
    self.assertEqual([c["argv"][1] for c in calls], self.ids)  # CRITICAL first
    for prev, nxt in zip(calls, calls[1:]):
      self.assertLessEqual(prev["t1"], nxt["t0"])  # sequential
    repo_dir = str(self.home / "workspace" / REPO)
    for c in calls:
      argv = c["argv"]
      for flag in ("--no-reset", "--unrestricted", "-y", "--bypass-warning"):
        self.assertIn(flag, argv)
      self.assertEqual(argv[argv.index("--model") + 1], "gemini-3.8-flash")
      ctx = argv[argv.index("-c") + 1]
      self.assertIn(f"{repo_dir} is a depth-1 source checkout of {REPO}", ctx)
      self.assertIn("primary language: python", ctx)
      self.assertIn("   - python3: ", ctx)
      self.assertNotIn("$", ctx)
      self.assertFalse(c["dirty_at_start"], "reset/clean must run between findings")
    out = self.results(VERIFY, "VR")
    for fid in self.ids:
      fdir = out / "findings" / fid
      for name in ("context.txt", "verify.log", "exit_code", "token_stats.json"):
        self.assertTrue((fdir / name).is_file(), f"{fid}/{name}")
      self.assertEqual((fdir / "exploit" / "poc.txt").read_text(), fid)
      self.assertEqual((fdir / "exit_code").read_text().strip(), "0")
    for name in ("post_verify_report.json", "state.db", "summary.json",
                 "tool_inventory.txt", "matching_finding_ids.txt"):
      self.assertTrue((out / name).is_file(), name)
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok")
    self.assertEqual(summary["findings_expected"], 3)
    self.assertEqual(summary["status_counts"],
                     {"VERIFIED": 1, "DISMISSED": 1, "OTHER:OPEN": 1})
    self.assertEqual(summary["timeout_count"], 0)
    self.assertFalse((pathlib.Path(repo_dir) / "dirty.txt").exists())
    self.assertFalse((self.emu / FIND / "exp" / "VR").exists())

  def test_tok_02_verify_token_stats_scoped_with_since(self):
    p = self.run_ep("verify", "VR", extra_env={
        "CM_STUB_REPORT": str(self.report), "FROM_FIND_RUN": "FRUN"})
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(VERIFY, "VR")
    per_finding_tokens = []
    for fid in self.ids:
      ts = json.loads((out / "findings" / fid / "token_stats.json").read_text())
      argv = ts.get("argv", [])
      self.assertNotIn("--since-time", argv)
      self.assertRegex(argv[argv.index("--since") + 1], r"^[1-9]\d*s$")
      per_finding_tokens.append(ts["total_tokens"])
    # Each finding should record only its own tokens (42), not cumulative totals
    self.assertEqual(per_finding_tokens, [42, 42, 42])
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["tokens"]["total_tokens"], 126)

  def test_cms_06_verify_cm_stats_per_finding(self):
    p = self.run_ep("verify", "VR", extra_env={
        "CM_STUB_REPORT": str(self.report), "FROM_FIND_RUN": "FRUN"})
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(VERIFY, "VR")
    for fid in self.ids:
      cs = json.loads((out / "findings" / fid / "cm_stats.json").read_text())
      self.assertEqual(cs["total_tokens"], 35)
      self.assertRegex(cs["since"], r"^[1-9]\d*s$")
    self.assertEqual(len(self.cm_calls("stats")), len(self.ids))
    # summary.json tokens still come from cm-api-token-stats only.
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["tokens"]["total_tokens"], 126)

  def test_tok_09_verify_workers_passed_through(self):
    p = self.run_ep("verify", "VR", extra_env={
        "CM_STUB_REPORT": str(self.report), "FROM_FIND_RUN": "FRUN",
        "VERIFY_LIMIT": "1", "TOKEN_STATS_WORKERS": "5"})
    self.assertEqual(p.returncode, 0, p.stderr)
    ts = self.results(VERIFY, "VR") / "findings" / self.ids[0] / "token_stats.json"
    argv = json.loads(ts.read_text())["argv"]
    self.assertEqual(argv[argv.index("--workers") + 1], "5")
    self.assertIn("--since", argv)

  def test_tok_05_finding_stats_capped_by_deadline(self):
    # MIN_FINDING_SECONDS is 60, so the finding must start with >= 60s left.
    p = self.run_ep("verify", "VR", extra_env={
        "CM_STUB_REPORT": str(self.report), "VERIFY_LIMIT": "1",
        "JOB_TIMEOUT": "66", "SOFT_TIMEOUT_RESERVE": "0",
        "TOKEN_STATS_TIMEOUT": "40", "CM_STUB_VERIFY_SLEEP": "58",
        "CM_STUB_TS_SLEEP": "25"})
    self.assertEqual(p.returncode, 0, p.stderr)
    ts = self.results(VERIFY, "VR") / "findings" / self.ids[0] / "token_stats.json"
    self.assertEqual(json.loads(ts.read_text()), {"error": "timeout"})

  def test_verify_timeout_records_124_and_continues(self):
    p = self.run_ep("verify", "VR", extra_env={
        "VERIFY_FINDING_TIMEOUT": "1", "CM_STUB_VERIFY_SLEEP": "4",
        "CM_STUB_REPORT": str(self.report)})
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(VERIFY, "VR")
    codes = [(out / "findings" / i / "exit_code").read_text().strip()
             for i in self.ids]
    self.assertEqual(codes, ["124", "124", "124"])
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["timeout_count"], 3)
    self.assertEqual(summary["nonzero_exit_count"], 3)
    self.assertEqual(summary["status"], "timeout")

  def test_verify_symlinked_exploit_dereferenced_and_uploaded_cleanly(self):
    self.stage_tasks("VR_SYM", [{"repo_id": REPO, "language": "python",
                                 "findings_gcs_uri": self.find_uri,
                                 "severity": "CRITICAL,HIGH"}])
    p = self.run_ep("verify", "VR_SYM", extra_env={
        "CM_STUB_REPORT": str(self.report), "FROM_FIND_RUN": "FRUN",
        "CM_STUB_SYMLINK_EXPLOIT": "1", "VERIFY_LIMIT": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(VERIFY, "VR_SYM")
    fid = self.ids[0]
    fdir = out / "findings" / fid
    poc = fdir / "exploit" / "poc.txt"
    self.assertTrue(poc.is_file(), f"missing dereferenced exploit poc: {poc}")
    self.assertEqual(poc.read_text(), fid)
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok")


class FixTest(EntrypointTestBase):

  def setUp(self):
    super().setUp()
    self.find_uri = f"gs://{FIND}/exp/FRUN/{REPO}/findings.json"
    self.put(self.find_uri, FIXTURE.read_bytes())
    self.ids = [f["finding_id"] for f in json.loads(FIXTURE.read_text())
                if f["severity"] in ("CRITICAL", "HIGH")]
    self.verify_report_uri = f"gs://{VERIFY}/exp/VRUN/{REPO}/post_verify_report.json"
    self.put(self.verify_report_uri, json.dumps([
        {"finding_id": self.ids[0], "status": "VERIFIED"},
        {"finding_id": self.ids[1], "status": "DISMISSED"},
        {"finding_id": self.ids[2], "status": "OPEN"},
    ]))
    self.verify_ids_uri = f"gs://{VERIFY}/exp/VRUN/{REPO}/matching_finding_ids.txt"
    self.put(self.verify_ids_uri, f"{self.ids[0]}\n")
    self.verify_repo_prefix = f"gs://{VERIFY}/exp/VRUN/{REPO}"
    self.put(f"{self.verify_repo_prefix}/findings/{self.ids[0]}/exploit/poc.txt", "payload")

  def test_fix_from_verify_restores_exploit_and_captures_patch(self):
    self.stage_tasks("XR", [{
        "repo_id": REPO,
        "language": "python",
        "findings_gcs_uri": self.find_uri,
        "verify_report_gcs_uri": self.verify_report_uri,
        "verify_ids_gcs_uri": self.verify_ids_uri,
        "verify_repo_prefix": self.verify_repo_prefix,
        "severity": "CRITICAL,HIGH",
    }])
    p = self.run_ep("fix", "XR", extra_env={"FROM_VERIFY_RUN": "VRUN"})
    self.assertEqual(p.returncode, 0, p.stderr)
    cfg = (self.home / ".codemender" / "config.yaml").read_text()
    self.assertIn("project_paths:", cfg)
    self.assertIn(f"- \"{self.home}/workspace/{REPO}\"", cfg)
    calls = self.cm_calls("fix")
    self.assertEqual(len(calls), 1)
    self.assertEqual(calls[0]["argv"][1], self.ids[0])
    self.assertTrue(calls[0]["exploit_restored"], "exploit should be restored from artifacts")
    self.assertFalse(calls[0]["dirty_at_start"], "workspace must be clean before fix")
    out = self.results(FIX, "XR")
    fdir = out / "findings" / self.ids[0]
    self.assertTrue((fdir / "patch.diff").is_file())
    diff = (fdir / "patch.diff").read_text()
    self.assertIn(f"# fix applied for {self.ids[0]}", diff)
    self.assertNotIn(".exploit", diff)
    self.assertTrue((fdir / "exploit" / "poc.txt").is_file())
    for name in ("post_fix_report.json", "state.db", "summary.json", "patch.diff"):
      self.assertTrue((out / name).is_file(), name)
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok")
    self.assertEqual(summary["patches_generated"], 1)
    self.assertEqual(summary["exploits_imported"], 1)
    self.assertEqual(summary["source_verify_run"], "VRUN")

  def test_fix_from_find_without_exploits(self):
    self.stage_tasks("XR_FIND", [{
        "repo_id": REPO,
        "language": "python",
        "findings_gcs_uri": self.find_uri,
        "severity": "CRITICAL,HIGH",
    }])
    p = self.run_ep("fix", "XR_FIND", extra_env={"FROM_FIND_RUN": "FRUN"})
    self.assertEqual(p.returncode, 0, p.stderr)
    calls = self.cm_calls("fix")
    self.assertEqual([c["argv"][1] for c in calls], self.ids)
    for c in calls:
      self.assertFalse(c["exploit_restored"])
    out = self.results(FIX, "XR_FIND")
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok")
    self.assertEqual(summary["patches_generated"], 3)
    self.assertEqual(summary["exploits_imported"], 0)
    self.assertEqual(summary["source_find_run"], "FRUN")
    for fid in self.ids:
      cs = json.loads((out / "findings" / fid / "cm_stats.json").read_text())
      self.assertEqual(cs["total_tokens"], 35)

  def test_fix_limit_and_timeout(self):
    self.stage_tasks("XR_LIM", [{
        "repo_id": REPO,
        "language": "python",
        "findings_gcs_uri": self.find_uri,
        "severity": "CRITICAL,HIGH",
    }])
    p = self.run_ep("fix", "XR_LIM", extra_env={
        "FROM_FIND_RUN": "FRUN", "FIX_LIMIT": "1",
        "FIX_FINDING_TIMEOUT": "1", "CM_STUB_FIX_SLEEP": "4"})
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(FIX, "XR_LIM")
    attempted_dirs = [d.name for d in (out / "findings").iterdir()]
    self.assertEqual(attempted_dirs, [self.ids[0]])
    code = (out / "findings" / self.ids[0] / "exit_code").read_text().strip()
    self.assertEqual(code, "124")
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "timeout")
    self.assertEqual(summary["timeout_count"], 1)

  def test_fix_limit_with_exploits_keeps_ids_capped(self):
    # Two verified findings with exploits; the exploit re-import must not
    # rewrite matching_finding_ids.txt past FIX_LIMIT (it feeds summary.json).
    self.put(self.verify_report_uri, json.dumps([
        {"finding_id": self.ids[0], "status": "VERIFIED"},
        {"finding_id": self.ids[1], "status": "VERIFIED"},
    ]))
    self.put(self.verify_ids_uri, f"{self.ids[0]}\n{self.ids[1]}\n")
    self.put(f"{self.verify_repo_prefix}/findings/{self.ids[1]}/exploit/poc.txt", "p2")
    self.stage_tasks("XR_CAP", [{
        "repo_id": REPO,
        "language": "python",
        "findings_gcs_uri": self.find_uri,
        "verify_report_gcs_uri": self.verify_report_uri,
        "verify_ids_gcs_uri": self.verify_ids_uri,
        "verify_repo_prefix": self.verify_repo_prefix,
        "severity": "CRITICAL,HIGH",
    }])
    p = self.run_ep("fix", "XR_CAP", extra_env={"FROM_VERIFY_RUN": "VRUN",
                                                "FIX_LIMIT": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual([c["argv"][1] for c in self.cm_calls("fix")], [self.ids[0]])
    out = self.results(FIX, "XR_CAP")
    self.assertEqual((out / "matching_finding_ids.txt").read_text(), f"{self.ids[0]}\n")
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["findings_expected"], 1)

  def test_invalid_limit_dies(self):
    self.stage_tasks("XR_BAD", [{
        "repo_id": REPO, "language": "python",
        "findings_gcs_uri": self.find_uri, "severity": "CRITICAL,HIGH",
    }])
    for var in ("VERIFY_LIMIT", "FIX_LIMIT"):
      for value in ("abc", "-1", "08", "1.5"):
        with self.subTest(var=var, value=value):
          p = self.run_ep("fix", "XR_BAD", extra_env={"FROM_FIND_RUN": "FRUN",
                                                      var: value})
          self.assertEqual(p.returncode, 1, p.stderr)
          self.assertIn(f"FATAL: {var} must be a non-negative integer", p.stderr)
          self.assertEqual(self.cm_calls(), [])


class SelftestTest(EntrypointTestBase):

  def run_selftest(self, job, deny_write, deny_read=""):
    for s in ("getent",):
      shutil.copy(STUBS / s, self.bin / s)
    self.put(f"gs://{PAYLOAD}/marker", "x")
    self.put(f"gs://{FIND}/marker", "x")
    self.put(f"gs://{VERIFY}/marker", "x")
    return self.run_ep("selftest", "unused", extra_env={
        "CLOUD_RUN_JOB": job, "CLOUD_RUN_EXECUTION": f"{job}-exec1",
        "GCS_DENY_WRITE": deny_write, "GCS_DENY_READ": deny_read})

  def result(self, bucket, job):
    path = self.emu / bucket / "selftest" / f"{job}-exec1" / "result.json"
    return json.loads(path.read_text())

  def test_find_selftest_all_pass(self):
    p = self.run_selftest("cm-find-runner", f"{PAYLOAD},{VERIFY},{FIX}", f"{VERIFY},{FIX}")
    self.assertEqual(p.returncode, 0, p.stderr)
    r = self.result(FIND, "cm-find-runner")
    self.assertEqual(r["role"], "find")
    names = {c["name"]: c["pass"] for c in r["checks"]}
    for n in ("dns_private_vip", "googleapis_https", "egress_github_blocked",
              "egress_1111_blocked", "own_bucket_create",
              "own_bucket_overwrite_denied", "payload_write_denied",
              "find_sa_read_verify_results_denied", "find_sa_read_fix_results_denied",
              "payload_read"):
      self.assertTrue(names.get(n), f"{n}: {r['checks']}")
    self.assertTrue(r["all_pass"])
    self.assertNotIn("toolbox_gcc", names)
    self.assertEqual(self.cm_calls(), [])

  def test_verify_selftest_detects_open_payload(self):
    p = self.run_selftest("cm-verify-runner", f"{FIND},{FIX}", FIX)  # payload writable: a bug
    self.assertEqual(p.returncode, 0, p.stderr)
    r = self.result(VERIFY, "cm-verify-runner")
    names = {c["name"]: c["pass"] for c in r["checks"]}
    self.assertFalse(names["payload_write_denied"])
    self.assertTrue(names["verify_sa_write_find_results_denied"])
    self.assertTrue(names["verify_sa_read_find_results"])
    self.assertTrue(names["verify_sa_read_fix_results_denied"])
    self.assertFalse(r["all_pass"])
    for n in ("toolbox_python_libs", "toolbox_gxx_asan", "airgap_pip_install_fails",
              "airgap_git_ls_remote_fails", "render_verify_context"):
      self.assertIn(n, names)
    self.assertTrue(names["render_verify_context"])

  def test_fix_selftest_detects_open_payload(self):
    p = self.run_selftest("cm-fix-runner", f"{FIND},{VERIFY}", "")
    self.assertEqual(p.returncode, 0, p.stderr)
    r = self.result(FIX, "cm-fix-runner")
    self.assertEqual(r["role"], "fix")
    names = {c["name"]: c["pass"] for c in r["checks"]}
    self.assertFalse(names["payload_write_denied"])
    self.assertTrue(names["fix_sa_write_find_results_denied"])
    self.assertTrue(names["fix_sa_write_verify_results_denied"])
    self.assertTrue(names["fix_sa_read_find_results"])
    self.assertTrue(names["fix_sa_read_verify_results"])
    self.assertFalse(r["all_pass"])
    for n in ("toolbox_python_libs", "toolbox_gxx_asan", "airgap_pip_install_fails",
              "airgap_git_ls_remote_fails", "render_verify_context"):
      self.assertIn(n, names)
    self.assertTrue(names["render_verify_context"])

  def test_selftest_unknown_job_fails(self):
    p = self.run_selftest("other-job", "")
    self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
  unittest.main()
