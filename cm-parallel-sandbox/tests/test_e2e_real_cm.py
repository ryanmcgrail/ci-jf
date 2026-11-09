"""Opt-in E2E: the real cm binary through entrypoint.sh (LE2E-01).

DiffRealCmTest runs MODE=diff on the VAmPI cases of config/repos_with_diff.tsv.

Skipped unless CM_E2E_REAL_ZIP points at the real cm-linux-amd64.zip, because
it spends model tokens. GCS stays emulated; cm and cm-api-token-stats talk to
Vertex with the caller's ADC. Run via `gate.sh LE2E`. Set CM_E2E_CM_VERSION
when the zip is not cm 0.11.0.
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
import unittest

import stage_repos
from cmrun import common
from tests.test_run_diff import RealGitRunner
from tests.test_entrypoint import (EntrypointTestBase, FIND, PAYLOAD, REPO,
                                   ROOT)

REAL_ZIP = os.environ.get("CM_E2E_REAL_ZIP")
# Version the zip in CM_E2E_REAL_ZIP is (>= 0.10.0); defaults to run.py's.
CM_VERSION = os.environ.get("CM_E2E_CM_VERSION", "0.11.0")
ACCEPTED = re.compile(r"StartSession\b.*\baccepted\b.*\bsession=(Ch[\w-]+)")
VULNERABLE_APP = '''import os, pickle, sqlite3
from flask import Flask, request
app = Flask(__name__)

@app.route("/ping")
def ping():
  return os.popen("ping -c 1 " + request.args["host"]).read()

@app.route("/user")
def user():
  db = sqlite3.connect("app.db")
  return str(db.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"]).fetchall())

@app.route("/load", methods=["POST"])
def load():
  return str(pickle.loads(request.data))
'''


@unittest.skipUnless(REAL_ZIP, "set CM_E2E_REAL_ZIP to run against real cm")
class RealCmTest(EntrypointTestBase):

  def setUp(self):
    super().setUp()
    shutil.copy(ROOT / "container" / "scripts" / "cm-api-token-stats",
                self.bin / "cm-api-token-stats")
    gcloud_dir = pathlib.Path.home() / ".config" / "gcloud"
    self.project = os.environ.get("CM_E2E_PROJECT") or subprocess.run(
        ["gcloud", "config", "get-value", "project"], capture_output=True,
        text=True).stdout.strip()
    # cm and the token-stats script run under the temporary HOME, so point
    # them at the caller's gcloud config and ADC explicitly.
    self.auth_env = {
        "CLOUDSDK_CONFIG": os.environ.get("CLOUDSDK_CONFIG", str(gcloud_dir)),
        "GOOGLE_APPLICATION_CREDENTIALS": os.environ.get(
            "GOOGLE_APPLICATION_CREDENTIALS",
            str(gcloud_dir / "application_default_credentials.json")),
        "PROJECT_ID": self.project,
    }
    # The gcloud stub on PATH hands out a fake token, so cm-api-token-stats
    # would 401 on every turn and report 0 tokens. Mint a real ADC token here,
    # in the caller's environment, and pass it as ACCESS_TOKEN (which the
    # script prefers); the stub keeps serving the emulated-GCS uploads.
    if os.environ.get("GCLOUD_STUB_REAL_AUTH"):
      self.auth_env["GCLOUD_STUB_REAL_AUTH"] = os.environ["GCLOUD_STUB_REAL_AUTH"]
    token = os.environ.get("ACCESS_TOKEN") or subprocess.run(
        ["gcloud", "auth", "application-default", "print-access-token"],
        capture_output=True, text=True).stdout.strip()
    if not token:
      self.fail("no ADC token: run `gcloud auth application-default login`")
    self.auth_env["ACCESS_TOKEN"] = token
    if not self.project:
      self.fail("no project: set CM_E2E_PROJECT or gcloud config project")

  def _stage_cm_zip(self, cm_version="0.9.0"):
    if not REAL_ZIP:
      return super()._stage_cm_zip(cm_version)
    data = pathlib.Path(REAL_ZIP).read_bytes()
    self.put(f"gs://{PAYLOAD}/bin/cm/{cm_version}/cm-linux-amd64.zip", data)
    return hashlib.sha256(data).hexdigest()

  def _stage_repo_tarball(self):
    src = self.tmp / "src" / REPO
    src.mkdir(parents=True)
    (src / "app.py").write_text(VULNERABLE_APP)
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    subprocess.run(["git", "-C", str(src), "add", "."], check=True)
    subprocess.run(["git", "-C", str(src), "commit", "-qm", "init"], check=True,
                   env=env)
    tgz = self.tmp / "repo.tar.gz"
    with tarfile.open(tgz, "w:gz") as tf:
      tf.add(src, arcname=REPO)
    self.put(f"gs://{PAYLOAD}/repos/{REPO}.tar.gz", tgz.read_bytes())

  def _find(self, run_id, **env):
    self.stage_tasks(run_id, [{"repo_id": REPO, "language": "python"}])
    p = self.run_ep("find", run_id, cm_version=CM_VERSION, timeout=3600,
                    extra_env={**self.auth_env, **env})
    self.assertEqual(p.returncode, 0, p.stderr[-4000:])
    out = self.results(FIND, run_id)
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok", summary)
    severities = summary["severity_counts"]
    self.assertGreaterEqual(
        severities.get("CRITICAL", 0) + severities.get("HIGH", 0), 1, summary)
    self.assertTrue((out / "state.db").is_file())
    for side in ("state.db-wal", "state.db-shm"):
      self.assertFalse((out / side).exists(), side)
    self.assertTrue((out / "logs" / "cm_logs.tar.gz").is_file())
    self.assertEqual(summary["token_stats_status"], "ok", summary)
    self.assertGreater(summary["tokens"]["total_tokens"], 0, summary)
    cm_stats = json.loads((out / "cm_stats.json").read_text())
    self.assertNotIn("error", cm_stats)
    self.assertIn("total_tokens", cm_stats)
    return out, summary

  def test_le2e_01_shallow(self):
    self._find("LS")

  def test_le2e_01_deep(self):
    out, summary = self._find("LD", MODE="deep", DEEP_WORKERS="2")
    sessions = summary["sessions"]
    self.assertEqual(summary["deep_workers"], 2)
    self.assertGreaterEqual(sessions["union"], 1)
    with tarfile.open(out / "logs" / "cm_logs.tar.gz") as tf:
      text = "".join(tf.extractfile(m).read().decode(errors="replace")
                     for m in tf.getmembers() if m.isfile())
    logged = set(ACCEPTED.findall(text))
    self.assertGreaterEqual(len(logged), 1)
    self.assertEqual(len(logged), sessions["logs"])
    c = sqlite3.connect(f"file:{out / 'state.db'}?immutable=1", uri=True)
    try:
      rows = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    finally:
      c.close()
    self.assertEqual(rows, sessions["state_db"])


@unittest.skipUnless(REAL_ZIP, "set CM_E2E_REAL_ZIP to run against real cm")
class DiffRealCmTest(RealCmTest):
  """MODE=diff on the VAmPI cases of config/repos_with_diff.tsv.

  Tarballs come from stage_repos.stage_one_diff (real git against GitHub,
  emulated GCS); counts must match a local diff_stats.py run on the same tree.
  """

  CASES = ("o04-vampi--f16052d-beca461", "o04-vampi--f16052d-a488a52")

  def _stage_repo_tarball(self):
    pass  # staged per case in _diff

  def _diff(self, case):
    row = common.load_repos(ROOT / "config" / "repos_with_diff.tsv")[case]
    runner = RealGitRunner()
    stage_repos.stage_one_diff(runner, case, row, f"gs://{PAYLOAD}", False,
                               str(self.tmp / "stage"))
    uri = common.repo_tarball_uri(PAYLOAD, case)
    self.put(uri, runner.gcs[uri])
    local = self.tmp / "local"
    local.mkdir(exist_ok=True)
    with tarfile.open(self.gcs(uri)) as tf:
      tf.extractall(local, filter="fully_trusted")
    expected = json.loads(subprocess.run(
        ["python3", str(ROOT / "container" / "scripts" / "diff_stats.py"),
         "--repo", str(local / case), "--config",
         str(ROOT / "config" / "cm_config.yaml"), "--base", row["diff_ref"]],
        check=True, capture_output=True, text=True).stdout)
    self.stage_tasks(case, [{"repo_id": case, "language": "python",
                             "pinned_ref": row["pinned_ref"],
                             "diff_ref": row["diff_ref"]}])
    p = self.run_ep("find", case, cm_version=CM_VERSION, timeout=3600,
                    extra_env={**self.auth_env, "MODE": "diff"})
    self.assertEqual(p.returncode, 0, p.stderr[-4000:])
    out = self.emu / FIND / "exp" / case / case
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "ok", summary)
    self.assertEqual(summary["mode"], "diff")
    self.assertEqual((summary["pinned_ref"], summary["diff_ref"]),
                     (row["pinned_ref"], row["diff_ref"]))
    self.assertEqual({k: summary[k] for k in expected}, expected)
    self.assertIn(summary["cm_exit_code"], (0, 1))
    self.assertIsNone(summary["diff_workers"])
    log = (out / "logs" / "execution.log").read_text()
    self.assertIn("PR Delta Scan Complete", log)
    self.assertIn(f"merge-base({row['diff_ref']}", log)
    self.assertNotIn("No changes detected in diff", log)
    json.loads((out / "findings.json").read_text())
    print(f"\n[e2e-diff] {case}: " + json.dumps(
        {k: summary.get(k) for k in ("changed_files", "changed_lines",
                                     "cm_exit_code", "findings_count",
                                     "severity_counts", "wall_clock_seconds",
                                     "diff_timed_out", "diff_jobs_total",
                                     "diff_jobs_completed")}
        | {"total_tokens": summary["tokens"]["total_tokens"],
           "input_tokens": summary["tokens"]["input_tokens"],
           "output_tokens": summary["tokens"]["output_tokens"]}))
    return summary

  def test_le2e_01_shallow(self):
    self.skipTest("covered by RealCmTest")

  def test_le2e_01_deep(self):
    self.skipTest("covered by RealCmTest")

  def test_le2e_diff_vampi_s(self):
    self._diff(self.CASES[0])

  def test_le2e_diff_vampi_m(self):
    self._diff(self.CASES[1])


if __name__ == "__main__":
  unittest.main()
