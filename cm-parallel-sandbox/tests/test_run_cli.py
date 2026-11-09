"""Tests for run.py (fake runner; no real gcloud)."""

import contextlib
import io
import json
import pathlib
import unittest
import unittest.mock

import run
from cmrun import common
from tests.fakes import FakeRunner

P = "proj"
PAYLOAD = f"gs://{P}-cm-payload"
FIND = f"gs://{P}-cm-find-results"
VERIFY = f"gs://{P}-cm-verify-results"
FIX = f"gs://{P}-cm-fix-results"
ZIP = f"{PAYLOAD}/bin/cm/0.11.0/cm-linux-amd64.zip"
SHA = "a" * 64
FIXTURE = (pathlib.Path(__file__).parent / "fixtures" / "findings.json").read_bytes()


import time


def fake_download(args):
  dest = [a for a in args if a.startswith("--destination=")][0].split("=", 1)[1]
  (pathlib.Path(dest) / "cm-linux-amd64.zip").write_bytes(b"zipbytes")
  return common.Result(0)


def fake_execute(args):
  job = args[4]
  return common.Result(0, json.dumps({"metadata": {"name": f"{job}-exec1"}}))


def fake_describe(args):
  name = args[5]
  return common.Result(0, json.dumps({
      "metadata": {"name": name},
      "spec": {"taskCount": 1},
      "status": {
          "succeededCount": 1,
          "conditions": [{
              "type": "Completed",
              "status": "True",
              "message": "Execution completed successfully in 10s."
          }]
      }
  }))


def staged_runner(responses=None, **extra):
  gcs = {ZIP: b"z", ZIP + ".sha256": f"{SHA}  cm-linux-amd64.zip\n".encode(),
         f"{PAYLOAD}/repos/o04-vampi.tar.gz": b"t",
         f"{PAYLOAD}/repos/p01-flask.tar.gz": b"t"}
  gcs.update(extra)
  resp = {
      "gcloud artifacts generic download": fake_download,
      "gcloud run jobs execute": fake_execute,
      "gcloud run jobs executions": fake_describe,
  }
  if responses:
    resp.update(responses)
  return FakeRunner(gcs=gcs, responses=resp)


def main(argv, runner, sleep=lambda _: None, clock=time.monotonic,
         poll_interval=0, is_tty=False):
  out = []
  rc = run.main(["--project", P] + argv, runner=runner, log=out.append,
                sleep=sleep, clock=clock,
                poll_interval=poll_interval, is_tty=is_tty)
  return rc, "\n".join(out)


def execute_call(r):
  return [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]][0]


def uploaded_json(r, suffix):
  key = [k for k in r.gcs if k.endswith(suffix)][0]
  return json.loads(r.gcs[key])


class DefaultsTest(unittest.TestCase):

  def test_defaults(self):
    _, a = run.parse_args([])
    self.assertEqual(a.cm_version, "0.11.0")
    self.assertEqual(a.operation, "find")
    self.assertEqual(a.mode, "shallow")
    self.assertEqual(a.container_timeout, 172800)
    self.assertEqual(a.fix_timeout, 10800)
    self.assertEqual(a.severity, "CRITICAL,HIGH")
    self.assertEqual(a.model, "gemini-3.8-flash")
    self.assertEqual(a.experiment_id, "default")
    self.assertEqual(a.region, "us-central1")
    self.assertFalse(a.wait)
    self.assertFalse(a.dry_run)
    self.assertIsNone(a.deep_workers)
    self.assertEqual(a.poll_interval, 300)
    self.assertEqual(a.verify_limit, 0)
    self.assertEqual(a.fix_limit, 0)
    self.assertIsNone(a.from_verify_run)
    self.assertFalse(a.include_unverified)
    self.assertIsNone(a.finding_ids)

  def test_poll_interval_flag(self):
    _, a = run.parse_args(["--poll-interval", "60"])
    self.assertEqual(a.poll_interval, 60)

  def test_invalid_poll_interval_rejected(self):
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
      run.parse_args(["--poll-interval", "0"])
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
      run.parse_args(["--poll-interval", "-10"])

  def test_verify_requires_from_find_run(self):
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
      run.parse_args(["--operation", "verify"])

  def test_deep_rejected_on_cm_0_9_0(self):
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--mode", "deep", "--cm-version", "0.9.0"])
    self.assertIn("--mode deep requires --cm-version >= 0.10.0", err.getvalue())

  def test_unknown_repo(self):
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
      main(["--repos", "nope"], staged_runner())


class FindTest(unittest.TestCase):

  def test_find_routing_and_tasks(self):
    r = staged_runner()
    rc, out = main(["--repos", "o04-vampi",
                    "--experiment-id", "smoke", "--run-id", "RID"], r)
    self.assertEqual(rc, 0)
    ex = execute_call(r)
    self.assertEqual(ex[4], "cm-find-runner")
    self.assertIn("--tasks=1", ex)
    self.assertIn("--task-timeout=172800s", ex)
    self.assertIn("--async", ex)
    tasks = uploaded_json(r, "/runs/smoke/RID/tasks.json")
    self.assertEqual([t["repo_id"] for t in tasks], ["o04-vampi"])
    self.assertNotIn("repeat", tasks[0])
    man = uploaded_json(r, "/runs/smoke/RID/run_manifest.json")
    self.assertEqual(man["results_prefix"], f"{FIND}/smoke/RID/")
    self.assertNotIn("repeats", man)
    self.assertEqual(man["cm_sha256"], SHA)
    self.assertIn(f"{FIND}/smoke/RID/", out)

  def test_repos_filter_all_batches_single_ls(self):
    r = FakeRunner(gcs={ZIP: b"z", ZIP + ".sha256": SHA.encode(),
                        **{f"{PAYLOAD}/repos/{k}.tar.gz": b"t"
                           for k in common.load_repos()}})
    main(["--run-id", "R"], r)
    self.assertIn("--tasks=88", execute_call(r))
    repo_ls = [c for c in r.calls
               if c[:3] == ["gcloud", "storage", "ls"] and "/repos/" in c[-1]]
    self.assertEqual(repo_ls, [["gcloud", "storage", "ls", f"{PAYLOAD}/repos/"]])

  def test_wait_flag(self):
    r = staged_runner()
    main(["--repos", "o04-vampi", "--wait"], r)
    self.assertIn("--async", execute_call(r))
    self.assertNotIn("--wait", execute_call(r))
    describes = [c for c in r.calls
                 if c[:5] == ["gcloud", "run", "jobs", "executions", "describe"]]
    self.assertEqual(len(describes), 1)
    self.assertEqual(describes[0][5], "cm-find-runner-exec1")

  def test_env_vars_passed(self):
    r = staged_runner()
    main(["--repos", "o04-vampi", "--run-id", "RID", "--extra-cm-args",
          "--max-turns 16, --verbose"], r)
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertTrue(env.startswith("--update-env-vars=^##^"))
    pairs = dict(kv.split("=", 1) for kv in env.split("^##^", 1)[1].split("##"))
    self.assertEqual(pairs["EXPECTED_CM_SHA256"], SHA)
    self.assertEqual(pairs["CM_VERSION"], "0.11.0")
    self.assertEqual(pairs["RUN_ID"], "RID")
    self.assertEqual(pairs["EXTRA_CM_ARGS"], "--max-turns 16, --verbose")

  def test_existing_run_id_refused(self):
    r = staged_runner(**{f"{PAYLOAD}/runs/smoke/RID/tasks.json": b"[]"})
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      main(["--repos", "o04-vampi", "--experiment-id", "smoke", "--run-id", "RID"], r)
    self.assertIn("run RID already exists in experiment 'smoke'", err.getvalue())
    self.assertFalse(any(c[:3] == ["gcloud", "run", "jobs"] for c in r.calls))

  def test_run_id_format(self):
    r = staged_runner()
    _, out = main(["--repos", "o04-vampi"], r)
    rid = [l for l in out.splitlines() if l.startswith("run_id=")][0][7:]
    self.assertRegex(rid, r"^\d{8}_\d{6}_find_v0\.11\.0_gemini-3\.8-flash$")


class TokenStatsWorkersTest(unittest.TestCase):
  """--token-stats-workers is always sent as TOKEN_STATS_WORKERS (default 8)."""

  def _env(self, r):
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    return dict(kv.split("=", 1) for kv in env.split("^##^", 1)[1].split("##"))

  def test_token_stats_workers_default(self):
    self.assertEqual(run.DEFAULT_TOKEN_STATS_WORKERS, 8)
    _, a = run.parse_args([])
    self.assertEqual(a.token_stats_workers, 8)
    r = staged_runner()
    rc, _ = main(["--repos", "o04-vampi", "--experiment-id", "smoke",
                  "--run-id", "RID"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(self._env(r)["TOKEN_STATS_WORKERS"], "8")
    man = uploaded_json(r, "/runs/smoke/RID/run_manifest.json")
    self.assertEqual(man["token_stats_workers"], 8)

  def test_token_stats_workers_override_and_validation(self):
    r = staged_runner()
    rc, _ = main(["--repos", "o04-vampi", "--token-stats-workers", "3"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(self._env(r)["TOKEN_STATS_WORKERS"], "3")
    for value in ("0", "-2"):
      with self.subTest(value=value):
        err = io.StringIO()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):
          run.parse_args(["--token-stats-workers", value])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("--token-stats-workers must be >= 1", err.getvalue())


class DeepWorkersTest(unittest.TestCase):
  """F21: deep concurrency is --deep-workers x repos, capped by the budget."""

  def _run(self, argv, repos=None):
    zip10 = f"{PAYLOAD}/bin/cm/0.10.0/cm-linux-amd64.zip"
    gcs = {ZIP: b"z", ZIP + ".sha256": SHA.encode(),
           zip10: b"z", zip10 + ".sha256": SHA.encode()}
    gcs.update({f"{PAYLOAD}/repos/{k}.tar.gz": b"t" for k in common.load_repos()})
    r = FakeRunner(gcs=gcs)
    deep = ["--mode", "deep"]
    if repos is not None:
      deep += ["--repos", *sorted(common.load_repos())[:repos]]
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
      try:
        rc, out = main(deep + argv, r)
      except SystemExit as e:
        rc, out = e.code, ""
    return rc, out, err.getvalue(), r

  def _env(self, r):
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    return dict(kv.split("=", 1) for kv in env.split("^##^", 1)[1].split("##"))

  def test_run_01_defaults_and_range(self):
    total = len(common.load_repos())
    self.assertEqual(run.DEFAULT_DEEP_WORKERS, 8)
    rc, out, _, r = self._run([])
    self.assertEqual(rc, 0)
    self.assertEqual(self._env(r)["CM_VERSION"], "0.11.0")
    self.assertEqual(self._env(r)["DEEP_WORKERS"], "8")
    self.assertIn(f"deep workers 8/task ({total * 8}/900 calls)", out)
    rc, _, _, r = self._run(["--deep-workers", "16"], repos=56)
    self.assertEqual((rc, self._env(r)["DEEP_WORKERS"]), (0, "16"))
    rc, _, err, _ = self._run(["--deep-workers", "17"], repos=1)
    self.assertEqual(rc, 2)
    self.assertIn("--deep-workers must be between 1 and 16", err)
    rc, _, err, _ = self._run(["--cm-version", "0.9.0"], repos=1)
    self.assertEqual(rc, 2)
    self.assertIn("--mode deep requires --cm-version >= 0.10.0", err)

  def test_over_budget_errors_before_staging(self):
    rc, _, err, r = self._run(["--deep-workers", "16"], repos=57)
    self.assertEqual(rc, 2)
    self.assertIn("deep find would run 57 repo(s) x 16 worker(s) = 912 concurrent"
                  " model calls, over the budget of 900; rerun with"
                  " --deep-workers 15 or at most 56 repo(s) via --repos", err)
    self.assertEqual(r.calls, [])

  def test_all_repos_at_default_workers(self):
    # Without --deep-workers, all repos must fit the call budget (88 x 8 = 704).
    total = len(common.load_repos())
    workers = run.DEFAULT_DEEP_WORKERS
    self.assertLessEqual(total * workers, run.DEEP_CALL_BUDGET)
    rc, out, _, r = self._run([])
    self.assertEqual(rc, 0)
    self.assertEqual(self._env(r)["DEEP_WORKERS"], str(workers))
    self.assertIn(f"({total * workers}/{run.DEEP_CALL_BUDGET} calls)", out)

  def test_shallow_sends_empty_deep_workers(self):
    r = staged_runner()
    rc, out = main(["--repos", "o04-vampi"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(self._env(r)["DEEP_WORKERS"], "")
    self.assertIn("[dispatch] cm-find-runner: 1 task(s)\n", out + "\n")
    _, a = run.parse_args([])
    self.assertIsNone(a.deep_workers)

  def test_never_updates_job(self):
    r = staged_runner()
    main(["--repos", "o04-vampi"], r)
    jobs = [c[3] for c in r.calls if c[:3] == ["gcloud", "run", "jobs"]]
    self.assertEqual(jobs, ["execute"])


class CmBinaryTest(unittest.TestCase):

  def test_download_when_missing(self):
    r = FakeRunner(gcs={f"{PAYLOAD}/repos/o04-vampi.tar.gz": b"t"},
                   responses={"gcloud artifacts generic download": fake_download})
    main(["--repos", "o04-vampi"], r)
    dl = [c for c in r.calls if c[:4] == ["gcloud", "artifacts", "generic", "download"]][0]
    for flag in ("--project=cmoc-prod", "--location=us",
                 "--repository=codemender-cli-production", "--package=cm",
                                   "--version=0.11.0", "--name=cm-linux-amd64.zip"):
      self.assertIn(flag, dl)
    import hashlib
    want = hashlib.sha256(b"zipbytes").hexdigest()
    self.assertEqual(r.gcs[ZIP], b"zipbytes")
    self.assertTrue(r.gcs[ZIP + ".sha256"].decode().startswith(want))
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertIn(f"EXPECTED_CM_SHA256={want}", env)

  def test_download_failure_errors_with_credentials_hint(self):
    def denied(args):  # what common.Runner.run(check=True) raises
      raise RuntimeError(
          f"command failed (1): {' '.join(args)}\n"
          "ERROR: (gcloud.artifacts.generic.download) PERMISSION_DENIED: "
          "caller lacks permission\n")
    r = FakeRunner(gcs={f"{PAYLOAD}/repos/o04-vampi.tar.gz": b"t"},
                   responses={"gcloud artifacts generic download": denied})
    rc, out = main(["--repos", "o04-vampi"], r)
    self.assertEqual(rc, 1)
    self.assertIn("error: failed to download cm 0.11.0 from Artifact Registry", out)
    self.assertIn("gcloud auth login", out)
    self.assertIn("PERMISSION_DENIED", out)
    self.assertNotIn(ZIP, r.gcs)
    self.assertFalse(any(c[:1] == ["curl"] for c in r.calls))
    self.assertFalse(any(c[:3] == ["gcloud", "run", "jobs"] for c in r.calls))

  def test_skip_download_when_cached(self):
    r = staged_runner()
    main(["--repos", "o04-vampi"], r)
    self.assertFalse(any(c[:3] == ["gcloud", "artifacts", "generic"] for c in r.calls))

  def test_cm_version_flag(self):
    r = FakeRunner(gcs={f"{PAYLOAD}/repos/o04-vampi.tar.gz": b"t"},
                   responses={"gcloud artifacts generic download": fake_download})
    main(["--repos", "o04-vampi", "--cm-version", "0.8.0"], r)
    self.assertIn(f"{PAYLOAD}/bin/cm/0.8.0/cm-linux-amd64.zip", r.gcs)


class DryRunTest(unittest.TestCase):

  def test_dry_run_no_mutations(self):
    r = FakeRunner()  # nothing cached, nothing staged
    rc, out = main(["--repos", "o04-vampi", "--dry-run"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(r.mutating_calls(), [])
    self.assertIn("gcloud run jobs execute cm-find-runner", out)
    self.assertIn('"repo_id": "o04-vampi"', out)


class VerifyTest(unittest.TestCase):

  def _runner(self):
    empty = json.dumps([{"finding_id": "x", "severity": "LOW"}]).encode()
    return staged_runner(**{
        f"{FIND}/smoke/FRUN/o04-vampi/findings.json": FIXTURE,
        f"{FIND}/smoke/FRUN/p01-flask/findings.json": empty,
    })

  def test_verify_routing_and_severity_filter(self):
    r = self._runner()
    rc, _ = main(["--operation", "verify", "--from-find-run", "FRUN",
                  "--repos", "o04-vampi", "p01-flask", "--run-id", "VR",
                  "--experiment-id", "smoke"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(execute_call(r)[4], "cm-verify-runner")
    tasks = uploaded_json(r, "/runs/smoke/VR/tasks.json")
    self.assertEqual([t["repo_id"] for t in tasks], ["o04-vampi"])
    self.assertEqual(tasks[0]["matching_findings"], 3)
    self.assertEqual(tasks[0]["findings_gcs_uri"],
                     f"{FIND}/smoke/FRUN/o04-vampi/findings.json")
    man = uploaded_json(r, "/runs/smoke/VR/run_manifest.json")
    self.assertEqual(man["results_prefix"], f"gs://{P}-cm-verify-results/smoke/VR/")
    self.assertNotIn("repeats", man)
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertIn("FROM_FIND_RUN=FRUN", env)
    self.assertIn("SOURCE_FIND_EXPERIMENT=smoke", env)
    self.assertIn("VERIFY_LIMIT=0", env)

  def test_verify_from_find_run_latest(self):
    r = staged_runner(**{
        f"{FIND}/smoke/20260927_001000_find/o04-vampi/findings.json": b"[]",
        f"{FIND}/smoke/20260927_002000_find/o04-vampi/findings.json": FIXTURE,
        f"{FIND}/smoke/20260927_001000_find/o04-vampi/summary.json": b"{}",
        f"{FIND}/smoke/20260927_002000_find/o04-vampi/summary.json": b"{}",
    })
    rc, _ = main(["--operation", "verify", "--from-find-run", "latest",
                  "--experiment-id", "smoke", "--repos", "o04-vampi",
                  "--run-id", "VR"], r)
    self.assertEqual(rc, 0)
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertIn("FROM_FIND_RUN=20260927_002000_find", env)
    self.assertIn("SOURCE_FIND_EXPERIMENT=smoke", env)

  def test_find_verify_pipeline(self):
    r = staged_runner(**{
        f"{FIND}/smoke/PIPE/o04-vampi/findings.json": FIXTURE,
    })
    rc, out = main(["--operation", "find-verify", "--experiment-id", "smoke",
                    "--repos", "o04-vampi", "--run-id", "PIPE", "--verify-limit", "1"], r)
    self.assertEqual(rc, 0)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs], ["cm-find-runner", "cm-verify-runner"])
    self.assertIn("--async", execs[0])   # find phase always dispatches async then polls
    self.assertIn("--async", execs[1])  # verify phase respects caller's --wait
    describes = [c for c in r.calls
                 if c[:5] == ["gcloud", "run", "jobs", "executions", "describe"]]
    self.assertEqual(len(describes), 1)
    self.assertEqual(describes[0][5], "cm-find-runner-exec1")
    self.assertIn("run_id=PIPE\n", out)
    self.assertIn("run_id=PIPE_verify", out)
    self.assertIn("[phase] find phase (PIPE) complete; transitioning to verify", out)
    self.assertIn("[summary] o04-vampi: 5 finding(s)", out)
    self.assertIn("CRITICAL=1, HIGH=2, MEDIUM=1, LOW=1", out)
    self.assertIn("3 matching CRITICAL,HIGH", out)

  def _env(self, r, job):
    ex = [c for c in r.calls if c[:5] == ["gcloud", "run", "jobs", "execute",
                                          job]][0]
    env = [a for a in ex if a.startswith("--update-env-vars=")][0]
    return dict(kv.split("=", 1) for kv in env.split("^##^", 1)[1].split("##"))

  def test_run_03_chained_verify_is_shallow(self):
    r = staged_runner(**{
        f"{FIND}/smoke/PIPE/o04-vampi/findings.json": FIXTURE,
    })
    rc, _ = main(["--operation", "find-verify", "--experiment-id", "smoke",
                  "--repos", "o04-vampi", "--run-id", "PIPE", "--mode", "deep",
                  "--deep-workers", "4"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(self._env(r, "cm-find-runner")["MODE"], "deep")
    env = self._env(r, "cm-verify-runner")
    self.assertEqual((env["MODE"], env["DEEP_WORKERS"]), ("shallow", ""))
    man = uploaded_json(r, "/runs/smoke/PIPE_verify/run_manifest.json")
    self.assertEqual(man["source_find_mode"], "deep")
    tasks = uploaded_json(r, "/runs/smoke/PIPE_verify/tasks.json")
    self.assertEqual(tasks[0]["source_find_mode"], "deep")

  def test_run_03_standalone_verify_reads_find_manifest(self):
    r = self._runner()
    r.gcs[f"{PAYLOAD}/runs/smoke/FRUN/run_manifest.json"] = json.dumps(
        {"mode": "deep"}).encode()
    rc, _ = main(["--operation", "verify", "--from-find-run", "FRUN",
                  "--experiment-id", "smoke", "--repos", "o04-vampi",
                  "--run-id", "VR"], r)
    self.assertEqual(rc, 0)
    env = self._env(r, "cm-verify-runner")
    self.assertEqual((env["MODE"], env["DEEP_WORKERS"]), ("shallow", ""))
    self.assertEqual(
        uploaded_json(r, "/runs/smoke/VR/run_manifest.json")["source_find_mode"],
        "deep")
    self.assertEqual(
        uploaded_json(r, "/runs/smoke/VR/tasks.json")[0]["source_find_mode"],
        "deep")

  def test_find_verify_find_failure_clean_rc(self):
    r = staged_runner(**{
        f"{FIND}/smoke/OLD/o04-vampi/findings.json": FIXTURE,
    })
    r.responses["gcloud run jobs execute"] = common.Result(1, "", "failed")
    rc, out = main(["--operation", "find-verify", "--experiment-id", "smoke",
                    "--repos", "o04-vampi", "--run-id", "PIPE"], r)
    self.assertEqual(rc, 1)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs], ["cm-find-runner"])  # no verify
    self.assertIn("run_id=PIPE\n", out)  # logged before the blocking wait
    self.assertIn("error: cm-find-runner run PIPE failed", out)
    self.assertIn("--from-find-run smoke/PIPE", out)

  def test_run_id_logged_before_dispatch(self):
    r = staged_runner()
    _, out = main(["--operation", "find", "--repos", "o04-vampi",
                   "--run-id", "RID"], r)
    lines = out.splitlines()
    self.assertLess(lines.index("run_id=RID"),
                    [i for i, l in enumerate(lines) if l.startswith("[dispatch]")][0])

  def test_execution_name_and_describe_logged(self):
    r = staged_runner(**{
        f"{FIND}/smoke/PIPE/o04-vampi/findings.json": FIXTURE,
    })
    r.responses["gcloud run jobs execute"] = lambda args: common.Result(
        0, json.dumps({"metadata": {"name": f"{args[4]}-x1y2z"}}))
    rc, out = main(["--operation", "find-verify", "--experiment-id", "smoke",
                    "--repos", "o04-vampi", "--run-id", "PIPE"], r)
    self.assertEqual(rc, 0)
    verify_exec = [c for c in r.calls
                   if c[:5] == ["gcloud", "run", "jobs", "execute",
                                "cm-verify-runner"]][0]
    self.assertIn("--async", verify_exec)
    for job in ("cm-find-runner", "cm-verify-runner"):
      self.assertIn(f"execution={job}-x1y2z\n", out)
      self.assertIn(
          f"status: gcloud run jobs executions describe {job}-x1y2z "
          f"--project={P} --region={common.DEFAULT_REGION}", out)
      self.assertIn(
          f"logs: gcloud logging read 'resource.type=\"cloud_run_job\" AND "
          f"resource.labels.job_name=\"{job}\" AND resource.labels.location=\"{common.DEFAULT_REGION}\" "
          f"AND labels.\"run.googleapis.com/execution_name\"=\"{job}-x1y2z\"' --project={P} --limit=50", out)
      self.assertIn("console: https://console.cloud.google.com/logs/viewer?project=", out)

  def test_unparseable_execute_output_warns(self):
    r = staged_runner()
    r.responses["gcloud run jobs execute"] = common.Result(0, "not json")
    rc, out = main(["--operation", "find", "--repos", "o04-vampi"], r)
    self.assertEqual(rc, 0)
    self.assertIn("warning: could not parse execution name", out)
    self.assertNotIn("execution=", out)

  def test_unparseable_execute_output_with_wait_fails_cleanly(self):
    r = staged_runner()
    r.responses["gcloud run jobs execute"] = common.Result(0, "not json")
    rc, out = main(["--operation", "find", "--repos", "o04-vampi", "--wait", "--run-id", "R1"], r)
    self.assertEqual(rc, 1)
    self.assertIn("warning: could not parse execution name", out)
    self.assertIn("error: cm-find-runner run R1 failed: cannot wait on cm-find-runner run R1: execution name could not be parsed", out)

  def test_polling_progress_multistep(self):
    states = [
        {"status": {"runningCount": 2, "succeededCount": 0, "failedCount": 0}, "spec": {"taskCount": 2}},
        {"status": {"runningCount": 1, "succeededCount": 1, "failedCount": 0}, "spec": {"taskCount": 2}},
        {"status": {"runningCount": 0, "succeededCount": 2, "failedCount": 0,
                    "conditions": [{"type": "Completed", "status": "True", "message": "All tasks succeeded"}]},
         "spec": {"taskCount": 2}},
    ]
    it = iter(states)
    def describe_stepped(args):
      state = next(it)
      return common.Result(0, json.dumps(state))

    r = staged_runner(responses={"gcloud run jobs executions": describe_stepped})
    times = [0.0, 0.0, 10.0, 25.0]
    time_it = iter(times)
    rc, out = main(["--repos", "o04-vampi", "--wait"], r, clock=lambda: next(time_it, 25.0))
    self.assertEqual(rc, 0)
    self.assertIn("[progress] [00:00] cm-find-runner-exec1: 2 running, 0 succeeded, 0 failed / 2 total", out)
    self.assertIn("[progress] [00:10] cm-find-runner-exec1: 1 running, 1 succeeded, 0 failed / 2 total", out)
    self.assertIn("[summary] cm-find-runner-exec1: Completed=True (2/2 succeeded, 0 failed) in 00:25 (exit_code=0) — All tasks succeeded", out)

  def test_polling_failure_summary_and_rc1(self):
    fail_state = {
        "metadata": {"name": "cm-find-runner-fail"},
        "spec": {"taskCount": 2},
        "status": {
            "runningCount": 0,
            "succeededCount": 1,
            "failedCount": 1,
            "conditions": [{
                "type": "Completed",
                "status": "False",
                "reason": "NonZeroExitCode",
                "message": "Task 1 exited with code 1"
            }]
        }
    }
    r = staged_runner(responses={"gcloud run jobs executions": common.Result(0, json.dumps(fail_state))})
    rc, out = main(["--repos", "o04-vampi", "--wait", "--run-id", "FAIL_RUN"], r)
    self.assertEqual(rc, 1)
    self.assertIn("[summary] cm-find-runner-exec1: Completed=False [NonZeroExitCode] (1 succeeded, 1 failed / 2 total)", out)
    self.assertIn("error: cm-find-runner run FAIL_RUN failed: cm-find-runner execution cm-find-runner-exec1 failed (NonZeroExitCode): Task 1 exited with code 1", out)

  def test_polling_tty_mode_carriage_return(self):
    terminal_state = {
        "metadata": {"name": "cm-find-runner-exec1"},
        "spec": {"taskCount": 1},
        "status": {
            "succeededCount": 1,
            "conditions": [{"type": "Completed", "status": "True", "message": "Done"}]
        }
    }
    r = staged_runner(responses={"gcloud run jobs executions": common.Result(0, json.dumps(terminal_state))})
    cur_time = [0.0]
    def fake_clock():
      val = cur_time[0]
      cur_time[0] = 12.0
      return val

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
      rc = run.main(["--project", P, "--repos", "o04-vampi", "--wait"],
                    runner=r, sleep=lambda _: None, clock=fake_clock,
                    poll_interval=0, is_tty=True)
    self.assertEqual(rc, 0)
    stdout_val = captured.getvalue()
    self.assertIn("\r\033[K[progress] [00:12] cm-find-runner-exec1: 0 running, 1 succeeded, 0 failed / 1 total", stdout_val)
    self.assertIn("[summary] cm-find-runner-exec1: Completed=True (1/1 succeeded, 0 failed) in 00:12 (exit_code=0) — Done", stdout_val)

  def test_interactive_tty_detection(self):
    class FakeStdout:
      def __init__(self, isatty_val):
        self._isatty = isatty_val
      def isatty(self):
        return self._isatty

    self.assertFalse(run.is_interactive_tty(log_fn=lambda _: None, stdout=FakeStdout(True)))
    self.assertFalse(run.is_interactive_tty(log_fn=print, stdout=FakeStdout(False)))
    with unittest.mock.patch.dict("os.environ", {"TERM": "dumb"}):
      self.assertFalse(run.is_interactive_tty(log_fn=print, stdout=FakeStdout(True)))
    with unittest.mock.patch.dict("os.environ", {"TERM": ""}):
      self.assertFalse(run.is_interactive_tty(log_fn=print, stdout=FakeStdout(True)))
    with unittest.mock.patch.dict("os.environ", {"TERM": "xterm-256color", "CI": "true"}):
      self.assertFalse(run.is_interactive_tty(log_fn=print, stdout=FakeStdout(True)))
    with unittest.mock.patch.dict("os.environ", {"TERM": "xterm-256color"}, clear=True):
      self.assertTrue(run.is_interactive_tty(log_fn=print, stdout=FakeStdout(True)))

  def test_verify_summary_logging_with_severity_breakdown(self):
    r = self._runner()
    rc, out = main(["--operation", "verify", "--from-find-run", "FRUN",
                    "--repos", "o04-vampi", "p01-flask", "--run-id", "VR"], r)
    self.assertEqual(rc, 0)
    self.assertIn("[summary] o04-vampi: 5 finding(s) (CRITICAL=1, HIGH=2, MEDIUM=1, LOW=1); 3 matching CRITICAL,HIGH", out)
    self.assertIn("[summary] findings from smoke/FRUN: 6 total (CRITICAL=1, HIGH=2, MEDIUM=1, LOW=2); 3 matching CRITICAL,HIGH across 1/2 repo(s) queued for verify", out)
    self.assertIn("[verify] skip p01-flask: no CRITICAL,HIGH findings (1 total: LOW=1)", out)



  def test_verify_limit_passed_to_job(self):
    r = self._runner()
    main(["--operation", "verify", "--from-find-run", "FRUN", "--repos", "o04-vampi",
          "--run-id", "VR", "--verify-limit", "1"], r)
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertIn("VERIFY_LIMIT=1", env)

  def test_verify_severity_medium(self):
    r = self._runner()
    main(["--operation", "verify", "--from-find-run", "smoke/FRUN",
          "--repos", "o04-vampi", "--severity", "medium", "--run-id", "VR"], r)
    tasks = uploaded_json(r, "/VR/tasks.json")
    self.assertEqual(tasks[0]["matching_findings"], 1)
    self.assertEqual(tasks[0]["severity"], "MEDIUM")

  def test_verify_no_matches_returns_2(self):
    r = self._runner()
    rc, _ = main(["--operation", "verify", "--from-find-run", "FRUN",
                  "--repos", "p01-flask"], r)
    self.assertEqual(rc, 2)
    self.assertFalse(any(c[:3] == ["gcloud", "run", "jobs"] for c in r.calls))

  def test_verify_unknown_run_clear_error(self):
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      main(["--operation", "verify", "--from-find-run", "NOPE", "--repos",
            "o04-vampi", "--dry-run"], self._runner())
    self.assertIn("find run 'NOPE' not found", err.getvalue())

  def test_verify_dry_run_readonly(self):
    r = self._runner()
    rc, _ = main(["--operation", "verify", "--from-find-run", "FRUN",
                  "--repos", "o04-vampi", "--dry-run"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(r.mutating_calls(), [])


class FlagValidationMatrixTest(unittest.TestCase):

  def test_container_timeout_validation(self):
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--container-timeout", "300"])
    self.assertIn("--container-timeout must be > 300", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--container-timeout", "604801"])
    self.assertIn("--container-timeout must be <= 604800", err.getvalue())

    _, a = run.parse_args(["--container-timeout", "1000"])
    self.assertEqual(a.container_timeout, 1000)
    self.assertEqual(a.fix_timeout, 700)

  def test_fix_timeout_validation(self):
    for op in ("find", "verify", "find-verify"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        args = ["--operation", op, "--fix-timeout", "100"]
        if op == "verify":
          args += ["--from-find-run", "R"]
        run.parse_args(args)
      self.assertIn(f"--fix-timeout is not supported for --operation {op}", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix", "--from-find-run", "R", "--fix-timeout", "0"])
    self.assertIn("--fix-timeout must be > 0", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix", "--from-find-run", "R",
                      "--container-timeout", "1000", "--fix-timeout", "701"])
    self.assertIn("cannot exceed --container-timeout - 300", err.getvalue())

    _, a = run.parse_args(["--operation", "fix", "--from-find-run", "R",
                           "--container-timeout", "1000", "--fix-timeout", "700"])
    self.assertEqual(a.fix_timeout, 700)

  def test_verify_limit_validation(self):
    for op in ("find", "fix", "find-fix"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        args = ["--operation", op, "--verify-limit", "1"]
        if op == "fix":
          args += ["--from-find-run", "R"]
        run.parse_args(args)
      self.assertIn(f"--verify-limit is not supported for --operation {op}", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "verify", "--from-find-run", "R", "--verify-limit", "-1"])
    self.assertIn("--verify-limit must be >= 0", err.getvalue())

    for op in ("verify", "find-verify", "verify-fix", "find-verify-fix"):
      args = ["--operation", op, "--verify-limit", "5"]
      if op in ("verify", "verify-fix"):
        args += ["--from-find-run", "R"]
      _, a = run.parse_args(args)
      self.assertEqual(a.verify_limit, 5)

  def test_fix_limit_validation(self):
    for op in ("find", "verify", "find-verify"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        args = ["--operation", op, "--fix-limit", "1"]
        if op == "verify":
          args += ["--from-find-run", "R"]
        run.parse_args(args)
      self.assertIn(f"--fix-limit is not supported for --operation {op}", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix", "--from-find-run", "R", "--fix-limit", "-1"])
    self.assertIn("--fix-limit must be >= 0", err.getvalue())

    for op in ("fix", "verify-fix", "find-fix", "find-verify-fix"):
      args = ["--operation", op, "--fix-limit", "5"]
      if op in ("fix", "verify-fix"):
        args += ["--from-find-run", "R"]
      _, a = run.parse_args(args)
      self.assertEqual(a.fix_limit, 5)

  def test_severity_validation(self):
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "find", "--severity", "CRITICAL"])
    self.assertIn("--severity is not supported for --operation find", err.getvalue())

    _, a = run.parse_args(["--operation", "verify", "--from-find-run", "R",
                           "--severity", " critical, high,medium "])
    self.assertEqual(a.severity, "CRITICAL,HIGH,MEDIUM")

  def test_mode_deep_validation(self):
    for op in ("verify", "fix", "verify-fix"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        args = ["--operation", op, "--mode", "deep"]
        if op in ("verify", "verify-fix", "fix"):
          args += ["--from-find-run", "R"]
        run.parse_args(args)
      self.assertIn(f"--mode deep is not supported for --operation {op}", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--mode", "deep", "--cm-version", "0.9.0"])
    self.assertIn("--mode deep requires --cm-version >= 0.10.0", err.getvalue())

    _, a = run.parse_args(["--mode", "deep", "--cm-version", "0.10.0"])
    self.assertEqual(a.mode, "deep")

  def test_from_find_run_validation(self):
    for op in ("verify", "verify-fix"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        run.parse_args(["--operation", op])
      self.assertIn(f"--from-find-run is required for --operation {op}", err.getvalue())

    for op in ("find", "find-verify", "find-fix", "find-verify-fix"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        run.parse_args(["--operation", op, "--from-find-run", "R"])
      self.assertIn(f"--from-find-run is not supported for --operation {op}", err.getvalue())

  def test_from_verify_run_validation(self):
    for op in ("find", "verify", "find-verify", "verify-fix", "find-fix", "find-verify-fix"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        args = ["--operation", op, "--from-verify-run", "VR"]
        if op in ("verify", "verify-fix"):
          args += ["--from-find-run", "FR"]
        run.parse_args(args)
      self.assertIn(f"--from-verify-run is not supported for --operation {op}", err.getvalue())

  def test_fix_source_requirement(self):
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix"])
    self.assertIn("requires either --from-verify-run or --from-find-run", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix", "--from-find-run", "FR", "--from-verify-run", "VR"])
    self.assertIn("--from-find-run and --from-verify-run are mutually exclusive", err.getvalue())

    _, a = run.parse_args(["--operation", "fix", "--from-find-run", "FR"])
    self.assertEqual(a.from_find_run, "FR")
    self.assertIsNone(a.from_verify_run)

    _, a = run.parse_args(["--operation", "fix", "--from-verify-run", "VR"])
    self.assertEqual(a.from_verify_run, "VR")
    self.assertIsNone(a.from_find_run)

  def test_include_unverified_validation(self):
    for op in ("find", "verify", "find-verify", "find-fix"):
      err = io.StringIO()
      with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
        args = ["--operation", op, "--include-unverified"]
        if op == "verify":
          args += ["--from-find-run", "FR"]
        run.parse_args(args)
      self.assertIn(f"--include-unverified is not supported for --operation {op}", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix", "--from-find-run", "FR", "--include-unverified"])
    self.assertIn("--include-unverified is only supported when fixing from a verify run", err.getvalue())

    for args in (
        ["--operation", "fix", "--from-verify-run", "VR", "--include-unverified"],
        ["--operation", "verify-fix", "--from-find-run", "FR", "--include-unverified"],
        ["--operation", "find-verify-fix", "--include-unverified"],
    ):
      _, a = run.parse_args(args)
      self.assertTrue(a.include_unverified)

  def test_finding_ids_validation(self):
    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "find", "--finding-ids", "id1"])
    self.assertIn("--finding-ids is not supported for --operation find", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "verify", "--from-find-run", "FR",
                      "--finding-ids", "id1", "--severity", "CRITICAL"])
    self.assertIn("--severity cannot be used with --finding-ids", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "verify", "--from-find-run", "FR",
                      "--finding-ids", "id1", "--verify-limit", "1"])
    self.assertIn("--verify-limit cannot be used with --finding-ids", err.getvalue())

    err = io.StringIO()
    with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
      run.parse_args(["--operation", "fix", "--from-find-run", "FR",
                      "--finding-ids", "id1", "--fix-limit", "1"])
    self.assertIn("--fix-limit cannot be used with --finding-ids", err.getvalue())

    _, a = run.parse_args(["--operation", "verify", "--from-find-run", "FR",
                           "--finding-ids", "id1,id2", "id3"])
    self.assertEqual(a.finding_ids, ["id1", "id2", "id3"])


class FixCliTest(unittest.TestCase):

  def _staged_verify_run(self):
    matching_ids = b"f1\nf2\n"
    post_verify = json.dumps({
        "summary": {"verified": 1, "unverified": 1, "failed": 0},
        "findings": [
            {"finding_id": "f1", "status": "VERIFIED"},
            {"finding_id": "f2", "status": "UNVERIFIED"},
        ],
    }).encode()
    source_findings = json.dumps([
        {"finding_id": "f1", "severity": "CRITICAL", "description": "desc1"},
        {"finding_id": "f2", "severity": "HIGH", "description": "desc2"},
        {"finding_id": "f3", "severity": "LOW", "description": "desc3"},
    ]).encode()
    return staged_runner(**{
        f"{VERIFY}/smoke/VRUN/o04-vampi/matching_finding_ids.txt": matching_ids,
        f"{VERIFY}/smoke/VRUN/o04-vampi/post_verify_report.json": post_verify,
        f"{VERIFY}/smoke/VRUN/o04-vampi/source_findings.json": source_findings,
    })

  def test_fix_from_verify_run_filters_verified_and_respects_matching_ids(self):
    r = self._staged_verify_run()
    rc, out = main(["--operation", "fix", "--from-verify-run", "VRUN",
                    "--experiment-id", "smoke", "--repos", "o04-vampi",
                    "--run-id", "FIX1"], r)
    self.assertEqual(rc, 0)
    self.assertEqual(execute_call(r)[4], "cm-fix-runner")
    tasks = uploaded_json(r, "/runs/smoke/FIX1/tasks.json")
    self.assertEqual([t["repo_id"] for t in tasks], ["o04-vampi"])
    self.assertEqual(tasks[0]["matching_findings"], 1)
    self.assertEqual(tasks[0]["source_stage"], "verify")
    self.assertEqual(tasks[0]["verify_report_gcs_uri"],
                     f"{VERIFY}/smoke/VRUN/o04-vampi/post_verify_report.json")
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertIn("FROM_VERIFY_RUN=VRUN", env)
    self.assertIn("SOURCE_VERIFY_EXPERIMENT=smoke", env)
    self.assertIn("INCLUDE_UNVERIFIED=0", env)

    r2 = self._staged_verify_run()
    rc2, out2 = main(["--operation", "fix", "--from-verify-run", "VRUN",
                     "--experiment-id", "smoke", "--repos", "o04-vampi",
                     "--run-id", "FIX2", "--include-unverified"], r2)
    self.assertEqual(rc2, 0)
    tasks2 = uploaded_json(r2, "/runs/smoke/FIX2/tasks.json")
    self.assertEqual(tasks2[0]["matching_findings"], 2)
    self.assertEqual(tasks2[0]["source_stage"], "verify")
    env2 = [a for a in execute_call(r2) if a.startswith("--update-env-vars=")][0]
    self.assertIn("INCLUDE_UNVERIFIED=1", env2)

  def test_fix_from_find_run_routing_and_env(self):
    r = staged_runner(**{
        f"{FIND}/smoke/FRUN/o04-vampi/findings.json": FIXTURE,
    })
    rc, out = main(["--operation", "fix", "--from-find-run", "FRUN",
                    "--experiment-id", "smoke", "--repos", "o04-vampi",
                    "--run-id", "FIX_FIND"], r)
    self.assertEqual(rc, 0)
    ex = execute_call(r)
    self.assertEqual(ex[4], "cm-fix-runner")
    self.assertIn("--task-timeout=172800s", ex)
    tasks = uploaded_json(r, "/runs/smoke/FIX_FIND/tasks.json")
    self.assertEqual([t["repo_id"] for t in tasks], ["o04-vampi"])
    self.assertEqual(tasks[0]["matching_findings"], 3)
    self.assertEqual(tasks[0]["source_stage"], "find")
    man = uploaded_json(r, "/runs/smoke/FIX_FIND/run_manifest.json")
    self.assertEqual(man["results_prefix"], f"{FIX}/smoke/FIX_FIND/")
    env = [a for a in ex if a.startswith("--update-env-vars=")][0]
    self.assertIn("FROM_FIND_RUN=FRUN", env)
    self.assertIn("SOURCE_FIND_EXPERIMENT=smoke", env)
    self.assertIn("FIX_LIMIT=0", env)
    self.assertIn("FIX_FINDING_TIMEOUT=10800", env)
    self.assertIn("INCLUDE_UNVERIFIED=0", env)

  def test_fix_with_finding_ids_bypasses_severity(self):
    r = staged_runner(**{
        f"{FIND}/smoke/FRUN/o04-vampi/findings.json": FIXTURE,
    })
    rc, out = main(["--operation", "fix", "--from-find-run", "FRUN",
                    "--experiment-id", "smoke", "--repos", "o04-vampi",
                    "--finding-ids", "3e84cd12",
                    "--run-id", "FIX_BY_ID"], r)
    self.assertEqual(rc, 0)
    tasks = uploaded_json(r, "/runs/smoke/FIX_BY_ID/tasks.json")
    self.assertEqual(tasks[0]["matching_findings"], 1)
    env = [a for a in execute_call(r) if a.startswith("--update-env-vars=")][0]
    self.assertIn("FINDING_IDS=3e84cd12", env)

  def test_verify_fix_pipeline(self):
    r = staged_runner(**{
        f"{FIND}/smoke/FRUN/o04-vampi/findings.json": FIXTURE,
        f"{VERIFY}/smoke/PIPE/o04-vampi/matching_finding_ids.txt": b"3e84cd12-afc1-508b-959e-e58c3b19e556\n",
        f"{VERIFY}/smoke/PIPE/o04-vampi/post_verify_report.json": json.dumps({
            "summary": {"verified": 1, "unverified": 0, "failed": 0},
            "findings": [{"finding_id": "3e84cd12-afc1-508b-959e-e58c3b19e556", "status": "VERIFIED"}],
        }).encode(),
        f"{VERIFY}/smoke/PIPE/o04-vampi/source_findings.json": FIXTURE,
    })
    rc, out = main(["--operation", "verify-fix", "--from-find-run", "FRUN",
                    "--experiment-id", "smoke", "--repos", "o04-vampi",
                    "--run-id", "PIPE", "--verify-limit", "1", "--fix-limit", "1"], r)
    self.assertEqual(rc, 0)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs], ["cm-verify-runner", "cm-fix-runner"])
    self.assertIn("run_id=PIPE\n", out)
    self.assertIn("run_id=PIPE_fix\n", out)
    self.assertIn("[phase] verify phase (PIPE) complete; transitioning to fix", out)

  def test_find_fix_pipeline(self):
    r = staged_runner(**{
        f"{FIND}/smoke/PIPE/o04-vampi/findings.json": FIXTURE,
    })
    rc, out = main(["--operation", "find-fix", "--experiment-id", "smoke",
                    "--repos", "o04-vampi", "--run-id", "PIPE", "--fix-limit", "1"], r)
    self.assertEqual(rc, 0)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs], ["cm-find-runner", "cm-fix-runner"])
    self.assertIn("run_id=PIPE\n", out)
    self.assertIn("run_id=PIPE_fix\n", out)
    self.assertIn("[phase] find phase (PIPE) complete; transitioning to fix", out)

  def test_find_verify_fix_pipeline(self):
    r = staged_runner(**{
        f"{FIND}/smoke/PIPE/o04-vampi/findings.json": FIXTURE,
        f"{VERIFY}/smoke/PIPE_verify/o04-vampi/matching_finding_ids.txt": b"3e84cd12-afc1-508b-959e-e58c3b19e556\n",
        f"{VERIFY}/smoke/PIPE_verify/o04-vampi/post_verify_report.json": json.dumps({
            "summary": {"verified": 1, "unverified": 0, "failed": 0},
            "findings": [{"finding_id": "3e84cd12-afc1-508b-959e-e58c3b19e556", "status": "VERIFIED"}],
        }).encode(),
        f"{VERIFY}/smoke/PIPE_verify/o04-vampi/source_findings.json": FIXTURE,
    })
    rc, out = main(["--operation", "find-verify-fix", "--experiment-id", "smoke",
                    "--repos", "o04-vampi", "--run-id", "PIPE",
                    "--verify-limit", "1", "--fix-limit", "1"], r)
    self.assertEqual(rc, 0)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs],
                     ["cm-find-runner", "cm-verify-runner", "cm-fix-runner"])
    self.assertIn("run_id=PIPE\n", out)
    self.assertIn("run_id=PIPE_verify\n", out)
    self.assertIn("run_id=PIPE_fix\n", out)
    self.assertIn("[phase] find phase (PIPE) complete; transitioning to verify", out)
    self.assertIn("[phase] verify phase (PIPE_verify) complete; transitioning to fix", out)

  def test_verify_fix_verify_failure_clean_rc_and_resume_hint(self):
    r = staged_runner(**{
        f"{FIND}/smoke/FRUN/o04-vampi/findings.json": FIXTURE,
    })
    r.responses["gcloud run jobs execute"] = common.Result(1, "", "failed")
    rc, out = main(["--operation", "verify-fix", "--from-find-run", "FRUN",
                    "--experiment-id", "smoke", "--repos", "o04-vampi",
                    "--run-id", "PIPE"], r)
    self.assertEqual(rc, 1)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs], ["cm-verify-runner"])
    self.assertIn("fix skipped; inspect verify results, then resume with: --operation fix --from-verify-run smoke/PIPE", out)

  def test_find_verify_fix_find_failure_clean_rc_and_resume_hint(self):
    r = staged_runner()
    r.responses["gcloud run jobs execute"] = common.Result(1, "", "failed")
    rc, out = main(["--operation", "find-verify-fix", "--experiment-id", "smoke",
                    "--repos", "o04-vampi", "--run-id", "PIPE"], r)
    self.assertEqual(rc, 1)
    execs = [c for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual([c[4] for c in execs], ["cm-find-runner"])
    self.assertIn("verify-fix skipped; inspect find results, then resume with: --operation verify-fix --from-find-run smoke/PIPE", out)


if __name__ == "__main__":
  unittest.main()
