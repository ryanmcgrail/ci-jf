"""Characterization tests for run.py behavior the refactor touches.

These pin down paths the inventory marked UNTESTED (run resolution edge cases,
fix-from-verify fallbacks, polling failure modes, staging, chained dry-runs).
"""

import contextlib
import io
import json
import unittest

import run
from cmrun import common
from tests import test_run_cli as t
from tests.fakes import FakeRunner

FIXTURE_ITEMS = json.loads(t.FIXTURE)
CRIT = FIXTURE_ITEMS[0]["finding_id"]


def exits_with(test, fn, message):
  err = io.StringIO()
  with test.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):
    fn()
  test.assertEqual(cm.exception.code, 2)
  test.assertIn(message, err.getvalue())


class ResolveRunTest(unittest.TestCase):

  def test_find_latest_with_experiment_prefix(self):
    r = FakeRunner(gcs={f"{t.FIND}/e2/20260101_000000_a/x/summary.json": b"",
                        f"{t.FIND}/e2/20260102_000000_b/x/summary.json": b"",
                        f"{t.FIND}/default/20260103_000000_c/x/summary.json": b""})
    self.assertEqual(run.resolve_find_run(r, "proj-cm-find-results", "e2/latest"),
                     ("e2", "20260102_000000_b"))

  def test_latest_empty_raises(self):
    r = FakeRunner()
    with self.assertRaisesRegex(common.UsageError,
                                r"^no find runs found under gs://b/exp/$"):
      run.resolve_find_run(r, "b", "latest", "exp")
    with self.assertRaisesRegex(common.UsageError,
                                r"^no verify runs found under gs://b/exp/$"):
      run.resolve_verify_run(r, "b", "exp/latest")

  def test_exp_slash_run_checks_existence(self):
    r = FakeRunner(gcs={"gs://b/e/R/x": b""})
    self.assertEqual(run.resolve_find_run(r, "b", "e/R/"), ("e", "R"))
    self.assertEqual(run.resolve_verify_run(r, "b", "e/R"), ("e", "R"))
    with self.assertRaisesRegex(common.UsageError,
                                r"^verify run 'e/X' not found under gs://b/$"):
      run.resolve_verify_run(r, "b", "e/X")

  def test_bare_run_ambiguous(self):
    gcs = {"gs://b/a/R/x/f": b"", "gs://b/c/R/x/f": b""}
    with self.assertRaises(common.UsageError) as cm:
      run.resolve_find_run(FakeRunner(gcs=gcs), "b", "R")
    self.assertEqual(
        str(cm.exception),
        "find run 'R' exists in several experiments ['a', 'c']; "
        "pass --from-find-run <experiment_id>/<run_id>")
    with self.assertRaises(common.UsageError) as cm:
      run.resolve_verify_run(FakeRunner(gcs=gcs), "b", "R")
    self.assertEqual(
        str(cm.exception),
        "verify run 'R' exists in several experiments ['a', 'c']; "
        "pass --from-verify-run <experiment_id>/<run_id>")

  def test_bare_run_excludes_selftest(self):
    gcs = {"gs://b/selftest/R/x": b"", "gs://b/a/R/x/f": b""}
    self.assertEqual(run.resolve_find_run(FakeRunner(gcs=gcs), "b", "R"),
                     ("a", "R"))
    self.assertEqual(run.resolve_verify_run(FakeRunner(gcs=gcs), "b", "R"),
                     ("a", "R"))

  def test_bare_run_not_found(self):
    with self.assertRaises(common.UsageError) as cm:
      run.resolve_verify_run(FakeRunner(gcs={"gs://b/selftest/R/x": b""}),
                             "b", "R")
    self.assertEqual(str(cm.exception), "verify run 'R' not found under gs://b/*/")

  def test_verify_latest_through_main(self):
    prefix = f"{t.VERIFY}/smoke/20260102_x/o04-vampi"
    r = t.staged_runner(**{
        f"{t.VERIFY}/smoke/20260101_x/o04-vampi/matching_finding_ids.txt": b"",
        f"{t.VERIFY}/smoke/20260101_x/o04-vampi/summary.json": b"{}",
        f"{prefix}/summary.json": b"{}",
        f"{prefix}/matching_finding_ids.txt": f"{CRIT}\n".encode(),
        f"{prefix}/post_verify_report.json": json.dumps(
            [{"finding_id": CRIT, "status": "VERIFIED"}]).encode(),
        f"{prefix}/source_findings.json": t.FIXTURE,
    })
    rc, out = t.main(["--operation", "fix", "--from-verify-run", "latest",
                      "--experiment-id", "smoke", "--repos", "o04-vampi",
                      "--run-id", "F"], r)
    self.assertEqual(rc, 0)
    self.assertIn("FROM_VERIFY_RUN=20260102_x", " ".join(t.execute_call(r)))
    self.assertIn("[summary] candidates from smoke/20260102_x: 1 attempted; "
                  "1 matching across 1/1 repo(s) queued for fix", out)


class FixFromVerifyEdgeTest(unittest.TestCase):

  def _run(self, gcs, *extra):
    r = t.staged_runner(**gcs)
    rc, out = t.main(["--operation", "fix", "--from-verify-run", "smoke/V",
                      "--repos", "o04-vampi", "--run-id", "F", *extra], r)
    return r, rc, out

  def test_report_listing_fallback_when_ids_missing(self):
    prefix = f"{t.VERIFY}/smoke/V/o04-vampi"
    r, rc, out = self._run({
        f"{prefix}/post_verify_report.json": json.dumps({"findings": [
            {"finding_id": CRIT, "status": "verified"}]}).encode(),
        f"{prefix}/source_findings.json": t.FIXTURE,
    })
    self.assertEqual(rc, 0)
    ls = [c[-1] for c in r.calls if c[:3] == ["gcloud", "storage", "ls"]]
    self.assertIn(f"gs://{t.P}-cm-verify-results/smoke/V/*/matching_finding_ids.txt", ls)
    self.assertIn(f"gs://{t.P}-cm-verify-results/smoke/V/*/post_verify_report.json", ls)
    self.assertIn("[summary] o04-vampi: 1 finding(s) attempted; 1 verified "
                  "matching CRITICAL,HIGH", out)

  def test_no_attempted_findings_skips_and_returns_2(self):
    prefix = f"{t.VERIFY}/smoke/V/o04-vampi"
    r, rc, out = self._run({f"{prefix}/post_verify_report.json": b"[]"})
    self.assertEqual(rc, 2)
    self.assertIn("[fix] skip o04-vampi: no attempted findings found in verify run",
                  out)
    self.assertIn("[summary] candidates from smoke/V: 0 attempted; 0 matching "
                  "across 0/1 repo(s) queued for fix", out)
    self.assertIn("error: no tasks to run (fix: no findings matched criteria)", out)
    self.assertFalse(any(c[:3] == ["gcloud", "run", "jobs"] for c in r.calls))

  def test_unknown_source_id_stub_matches_by_finding_id(self):
    prefix = f"{t.VERIFY}/smoke/V/o04-vampi"
    r, rc, out = self._run({
        f"{prefix}/matching_finding_ids.txt": b"zzz-1\n",
        f"{prefix}/source_findings.json": b"not json",
    }, "--finding-ids", "zzz")
    self.assertEqual(rc, 0)
    self.assertIn("[summary] o04-vampi: 1 finding(s) attempted; 1 verified "
                  "matching finding ID(s) zzz", out)

  def test_no_verified_skip_message(self):
    prefix = f"{t.VERIFY}/smoke/V/o04-vampi"
    _, rc, out = self._run({
        f"{prefix}/matching_finding_ids.txt": f"{CRIT}\n".encode(),
        f"{prefix}/post_verify_report.json": json.dumps(
            [{"finding_id": CRIT, "status": "DISMISSED"}]).encode(),
        f"{prefix}/source_findings.json": t.FIXTURE,
    }, "--include-unverified")
    self.assertEqual(rc, 2)
    self.assertIn("[fix] skip o04-vampi: no non-dismissed findings matching "
                  "CRITICAL,HIGH (1 attempted in verify)", out)


class VerifyAndFixFromFindEdgeTest(unittest.TestCase):

  def test_dict_form_and_invalid_json_findings(self):
    r = t.staged_runner(**{
        f"{t.FIND}/smoke/R/o04-vampi/findings.json": json.dumps(
            {"findings": FIXTURE_ITEMS}).encode(),
        f"{t.FIND}/smoke/R/p01-flask/findings.json": b"not json",
    })
    rc, out = t.main(["--operation", "verify", "--from-find-run", "smoke/R",
                      "--repos", "o04-vampi", "p01-flask", "--run-id", "V"], r)
    self.assertEqual(rc, 0)
    self.assertIn("[summary] o04-vampi: 5 finding(s) (CRITICAL=1, HIGH=2, "
                  "MEDIUM=1, LOW=1); 3 matching CRITICAL,HIGH", out)
    self.assertIn("[verify] skip p01-flask: no CRITICAL,HIGH findings "
                  "(0 total: none)", out)

  def test_verify_finding_ids_skip_message(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/R/o04-vampi/findings.json": t.FIXTURE})
    rc, out = t.main(["--operation", "verify", "--from-find-run", "smoke/R",
                      "--repos", "o04-vampi", "--finding-ids", "nope"], r)
    self.assertEqual(rc, 2)
    self.assertIn("[verify] skip o04-vampi: no matching finding ID(s) nope "
                  "(5 total: CRITICAL=1, HIGH=2, MEDIUM=1, LOW=1)", out)
    self.assertIn("error: no tasks to run (verify: no findings matched --severity)",
                  out)

  def test_fix_from_find_skip_message(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/R/o04-vampi/findings.json": t.FIXTURE})
    rc, out = t.main(["--operation", "fix", "--from-find-run", "smoke/R",
                      "--repos", "o04-vampi", "--severity", "info"], r)
    self.assertEqual(rc, 2)
    self.assertIn("[fix] skip o04-vampi: no matching INFO findings (5 total: "
                  "CRITICAL=1, HIGH=2, MEDIUM=1, LOW=1)", out)
    self.assertIn("error: no tasks to run (fix: no findings matched criteria)", out)


class DeepWorkersAndSeverityTest(unittest.TestCase):

  def test_deep_workers_flag_errors(self):
    deep = ["--mode", "deep", "--cm-version", "0.10.0"]
    for argv, msg in (
        (["--deep-workers", "4"], "--deep-workers requires --mode deep"),
        (deep + ["--deep-workers", "0"], "--deep-workers must be between 1 and 16"),
        (deep + ["--deep-workers", "17"], "--deep-workers must be between 1 and 16"),
        (deep + ["--extra-cm-args", "--deep-workers 4"],
         "--extra-cm-args cannot contain --deep-workers; use --deep-workers"),
        (["--extra-cm-args", "--x, --deep-workers=4"],
         "--extra-cm-args cannot contain --deep-workers; use --deep-workers"),
    ):
      with self.subTest(argv=argv):
        exits_with(self, lambda a=argv: run.parse_args(a), msg)
    _, a = run.parse_args(deep)
    self.assertEqual(a.deep_workers, 8)

  def test_format_severity_breakdown(self):
    self.assertEqual(run.format_severity_breakdown({}), "none")
    self.assertEqual(
        run.format_severity_breakdown({"ZED": 2, "INFO": 1, "ABC": 1,
                                       "CRITICAL": 3}),
        "CRITICAL=3, INFO=1, ABC=1, ZED=2")

  def test_summarize_findings_shapes(self):
    items = [{"Severity": "high"}, {"severity": None}, {}]
    self.assertEqual(run.summarize_findings(items, " high ,x"),
                     (3, {"HIGH": 1, "UNKNOWN": 2}, 1))
    self.assertEqual(run.summarize_findings({"findings": items}, "UNKNOWN"),
                     (3, {"HIGH": 1, "UNKNOWN": 2}, 2))
    self.assertEqual(run.summarize_findings(None, "HIGH"), (0, {}, 0))
    self.assertEqual(run.summarize_findings("x", "HIGH"), (0, {}, 0))

  def test_empty_severity_and_finding_ids_normalization(self):
    _, a = run.parse_args(["--operation", "verify", "--from-find-run", "R",
                           "--severity", " , "])
    self.assertEqual(a.severity, "")
    _, a = run.parse_args(["--operation", "verify", "--from-find-run", "R",
                           "--finding-ids", ",", " "])
    self.assertIsNone(a.finding_ids)

  def test_fix_timeout_defaults_and_bounds(self):
    _, a = run.parse_args(["--container-timeout", "301"])
    self.assertEqual(a.fix_timeout, 1)
    _, a = run.parse_args(["--container-timeout", "11100"])
    self.assertEqual(a.fix_timeout, 10800)
    _, a = run.parse_args(["--container-timeout", "11099"])
    self.assertEqual(a.fix_timeout, 10799)


class PollingTest(unittest.TestCase):

  def test_five_consecutive_describe_errors_abort(self):
    r = t.staged_runner(responses={
        "gcloud run jobs executions": common.Result(1, "", "boom\n")})
    rc, out = t.main(["--repos", "o04-vampi", "--wait", "--run-id", "R"], r)
    self.assertEqual(rc, 1)
    describes = [c for c in r.calls if c[:5] == ["gcloud", "run", "jobs",
                                                 "executions", "describe"]]
    self.assertEqual(len(describes), 5)
    self.assertIn("error: cm-find-runner run R failed: failed to poll execution "
                  "cm-find-runner-exec1 (1): boom", out)

  def test_errors_reset_and_bad_json_keeps_polling(self):
    seq = iter([common.Result(1, "", "e")] * 4 + [common.Result(0, "not json")]
               + [common.Result(1, "", "e")] * 4)
    def describe(args):
      return next(seq, t.fake_describe(args))
    sleeps = []
    r = t.staged_runner(responses={"gcloud run jobs executions": describe})
    rc, out = t.main(["--repos", "o04-vampi", "--wait"], r,
                     sleep=sleeps.append, poll_interval=7)
    self.assertEqual(rc, 0)
    self.assertEqual(sleeps, [7] * 9)
    self.assertIn("[progress] [00:00] cm-find-runner-exec1: 0 running, "
                  "0 succeeded, 0 failed / 1 total", out)

  def test_default_failure_reason_and_message(self):
    state = {"status": {"conditions": [{"type": "Completed", "status": "False"}]}}
    r = t.staged_runner(responses={
        "gcloud run jobs executions": common.Result(0, json.dumps(state))})
    rc, out = t.main(["--repos", "o04-vampi", "--wait", "--run-id", "R"], r)
    self.assertEqual(rc, 1)
    self.assertIn("[summary] cm-find-runner-exec1: Completed=False [Failed] "
                  "(0 succeeded, 0 failed / 1 total) in 00:00 (exit_code=1) — "
                  "Execution failed.", out)
    self.assertIn("error: cm-find-runner run R failed: cm-find-runner execution "
                  "cm-find-runner-exec1 failed (Failed): Execution failed.", out)

  def test_status_log_uri_preferred(self):
    r = t.staged_runner()
    r.responses["gcloud run jobs execute"] = lambda a: common.Result(0, json.dumps(
        {"metadata": {"name": "n1"}, "status": {"logUri": "https://log/x"}}))
    _, out = t.main(["--repos", "o04-vampi"], r)
    self.assertTrue(out.endswith("\nconsole: https://log/x"), out)

  def test_execute_failure_without_wait_returns_1(self):
    r = t.staged_runner()
    r.responses["gcloud run jobs execute"] = common.Result(1, "", "denied")
    rc, out = t.main(["--repos", "o04-vampi", "--run-id", "R"], r)
    self.assertEqual(rc, 1)
    self.assertIn("error: cm-find-runner run R failed: fake command failed:", out)


class StagingTest(unittest.TestCase):

  def test_sidecar_missing_restages(self):
    r = FakeRunner(gcs={t.ZIP: b"old", f"{t.PAYLOAD}/repos/o04-vampi.tar.gz": b"t"},
                   responses={"gcloud artifacts generic download": t.fake_download})
    rc, out = t.main(["--repos", "o04-vampi", "--dry-run"], r)
    self.assertEqual(rc, 0)
    self.assertIn(f"[stage] cm 0.11.0: {t.ZIP} exists but sidecar missing; "
                  "re-staging", out)
    self.assertIn("[dry-run] would run: gcloud artifacts generic download "
                  "--project=cmoc-prod --location=us "
                  "--repository=codemender-cli-production --package=cm "
                  "--version=0.11.0 --name=cm-linux-amd64.zip --destination=<tmp>",
                  out)
    self.assertIn(f"[dry-run] would upload to {t.ZIP} and {t.ZIP}.sha256", out)
    self.assertIn("EXPECTED_CM_SHA256=<sha256-of-downloaded-zip>", out)

  def test_download_log_lines(self):
    r = FakeRunner(gcs={f"{t.PAYLOAD}/repos/o04-vampi.tar.gz": b"t"},
                   responses={"gcloud artifacts generic download": t.fake_download})
    _, out = t.main(["--repos", "o04-vampi"], r)
    self.assertIn(f"[stage] cm 0.11.0: downloading from Artifact Registry and "
                  f"uploading to {t.ZIP}...", out)
    self.assertRegex(out, r"\[stage\] cm 0\.11\.0: staged \S+ sha256=[0-9a-f]{64}")

  def test_missing_repo_tarball_staged_via_stage_repos(self):
    r = FakeRunner(gcs={t.ZIP: b"z", t.ZIP + ".sha256": t.SHA.encode()})
    with contextlib.redirect_stdout(io.StringIO()):
      rc, out = t.main(["--repos", "o04-vampi", "p01-flask", "--run-id", "R"], r)
    self.assertEqual(rc, 0)
    self.assertIn("[stage] repos: 0/2 cached; staging 2 missing tarball(s): "
                  "o04-vampi, p01-flask", out)
    self.assertIn("[stage] repos: staged 2 tarball(s) (2/2 ready)", out)
    self.assertIn(f"{t.PAYLOAD}/repos/o04-vampi.tar.gz", r.gcs)

  def test_dry_run_missing_repo_message(self):
    r = FakeRunner(gcs={t.ZIP: b"z", t.ZIP + ".sha256": t.SHA.encode()})
    _, out = t.main(["--repos", "o04-vampi", "p01-flask", "--dry-run"], r)
    self.assertIn("[dry-run] repos: 0/2 cached; would stage 2 missing: "
                  "o04-vampi p01-flask", out)

  def test_no_project_errors(self):
    r = FakeRunner(responses={"gcloud config get-value project": common.Result(0, "\n")})
    exits_with(self, lambda: run.main([], runner=r, log=lambda _: None),
               "no --project given and no gcloud default project set")


class ChainedPipelineTest(unittest.TestCase):

  def test_dry_run_chain_hints(self):
    cases = {
        "find-verify": "[dry-run] would then run verify --from-find-run smoke/R",
        "find-fix": "[dry-run] would then run fix --from-find-run smoke/R",
        "find-verify-fix": "[dry-run] would then run verify --from-find-run smoke/R",
    }
    for op, hint in cases.items():
      with self.subTest(op):
        r = t.staged_runner()
        rc, out = t.main(["--operation", op, "--experiment-id", "smoke",
                          "--repos", "o04-vampi", "--run-id", "R", "--dry-run"], r)
        self.assertEqual(rc, 0)
        self.assertTrue(out.endswith(hint), out)
        self.assertEqual(len([c for c in r.calls if c[:4] == ["gcloud", "run", "jobs",
                                                              "execute"]]), 0)

  def test_dry_run_chain_hint_printed_even_when_no_tasks(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/F/o04-vampi/findings.json": b"[]"})
    rc, out = t.main(["--operation", "verify-fix", "--from-find-run", "smoke/F",
                      "--experiment-id", "smoke", "--repos", "o04-vampi",
                      "--run-id", "R", "--dry-run"], r)
    self.assertEqual(rc, 2)
    self.assertTrue(out.endswith(
        "error: no tasks to run (verify: no findings matched --severity)\n"
        "[dry-run] would then run fix --from-verify-run smoke/R"), out)

  def test_chain_phase1_no_tasks_returns_2_silently(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/F/o04-vampi/findings.json": b"[]"})
    rc, out = t.main(["--operation", "verify-fix", "--from-find-run", "smoke/F",
                      "--experiment-id", "smoke", "--repos", "o04-vampi",
                      "--run-id", "R"], r)
    self.assertEqual(rc, 2)
    self.assertNotIn("skipped", out)

  def test_find_fix_failure_hint(self):
    r = t.staged_runner()
    r.responses["gcloud run jobs execute"] = common.Result(1, "", "failed")
    rc, out = t.main(["--operation", "find-fix", "--experiment-id", "smoke",
                      "--repos", "o04-vampi", "--run-id", "R"], r)
    self.assertEqual(rc, 1)
    self.assertTrue(out.endswith(
        "fix skipped; inspect find results, then resume with: "
        "--operation fix --from-find-run smoke/R"), out)

  def test_find_verify_fix_verify_failure_hint(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/R/o04-vampi/findings.json": t.FIXTURE})
    def execute(args):
      if args[4] == common.VERIFY_JOB:
        return common.Result(1, "", "failed")
      return t.fake_execute(args)
    r.responses["gcloud run jobs execute"] = execute
    rc, out = t.main(["--operation", "find-verify-fix", "--experiment-id", "smoke",
                      "--repos", "o04-vampi", "--run-id", "R"], r)
    self.assertEqual(rc, 1)
    self.assertTrue(out.endswith(
        "fix skipped; inspect verify results, then resume with: "
        "--operation fix --from-verify-run smoke/R_verify"), out)

  def test_second_phase_existing_run_exits_2_after_phase1(self):
    r = t.staged_runner(**{
        f"{t.FIND}/smoke/R/o04-vampi/findings.json": t.FIXTURE,
        f"{t.PAYLOAD}/runs/smoke/R_verify/tasks.json": b"[]",
    })
    exits_with(self, lambda: t.main(["--operation", "find-verify",
                                     "--experiment-id", "smoke", "--repos",
                                     "o04-vampi", "--run-id", "R"], r),
               "run R_verify already exists in experiment 'smoke'")
    execs = [c[4] for c in r.calls if c[:4] == ["gcloud", "run", "jobs", "execute"]]
    self.assertEqual(execs, ["cm-find-runner"])

  def test_existing_run_refused_in_dry_run(self):
    r = t.staged_runner(**{f"{t.PAYLOAD}/runs/default/R/tasks.json": b"[]"})
    exits_with(self, lambda: t.main(["--repos", "o04-vampi", "--run-id", "R",
                                     "--dry-run"], r),
               "run R already exists in experiment 'default' "
               f"({t.PAYLOAD}/runs/default/R/tasks.json present); "
               "specify a different --run-id")

  def test_auto_run_ids_per_phase(self):
    r = t.staged_runner()
    def execute(args):
      return common.Result(1, "", "stop") if args[4] == common.VERIFY_JOB \
          else t.fake_execute(args)
    r.responses["gcloud run jobs execute"] = execute
    # Phase 2 needs the find results under the generated run id; seed them
    # lazily from the tasks.json upload.
    orig = r.run
    def run_hook(args, check=True, cwd=None):
      res = orig(args, check=check, cwd=cwd)
      if args[:3] == ["gcloud", "storage", "cp"] and args[-1].endswith(
          "/tasks.json") and "_find_" in args[-1]:
        rid = args[-1].split("/")[-2]
        r.gcs[f"{t.FIND}/default/{rid}/o04-vampi/findings.json"] = t.FIXTURE
      return res
    r.run = run_hook
    rc, out = t.main(["--operation", "find-verify", "--repos", "o04-vampi"], r)
    self.assertEqual(rc, 1)
    ids = [l[len("run_id="):] for l in out.splitlines() if l.startswith("run_id=")]
    self.assertEqual(len(ids), 2)
    self.assertRegex(ids[0], r"^\d{8}_\d{6}_find_v0\.11\.0_gemini-3\.8-flash$")
    self.assertRegex(ids[1], r"^\d{8}_\d{6}_verify_v0\.11\.0_gemini-3\.8-flash$")


if __name__ == "__main__":
  unittest.main()
