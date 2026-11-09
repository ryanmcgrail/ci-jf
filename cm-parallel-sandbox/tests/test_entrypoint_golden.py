"""Golden + characterization tests for container/entrypoint.sh.

Snapshots (generated from the pre-refactor script) pin the container contract:
exit code, `[entrypoint <ts>]` log lines, every gcloud argv, every cm argv, the
uploaded object layout, and deterministic uploaded file contents.
"""

import json
import re
import shutil
import unittest

from tests.golden_util import assert_golden
from tests.test_entrypoint import (EntrypointTestBase, FIND, FIX, FIXTURE,
                                   PAYLOAD, REPO, STUBS, VERIFY)

SKIP_CONTENT = {"state.db"}
CONTENT_SUFFIXES = (".txt", ".diff", ".json", "exit_code")
VOLATILE_SUMMARY_KEYS = ("start_epoch", "end_epoch", "wall_clock_seconds")


class GoldenBase(EntrypointTestBase):

  def setUp(self):
    super().setUp()
    self.gcloud_log = self.tmp / "gcloud_calls.log"
    self.find_uri = f"gs://{FIND}/exp/FRUN/{REPO}/findings.json"
    self.put(self.find_uri, FIXTURE.read_bytes())
    self.ids = [f["finding_id"] for f in json.loads(FIXTURE.read_text())
                if f["severity"] in ("CRITICAL", "HIGH")]
    self.vprefix = f"gs://{VERIFY}/exp/VRUN/{REPO}"
    self.report_uri = f"{self.vprefix}/post_verify_report.json"
    self.put(self.report_uri, json.dumps([
        {"finding_id": self.ids[0], "status": "VERIFIED"},
        {"finding_id": self.ids[1], "status": "DISMISSED"},
        {"finding_id": self.ids[2], "status": "OPEN"},
    ]))
    self.verify_ids_uri = f"{self.vprefix}/matching_finding_ids.txt"
    self.put(self.verify_ids_uri, f"{self.ids[0]}\n{self.ids[2]}\n")
    self.put(f"{self.vprefix}/findings/{self.ids[0]}/exploit/poc.txt", "payload")
    self.cm_report = self.tmp / "report.json"
    self.cm_report.write_text(json.dumps(
        [{"finding_id": i, "status": s} for i, s in
         zip(self.ids, ["VERIFIED", "DISMISSED", "OPEN"])]))

  def run_ep(self, operation, run_id, sha=None, extra_env=None, **kw):
    env = {"GCLOUD_STUB_LOG": str(self.gcloud_log)}
    env.update(extra_env or {})
    return super().run_ep(operation, run_id, sha=sha, extra_env=env, **kw)

  def task(self, **kw):
    t = {"repo_id": REPO, "language": "python", "severity": "CRITICAL,HIGH"}
    t.update(kw)
    return t

  def norm(self, text):
    text = text.replace(str(self.tmp), "<tmp>")
    text = re.sub(r"cmtask\.\w{6}", "cmtask.X", text)
    text = re.sub(r"/tmp\.\w{10}", "/tmp.X", text)
    text = re.sub(r"\[entrypoint \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\]",
                  "[entrypoint TS]", text)
    text = re.sub(r"soft timeout \d+s", "soft timeout Ns", text)
    # `cm stats --since` is the elapsed task/finding window in seconds.
    text = re.sub(r'("--since", |"since": )"\d+s"', r'\1"Ns"', text)
    return re.sub(r"manual-\d+", "manual-N", text)

  def snapshot(self, proc, prefix_dir):
    logs = [l for l in proc.stderr.splitlines() if l.startswith("[entrypoint ")]
    gcloud = (self.gcloud_log.read_text().splitlines()
              if self.gcloud_log.exists() else [])
    cm = []
    for c in self.cm_calls():
      argv = list(c["argv"])
      if "-c" in argv:
        argv[argv.index("-c") + 1] = "<context>"
      cm.append(json.dumps(argv))
    files, contents = [], []
    if prefix_dir.exists():
      for p in sorted(x for x in prefix_dir.rglob("*") if x.is_file()):
        rel = str(p.relative_to(prefix_dir))
        files.append(rel)
        if p.name in SKIP_CONTENT or "token_stats" in p.name:
          continue
        if p.name == "summary.json":
          s = json.loads(p.read_text())
          for k in VOLATILE_SUMMARY_KEYS:
            s.pop(k, None)
          contents.append(f"=== {rel}\n{json.dumps(s, indent=2, sort_keys=True)}")
        elif p.name == "repo_commit.txt":
          # The fixture repo is re-committed per test run; pin only the shape.
          sha = p.read_text()
          contents.append(f"=== {rel}\n" + re.sub(r"^[0-9a-f]{40}$", "<sha40>",
                                                  sha, flags=re.M))
        elif p.name.endswith(CONTENT_SUFFIXES) and not rel.startswith("logs/") \
            and "context.txt" not in rel and "tool_inventory" not in rel:
          contents.append(f"=== {rel}\n{p.read_text()}")
    return self.norm(
        f"rc={proc.returncode}\n--- log ---\n" + "\n".join(logs) +
        "\n--- gcloud ---\n" + "\n".join(gcloud) +
        "\n--- cm ---\n" + "\n".join(cm) +
        "\n--- files ---\n" + "\n".join(files) +
        "\n--- contents ---\n" + "\n".join(contents) + "\n")


class EntrypointGoldenTest(GoldenBase):

  def test_find(self):
    self.stage_tasks("G", [self.task()])
    p = self.run_ep("find", "G")
    assert_golden(self, "ep_find.txt", self.snapshot(p, self.results(FIND, "G")))

  def test_find_deep_extra_args(self):
    self.stage_tasks("G", [self.task()])
    p = self.run_ep("find", "G", extra_env={"MODE": "deep",
                                            "EXTRA_CM_ARGS": "--foo 1  --bar"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(self.cm_calls("find")[0]["argv"],
                     ["find", "--deep", ".", "--model", "gemini-3.8-flash", "-y",
                      "--bypass-warning", "--foo", "1", "--bar"])
    assert_golden(self, "ep_find_deep.txt",
                  self.snapshot(p, self.results(FIND, "G")))

  def test_verify(self):
    self.stage_tasks("G", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("verify", "G", extra_env={
        "CM_STUB_REPORT": str(self.cm_report), "FROM_FIND_RUN": "FRUN",
        "VERIFY_LIMIT": "2", "EXTRA_CM_ARGS": "--x"})
    assert_golden(self, "ep_verify.txt",
                  self.snapshot(p, self.results(VERIFY, "G")))

  def test_verify_finding_ids(self):
    self.stage_tasks("G", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("verify", "G", extra_env={
        "CM_STUB_REPORT": str(self.cm_report),
        "FINDING_IDS": f"{self.ids[1][:8]}, nope"})
    self.assertEqual([c["argv"][1] for c in self.cm_calls("verify")],
                     [self.ids[1]])
    assert_golden(self, "ep_verify_ids.txt",
                  self.snapshot(p, self.results(VERIFY, "G")))

  def test_fix_from_verify(self):
    self.stage_tasks("G", [self.task(
        findings_gcs_uri=self.find_uri, verify_report_gcs_uri=self.report_uri,
        verify_ids_gcs_uri=self.verify_ids_uri,
        verify_repo_prefix=self.vprefix)])
    p = self.run_ep("fix", "G", extra_env={"FROM_VERIFY_RUN": "VRUN"})
    assert_golden(self, "ep_fix_from_verify.txt",
                  self.snapshot(p, self.results(FIX, "G")))

  def test_fix_from_find(self):
    self.stage_tasks("G", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("fix", "G", extra_env={"FROM_FIND_RUN": "FRUN",
                                           "FIX_LIMIT": "2"})
    assert_golden(self, "ep_fix_from_find.txt",
                  self.snapshot(p, self.results(FIX, "G")))

  def test_fix_include_unverified_with_ids(self):
    self.stage_tasks("G", [self.task(findings_gcs_uri=self.find_uri,
                                     verify_report_gcs_uri=self.report_uri)])
    p = self.run_ep("fix", "G", extra_env={
        "INCLUDE_UNVERIFIED": "1", "FINDING_IDS": self.ids[2][:8]})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual([c["argv"][1] for c in self.cm_calls("fix")], [self.ids[2]])
    assert_golden(self, "ep_fix_unverified_ids.txt",
                  self.snapshot(p, self.results(FIX, "G")))

  def test_fix_include_unverified_excludes_only_dismissed(self):
    self.stage_tasks("G", [self.task(findings_gcs_uri=self.find_uri,
                                     verify_report_gcs_uri=self.report_uri)])
    p = self.run_ep("fix", "G", extra_env={"INCLUDE_UNVERIFIED": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual([c["argv"][1] for c in self.cm_calls("fix")],
                     [self.ids[0], self.ids[2]])

  def test_selftest_roles(self):
    shutil.copy(STUBS / "getent", self.bin / "getent")
    for b in (PAYLOAD, FIND, VERIFY):
      self.put(f"gs://{b}/marker", "x")
    cases = {
        "cm-find-runner": (FIND, f"{PAYLOAD},{VERIFY},{FIX}", f"{VERIFY},{FIX}"),
        "cm-verify-runner": (VERIFY, f"{PAYLOAD},{FIND},{FIX}", FIX),
        "cm-fix-runner": (FIX, f"{PAYLOAD},{FIND},{VERIFY}", ""),
    }
    for job, (own, deny_w, deny_r) in cases.items():
      with self.subTest(job):
        if self.gcloud_log.exists():
          self.gcloud_log.unlink()
        p = self.run_ep("selftest", "unused", extra_env={
            "CLOUD_RUN_JOB": job, "CLOUD_RUN_EXECUTION": f"{job}-g",
            "GCS_DENY_WRITE": deny_w, "GCS_DENY_READ": deny_r})
        result = json.loads(
            (self.emu / own / "selftest" / f"{job}-g" / "result.json").read_text())
        # toolbox_*/airgap_* results (and so all_pass) depend on the host
        # running the test, so only their names are pinned.
        host_dependent = ("toolbox_", "airgap_")
        self.assertTrue(all(c["pass"] for c in result["checks"]
                            if not c["name"].startswith(host_dependent)), result)
        checks = [c["name"] if c["name"].startswith(host_dependent)
                  else f"{c['name']}={c['pass']}" for c in result["checks"]]
        header = {k: result[k] for k in ("role", "execution", "job")}
        snap = self.snapshot(p, self.emu / own / "selftest" / f"{job}-g")
        snap = re.sub(r"all_pass=\w+", "all_pass=X",
                      snap.split("--- contents ---")[0])
        assert_golden(self, f"ep_selftest_{job}.txt",
                      snap + json.dumps(header) + "\n" + "\n".join(checks) + "\n")


class Cm010GoldenTest(GoldenBase):
  """cm 0.10.0 keeps the 0.9.0 argv contract (its --fail-on gates only --diff)."""

  def test_argv_01_deep_v010(self):
    self.stage_tasks("G", [self.task()])
    p = self.run_ep("find", "G", cm_version="0.10.0",
                    extra_env={"MODE": "deep", "DEEP_WORKERS": "16"})
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(self.cm_calls("find")[0]["argv"],
                     ["find", "--deep", "--deep-workers", "16", ".", "--model",
                      "gemini-3.8-flash", "-y", "--bypass-warning"])
    assert_golden(self, "ep_find_deep_v0_10.txt",
                  self.snapshot(p, self.results(FIND, "G")))

  def test_argv_02_shallow_v010(self):
    self.stage_tasks("G", [self.task()])
    p = self.run_ep("find", "G", cm_version="0.10.0")
    self.assertEqual(p.returncode, 0, p.stderr)
    self.assertEqual(self.cm_calls("find")[0]["argv"][:2], ["find", "."])
    assert_golden(self, "ep_find_v0_10.txt",
                  self.snapshot(p, self.results(FIND, "G")))

  def test_argv_07_verify_fix_v010(self):
    self.stage_tasks("G", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("verify", "G", cm_version="0.10.0", extra_env={
        "CM_STUB_REPORT": str(self.cm_report), "FROM_FIND_RUN": "FRUN",
        "VERIFY_LIMIT": "2", "EXTRA_CM_ARGS": "--x"})
    assert_golden(self, "ep_verify_v0_10.txt",
                  self.snapshot(p, self.results(VERIFY, "G")))
    p = self.run_ep("fix", "G", cm_version="0.10.0",
                    extra_env={"FROM_FIND_RUN": "FRUN", "FIX_LIMIT": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    for c in self.cm_calls("verify") + self.cm_calls("fix"):
      for flag in ("--unrestricted", "-c"):
        self.assertIn(flag, c["argv"])
    self.assertTrue(all("--no-reset" in c["argv"] for c in self.cm_calls("verify")))


class EntrypointCharacterizationTest(GoldenBase):

  def test_verify_deadline_skip(self):
    self.stage_tasks("D", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("verify", "D", extra_env={"JOB_TIMEOUT": "70",
                                              "SOFT_TIMEOUT_RESERVE": "15"})
    self.assertEqual(p.returncode, 124, p.stderr)
    out = self.results(VERIFY, "D")
    for fid in self.ids:
      self.assertEqual((out / "findings" / fid / "exit_code").read_text(),
                       "deadline\n")
      self.assertIn(f"soft deadline reached; skipping {fid}", p.stderr)
    self.assertEqual(self.cm_calls("verify"), [])
    summary = json.loads((out / "summary.json").read_text())
    self.assertEqual(summary["status"], "timeout")
    assert_golden(self, "ep_verify_deadline.txt", self.snapshot(p, out))

  def test_fix_deadline_skip(self):
    self.stage_tasks("D", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("fix", "D", extra_env={"JOB_TIMEOUT": "70",
                                           "SOFT_TIMEOUT_RESERVE": "15"})
    self.assertEqual(p.returncode, 124, p.stderr)
    out = self.results(FIX, "D")
    self.assertEqual(self.cm_calls("fix"), [])
    self.assertFalse((out / "patch.diff").exists())
    assert_golden(self, "ep_fix_deadline.txt", self.snapshot(p, out))

  def test_top_level_patch_is_glob_ordered_concatenation(self):
    self.stage_tasks("P", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("fix", "P")
    self.assertEqual(p.returncode, 0, p.stderr)
    out = self.results(FIX, "P")
    self.assertNotEqual(self.ids, sorted(self.ids))  # severity != glob order
    expected = "".join((out / "findings" / fid / "patch.diff").read_text()
                       for fid in sorted(self.ids))
    self.assertEqual((out / "patch.diff").read_text(), expected)

  def test_patch_falls_back_to_state_db(self):
    self.stage_tasks("P", [self.task(findings_gcs_uri=self.find_uri)])
    p = self.run_ep("fix", "P", extra_env={"CM_STUB_FIX_NO_EDIT": "1",
                                           "FIX_LIMIT": "1"})
    self.assertEqual(p.returncode, 0, p.stderr)
    diff = (self.results(FIX, "P") / "findings" / self.ids[0] /
            "patch.diff").read_text()
    self.assertEqual(diff, "--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n"
                     f"+# fix applied for {self.ids[0]}\n")

  def test_nested_exploit_is_flattened(self):
    prefix = f"gs://{VERIFY}/exp/VRUN2/{REPO}"
    self.put(f"{prefix}/findings/{self.ids[0]}/exploit/exploit/run.sh", "echo")
    self.stage_tasks("X", [self.task(
        findings_gcs_uri=self.find_uri, verify_report_gcs_uri=self.report_uri,
        verify_ids_gcs_uri=self.verify_ids_uri, verify_repo_prefix=prefix)])
    p = self.run_ep("fix", "X")
    self.assertEqual(p.returncode, 0, p.stderr)
    edir = self.results(FIX, "X") / "findings" / self.ids[0] / "exploit"
    self.assertEqual((edir / "run.sh").read_text(), "echo")
    self.assertFalse((edir / "exploit").exists())

  def test_unknown_operation_dies(self):
    p = self.run_ep("bogus", "U")
    self.assertEqual(p.returncode, 1)
    self.assertRegex(p.stderr, r"\[entrypoint [^\]]+\] FATAL: unknown OPERATION "
                     r"'bogus'")

  def test_missing_findings_uri_dies(self):
    for op in ("verify", "fix"):
      with self.subTest(op):
        self.stage_tasks(f"M{op}", [self.task()])
        p = self.run_ep(op, f"M{op}")
        self.assertEqual(p.returncode, 1)
        self.assertIn(f"FATAL: {op} task has no findings_gcs_uri", p.stderr)

  def test_missing_tasks_json_dies(self):
    p = self.run_ep("find", "NOPE")
    self.assertEqual(p.returncode, 1)
    self.assertIn("FATAL: cannot read tasks.json", p.stderr)

  def test_task_without_repo_id_dies(self):
    self.stage_tasks("R", [{"language": "python"}])
    p = self.run_ep("find", "R")
    self.assertEqual(p.returncode, 1)
    self.assertIn("FATAL: task 0 has no repo_id", p.stderr)

  def test_selftest_manual_execution_and_no_fix_bucket(self):
    shutil.copy(STUBS / "getent", self.bin / "getent")
    for b in (PAYLOAD, FIND, VERIFY):
      self.put(f"gs://{b}/marker", "x")
    p = self.run_ep("selftest", "u", extra_env={
        "CLOUD_RUN_JOB": "cm-find-runner", "FIX_RESULTS_BUCKET": "",
        "GCS_DENY_WRITE": f"{PAYLOAD},{VERIFY}", "GCS_DENY_READ": VERIFY})
    self.assertEqual(p.returncode, 0, p.stderr)
    results = list((self.emu / FIND / "selftest").glob("manual-*/result.json"))
    self.assertEqual(len(results), 1)
    r = json.loads(results[0].read_text())
    self.assertRegex(r["execution"], r"^manual-\d+$")
    names = [c["name"] for c in r["checks"]]
    self.assertNotIn("find_sa_read_fix_results_denied", names)
    self.assertTrue(r["all_pass"], r)
    self.assertTrue(p.stdout.lstrip().startswith("{"))


del EntrypointTestBase  # keep unittest from collecting the imported base twice

if __name__ == "__main__":
  unittest.main()
