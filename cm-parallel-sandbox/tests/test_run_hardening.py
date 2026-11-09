"""Tests for the run.py hardening fixes (F21, F22, F23, F27, F28)."""

import json
import unittest

import run
from cmrun import common

from tests import test_run_cli as t
from tests.fakes import FakeRunner

FIXTURE_ITEMS = json.loads(t.FIXTURE)
CRIT = FIXTURE_ITEMS[0]["finding_id"]
HIGH_IDS = [f["finding_id"] for f in FIXTURE_ITEMS if f["severity"] == "HIGH"]


class TaskMatchingCapTest(unittest.TestCase):
  """F22: per-task matching_findings agrees with the capped aggregate."""

  def test_verify_limit_caps_task_matching_findings(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/R/o04-vampi/findings.json": t.FIXTURE})
    rc, out = t.main(["--operation", "verify", "--from-find-run", "smoke/R",
                      "--repos", "o04-vampi", "--verify-limit", "2",
                      "--run-id", "V"], r)
    self.assertEqual(rc, 0, out)
    tasks = t.uploaded_json(r, "/V/tasks.json")
    self.assertEqual([task["matching_findings"] for task in tasks], [2])
    self.assertIn("2 matching CRITICAL,HIGH across 1/1 repo(s)", out)

  def test_fix_limit_caps_task_matching_findings_from_verify(self):
    prefix = f"{t.VERIFY}/smoke/V/o04-vampi"
    ids = [CRIT, *HIGH_IDS]
    r = t.staged_runner(**{
        f"{prefix}/matching_finding_ids.txt": "".join(i + "\n" for i in ids).encode(),
        f"{prefix}/post_verify_report.json": json.dumps(
            [{"finding_id": i, "status": "VERIFIED"} for i in ids]).encode(),
        f"{prefix}/source_findings.json": t.FIXTURE,
    })
    rc, out = t.main(["--operation", "fix", "--from-verify-run", "smoke/V",
                      "--repos", "o04-vampi", "--fix-limit", "1",
                      "--run-id", "F"], r)
    self.assertEqual(rc, 0, out)
    tasks = t.uploaded_json(r, "/F/tasks.json")
    self.assertEqual([task["matching_findings"] for task in tasks], [1])
    self.assertIn("1 matching across 1/1 repo(s) queued for fix", out)

  def test_uncapped_task_matching_findings_unchanged(self):
    r = t.staged_runner(**{f"{t.FIND}/smoke/R/o04-vampi/findings.json": t.FIXTURE})
    rc, out = t.main(["--operation", "fix", "--from-find-run", "smoke/R",
                      "--repos", "o04-vampi", "--run-id", "F"], r)
    self.assertEqual(rc, 0, out)
    tasks = t.uploaded_json(r, "/F/tasks.json")
    self.assertEqual([task["matching_findings"] for task in tasks], [3])


class SidecarShaTest(unittest.TestCase):
  """F23: the cached cm sidecar must hold a lowercase hex SHA-256."""

  def _run(self, sidecar):
    r = FakeRunner(gcs={t.ZIP: b"old", f"{t.ZIP}.sha256": sidecar,
                        f"{t.PAYLOAD}/repos/o04-vampi.tar.gz": b"t"},
                   responses={"gcloud artifacts generic download": t.fake_download})
    rc, out = t.main(["--repos", "o04-vampi", "--dry-run"], r)
    self.assertEqual(rc, 0, out)
    return out

  def test_non_hex_sidecar_restages(self):
    for bad in ("z" * 64, "A" * 64, "a" * 63 + "-"):
      with self.subTest(bad=bad):
        out = self._run(f"{bad}  cm-linux-amd64.zip\n".encode())
        self.assertIn(f"[stage] cm 0.11.0: {t.ZIP} exists but sidecar invalid; "
                      "re-staging", out)
        self.assertIn("EXPECTED_CM_SHA256=<sha256-of-downloaded-zip>", out)

  def test_empty_sidecar_still_reports_missing(self):
    out = self._run(b"\n")
    self.assertIn(f"{t.ZIP} exists but sidecar missing; re-staging", out)

  def test_valid_sidecar_is_cached(self):
    out = self._run(f"{t.SHA}  cm-linux-amd64.zip\n".encode())
    self.assertIn(f"[stage] cm 0.11.0: cached {t.ZIP} sha256={t.SHA}", out)
    self.assertIn(f"EXPECTED_CM_SHA256={t.SHA}", out)


class LatestRunTest(unittest.TestCase):
  """F28: 'latest' is the run with the newest summary.json, not max(run_id)."""

  def _resolve(self, times):
    gcs, gcs_times = {}, {}
    for run_id, ts in times.items():
      uri = f"gs://b/e/{run_id}/o04-vampi/summary.json"
      gcs[uri], gcs_times[uri] = b"{}", ts
    gcs["gs://b/e/zzz_in_progress/o04-vampi/findings.json"] = b""
    return run.resolve_find_run(FakeRunner(gcs=gcs, gcs_times=gcs_times),
                                "b", "e/latest")

  def test_custom_id_newer_wins(self):
    self.assertEqual(self._resolve({"20260101_000000_a": "2026-01-01T00:00:00Z",
                                    "my-custom-run": "2026-02-01T00:00:00Z"}),
                     ("e", "my-custom-run"))

  def test_custom_id_older_loses(self):
    self.assertEqual(self._resolve({"20260101_000000_a": "2026-03-01T00:00:00Z",
                                    "my-custom-run": "2026-02-01T00:00:00Z"}),
                     ("e", "20260101_000000_a"))

  def test_tie_breaks_on_run_id(self):
    ts = "2026-01-01T00:00:00Z"
    self.assertEqual(self._resolve({"a": ts, "b": ts}), ("e", "b"))

  def test_no_summaries_raises(self):
    r = FakeRunner(gcs={"gs://b/e/R/o04-vampi/findings.json": b""})
    with self.assertRaisesRegex(common.UsageError,
                                r"^no find runs found under gs://b/e/$"):
      run.resolve_find_run(r, "b", "e/latest")


if __name__ == "__main__":
  unittest.main()
