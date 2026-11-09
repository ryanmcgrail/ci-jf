"""Golden snapshots of run.py's external contract (fake runner; no real gcloud).

Each scenario is captured twice: --dry-run (full log output) and a full run
(log output, every mutating gcloud argv including the ^##^ env payload, and the
uploaded tasks.json / run_manifest.json bytes). Goldens were generated from the
pre-refactor code, so any contract drift fails here.
"""

import contextlib
import io
import json
import re
import tempfile
import unittest
import unittest.mock

import run
from tests import test_run_cli as t
from tests.golden_util import assert_golden

FIXTURE_ITEMS = json.loads(t.FIXTURE)
CRIT, HIGH1, HIGH2 = (FIXTURE_ITEMS[i]["finding_id"] for i in range(3))

BASE = ["--experiment-id", "smoke", "--run-id", "GOLD",
        "--repos", "o04-vampi", "p01-flask"]

SCENARIOS = {
    "find": ["--operation", "find"],
    "find_deep": ["--operation", "find", "--mode", "deep",
                  "--cm-version", "0.10.0"],
    "find_deep_budget": ["--operation", "find", "--mode", "deep",
                         "--cm-version", "0.10.0", "--deep-workers", "15",
                         "--container-timeout", "1000", "--model", "m/x y",
                         "--region", "europe-west4"],
    "verify": ["--operation", "verify", "--from-find-run", "FRUN"],
    "verify_latest": ["--operation", "verify", "--from-find-run", "latest"],
    "verify_limit_severity": ["--operation", "verify", "--from-find-run", "FRUN",
                              "--verify-limit", "1",
                              "--severity", "critical,high,medium"],
    "verify_finding_ids": ["--operation", "verify", "--from-find-run",
                           "smoke/FRUN", "--finding-ids", CRIT[:4], HIGH1[:4]],
    "fix_from_verify": ["--operation", "fix", "--from-verify-run", "VRUN"],
    "fix_from_verify_unverified": ["--operation", "fix", "--from-verify-run",
                                   "VRUN", "--include-unverified",
                                   "--fix-limit", "1", "--fix-timeout", "600"],
    "fix_from_verify_ids": ["--operation", "fix", "--from-verify-run",
                            "smoke/VRUN", "--finding-ids", HIGH2[:4]],
    "fix_from_find": ["--operation", "fix", "--from-find-run", "FRUN",
                      "--fix-limit", "2"],
    "find_verify": ["--operation", "find-verify", "--verify-limit", "2",
                    "--extra-cm-args", "--a 1, --b"],
    "verify_fix": ["--operation", "verify-fix", "--from-find-run", "FRUN",
                   "--verify-limit", "2", "--fix-limit", "1"],
    "find_fix": ["--operation", "find-fix", "--fix-limit", "1"],
    "find_verify_fix": ["--operation", "find-verify-fix", "--verify-limit", "2",
                        "--fix-limit", "2", "--include-unverified", "--wait"],
}

PARSE_ERRORS = [
    ["--poll-interval", "0"],
    ["--container-timeout", "300"],
    ["--container-timeout", "604801"],
    ["--fix-timeout", "5"],
    ["--operation", "fix", "--from-find-run", "R", "--fix-timeout", "0"],
    ["--operation", "fix", "--from-find-run", "R", "--container-timeout",
     "1000", "--fix-timeout", "701"],
    ["--operation", "find-verify", "--verify-limit", "1", "--fix-timeout", "9"],
    ["--verify-limit", "1"],
    ["--operation", "verify", "--from-find-run", "R", "--verify-limit", "-1"],
    ["--operation", "find-verify", "--fix-limit", "1"],
    ["--operation", "fix", "--from-find-run", "R", "--fix-limit", "-1"],
    ["--severity", "HIGH"],
    ["--operation", "verify", "--from-find-run", "R", "--mode", "deep"],
    ["--mode", "deep", "--cm-version", "0.9.0"],
    ["--mode", "deep", "--cm-version", "banana"],
    ["--operation", "verify-fix"],
    ["--operation", "find-fix", "--from-find-run", "R"],
    ["--operation", "find-verify", "--from-verify-run", "V"],
    ["--operation", "fix"],
    ["--operation", "fix", "--from-find-run", "R", "--from-verify-run", "V"],
    ["--operation", "find-fix", "--include-unverified"],
    ["--operation", "fix", "--from-find-run", "R", "--include-unverified"],
    ["--finding-ids", "x"],
    ["--operation", "verify", "--from-find-run", "R", "--finding-ids", "x",
     "--severity", "HIGH"],
    ["--operation", "verify", "--from-find-run", "R", "--finding-ids", "x",
     "--verify-limit", "0"],
    ["--operation", "fix", "--from-find-run", "R", "--finding-ids", "x",
     "--fix-limit", "0"],
    ["--operation", "selftest"],
    ["--deep-workers", "two"],
    ["--deep-workers", "4"],
    ["--mode", "deep", "--cm-version", "0.10.0", "--deep-workers", "17"],
    ["--extra-cm-args", "--x, --deep-workers=4"],
    ["--bogus"],
]


def golden_runner():
  low = json.dumps([{"finding_id": "low1", "severity": "LOW"}]).encode()
  report = json.dumps({"summary": {}, "findings": [
      {"finding_id": CRIT, "status": "VERIFIED"},
      {"finding_id": HIGH1, "status": "UNVERIFIED"},
      {"finding_id": HIGH2, "status": "DISMISSED"},
  ]}).encode()
  gcs = {}
  for run_id in ("FRUN", "GOLD"):
    gcs[f"{t.FIND}/smoke/{run_id}/o04-vampi/findings.json"] = t.FIXTURE
    gcs[f"{t.FIND}/smoke/{run_id}/p01-flask/findings.json"] = low
    gcs[f"{t.FIND}/smoke/{run_id}/o04-vampi/summary.json"] = b"{}"
  for run_id in ("VRUN", "GOLD", "GOLD_verify"):
    prefix = f"{t.VERIFY}/smoke/{run_id}/o04-vampi"
    gcs[f"{prefix}/matching_finding_ids.txt"] = (
        f"{CRIT}\n{HIGH1}\n{HIGH2}\n".encode())
    gcs[f"{prefix}/post_verify_report.json"] = report
    gcs[f"{prefix}/source_findings.json"] = t.FIXTURE
  return t.staged_runner(**gcs)


def normalize(text):
  return re.sub(re.escape(tempfile.gettempdir()) + r"/cm_(run|zip|stage)_[^/\s]+",
                "<tmp>", text)


def run_scenario(argv):
  r = golden_runner()
  if "deep" in argv:
    # Only 0.9.0 is cached so deep scenarios keep covering the download path.
    for suffix in ("", ".sha256"):
      r.gcs[t.ZIP.replace("0.11.0", "0.9.0") + suffix] = r.gcs.pop(t.ZIP + suffix)
  rc, out = t.main(argv, r, clock=lambda: 0.0)
  return r, rc, out


class RunGoldenTest(unittest.TestCase):

  def test_dry_run_snapshots(self):
    for name, argv in SCENARIOS.items():
      with self.subTest(name):
        _, rc, out = run_scenario(BASE + argv + ["--dry-run"])
        assert_golden(self, f"run_{name}_dry.txt",
                      normalize(f"rc={rc}\n--- log ---\n{out}\n"))

  def test_full_run_snapshots(self):
    for name, argv in SCENARIOS.items():
      with self.subTest(name):
        r, rc, out = run_scenario(BASE + argv)
        calls = "\n".join(json.dumps(c) for c in r.mutating_calls())
        uploads = "\n".join(
            f"=== {k}\n{r.gcs[k].decode()}" for k in sorted(r.gcs)
            if "/runs/" in k or k.endswith(".sha256"))
        assert_golden(self, f"run_{name}_full.txt", normalize(
            f"rc={rc}\n--- log ---\n{out}\n--- mutating calls ---\n{calls}\n"
            f"--- uploads ---\n{uploads}\n"))

  def test_parse_error_snapshots(self):
    chunks = []
    with unittest.mock.patch("sys.argv", ["run.py"]), \
        unittest.mock.patch.dict("os.environ", {"COLUMNS": "100"}):
      for argv in PARSE_ERRORS:
        err = io.StringIO()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):
          run.parse_args(argv)
        chunks.append(f"$ {' '.join(argv)}\nexit={cm.exception.code}\n"
                      f"{err.getvalue()}")
    assert_golden(self, "run_parse_errors.txt", "\n".join(chunks))

  def test_help_snapshot(self):
    out = io.StringIO()
    with unittest.mock.patch("sys.argv", ["run.py"]), \
        unittest.mock.patch.dict("os.environ", {"COLUMNS": "100"}), \
        self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(out):
      run.parse_args(["--help"])
    self.assertEqual(cm.exception.code, 0)
    assert_golden(self, "run_help.txt", out.getvalue())


if __name__ == "__main__":
  unittest.main()
