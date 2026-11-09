"""Tests for scripts/aggregate_diff_results.py with a fake `gcloud` on PATH."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "aggregate_diff_results.py"

_spec = importlib.util.spec_from_file_location("aggregate_diff_results", SCRIPT)
agg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agg)

BUCKET = "gs://fake-results/cm-011-diff"
RUN = "20261004_000000_find_v0.11.0_gemini-test"
MODEL = "gemini-test"

FAKE_GCLOUD = textwrap.dedent("""\
    #!/usr/bin/env python3
    # Minimal `gcloud storage ls|cp` backed by $FAKE_GCS_ROOT/<bucket>/<path>.
    import os, shutil, sys
    root = os.environ["FAKE_GCS_ROOT"]
    def local(uri):
      return os.path.join(root, uri[len("gs://"):].rstrip("/"))
    args = sys.argv[1:]
    if args[:2] == ["storage", "ls"]:
      d = local(args[2])
      if not os.path.isdir(d):
        sys.exit(1)
      for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        print(args[2].rstrip("/") + "/" + n + ("/" if os.path.isdir(p) else ""))
    elif args[:2] == ["storage", "cp"]:
      src = local(args[2])
      if not os.path.isfile(src):
        sys.exit(1)
      shutil.copy(src, args[3])
    else:
      sys.exit(3)
    """)

TSV_HEADER = ["repo_id", "diff_bucket", "source_repo_id", "evidence"]
# (case, band, changed_files, changed_lines)
CASES = [
    ("r1--a-s1", "S", 2, 10),
    ("r1--a-s2", "S", 3, 20),
    ("r1--a-s3", "S", 1, 30),
    ("r2--b-m1", "M", 5, 200),
    ("r2--b-m2", "M", 6, 300),
    ("r3--c-l1", "L", 40, 5000),
]


def summary(case, files, lines, tokens, wall=100, timed_out=False, **kw):
  s = {"repo_id": case, "run_id": RUN, "model": MODEL, "mode": "diff",
       "cm_version": "0.11.0", "status": "ok", "wall_clock_seconds": wall,
       "findings_count": 0, "severity_counts": {},
       "tokens": {"input_tokens": tokens - 100, "output_tokens": 100,
                  "total_tokens": tokens},
       "changed_files": files, "changed_lines": lines, "cm_exit_code": 0,
       "diff_workers": None, "diff_timed_out": timed_out,
       "diff_jobs_total": 4, "diff_jobs_completed": 4}
  s.update(kw)
  return s


class AggregateDiffResultsTest(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    t = pathlib.Path(self.tmp.name)
    self.gcs = t / "gcs"
    self.cache = t / "cache"
    bindir = t / "bin"
    bindir.mkdir()
    gcloud = bindir / "gcloud"
    gcloud.write_text(FAKE_GCLOUD)
    gcloud.chmod(0o755)
    self.env = dict(os.environ, FAKE_GCS_ROOT=str(self.gcs),
                    PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")
    self.tsv = t / "cases.tsv"
    lines = ["\t".join(TSV_HEADER)]
    for case, band, files, nl in CASES:
      lines.append("\t".join([case, band, case.split("--")[0],
                              f"k=1; changed_files={files}; changed_lines={nl}"]))
    self.tsv.write_text("\r\n".join(lines) + "\r\n")
    self.run_dir = self.gcs / BUCKET[len("gs://"):] / RUN

  def put(self, s):
    d = self.run_dir / s["repo_id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "summary.json").write_text(json.dumps(s))

  def put_all_ok(self):
    toks = {"r1--a-s1": 1000, "r1--a-s2": 2000, "r1--a-s3": 4000,
            "r2--b-m1": 10000, "r2--b-m2": 30000, "r3--c-l1": 90000}
    for case, _, files, nl in CASES:
      self.put(summary(case, files, nl, toks[case], wall=toks[case] // 100))

  def run_agg(self, *extra, model=MODEL):
    args = [sys.executable, str(SCRIPT), "--tsv", str(self.tsv),
            "--out", str(self.cache), "--model-label", model, *extra,
            f"A={BUCKET}/{RUN}"]
    return subprocess.run(args, env=self.env, capture_output=True, text=True)

  def test_pct_interpolates(self):
    self.assertIsNone(agg.pct([], .5))
    self.assertEqual(agg.pct([5], .9), 5)
    self.assertEqual(agg.pct([1, 2, 4], .5), 2)
    self.assertAlmostEqual(agg.pct([1, 2, 4], .9), 3.6)
    self.assertEqual(agg.pct([4, 1, 3, 2], .5), 2.5)

  def test_parse_evidence(self):
    self.assertEqual(agg.parse_evidence("k=14; changed_files=12; changed_lines=130"),
                     {"k": "14", "changed_files": "12", "changed_lines": "130"})

  def test_all_ok_percentiles_and_json(self):
    self.put_all_ok()
    out = pathlib.Path(self.tmp.name) / "agg.json"
    r = self.run_agg("--json", str(out))
    self.assertEqual(r.returncode, 0, r.stderr)
    self.assertIn("| S | 3 | 0 | 0 | 2,000 | 3,600 |", r.stdout)
    self.assertIn("Total tokens across 6 valid cases (6 listed): 137,000", r.stdout)
    data = json.loads(out.read_text())
    self.assertEqual(data["model"], MODEL)
    self.assertEqual(data["batches"], {"A": f"{BUCKET}/{RUN}"})
    s = data["bands"]["S"]
    self.assertEqual((s["cases"], s["timed_out"], s["excluded"]), (3, 0, 0))
    self.assertEqual(s["median_tokens"], 2000)
    self.assertAlmostEqual(s["p90_tokens"], 3600)
    self.assertEqual(s["median_wall_s"], 20)
    self.assertEqual(s["median_lines"], 20)
    self.assertEqual(s["median_tokens_per_line"], 100)
    self.assertEqual(data["bands"]["M"]["median_tokens"], 20000)
    self.assertEqual(data["bands"]["XL"]["cases"], 0)
    self.assertIsNone(data["bands"]["XL"]["median_tokens"])
    self.assertEqual(data["bands"]["ALL"]["cases"], 6)
    self.assertEqual(data["total_tokens"], 137000)
    self.assertEqual(data["correlation"]["n"], 6)
    self.assertGreater(data["correlation"]["pearson_r"], 0.9)
    self.assertEqual(data["problems"], {})

  def test_timeout_counted_but_excluded_from_medians(self):
    self.put_all_ok()
    self.put(summary("r1--a-s3", 1, 30, 50000, wall=330, timed_out=True,
                     cm_exit_code=1, diff_jobs_completed=2))
    out = pathlib.Path(self.tmp.name) / "agg.json"
    r = self.run_agg("--json", str(out))
    self.assertEqual(r.returncode, 0, r.stderr)
    s = json.loads(out.read_text())["bands"]["S"]
    self.assertEqual((s["cases"], s["valid"], s["timed_out"]), (3, 3, 1))
    self.assertEqual(s["median_tokens"], 1500)  # 1000 and 2000 only
    self.assertEqual(s["total_tokens"], 53000)  # timeout tokens still counted
    self.assertIn("| S | `r1--a-s3` | 1 | 30 | 2/4 | 50,000 | 330 |", r.stdout)
    self.assertEqual(json.loads(out.read_text())["correlation"]["n"], 5)

  def test_evidence_mismatch_is_a_problem(self):
    self.put_all_ok()
    self.put(summary("r2--b-m1", 5, 201, 10000))
    out = pathlib.Path(self.tmp.name) / "agg.json"
    r = self.run_agg("--json", str(out))
    self.assertEqual(r.returncode, 2)
    self.assertIn("r2--b-m1: changed_lines=201 != evidence '200'", r.stderr)
    data = json.loads(out.read_text())
    self.assertEqual(list(data["problems"]), ["r2--b-m1"])
    m = data["bands"]["M"]
    self.assertEqual((m["cases"], m["excluded"], m["median_tokens"]), (2, 1, 30000))

  def test_pipeline_fields_and_zero_tokens_are_problems(self):
    self.put_all_ok()
    self.put(summary("r1--a-s1", 2, 10, 1000, diff_workers=8))
    self.put(summary("r1--a-s2", 3, 20, 0))
    self.put(summary("r2--b-m1", 5, 200, 10000, cm_version="0.10.0"))
    r = self.run_agg()
    self.assertEqual(r.returncode, 2)
    self.assertIn("r1--a-s1: diff_workers=8 (want None)", r.stderr)
    self.assertIn("r1--a-s2: total_tokens=0", r.stderr)
    self.assertIn("r2--b-m1: cm_version='0.10.0' (want '0.11.0')", r.stderr)

  def test_wrong_model_is_a_problem(self):
    self.put_all_ok()
    r = self.run_agg(model="gemini-other")
    self.assertEqual(r.returncode, 2)
    self.assertIn("model='gemini-test' (want 'gemini-other')", r.stderr)

  def test_missing_summary_and_missing_case_dir(self):
    self.put_all_ok()
    (self.run_dir / "r3--c-l1" / "summary.json").unlink()
    (self.run_dir / "r3--c-l1" / "logs.txt").write_text("x")
    expect = pathlib.Path(self.tmp.name) / "expect.ids"
    expect.write_text("\n".join(c for c, *_ in CASES) + "\nr4--d-x1\n")
    r = self.run_agg("--expect", str(expect))
    self.assertEqual(r.returncode, 2)
    self.assertIn("r3--c-l1: missing summary.json", r.stderr)
    self.assertIn("r4--d-x1: no case directory", r.stderr)
    self.assertIn("| A | `r3--c-l1` | L | | | | | | | | | | | MISSING |", r.stdout)
    self.assertIn("Total tokens across 5 valid cases (7 listed): 47,000", r.stdout)

  def test_bad_batch_spec_is_a_usage_error(self):
    r = subprocess.run([sys.executable, str(SCRIPT), "--tsv", str(self.tsv),
                        "A=/local/path"], env=self.env, capture_output=True,
                       text=True)
    self.assertEqual(r.returncode, 2)
    self.assertIn("bad batch", r.stderr)


if __name__ == "__main__":
  unittest.main()
