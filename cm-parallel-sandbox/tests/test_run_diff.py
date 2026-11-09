"""run.py --mode diff (fake runner; no real gcloud or network)."""

import argparse
import contextlib
import csv
import io
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import unittest.mock

import run
import stage_repos
from cmrun import common
from cmrun import pipeline
from tests import test_run_cli as t
from tests.fakes import FakeRunner
from tests.golden_util import assert_golden
from tests.test_run_golden import normalize

DIFF_TSV = str(common.REPO_ROOT / "config" / "repos_with_diff.tsv")
VAMPI_S = "o04-vampi--f16052d-beca461"
VAMPI_M = "o04-vampi--f16052d-a488a52"
VAMPI = [VAMPI_S, VAMPI_M]
PINNED = "f16052dce83f05847133ec98f01c5193a41de7d8"
BASE = ["--operation", "find", "--mode", "diff", "--repos-tsv", DIFF_TSV,
        "--experiment-id", "cm-011-diff-smoke", "--run-id", "GOLD",
        "--repos", *VAMPI]


class DiffGitRunner(FakeRunner):
  """FakeRunner that also answers stage_one_diff's git queries."""

  def __init__(self, *a, count="3", ancestor=True, cat_file_rc=0, **kw):
    super().__init__(*a, **kw)
    # ancestor: one bool for every merge-base call, or a list consumed in order.
    self.count, self.ancestor, self.cat_file_rc = count, ancestor, cat_file_rc

  def _ancestor(self):
    if isinstance(self.ancestor, list):
      return self.ancestor.pop(0)
    return self.ancestor

  def run(self, args, check=True, cwd=None):
    args = list(args)
    if args[:1] == ["git"]:
      for sub, res in (("rev-list", lambda: common.Result(0, self.count + "\n")),
                       ("merge-base",
                        lambda: common.Result(0 if self._ancestor() else 1)),
                       ("cat-file", lambda: common.Result(self.cat_file_rc))):
        if sub in args:
          self.calls.append(args)
          res = res()
          if check and res.returncode:
            raise RuntimeError(f"fake command failed: {args}")
          return res
    return super().run(args, check=check, cwd=cwd)


def diff_runner(**kw):
  r = t.staged_runner()
  return DiffGitRunner(gcs=r.gcs, responses=r.responses, **kw)


def main(argv, runner, **kw):
  """t.main with stage_repos' progress prints silenced."""
  with contextlib.redirect_stdout(io.StringIO()):
    return t.main(argv, runner, **kw)


def parse_error(argv):
  err = io.StringIO()
  with unittest.mock.patch("sys.argv", ["run.py"]), \
      contextlib.redirect_stderr(err), \
      unittest.TestCase().assertRaises(SystemExit):
    run.parse_args(argv)
  return err.getvalue()


def write_tsv(path, rows, columns):
  with open(path, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=columns, delimiter="\t",
                       lineterminator="\n")
    w.writeheader()
    w.writerows(rows)


def diff_row(**kw):
  row = {"repo_id": VAMPI_S, "git_url": "https://github.com/erev0s/VAmPI.git",
         "pinned_ref": PINNED,
         "diff_ref": "beca4615d1bc947825a5e5bd8a9275c2a7cbda6a",
         "source_repo_id": "o04-vampi", "language": "python"}
  row.update(kw)
  return row


class DiffParseTest(unittest.TestCase):

  def test_requires_explicit_repos_tsv(self):
    self.assertIn("--mode diff requires an explicit --repos-tsv",
                  parse_error(["--mode", "diff"]))

  def test_other_modes_default_to_repos_tsv(self):
    _, a = run.parse_args([])
    self.assertEqual(a.repos_tsv, str(common.DEFAULT_REPOS_TSV))

  def test_diff_workers_default_unset(self):
    _, a = run.parse_args(["--mode", "diff", "--repos-tsv", DIFF_TSV])
    self.assertIsNone(a.diff_workers)
    self.assertIsNone(a.deep_workers)

  def test_diff_workers_range_and_mode(self):
    for argv, msg in (
        (["--diff-workers", "4"], "--diff-workers requires --mode diff"),
        (["--mode", "deep", "--cm-version", "0.10.0", "--diff-workers", "4"],
         "--diff-workers requires --mode diff"),
        (["--mode", "diff", "--repos-tsv", DIFF_TSV, "--diff-workers", "0"],
         "--diff-workers must be between 1 and 16"),
        (["--mode", "diff", "--repos-tsv", DIFF_TSV, "--diff-workers", "17"],
         "--diff-workers must be between 1 and 16"),
        (["--mode", "diff", "--repos-tsv", DIFF_TSV, "--deep-workers", "4"],
         "--deep-workers requires --mode deep")):
      with self.subTest(argv=argv):
        self.assertIn(msg, parse_error(argv))

  def test_extra_cm_args_rejections(self):
    for extra in ("--diff=abc", "--diff abc", "--staged", "--deep",
                  "--x, --diff-workers=2"):
      with self.subTest(extra=extra):
        self.assertIn("--extra-cm-args cannot contain",
                      parse_error(["--mode", "diff", "--repos-tsv", DIFF_TSV,
                                   f"--extra-cm-args={extra}"]))

  def test_diff_workers_in_extra_args_rejected_in_any_mode(self):
    self.assertIn("cannot contain --diff-workers; use --diff-workers",
                  parse_error(["--extra-cm-args", "--diff-workers 2"]))

  def test_fail_on_allowed(self):
    _, a = run.parse_args(["--mode", "diff", "--repos-tsv", DIFF_TSV,
                           "--extra-cm-args", "--fail-on CRITICAL"])
    self.assertEqual(a.extra_cm_args, "--fail-on CRITICAL")

  def test_unsupported_operation_and_version(self):
    self.assertIn("--mode diff is not supported for --operation verify",
                  parse_error(["--operation", "verify", "--from-find-run", "R",
                               "--mode", "diff", "--repos-tsv", DIFF_TSV]))
    self.assertIn("--mode diff requires --cm-version >= 0.10.0",
                  parse_error(["--mode", "diff", "--repos-tsv", DIFF_TSV,
                               "--cm-version", "0.9.0"]))

  def test_chained_operations_allowed(self):
    _, a = run.parse_args(["--operation", "find-verify-fix", "--mode", "diff",
                           "--repos-tsv", DIFF_TSV])
    self.assertEqual(a.mode, "diff")


class ValidateDiffReposTest(unittest.TestCase):

  def check(self, rows):
    common.validate_diff_repos({r["repo_id"]: r for r in rows})

  def test_checked_in_manifest_is_valid(self):
    common.validate_diff_repos(common.load_repos(DIFF_TSV))

  def test_diff_bucket_is_optional(self):
    self.check([diff_row()])  # no diff_bucket column at all
    self.check([diff_row(diff_bucket="bogus")])

  def test_errors(self):
    sha = "a" * 40
    for row, msg in (
        (diff_row(diff_ref=""), "diff_ref '' is not a 40-hex SHA"),
        (diff_row(pinned_ref="v1.0"), "pinned_ref 'v1.0' is not a 40-hex SHA"),
        (diff_row(diff_ref=PINNED), "diff_ref == pinned_ref"),
        (diff_row(diff_ref=sha), "id/ref mismatch"),
        (diff_row(source_repo_id=""), "missing source_repo_id"),
        (diff_row(repo_id="Bad_ID"), "does not match")):
      with self.subTest(msg=msg), self.assertRaisesRegex(common.UsageError,
                                                         msg):
        self.check([row])

  def test_missing_columns(self):
    for col in ("diff_ref", "source_repo_id"):
      row = diff_row()
      del row[col]
      with self.subTest(col=col), self.assertRaisesRegex(
          common.UsageError, f"column\\(s\\) {col}"):
        self.check([row])

  def test_repos_tsv_is_not_a_diff_manifest(self):
    with self.assertRaisesRegex(common.UsageError, "diff_ref, source_repo_id"):
      common.validate_diff_repos(common.load_repos())

  def test_run_rejects_invalid_manifest(self):
    with tempfile.TemporaryDirectory() as tmp:
      path = f"{tmp}/bad.tsv"
      write_tsv(path, [diff_row(diff_ref=PINNED)], list(diff_row()))
      err = io.StringIO()
      with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
        t.main(["--mode", "diff", "--repos-tsv", path, "--dry-run"],
               t.staged_runner())
      self.assertIn("invalid diff manifest", err.getvalue())

  def test_diff_manifest_validated_in_any_mode(self):
    # stage() diff-stages any row with a diff_ref, so e.g. a standalone verify
    # with the diff manifest must validate it too.
    with tempfile.TemporaryDirectory() as tmp:
      path = f"{tmp}/bad.tsv"
      write_tsv(path, [diff_row(diff_ref=PINNED)], list(diff_row()))
      err = io.StringIO()
      with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
        t.main(["--mode", "shallow", "--repos-tsv", path, "--dry-run"],
               t.staged_runner())
      self.assertIn("invalid diff manifest", err.getvalue())

  def test_is_diff_manifest(self):
    self.assertTrue(common.is_diff_manifest(common.load_repos(DIFF_TSV)))
    self.assertFalse(common.is_diff_manifest(common.load_repos()))
    self.assertFalse(common.is_diff_manifest({}))


class CallBudgetTest(unittest.TestCase):

  def ns(self, **kw):
    return argparse.Namespace(**{"mode": "diff", "diff_workers": None,
                                 "deep_workers": None, **kw})

  def test_unset_uses_cm_default_4(self):
    run.check_call_budget(self.ns(), 225)  # 900 calls
    with self.assertRaisesRegex(common.UsageError,
                                r"226 case\(s\) x 4 worker\(s\) = 904 .*"
                                r"--diff-workers 3 or at most 225 case"):
      run.check_call_budget(self.ns(), 226)

  def test_set_value_counts(self):
    run.check_call_budget(self.ns(diff_workers=1), 900)
    run.check_call_budget(self.ns(diff_workers=16), 56)  # 896 calls
    with self.assertRaisesRegex(common.UsageError, "= 912"):
      run.check_call_budget(self.ns(diff_workers=16), 57)

  def test_shallow_has_no_budget(self):
    run.check_call_budget(self.ns(mode="shallow"), 10000)

  def test_deep_alias_kept(self):
    self.assertIs(run.check_deep_budget, run.check_call_budget)


class DiffRunTest(unittest.TestCase):

  def test_dry_run_golden(self):
    rc, out = main(BASE + ["--dry-run"], diff_runner(), clock=lambda: 0.0)
    self.assertEqual(rc, 0, out)
    assert_golden(self, "run_find_diff_dry.txt",
                  normalize(f"rc={rc}\n--- log ---\n{out}\n"))

  def test_tasks_env_and_manifest(self):
    r = diff_runner()
    rc, out = main(BASE, r)
    self.assertEqual(rc, 0, out)
    tasks = t.uploaded_json(r, "/tasks.json")
    self.assertEqual([x["repo_id"] for x in tasks], VAMPI)
    self.assertEqual({x["pinned_ref"] for x in tasks}, {PINNED})
    self.assertEqual([x["diff_ref"][:7] for x in tasks], ["beca461", "a488a52"])
    for case in VAMPI:
      self.assertIn(common.repo_tarball_uri(t.PAYLOAD, case), r.gcs)
    execute = " ".join(t.execute_call(r))
    self.assertIn("MODE=diff", execute)
    self.assertNotIn("DIFF_WORKERS", execute)
    manifest = t.uploaded_json(r, "/run_manifest.json")
    self.assertEqual(manifest["mode"], "diff")
    self.assertIsNone(manifest["diff_workers"])
    self.assertIn("diff workers 4/task (cm default) (8/900 calls)", out)

  def test_diff_workers_propagates(self):
    r = diff_runner()
    rc, out = main(BASE + ["--diff-workers", "2"], r)
    self.assertEqual(rc, 0, out)
    self.assertIn("DIFF_WORKERS=2", " ".join(t.execute_call(r)))
    self.assertEqual(t.uploaded_json(r, "/run_manifest.json")["diff_workers"], 2)
    self.assertIn("diff workers 2/task (4/900 calls)", out)

  def test_second_run_reports_cached(self):
    r = diff_runner()
    rc, out = main(BASE, r)
    self.assertEqual(rc, 0, out)
    self.assertIn("staging 2 missing tarball(s)", out)
    rc, out = main(BASE[:-3] + ["--run-id", "GOLD2", "--repos", *VAMPI], r)
    self.assertEqual(rc, 0, out)
    self.assertIn("all 2 tarball(s) cached (2/2)", out)

  def test_shallow_tasks_and_env_unchanged(self):
    r = t.staged_runner()
    rc, out = main(["--repos", "o04-vampi"], r)
    self.assertEqual(rc, 0, out)
    self.assertNotIn("diff_ref", t.uploaded_json(r, "/tasks.json")[0])
    self.assertNotIn("diff_workers", t.uploaded_json(r, "/run_manifest.json"))
    self.assertNotIn("DIFF_WORKERS", " ".join(t.execute_call(r)))

  def test_chained_phases_reset_diff(self):
    a = argparse.Namespace(operation="find-verify", experiment_id="e",
                           run_id=None, mode="diff", deep_workers=None,
                           diff_workers=2, wait=False, from_find_run=None,
                           from_verify_run=None)
    later = pipeline.phase_args(a, 1, "R")
    self.assertEqual((later.mode, later.diff_workers), ("shallow", None))
    self.assertEqual(pipeline.phase_args(a, 0).diff_workers, 2)


class StageOneDiffTest(unittest.TestCase):

  META = diff_row()
  URI = f"gs://b/repos/{VAMPI_S}.tar.gz"

  def stage(self, r, force=False):
    with tempfile.TemporaryDirectory() as tmp, \
        contextlib.redirect_stdout(io.StringIO()):
      return stage_repos.stage_one_diff(r, VAMPI_S, self.META, "gs://b", force,
                                        tmp)

  def test_depth_is_range_count_plus_one(self):
    r = DiffGitRunner(count="41")
    self.assertEqual(self.stage(r), "uploaded")
    fetches = [c for c in r.calls if "fetch" in c]
    self.assertIn("--filter=tree:0", fetches[0])
    self.assertNotIn("--depth", fetches[0])
    full = fetches[1]
    self.assertEqual(full[full.index("--depth") + 1], "42")
    self.assertNotIn("--filter=tree:0", full)
    self.assertEqual(full[-2:], [self.META["git_url"], PINNED])
    self.assertIn(self.URI, r.gcs)

  def test_ancestry_failure_raises_and_uploads_nothing(self):
    r = DiffGitRunner(ancestor=False)
    with self.assertRaisesRegex(RuntimeError, "is not an ancestor"):
      self.stage(r)
    self.assertNotIn(self.URI, r.gcs)
    self.assertEqual(len([c for c in r.calls if "fetch" in c]), 1)

  def test_cache_hit_skips_and_force_restages(self):
    r = DiffGitRunner(gcs={self.URI: b"old"})
    self.assertEqual(self.stage(r), "skipped")
    self.assertFalse(any("fetch" in c for c in r.calls))
    self.assertEqual(self.stage(r, force=True), "uploaded")
    self.assertNotEqual(r.gcs[self.URI], b"old")

  def test_reverify_failure_after_full_fetch_uploads_nothing(self):
    for kw in ({"ancestor": [True, False]}, {"cat_file_rc": 1}):
      with self.subTest(**kw):
        r = DiffGitRunner(**kw)
        with self.assertRaisesRegex(RuntimeError, "does not contain diff_ref"):
          self.stage(r)
        self.assertEqual(len([c for c in r.calls if "fetch" in c]), 2)
        self.assertNotIn(self.URI, r.gcs)

  def test_bad_count_raises(self):
    with self.assertRaisesRegex(RuntimeError, "bad rev-list count"):
      self.stage(DiffGitRunner(count="0"))

  def test_dispatch_by_diff_ref(self):
    r = DiffGitRunner()
    with tempfile.TemporaryDirectory() as tmp, \
        contextlib.redirect_stdout(io.StringIO()):
      stage_repos.stage(r, VAMPI_S, self.META, "gs://b", False, tmp)
    self.assertTrue(any("--filter=tree:0" in c for c in r.calls))

  def test_cli_validates_diff_manifest(self):
    with tempfile.TemporaryDirectory() as tmp:
      path = f"{tmp}/bad.tsv"
      write_tsv(path, [diff_row(diff_ref=PINNED)], list(diff_row()))
      with contextlib.redirect_stderr(io.StringIO()), \
          self.assertRaises(SystemExit):
        stage_repos.main(["--repos-tsv", path, "--bucket", "gs://b"],
                         runner=DiffGitRunner())


class RealGitRunner(FakeRunner):
  """Runs git for real (against a file:// upstream); gcloud stays emulated."""

  def run(self, args, check=True, cwd=None):
    args = list(args)
    if args[:1] != ["git"]:
      return super().run(args, check=check, cwd=cwd)
    self.calls.append(args)
    p = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    if check and p.returncode:
      raise RuntimeError(f"git failed: {args}\n{p.stderr}")
    return common.Result(p.returncode, p.stdout, p.stderr)


class StageOneDiffRealGitTest(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="diff_stage_"))
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.up = self.tmp / "up"
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    git = lambda *a: subprocess.run(["git", "-C", str(self.up), *a], env=env,
                                    check=True, capture_output=True,
                                    text=True).stdout.strip()
    subprocess.run(["git", "init", "-q", "-b", "main", str(self.up)], check=True)
    git("config", "uploadpack.allowFilter", "true")
    git("config", "uploadpack.allowAnySHA1InWant", "true")
    shas = []
    for i in range(6):
      (self.up / f"f{i}.py").write_text(f"x = {i}\n")
      git("add", "-A")
      git("commit", "-qm", f"c{i}")
      shas.append(git("rev-parse", "HEAD"))
    git("checkout", "-qb", "side", shas[3])  # merge a side commit into main
    (self.up / "side.py").write_text("s = 1\n")
    git("add", "-A")
    git("commit", "-qm", "side")
    git("checkout", "-q", "main")
    git("merge", "-q", "--no-ff", "-m", "merge", "side")
    self.shas, self.pinned = shas, git("rev-parse", "HEAD")
    self.git = git

  def stage(self, diff, **meta):
    m = {"git_url": f"file://{self.up}", "pinned_ref": self.pinned,
         "diff_ref": diff, **meta}
    r = RealGitRunner()
    with contextlib.redirect_stdout(io.StringIO()):
      stage_repos.stage_one_diff(r, "case", m, "gs://b", False,
                                 str(self.tmp / "work"))
    out = self.tmp / "out"
    out.mkdir()
    tgz = out / "t.tar.gz"
    tgz.write_bytes(r.gcs["gs://b/repos/case.tar.gz"])
    with tarfile.open(tgz) as tf:
      tf.extractall(out, filter="fully_trusted")
    return r, out / "case"

  def test_full_clone_holds_diff_ref_as_ancestor(self):
    diff = self.shas[2]  # first-parent k=4 from the merge; range has 5 commits
    r, repo = self.stage(diff)
    count = self.git("rev-list", "--count", f"{diff}..{self.pinned}")
    depth = [c for c in r.calls if "--depth" in c][0]
    self.assertEqual(depth[depth.index("--depth") + 1], str(int(count) + 1))
    run_git = lambda *a: subprocess.run(["git", "-C", str(repo), *a],
                                        capture_output=True, text=True)
    self.assertEqual(run_git("rev-parse", "HEAD").stdout.strip(), self.pinned)
    self.assertEqual(run_git("merge-base", diff, "HEAD").stdout.strip(), diff)
    self.assertEqual(run_git("config", "extensions.partialclone").stdout, "")
    self.assertEqual(list((repo / ".git" / "objects" / "pack").glob("*.promisor")),
                     [])
    self.assertEqual(run_git("cat-file", "-e", f"{diff}:f2.py").returncode, 0)
    self.assertTrue((repo / ".git" / "shallow").exists())

  def test_unrelated_diff_ref_fails(self):
    tree = self.git("rev-parse", "HEAD^{tree}")
    orphan = self.git("commit-tree", "-m", "orphan", tree)
    with self.assertRaisesRegex(RuntimeError, "not an ancestor"):
      self.stage(orphan)


if __name__ == "__main__":
  unittest.main()
