"""Tests for stage_repos.py (fake runner; no network, no real gcloud)."""

import io
import pathlib
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout

import stage_repos
from tests.fakes import FakeRunner

URI = "gs://b/repos/o04-vampi.tar.gz"
SHA = "f16052dce83f05847133ec98f01c5193a41de7d8"


def run(argv, runner):
  with redirect_stdout(io.StringIO()):
    return stage_repos.main(argv, runner=runner)


class StageReposTest(unittest.TestCase):

  def test_skip_when_tarball_exists(self):
    r = FakeRunner(gcs={URI: b"old"})
    run(["--repos", "o04-vampi", "--bucket", "gs://b"], r)
    self.assertEqual(r.gcs[URI], b"old")
    self.assertFalse(any("clone" in c for c in r.calls))

  def test_upload_when_missing(self):
    r = FakeRunner()
    run(["--repos", "o04-vampi", "--bucket", "gs://b"], r)
    self.assertIn(URI, r.gcs)
    self.assertFalse(any("clone" in c for c in r.calls))
    fetch = [c for c in r.calls if "fetch" in c][0]
    self.assertEqual(fetch[fetch.index("--depth") + 1], "1")
    self.assertEqual(fetch[-2:], ["https://github.com/erev0s/VAmPI.git", SHA])
    self.assertIn("FETCH_HEAD", [c for c in r.calls if "reset" in c][0])

  def test_branch_ref_uses_shallow_clone(self):
    r = FakeRunner()
    run(["--repos", "p01-flask", "--bucket", "gs://b"], r)
    clone = [c for c in r.calls if "clone" in c][0]
    self.assertEqual(clone[clone.index("--depth") + 1], "1")
    self.assertIn("--branch", clone)

  def test_force_reuploads(self):
    r = FakeRunner(gcs={URI: b"old"})
    run(["--repos", "o04-vampi", "--bucket", "gs://b", "--force"], r)
    self.assertNotEqual(r.gcs[URI], b"old")

  def test_unknown_repo_errors(self):
    with self.assertRaises(SystemExit):
      with redirect_stdout(io.StringIO()), \
          __import__("contextlib").redirect_stderr(io.StringIO()):
        stage_repos.main(["--repos", "nope", "--bucket", "gs://b"],
                         runner=FakeRunner())

  def test_tar_layout_has_repo_prefix_and_git(self):
    r = FakeRunner()
    run(["--repos", "o04-vampi", "--bucket", "gs://b"], r)
    with tempfile.TemporaryDirectory() as tmp:
      p = pathlib.Path(tmp) / "t.tar.gz"
      p.write_bytes(r.gcs[URI])
      names = tarfile.open(p).getnames()
    self.assertTrue(all(n == "o04-vampi" or n.startswith("o04-vampi/")
                        for n in names))
    self.assertIn("o04-vampi/app.py", names)
    self.assertTrue(any(n.startswith("o04-vampi/.git/") for n in names))

  def test_sequential_order(self):
    r = FakeRunner()
    run(["--repos", "p01-flask", "o04-vampi", "--bucket", "gs://b"], r)
    urls = [c[-2] for c in r.calls if "clone" in c or "fetch" in c]
    self.assertEqual(urls, ["https://github.com/pallets/flask.git",
                            "https://github.com/erev0s/VAmPI.git"])

  def test_missing_pinned_ref_warns_and_raises(self):
    class FailingGitRunner(FakeRunner):
      def run(self, args, check=True, cwd=None):
        if args[:1] == ["git"] and ("clone" in args or "fetch" in args):
          self.calls.append(list(args))
          raise RuntimeError("Remote branch missing-tag not found")
        return super().run(args, check=check, cwd=cwd)

    r = FailingGitRunner()
    buf = io.StringIO()
    with self.assertRaisesRegex(RuntimeError, "fix config/repos.tsv"), \
        redirect_stdout(buf):
      stage_repos.main(["--repos", "p01-flask", "--bucket", "gs://b"], runner=r)
    self.assertIn("[WARN] p01-flask: failed to checkout pinned_ref", buf.getvalue())
    self.assertEqual(len([c for c in r.calls if c[:1] == ["git"]]), 1)


if __name__ == "__main__":
  unittest.main()
