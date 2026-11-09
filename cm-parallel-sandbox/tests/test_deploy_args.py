"""Tests for deploy.sh argument handling (stub gcloud; no real builds)."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

RECORDER = """#!/usr/bin/env bash
echo "$*" >> "$GCLOUD_CALLS"
case "$*" in
  *"jobs describe"*"parallelism"*) echo "${PARALLELISM:-}" ;;
  *"jobs describe"*"spec.template.spec.template.spec.containers[0].image"*)
    echo "${DESCRIBE_IMAGE:-}" ;;
  *"builds submit"*) echo "BUILD123" ;;
  *"builds describe"*) echo "${BUILD_STATUS:-SUCCESS}" ;;
esac
"""


class DeployArgsTest(unittest.TestCase):

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="deploy_test_"))
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.repo = self.tmp / "repo"
    self.repo.mkdir()
    shutil.copy(ROOT / "deploy.sh", self.repo / "deploy.sh")
    shutil.copytree(ROOT / "container", self.repo / "container")
    shutil.copytree(ROOT / "config", self.repo / "config")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
    subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "x"], check=True,
                   env=env)
    self.sha = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "--short",
                               "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    self.bin = self.tmp / "bin"
    self.bin.mkdir()
    (self.bin / "gcloud").write_text(RECORDER)
    (self.bin / "gcloud").chmod(0o755)
    self.calls = self.tmp / "calls.txt"

  def image(self, tag=None):
    return ("us-central1-docker.pkg.dev/proj/cm-parallel-sandbox/"
            f"cm-sandbox-runner:{tag or self.sha}")

  def run_deploy(self, *args, describe_image=None):
    env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
               GCLOUD_CALLS=str(self.calls), TMPDIR=str(self.tmp))
    env["DESCRIBE_IMAGE"] = (self.image() if describe_image is None
                             else describe_image)
    return subprocess.run(["bash", str(self.repo / "deploy.sh"), *args], env=env,
                          capture_output=True, text=True, timeout=60)

  def calls_list(self):
    return self.calls.read_text().splitlines() if self.calls.exists() else []

  def test_builds_and_updates_all_three_jobs(self):
    p = self.run_deploy("--project", "proj", "--region", "us-central1")
    self.assertEqual(p.returncode, 0, p.stderr)
    image = f"us-central1-docker.pkg.dev/proj/cm-parallel-sandbox/cm-sandbox-runner:{self.sha}"
    calls = self.calls_list()
    self.assertEqual(
        calls[:3],
        [f"run jobs describe {j} --project=proj --region=us-central1"
         " --format=value(spec.template.spec.parallelism)"
         for j in ("cm-find-runner", "cm-verify-runner", "cm-fix-runner")])
    self.assertTrue(calls[3].startswith("builds submit "))
    self.assertIn(f"--tag={image}", calls[3])
    self.assertIn("--project=proj", calls[3])
    self.assertIn("--async", calls[3])
    self.assertIn("builds describe BUILD123 --project=proj --format=value(status)", calls)
    self.assertIn(f"run jobs update cm-find-runner --project=proj --region=us-central1 --image={image} --quiet", calls)
    self.assertIn(f"run jobs update cm-verify-runner --project=proj --region=us-central1 --image={image} --quiet", calls)
    self.assertIn(f"run jobs update cm-fix-runner --project=proj --region=us-central1 --image={image} --quiet", calls)
    self.assertEqual(sum("jobs describe" in c for c in calls), 6)
    for j in ("cm-find-runner", "cm-verify-runner", "cm-fix-runner"):
      self.assertIn(f"run jobs describe {j} --project=proj --region=us-central1"
                    " --format=value(spec.template.spec.template.spec"
                    ".containers[0].image)", calls)
      self.assertIn(f"{j} image: {image}\n", p.stdout)
    self.assertFalse(any("parallelism=" in c for c in calls))
    self.assertFalse(any("services enable" in c for c in calls))

  def test_pinned_parallelism_fails_before_build(self):
    for value in ("2", "30"):
      with self.subTest(value=value):
        self.calls.unlink(missing_ok=True)
        os.environ["PARALLELISM"] = value
        self.addCleanup(os.environ.pop, "PARALLELISM", None)
        p = self.run_deploy("--project", "proj")
        self.assertEqual(p.returncode, 1)
        self.assertIn(f"cm-find-runner has parallelism={value} pinned", p.stderr)
        self.assertIn("one-time reset: gcloud run jobs update cm-find-runner"
                      " --parallelism=0 --project=proj --region=us-central1",
                      p.stderr)
        self.assertEqual(len(self.calls_list()), 1)

  def test_zero_parallelism_passes(self):
    os.environ["PARALLELISM"] = "0"
    self.addCleanup(os.environ.pop, "PARALLELISM", None)
    self.assertEqual(self.run_deploy("--project", "proj").returncode, 0)

  def test_failed_build_skips_job_updates(self):
    os.environ["BUILD_STATUS"] = "FAILURE"
    self.addCleanup(os.environ.pop, "BUILD_STATUS", None)
    p = self.run_deploy("--project", "proj")
    self.assertNotEqual(p.returncode, 0)
    self.assertIn("status FAILURE", p.stderr)
    self.assertFalse(any("jobs update" in c for c in self.calls_list()))

  def test_image_mismatch_after_update_fails(self):
    for got, shown in (("other:tag", "other:tag"), ("", "<none>")):
      with self.subTest(got=got):
        p = self.run_deploy("--project", "proj", describe_image=got)
        self.assertEqual(p.returncode, 1)
        self.assertIn(f"cm-find-runner image: {shown}", p.stdout)
        self.assertIn(f"expected '{self.image()}'", p.stderr)

  def test_custom_tag(self):
    p = self.run_deploy("--project", "proj", "--tag", "v1",
                        describe_image=self.image("v1"))
    self.assertEqual(p.returncode, 0, p.stderr)
    submit = [c for c in self.calls_list() if c.startswith("builds submit ")]
    self.assertIn("cm-sandbox-runner:v1", submit[0])

  def test_refuses_dirty_tree(self):
    (self.repo / "untracked.txt").write_text("x")
    p = self.run_deploy("--project", "proj")
    self.assertNotEqual(p.returncode, 0)
    self.assertIn("dirty tree", p.stderr)
    self.assertEqual(self.calls_list(), [])

  def test_requires_project(self):
    p = self.run_deploy()
    self.assertNotEqual(p.returncode, 0)
    self.assertIn("--project is required", p.stderr)
    self.assertEqual(self.calls_list(), [])

  def test_unknown_flag(self):
    p = self.run_deploy("--project", "proj", "--bogus")
    self.assertNotEqual(p.returncode, 0)
    self.assertEqual(self.calls_list(), [])


if __name__ == "__main__":
  unittest.main()
