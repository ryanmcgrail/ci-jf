"""Fake Runner for tests: records calls and emulates gcloud storage + git."""

import fnmatch
import os
import pathlib
import shutil
import subprocess

from cmrun import common


class FakeRunner:
  """Emulates `gcloud storage ls/cp/cat` over a local dict and fakes git clone.

  `git clone` creates a tiny local repo (real git, no network). `tar` runs for
  real. Any other command is recorded and returns `responses.get(key)`.
  """

  def __init__(self, gcs=None, responses=None, gcs_times=None):
    self.calls = []
    self.gcs = dict(gcs or {})
    self.responses = responses or {}
    self.gcs_times = dict(gcs_times or {})  # uri -> ISO-8601 creation time

  def run(self, args, check=True, cwd=None):
    args = list(args)
    self.calls.append(args)
    if args[:3] == ["gcloud", "storage", "ls"]:
      uri = args[-1]
      pat = uri + "*" if uri.endswith("/") else uri
      hits = sorted(k for k in self.gcs if fnmatch.fnmatchcase(k, pat))
      if "-l" in args:
        lines = [f"  {len(self.gcs[k]):>8}  "
                 f"{self.gcs_times.get(k, '1970-01-01T00:00:00Z')}  {k}"
                 for k in hits]
        lines.append(f"TOTAL: {len(hits)} objects")
      else:
        lines = hits
      res = common.Result(0 if hits else 1, "\n".join(lines) + "\n", "")
    elif args[:3] == ["gcloud", "storage", "cp"]:
      src, dst = args[-2], args[-1]
      if dst.startswith("gs://"):
        self.gcs[dst] = pathlib.Path(src).read_bytes()
      else:
        pathlib.Path(dst).parent.mkdir(parents=True, exist_ok=True)
        target = pathlib.Path(dst)
        if target.is_dir():
          target = target / src.rsplit("/", 1)[-1]
        target.write_bytes(self.gcs[src])
      res = common.Result(0)
    elif args[:3] == ["gcloud", "storage", "cat"]:
      uri = args[-1]
      res = (common.Result(0, self.gcs[uri].decode()) if uri in self.gcs
             else common.Result(1, "", "not found"))
    elif args[:1] == ["git"] and ("clone" in args or "init" in args):
      dest = pathlib.Path(args[-1])
      dest.mkdir(parents=True)
      env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                 GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
      subprocess.run(["git", "init", "-q", str(dest)], check=True)
      (dest / "app.py").write_text("print('hi')\n")
      subprocess.run(["git", "-C", str(dest), "add", "."], check=True)
      subprocess.run(["git", "-C", str(dest), "commit", "-qm", "x"], check=True,
                     env=env)
      res = common.Result(0)
    elif args[:1] == ["tar"]:
      p = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
      res = common.Result(p.returncode, p.stdout, p.stderr)
    else:
      key = " ".join(args[:4])
      res = self.responses.get(key, common.Result(0))
      if callable(res):
        res = res(args)
    if check and res.returncode != 0:
      raise RuntimeError(f"fake command failed: {args}")
    return res

  def mutating_calls(self):
    readonly = (["gcloud", "storage", "ls"], ["gcloud", "storage", "cat"],
                ["gcloud", "config", "get-value"])
    return [c for c in self.calls if c[:3] not in readonly]
