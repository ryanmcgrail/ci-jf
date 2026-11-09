"""Tests for container/scripts/diff_stats.py (code-only changed-file stats)."""

import contextlib
import importlib.util
import io
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config" / "cm_config.yaml"
_spec = importlib.util.spec_from_file_location(
    "diff_stats", ROOT / "container" / "scripts" / "diff_stats.py")
ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ds)


def git(repo, *args):
  return subprocess.run(
      ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
       "-c", "commit.gpgsign=false", *args],
      check=True, capture_output=True, text=True).stdout.strip()


class FilterTest(unittest.TestCase):

  def setUp(self):
    self.f = ds.load_filters(CONFIG)

  def test_config_filters_loaded(self):
    include, exclude, dirs = self.f
    self.assertIn(".py", include)
    self.assertIn(".pb.go", exclude)
    self.assertIn("vendor", dirs)

  def test_extension_include(self):
    self.assertTrue(ds.is_counted("pkg/a.go", self.f))
    self.assertTrue(ds.is_counted("a.py", self.f))
    self.assertFalse(ds.is_counted("README.md", self.f))
    self.assertFalse(ds.is_counted("openapi3.yml", self.f))
    self.assertFalse(ds.is_counted("Dockerfile", self.f))

  def test_extension_exclude(self):
    self.assertFalse(ds.is_counted("api/foo.pb.go", self.f))
    self.assertFalse(ds.is_counted("web/app.min.js", self.f))
    self.assertFalse(ds.is_counted("x/y.generated.go", self.f))
    self.assertTrue(ds.is_counted("web/app.js", self.f))

  def test_exclude_dirs_any_component(self):
    self.assertFalse(ds.is_counted("vendor/x.go", self.f))
    self.assertFalse(ds.is_counted("a/b/node_modules/c/d.js", self.f))
    self.assertFalse(ds.is_counted("src/third_party/z.c", self.f))
    # Only directory components count, not the file name or substrings.
    self.assertTrue(ds.is_counted("src/build.py", self.f))
    self.assertTrue(ds.is_counted("vendors/x.go", self.f))

  def test_parse_numstat_binary_and_lines(self):
    rows = ds.parse_numstat_z(b"3\t1\ta.py\0-\t-\timg.png\0" b"0\t5\tb c.go\0"
                              b"1\t0\tt\tab\nnl.py\0")
    self.assertEqual(rows, [(3, 1, "a.py"), (None, None, "img.png"),
                            (0, 5, "b c.go"), (1, 0, "t\tab\nnl.py")])

  def test_binary_with_code_extension_dropped(self):
    rows = ds.parse_numstat_z(b"-\t-\tblob.py\0" b"2\t2\tok.py\0")
    self.assertEqual(ds.counted_rows(rows, self.f), [(2, 2, "ok.py")])


class RepoTest(unittest.TestCase):
  """A temp repo with one counted .py edit among excluded changes."""

  def setUp(self):
    self.repo = pathlib.Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
    git(self.repo, "init", "-q")
    (self.repo / "app.py").write_text("a = 1\nb = 2\nc = 3\n")
    git(self.repo, "add", "-A")
    git(self.repo, "commit", "-q", "-m", "base")
    self.base = git(self.repo, "rev-parse", "HEAD")
    # One counted change: +2 -1 lines in app.py.
    (self.repo / "app.py").write_text("a = 1\nb = 20\nc = 3\nd = 4\n")
    # Changes that must not count.
    (self.repo / "logo.py").write_bytes(b"\x00\x01binary\x00" * 10)
    (self.repo / "vendor").mkdir()
    (self.repo / "vendor" / "x.go").write_text("package x\n")
    (self.repo / "foo.pb.go").write_text("package foo\n")
    (self.repo / "app.min.js").write_text("var a=1;\n")
    (self.repo / "README.md").write_text("# readme\n")
    git(self.repo, "add", "-A")
    git(self.repo, "commit", "-q", "-m", "head")
    self.head = git(self.repo, "rev-parse", "HEAD")

  def test_only_py_counts(self):
    stats, paths = ds.compute(self.repo, ds.load_filters(CONFIG), self.base,
                              self.head)
    self.assertEqual(stats, {"changed_files": 1, "changed_lines": 3})
    self.assertEqual(paths, ["app.py"])

  def test_default_head_is_HEAD(self):
    stats, _ = ds.compute(self.repo, ds.load_filters(CONFIG), self.base)
    self.assertEqual(stats["changed_files"], 1)

  def test_no_renames_counts_delete_plus_add(self):
    git(self.repo, "mv", "app.py", "moved.py")
    git(self.repo, "commit", "-q", "-m", "mv")
    stats, paths = ds.compute(self.repo, ds.load_filters(CONFIG), self.head)
    self.assertEqual(sorted(paths), ["app.py", "moved.py"])
    self.assertEqual(stats["changed_lines"], 8)

  def test_cli_json_and_list(self):
    base_args = ["--repo", str(self.repo), "--config", str(CONFIG),
                 "--base", self.base, "--head", self.head]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      self.assertEqual(ds.main(base_args), 0)
    self.assertEqual(json.loads(out.getvalue()),
                     {"changed_files": 1, "changed_lines": 3})
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
      ds.main(base_args + ["--list"])
    self.assertEqual(out.getvalue(), "app.py\n")

  def test_bad_ref_raises(self):
    with self.assertRaises(subprocess.CalledProcessError):
      ds.compute(self.repo, ds.load_filters(CONFIG), "0" * 40)

  def test_raw_blob_ids_code_paths_only(self):
    filters = ds.load_filters(CONFIG)
    ids, n = ds.raw_blob_ids(self.repo, self.base, self.head, filters)
    # app.py (both sides) and logo.py (binary: added side only).
    self.assertEqual(n, 2)
    want = {git(self.repo, "rev-parse", f"{self.base}:app.py"),
            git(self.repo, "rev-parse", f"{self.head}:app.py"),
            git(self.repo, "rev-parse", f"{self.head}:logo.py")}
    self.assertEqual(ids, want)


class SubmoduleTest(unittest.TestCase):
  """A gitlink whose path looks like code never counts."""

  def test_gitlink_ignored(self):
    tmp = pathlib.Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
    sub, repo = tmp / "sub", tmp / "repo"
    for r in (sub, repo):
      r.mkdir()
      git(r, "init", "-q")
      (r / "a.py").write_text("a = 1\n")
      git(r, "add", "-A")
      git(r, "commit", "-q", "-m", "init")
    base = git(repo, "rev-parse", "HEAD")
    sub_sha = git(sub, "rev-parse", "HEAD")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{sub_sha},lib.go")
    (repo / "b.py").write_text("b = 1\n")
    git(repo, "add", "b.py")
    git(repo, "commit", "-q", "-m", "add gitlink")
    filters = ds.load_filters(CONFIG)
    stats, paths = ds.compute(repo, filters, base)
    self.assertEqual(paths, ["b.py"])
    self.assertEqual(stats, {"changed_files": 1, "changed_lines": 1})
    ids, n = ds.raw_blob_ids(repo, base, "HEAD", filters)
    self.assertEqual(n, 1)
    self.assertNotIn(sub_sha, ids)


class PathspecEquivalenceTest(unittest.TestCase):
  """pathspecs() selects exactly the paths is_counted() accepts."""

  PATHS = ("a.py", "src/a.py", "deep/x/y/z.go", "README.md", "web/app.min.js",
           "web/app.js", "api/foo.pb.go", "x/y.generated.go", "vendor/x.go",
           "a/vendor/b/c.go", "vendors/x.go", "src/build.py", "build/out.c",
           "a/node_modules/m/i.js", "third_party/t.cc", "lib/h.hh", "lib/h.h",
           "Dockerfile", "main.tf", "x/.venv/y.py", "k.kts", "c.cshtml",
           "bin/tool.rs", "obj/o.cs", "dist/d.ts", "target/t.java")

  def test_equivalent(self):
    filters = ds.load_filters(CONFIG)
    repo = pathlib.Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, repo, ignore_errors=True)
    git(repo, "init", "-q")
    for p in self.PATHS:
      (repo / p).parent.mkdir(parents=True, exist_ok=True)
      (repo / p).write_text("x\n")
    git(repo, "add", "-A", "-f")
    selected = set(git(repo, "ls-files", "--", *ds.pathspecs(filters)).split())
    expected = {p for p in self.PATHS if ds.is_counted(p, filters)}
    self.assertEqual(selected, expected)
    self.assertIn("src/build.py", expected)
    self.assertNotIn("a/vendor/b/c.go", expected)


if __name__ == "__main__":
  unittest.main()
