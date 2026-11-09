"""Validates config/repos_with_diff.tsv (diff-mode cases) statically.

Also covers scripts/validate_diff_tsv.py's static_errors() branches.
"""

import collections
import contextlib
import csv
import importlib.util
import io
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TSV = ROOT / "config" / "repos_with_diff.tsv"
REPOS_TSV = ROOT / "config" / "repos.tsv"
HEADER = ["repo_id", "name", "git_url", "pinned_ref", "diff_ref", "diff_bucket",
          "language", "build_system", "domain", "size_bucket", "approx_loc",
          "split", "notes", "source_repo_id", "evidence"]
SHA = re.compile(r"^[0-9a-f]{40}$")
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_spec = importlib.util.spec_from_file_location(
    "validate_diff_tsv", ROOT / "scripts" / "validate_diff_tsv.py")
vdt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vdt)


def _read(path):
  with path.open(newline="", encoding="utf-8") as f:
    text = f.read().replace("\r\n", "\n")
  reader = csv.DictReader(text.splitlines(), delimiter="\t")
  return reader.fieldnames, list(reader)


class ReposWithDiffTsvTest(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.header, cls.rows = _read(TSV)
    cls.sources = {r["repo_id"]: r for r in _read(REPOS_TSV)[1]}

  def test_header(self):
    self.assertEqual(self.header, HEADER)

  def test_lf_line_endings(self):
    self.assertNotIn(b"\r", TSV.read_bytes())

  def test_refs_are_shas_and_differ(self):
    for r in self.rows:
      self.assertRegex(r["pinned_ref"], SHA, r["repo_id"])
      self.assertRegex(r["diff_ref"], SHA, r["repo_id"])
      self.assertNotEqual(r["pinned_ref"], r["diff_ref"], r["repo_id"])

  def test_unique_ids(self):
    ids = [r["repo_id"] for r in self.rows]
    self.assertEqual(len(ids), len(set(ids)))

  def test_id_format_and_refs(self):
    for r in self.rows:
      self.assertRegex(r["repo_id"], ID)
      self.assertEqual(
          r["repo_id"], f"{r['source_repo_id']}--{r['pinned_ref'][:7]}-"
          f"{r['diff_ref'][:7]}")

  def test_sources_exist_and_metadata_copied(self):
    for r in self.rows:
      src = self.sources.get(r["source_repo_id"])
      self.assertIsNotNone(src, r["repo_id"])
      for col in vdt.mine.META_COLS:
        self.assertEqual(r[col], src[col], f"{r['repo_id']} {col}")

  def test_at_most_four_rows_per_repo(self):
    per = collections.Counter(r["source_repo_id"] for r in self.rows)
    self.assertLessEqual(max(per.values()), 4)

  def test_one_pinned_ref_per_repo(self):
    pins = collections.defaultdict(set)
    for r in self.rows:
      pins[r["source_repo_id"]].add(r["pinned_ref"])
    for src, p in pins.items():
      self.assertEqual(len(p), 1, src)

  def test_vampi_smoke_cases(self):
    vampi = {r["repo_id"]: r for r in self.rows
             if r["source_repo_id"] == "o04-vampi"}
    self.assertEqual(set(vampi), {"o04-vampi--f16052d-beca461",
                                  "o04-vampi--f16052d-a488a52"})
    self.assertEqual(vampi["o04-vampi--f16052d-beca461"]["evidence"],
                     "k=6; changed_files=2; changed_lines=32")
    self.assertEqual(vampi["o04-vampi--f16052d-a488a52"]["evidence"],
                     "k=42; changed_files=7; changed_lines=164")

  def test_static_validator_passes(self):
    self.assertEqual(dict(vdt.static_errors(self.rows, self.sources)), {})


class StaticErrorsTest(unittest.TestCase):
  P = "f16052dce83f05847133ec98f01c5193a41de7d8"
  D = "beca4615d1bc947825a5e5bd8a9275c2a7cbda6a"
  SOURCES = {"o04-vampi": {}}

  def row(self, **kw):
    r = {"repo_id": "o04-vampi--f16052d-beca461", "pinned_ref": self.P,
         "diff_ref": self.D, "source_repo_id": "o04-vampi"}
    r.update(kw)
    return r

  def errors(self, rows):
    return " | ".join(e for errs in vdt.static_errors(rows, self.SOURCES)
                      .values() for e in errs)

  def test_valid_row(self):
    self.assertEqual(self.errors([self.row()]), "")

  def test_diff_bucket_optional(self):
    self.assertEqual(self.errors([self.row(diff_bucket="")]), "")
    self.assertEqual(self.errors([self.row(diff_bucket="whatever")]), "")

  def test_missing_diff_ref(self):
    self.assertIn("diff_ref '' is not a 40-hex SHA",
                  self.errors([self.row(diff_ref="")]))

  def test_bad_sha(self):
    self.assertIn("pinned_ref 'main' is not a 40-hex SHA",
                  self.errors([self.row(pinned_ref="main")]))

  def test_equal_refs(self):
    self.assertIn("diff_ref == pinned_ref", self.errors(
        [self.row(diff_ref=self.P, repo_id="o04-vampi--f16052d-f16052d")]))

  def test_id_ref_mismatch(self):
    self.assertIn("id/ref mismatch",
                  self.errors([self.row(repo_id="o04-vampi--f16052d-aaaaaaa")]))

  def test_bad_id_format(self):
    self.assertIn("does not match",
                  self.errors([self.row(repo_id="O04_vampi")]))

  def test_missing_and_unknown_source(self):
    self.assertIn("missing source_repo_id",
                  self.errors([self.row(source_repo_id="")]))
    self.assertIn("not in repos.tsv",
                  self.errors([self.row(source_repo_id="nope")]))

  def test_duplicate_and_too_many_rows(self):
    self.assertIn("duplicate repo_id", self.errors([self.row(), self.row()]))
    self.assertIn("has 5 rows", self.errors([self.row()] * 5))


class MinerSelectionTest(unittest.TestCase):
  """scripts/fetch_diff_repos.py band selection."""
  mine = vdt.mine

  def test_band_edges(self):
    got = {n: self.mine.band_of(n) for n in (0, 1, 3, 4, 15, 16, 49, 50, 150,
                                             151)}
    self.assertEqual(got, {0: None, 1: "S", 3: "S", 4: "M", 15: "M", 16: "L",
                           49: "L", 50: "XL", 150: "XL", 151: None})

  def test_pick_largest_k_per_band_non_monotonic(self):
    evals = [[1, "a", 0, 0], [2, "b", 2, 5], [3, "c", 5, 9], [4, "d", 3, 7],
             [5, "e", 20, 90], [6, "f", 151, 999]]
    picks = self.mine.pick(evals)
    self.assertEqual({b: e[0] for b, e in picks.items()},
                     {"S": 4, "M": 3, "L": 5})

  def test_xl_overflow_uses_stop_k_only_when_xl_missing(self):
    evals = [[1, "a", 0, 0], [2, "b", 0, 0], [3, "c", 635, 9000]]
    self.assertEqual(self.mine.pick(evals), {})
    self.assertEqual(self.mine.pick(evals, xl_overflow=True)["XL"][0], 3)
    with_xl = [[1, "a", 60, 1], [2, "b", 200, 2]]
    self.assertEqual(self.mine.pick(with_xl, xl_overflow=True)["XL"][0], 1)
    # Walks that ended at root/cap (no overflow) never borrow.
    self.assertNotIn("XL", self.mine.pick([[1, "a", 2, 2]], xl_overflow=True))

  def test_case_id(self):
    self.assertEqual(self.mine.case_id("o04-vampi", "f16052dce83f", "beca4615d1"),
                     "o04-vampi--f16052d-beca461")


def _git(repo, *args):
  return subprocess.run(
      ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t",
       "-c", "commit.gpgsign=false", *args],
      check=True, capture_output=True, text=True).stdout.strip()


class LocalRepoMiningTest(unittest.TestCase):
  """walk()/git_check() end to end against a local file:// upstream."""

  def setUp(self):
    self.tmp = pathlib.Path(tempfile.mkdtemp())
    self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
    self.up = self.tmp / "up"
    self.up.mkdir()
    _git(self.up, "init", "-q")
    _git(self.up, "config", "uploadpack.allowFilter", "true")
    _git(self.up, "config", "uploadpack.allowAnySHA1InWant", "true")
    # Commit i adds src/f<i>.py, plus a README change that never counts.
    self.shas = []
    for i in range(6):
      (self.up / "src").mkdir(exist_ok=True)
      (self.up / "src" / f"f{i}.py").write_text("x = 1\ny = 2\n")
      (self.up / "README.md").write_text(f"rev {i}\n")
      _git(self.up, "add", "-A")
      _git(self.up, "commit", "-q", "-m", f"c{i}")
      self.shas.append(_git(self.up, "rev-parse", "HEAD"))
    self.url = "file://" + str(self.up)
    self.cache = self.tmp / "cache"
    self.filters = vdt.diff_stats.load_filters(ROOT / "config" / "cm_config.yaml")
    self.head = self.shas[-1]

  def mirror(self, depth):
    return vdt.mine.ensure_mirror(self.cache, "r", self.url, self.head, depth)

  def test_walk_to_root_and_pick(self):
    mirror, sha = self.mirror(10)
    self.assertEqual(sha, self.head)
    evals, stop = vdt.mine.walk(mirror, sha, self.filters, 500, 150)
    self.assertEqual(stop, "root at k=5")
    self.assertEqual([(e[0], e[2], e[3]) for e in evals],
                     [(k, k, 2 * k) for k in range(1, 6)])
    picks = vdt.mine.pick(evals)
    self.assertEqual({b: e[0] for b, e in picks.items()}, {"S": 3, "M": 5})

  def test_walk_stops_at_cap_and_max_files(self):
    mirror, sha = self.mirror(10)
    self.assertEqual(vdt.mine.walk(mirror, sha, self.filters, 2, 150)[1],
                     "k=2 cap")
    evals, stop = vdt.mine.walk(mirror, sha, self.filters, 500, 2)
    self.assertEqual(stop, "changed_files>2 at k=3")
    self.assertEqual(len(evals), 3)

  def test_shallow_boundary_reported_and_refetched(self):
    mirror, sha = self.mirror(3)  # head + 2 ancestors
    self.assertEqual(vdt.mine.walk(mirror, sha, self.filters, 500, 150)[1],
                     "shallow boundary at k=2")
    # Asking for more depth refetches even though the commit is present.
    mirror, sha = self.mirror(10)
    self.assertEqual(vdt.mine.walk(mirror, sha, self.filters, 500, 150)[1],
                     "root at k=5")

  def test_missing_ref_fails_fast_with_sheet_hint(self):
    for ref in ("v9.9.9", "0" * 40):
      with self.subTest(ref=ref):
        start = time.monotonic()
        with self.assertRaises(vdt.mine.PinnedRefNotFound) as cm:
          vdt.mine.ensure_mirror(self.cache, "r", self.url, ref, 10)
        self.assertLess(time.monotonic() - start, 10)  # no retry backoff
        msg = str(cm.exception)
        self.assertIn(f"pinned ref '{ref}' for r can't be found", msg)
        self.assertIn("update r's ref in config/repos.tsv", msg)

  def test_main_reports_missing_ref_and_exits_1(self):
    tsv = self.tmp / "repos.tsv"
    tsv.write_text("repo_id\tname\tgit_url\tpinned_ref\n"
                   f"r\tR\t{self.url}\tv9.9.9\n")
    out = self.tmp / "out.tsv"
    err = io.StringIO()
    with contextlib.redirect_stderr(err), \
         contextlib.redirect_stdout(io.StringIO()):
      rc = vdt.mine.main(["--repos-tsv", str(tsv), "--out", str(out),
                          "--cache-dir", str(self.cache), "--jobs", "1"])
    self.assertEqual(rc, 1)
    self.assertIn("[r] ERROR: pinned ref 'v9.9.9' for r can't be found",
                  err.getvalue())
    self.assertIn(f"update r's ref in {tsv}", err.getvalue())

  def test_pin_flag_removed(self):
    with contextlib.redirect_stderr(io.StringIO()), \
         self.assertRaises(SystemExit):
      vdt.mine.main(["--pin", "r=v1"])

  def row(self, diff, evidence):
    return {"repo_id": vdt.mine.case_id("r", self.head, diff),
            "source_repo_id": "r", "pinned_ref": self.head, "diff_ref": diff,
            "diff_bucket": "S", "evidence": evidence}

  def check(self, row):
    return vdt.git_check(row, {"r": {"git_url": self.url}}, self.filters,
                         self.cache)

  def test_git_check_ok(self):
    rep, errs = self.check(
        self.row(self.shas[2], "k=3; changed_files=3; changed_lines=6"))
    self.assertEqual(errs, [])
    self.assertEqual((rep["changed_files"], rep["changed_lines"], rep["k"]),
                     (3, 6, "3"))

  def test_git_check_evidence_mismatch(self):
    _, errs = self.check(
        self.row(self.shas[2], "k=3; changed_files=9; changed_lines=6"))
    self.assertIn("evidence", errs[0])

  def test_git_check_non_ancestor(self):
    _git(self.up, "checkout", "-q", "-b", "side", self.shas[1])
    (self.up / "src" / "side.py").write_text("z = 3\n")
    _git(self.up, "add", "-A")
    _git(self.up, "commit", "-q", "-m", "side")
    side = _git(self.up, "rev-parse", "HEAD")
    self.mirror(10)
    mirror = self.cache / "r"
    _git(mirror, "fetch", "-q", "--filter=blob:none", "origin", side)
    _, errs = self.check(self.row(side, ""))
    self.assertIn("not an ancestor", errs[0])

  def test_git_check_zero_code_files(self):
    (self.up / "README.md").write_text("docs only\n")
    _git(self.up, "commit", "-qam", "docs")
    self.head = _git(self.up, "rev-parse", "HEAD")
    _, errs = self.check(self.row(self.shas[-1], ""))
    self.assertIn("changed_files == 0", errs[0])


if __name__ == "__main__":
  unittest.main()
