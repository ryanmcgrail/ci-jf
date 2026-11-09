"""Validates the vendored config/repos.tsv manifest."""

import csv
import pathlib
import unittest

TSV = pathlib.Path(__file__).resolve().parent.parent / "config" / "repos.tsv"
REQUIRED = ("repo_id", "git_url", "pinned_ref", "language")


class ReposTsvTest(unittest.TestCase):

  def setUp(self):
    with TSV.open(newline="") as f:
      reader = csv.DictReader(f, delimiter="\t")
      self.header = reader.fieldnames
      self.rows = list(reader)

  def test_required_columns(self):
    for col in REQUIRED:
      self.assertIn(col, self.header)

  def test_row_count(self):
    self.assertEqual(len(self.rows), 88)

  def test_unique_repo_ids(self):
    ids = [r["repo_id"] for r in self.rows]
    self.assertEqual(len(ids), len(set(ids)))

  def test_no_empty_required_values(self):
    for r in self.rows:
      for col in REQUIRED:
        self.assertTrue(r[col].strip(), f"{r['repo_id']} missing {col}")

  def test_smoke_repo_present(self):
    vampi = [r for r in self.rows if r["repo_id"] == "o04-vampi"]
    self.assertEqual(len(vampi), 1)
    self.assertEqual(vampi[0]["git_url"], "https://github.com/erev0s/VAmPI.git")
    self.assertEqual(vampi[0]["pinned_ref"], "f16052dce83f05847133ec98f01c5193a41de7d8")

  def test_small_repo_rows(self):
    small = [r for r in self.rows if r["repo_id"].startswith("s")]
    self.assertEqual(len(small), 22)
    for r in small:
      self.assertRegex(r["repo_id"], r"^s\d{2}-[a-z0-9-]+$")
      self.assertRegex(r["pinned_ref"], r"^[0-9a-f]{40}$", r["repo_id"])
      self.assertEqual(r["split"], "OPEN_SOURCE", r["repo_id"])
      self.assertIn(r["size_bucket"], ("micro", "small"), r["repo_id"])

  def test_valid_splits(self):
    splits = {r["split"] for r in self.rows}
    self.assertEqual(splits, {"OPEN_SOURCE", "OWASP"})
    open_source_count = sum(1 for r in self.rows if r["split"] == "OPEN_SOURCE")
    owasp_count = sum(1 for r in self.rows if r["split"] == "OWASP")
    self.assertEqual(open_source_count, 79)
    self.assertEqual(owasp_count, 9)


if __name__ == "__main__":
  unittest.main()
