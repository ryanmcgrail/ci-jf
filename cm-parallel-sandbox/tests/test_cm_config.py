"""Specs for config/cm_config.yaml against cm 0.10.0's scan config surface."""

import csv
import pathlib
import unittest

try:
  import yaml
except ImportError:  # PyYAML is optional; only this test needs it.
  yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Suffixes each repos.tsv language needs so none of its sources are skipped.
LANGUAGE_EXTENSIONS = {
    "c": {".c", ".h"}, "cpp": {".cc", ".cpp", ".cxx", ".h", ".hpp"},
    "csharp": {".cs"}, "go": {".go"}, "java": {".java"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"}, "kotlin": {".kt", ".kts"},
    "php": {".php"}, "python": {".py"}, "ruby": {".rb"}, "rust": {".rs"},
    "typescript": {".ts", ".tsx"},
}


@unittest.skipIf(yaml is None, "PyYAML not installed")
class CmConfigTest(unittest.TestCase):

  def setUp(self):
    self.scan = yaml.safe_load((ROOT / "config" / "cm_config.yaml").read_text())["scan"]
    self.cm_default = yaml.safe_load(
        (ROOT / "tests" / "fixtures" / "cm_0_10_0_init_scan.yaml").read_text())["scan"]

  def test_cfg_01_includes_cm_010_defaults(self):
    missing = (set(self.cm_default["extensions"]["include"])
               - set(self.scan["extensions"]["include"]))
    self.assertEqual(missing, set())

  def test_cfg_02_repo_languages_covered(self):
    with open(ROOT / "config" / "repos.tsv", encoding="utf-8") as f:
      languages = {r["language"] for r in csv.DictReader(f, delimiter="\t")}
    include = set(self.scan["extensions"]["include"])
    for lang in sorted(languages):
      with self.subTest(lang):
        self.assertIn(lang, LANGUAGE_EXTENSIONS)
        self.assertEqual(LANGUAGE_EXTENSIONS[lang] - include, set())

  def test_cfg_03_only_known_scan_keys(self):
    self.assertLessEqual(set(self.scan), {"extensions", "exclude_dirs",
                                          "max_file_size_kb", "incremental"})
    self.assertLessEqual(set(self.cm_default["exclude_dirs"]),
                         set(self.scan.get("exclude_dirs", [])))
    for pattern in self.scan["extensions"]["exclude"]:
      self.assertTrue(pattern.startswith("."), pattern)

  def test_cfg_04_framework_files_and_docs_src(self):
    # Svelte/Vue single-file components hold app code; fastapi docs_src/ is
    # tutorial code that inflated p02-fastapi from 578 to 1,220 files.
    self.assertLessEqual({".svelte", ".vue"}, set(self.scan["extensions"]["include"]))
    self.assertIn("docs_src", self.scan["exclude_dirs"])


if __name__ == "__main__":
  unittest.main()
