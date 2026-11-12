"""Unit tests for covered_lines.py."""

import json
import os
import tempfile
import unittest

from covered_lines import (
    find_snippet_line_range,
    find_snippet_line_ranges,
    summarize_covered_lines,
)


class CoveredLinesTests(unittest.TestCase):

  def test_find_snippet_line_range_exact_and_whitespace_normalized(self):
    file_lines = [
        "package demo;",
        "",
        "public class Crypto {",
        "  public void level1(String pwd) {",
        "    if (pwd.equals(SECRET)) {",
        "      allow();",
        "    }",
        "  }",
        "}",
    ]
    snip = "  public void level1(String pwd) {\n    if (pwd.equals(SECRET)) {\n      allow();\n    }\n  }"
    self.assertEqual(find_snippet_line_range(file_lines, snip), (4, 8))

    # Whitespace-shifted snippet
    snip_shifted = "public void level1(String pwd) {\n  if (pwd.equals(SECRET)) {\n    allow();\n  }\n}"
    self.assertEqual(find_snippet_line_range(file_lines, snip_shifted), (4, 8))

  def test_summarize_covered_lines_resolves_multiple_and_repeated_snippets(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      src_dir = os.path.join(tmpdir, "src")
      os.makedirs(src_dir)
      src_path = os.path.join(src_dir, "Hashing.java")
      with open(src_path, "w", encoding="utf-8") as fh:
        fh.write(
            "\n".join([
                "package demo;",
                "public class Hashing {",
                "  public String getMd5() {",
                "    String secret = SECRETS[new Random().nextInt(SECRETS.length)];",
                "    return md5(secret);",
                "  }",
                "  public String getSha256() {",
                "    String secret = SECRETS[new Random().nextInt(SECRETS.length)];",
                "    return sha256(secret);",
                "  }",
                "}",
            ])
            + "\n"
        )

      report_path = os.path.join(tmpdir, "report.json")
      with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(
            [
                {
                    "file_path": "src/Hashing.java",
                    "snippet": "    String secret = SECRETS[new Random().nextInt(SECRETS.length)];",
                },
                {
                    "file_path": "src/Hashing.java",
                    "snippet": "    String secret = SECRETS[new Random().nextInt(SECRETS.length)];",
                },
                {
                    "file_path": "src/Other.java",
                    "snippet": "other_sink();",
                },
            ],
            fh,
        )

      summary = summarize_covered_lines(
          report_path, "./src/hashing.java", repo_dir=tmpdir
      )
      self.assertEqual(
          summary,
          "\n".join([
              "Already-covered vulnerabilities in src/hashing.java:",
              "- Line 4: String secret = SECRETS[new Random().nextInt(SECRETS.length)];",
              "- Line 8: String secret = SECRETS[new Random().nextInt(SECRETS.length)];",
          ]),
      )

  def test_summarize_covered_lines_returns_notice_when_no_matches(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      report_path = os.path.join(tmpdir, "report.json")
      with open(report_path, "w", encoding="utf-8") as fh:
        json.dump([], fh)
      self.assertEqual(
          summarize_covered_lines(report_path, "src/Clean.java", repo_dir=tmpdir),
          "No preexisting findings for src/Clean.java.",
      )


if __name__ == "__main__":
  unittest.main()
