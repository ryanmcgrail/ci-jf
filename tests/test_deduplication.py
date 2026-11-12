"""Unit tests for deduplication.py."""

from collections.abc import Callable, Iterable
import functools
import json
import os
import tempfile
import types
from typing import Any
import unittest

import deduplication
from finding import Finding
from mock_codemender import MockCodeMender


def parameterized(
    cases: Iterable[tuple[Any, ...]],
) -> Callable[[Callable[..., None]], Callable[..., None]]:
    """Run a unittest test method across a list of parameter tuples using subTest."""
    case_list = list(cases)

    def decorator(func: Callable[..., None]) -> Callable[..., None]:
        @functools.wraps(func)
        def wrapper(self: unittest.TestCase) -> None:
            for params in case_list:
                with self.subTest(params=params):
                    func(self, *params)

        return wrapper

    return decorator


class TestDeduplication(unittest.TestCase):
    """Unit tests for deduplication functions and state.db consolidation."""

    # ─── norm_rel_path ───────────────────────────────────────────────────────

    @parameterized(
        [
            ("", "", ""),
            ("   ", "", ""),
            ("./src/Main.py", "", "src/main.py"),
            ("src\\utils\\Helper.py", "", "src/utils/helper.py"),
            ("/repo/root/./pkg/Server.go", "/repo/root/", "pkg/server.go"),
            (
                "frontend/src/app/search-result/search-result.component.ts",
                "/Users/alice/juice-shop",
                "frontend/src/app/search-result/search-result.component.ts",
            ),
            (
                "backend/src/utils.ts",
                "/Users/alice/monorepo",
                "backend/src/utils.ts",
            ),
        ]
    )
    def test_norm_rel_path(self, file_path: str, repo_root: str, expected: str) -> None:
        self.assertEqual(deduplication.norm_rel_path(file_path, repo_root), expected)

    # ─── code_lines ──────────────────────────────────────────────────────────

    @parameterized(
        [
            ("", set()),
            ("short = 1\n// a comment longer than twenty characters", set()),
            (
                "// comment line that is longer than twenty chars\n"
                "# python comment line longer than twenty chars\n"
                "/* block comment start longer than twenty chars */\n"
                "* block comment continuation longer than twenty\n"
                "short = 1\n"
                "result   =   compute_dangerous_query(user_input)  \\n"
                "return   execute_sql_statement(result,   connection)",
                {
                    "result = compute_dangerous_query(user_input)",
                    "return execute_sql_statement(result, connection)",
                },
            ),
        ]
    )
    def test_code_lines(self, snippet: str, expected: set[str]) -> None:
        self.assertEqual(deduplication.code_lines(snippet), expected)

    # ─── is_duplicate ────────────────────────────────────────────────────────

    @parameterized(
        [
            (
                "overlapping lines and related CWEs (CWE-125 and CWE-129)",
                Finding(
                    file_path="src/buffer.c",
                    vuln_type="CWE-125: Out-of-bounds Read",
                    start_line=10,
                    end_line=20,
                ),
                Finding(
                    file_path="./src/BUFFER.c",
                    vuln_type="CWE-129: Improper Validation of Array Index",
                    start_line=18,
                    end_line=25,
                ),
                True,
            ),
            (
                "non-overlapping lines with subset code_lines",
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=12,
                    snippet="query = 'SELECT * FROM users WHERE name = ' + user_supplied_name",
                ),
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=50,
                    end_line=55,
                    snippet=(
                        "query = 'SELECT * FROM users WHERE name = ' + user_supplied_name\n"
                        "cursor.execute(query, params_tuple_extra)"
                    ),
                ),
                True,
            ),
            (
                "different file paths",
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                ),
                Finding(
                    file_path="src/other.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                ),
                False,
            ),
            (
                "unrelated CWEs on same file and lines",
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                ),
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-22",
                    start_line=10,
                    end_line=15,
                ),
                False,
            ),
            (
                "non-overlapping lines and disjoint snippets",
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                    snippet="cursor.execute('SELECT * FROM t WHERE id=' + user_id)",
                ),
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=100,
                    end_line=105,
                    snippet="completely_different_statement_with_long_length(arg1, arg2)",
                ),
                False,
            ),
            (
                "missing file_path",
                Finding(
                    file_path="",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                ),
                Finding(
                    file_path="src/db.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                ),
                False,
            ),
        ]
    )
    def test_is_duplicate(self, _desc: str, a: Finding, b: Finding, expected: bool) -> None:
        self.assertEqual(deduplication.is_duplicate(a, b), expected)

    # ─── make_github_marker ──────────────────────────────────────────────────

    @parameterized(
        [
            (
                Finding(
                    file_path="/repo/src/Auth.py",
                    vuln_type="CWE-79: Cross-site Scripting",
                    start_line=12,
                    end_line=16,
                    snippet="response.write(untrusted_user_input_string)",
                ),
                "/repo",
                {
                    "file_path": "src/auth.py",
                    "vuln_type": "CWE-79",
                    "start_line": 12,
                    "end_line": 16,
                    "raw_lines": ["response.write(untrusted_user_input_string)"],
                },
            ),
            (
                Finding(file_path="a.py", vuln_type="CustomBug"),
                "",
                {
                    "file_path": "a.py",
                    "vuln_type": "CustomBug",
                    "start_line": 0,
                    "end_line": 0,
                    "raw_lines": [],
                },
            ),
        ]
    )
    def test_make_github_marker(
        self, finding: Finding, repo_root: str, expected_payload: dict
    ) -> None:
        marker = deduplication.make_github_marker(finding, repo_root=repo_root)
        self.assertTrue(marker.startswith("<!-- cm-dedup:v1:"))
        self.assertTrue(marker.endswith(" -->"))
        m = deduplication.GITHUB_MARKER_RE.search(marker)
        self.assertIsNotNone(m)
        self.assertEqual(json.loads(m.group(1)), expected_payload)

    # ─── unpack_findings & load_findings ─────────────────────────────────────

    @parameterized(
        [
            ("None input", None, []),
            (
                "direct list ignoring non-dicts",
                [{"finding_id": "f-1", "file_path": "a.py"}, "ignored_non_dict"],
                [{"finding_id": "f-1", "file_path": "a.py"}],
            ),
            (
                "wrapped in findings key",
                {"findings": [{"finding_id": "f-2", "file_path": "b.py"}]},
                [{"finding_id": "f-2", "file_path": "b.py"}],
            ),
            (
                "wrapped in results key",
                {"results": [{"finding_id": "f-3", "file_path": "c.py"}]},
                [{"finding_id": "f-3", "file_path": "c.py"}],
            ),
            (
                "wrapped in items key",
                {"items": [{"finding_id": "f-4", "file_path": "d.py"}]},
                [{"finding_id": "f-4", "file_path": "d.py"}],
            ),
            (
                "github issues with and without embedded marker",
                [
                    {
                        "number": 42,
                        "state": "open",
                        "body": (
                            "Issue details\n"
                            '<!-- cm-dedup:v1:{"file_path":"src/app.py","vuln_type":"CWE-89",'
                            '"start_line":5,"end_line":8,"raw_lines":[]} -->'
                        ),
                    },
                    {"number": 43, "state": "open", "body": "Issue without marker"},
                ],
                [
                    {
                        "file_path": "src/app.py",
                        "vuln_type": "CWE-89",
                        "start_line": 5,
                        "end_line": 8,
                        "raw_lines": [],
                        "gh_issue_number": 42,
                        "state": "open",
                    }
                ],
            ),
        ]
    )
    def test_unpack_findings(self, _desc: str, data: Any, expected: list[dict]) -> None:
        unpacked = deduplication.unpack_findings(data)
        self.assertTrue(all(isinstance(f, Finding) for f in unpacked))
        self.assertEqual([f.to_dict() for f in unpacked], expected)

    def test_load_findings_reads_and_unpacks_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "findings.json")
            data = {"findings": [{"finding_id": "f-10", "file_path": "src/main.py"}]}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            loaded = deduplication.load_findings(path)
            self.assertEqual(len(loaded), 1)
            self.assertIsInstance(loaded[0], Finding)
            self.assertEqual(loaded[0].to_dict(), {"finding_id": "f-10", "file_path": "src/main.py"})

    # ─── status_of & dup_id ──────────────────────────────────────────────────

    @parameterized(
        [
            (Finding(status="fixed"), "FIXED"),
            (Finding(state="closed"), "CLOSED"),
            (Finding(), "OPEN"),
            (Finding(status=""), "OPEN"),
        ]
    )
    def test_status_of(self, finding: Finding, expected: str) -> None:
        self.assertEqual(deduplication.status_of(finding), expected)

    @parameterized(
        [
            (Finding(finding_id="cm-1", gh_issue_number=9, file_path="a.py"), "cm-1"),
            (Finding(gh_issue_number=9, file_path="a.py"), 9),
            (Finding(file_path="a.py"), "a.py"),
            (Finding(), None),
        ]
    )
    def test_dup_id(self, finding: Finding, expected: Any) -> None:
        self.assertEqual(deduplication.dup_id(finding), expected)

    # ─── dedup ───────────────────────────────────────────────────────────────

    @parameterized(
        [
            (
                "both already existing (CWE-125 then CWE-129)",
                [
                    Finding(
                        finding_id="cm-1",
                        file_path="src/buf.c",
                        vuln_type="CWE-125: Out-of-bounds Read",
                        start_line=10,
                        end_line=20,
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cm-2",
                        file_path="src/buf.c",
                        vuln_type="CWE-129: Improper Validation of Array Index",
                        start_line=12,
                        end_line=18,
                        status="OPEN",
                    ),
                ],
                [],
                [],
            ),
            (
                "both already existing (CWE-129 then CWE-125)",
                [
                    Finding(
                        finding_id="cm-1",
                        file_path="src/buf.c",
                        vuln_type="CWE-129: Improper Validation of Array Index",
                        start_line=12,
                        end_line=18,
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cm-2",
                        file_path="src/buf.c",
                        vuln_type="CWE-125: Out-of-bounds Read",
                        start_line=10,
                        end_line=20,
                        status="OPEN",
                    ),
                ],
                [],
                [],
            ),
            (
                "CWE-125 existing and CWE-129 newly found",
                [
                    Finding(
                        finding_id="cm-1",
                        file_path="src/buf.c",
                        vuln_type="CWE-125: Out-of-bounds Read",
                        start_line=10,
                        end_line=20,
                        status="OPEN",
                    )
                ],
                [
                    Finding(
                        finding_id="cm-2",
                        file_path="src/buf.c",
                        vuln_type="CWE-129: Improper Validation of Array Index",
                        start_line=12,
                        end_line=18,
                        status="OPEN",
                    )
                ],
                [],
            ),
            (
                "CWE-129 existing and CWE-125 newly found",
                [
                    Finding(
                        finding_id="cm-1",
                        file_path="src/buf.c",
                        vuln_type="CWE-129: Improper Validation of Array Index",
                        start_line=12,
                        end_line=18,
                        status="OPEN",
                    )
                ],
                [
                    Finding(
                        finding_id="cm-2",
                        file_path="src/buf.c",
                        vuln_type="CWE-125: Out-of-bounds Read",
                        start_line=10,
                        end_line=20,
                        status="OPEN",
                    )
                ],
                [],
            ),
            (
                "both newly found together (CWE-125 then CWE-129)",
                [],
                [
                    Finding(
                        finding_id="cm-1",
                        file_path="src/buf.c",
                        vuln_type="CWE-125: Out-of-bounds Read",
                        start_line=10,
                        end_line=20,
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cm-2",
                        file_path="src/buf.c",
                        vuln_type="CWE-129: Improper Validation of Array Index",
                        start_line=12,
                        end_line=18,
                        status="OPEN",
                    ),
                ],
                ["cm-1"],
            ),
            (
                "both newly found together (CWE-129 then CWE-125)",
                [],
                [
                    Finding(
                        finding_id="cm-1",
                        file_path="src/buf.c",
                        vuln_type="CWE-129: Improper Validation of Array Index",
                        start_line=12,
                        end_line=18,
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cm-2",
                        file_path="src/buf.c",
                        vuln_type="CWE-125: Out-of-bounds Read",
                        start_line=10,
                        end_line=20,
                        status="OPEN",
                    ),
                ],
                ["cm-1"],
            ),
        ]
    )
    def test_dedup_cwe_125_and_cwe_129_all_cases(
        self,
        _desc: str,
        existing: list[Finding],
        current: list[Finding],
        expected_new_ids: list[str],
    ) -> None:
        res = deduplication.dedup(existing, current, "")
        self.assertEqual([f.finding_id for f in res["findings"]], expected_new_ids)
        self.assertEqual([f.finding_id for f in res["suppressed_duplicates"]], ["cm-2"])
        self.assertEqual(res["suppressed_duplicates"][0].duplicate_of, "cm-1")

    # ─── remove_duplicates_in_db ─────────────────────────────────────────────

    def test_remove_duplicates_in_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=[
                    Finding(finding_id="dup-unreferenced", status="OPEN"),
                    Finding(finding_id="dup-patched", status="OPEN"),
                    Finding(
                        finding_id="twin-dismissed",
                        status="DISMISSED",
                        dismiss_reason=deduplication.CM_TWIN_REASONS[0],
                    ),
                    Finding(finding_id="keep-open", status="OPEN"),
                ],
            )
            mock_cm.db.execute("INSERT INTO patches VALUES (?)", ("dup-patched",))
            mock_cm.db.commit()

            ctx = types.SimpleNamespace(cm=mock_cm)
            dups = [
                Finding(finding_id="dup-unreferenced", duplicate_of="orig-1"),
                Finding(finding_id="dup-patched", duplicate_of="orig-2"),
            ]
            res = deduplication.remove_duplicates_in_db(ctx, dups)
            self.assertEqual(res, (2, 1))

            findings = {f.finding_id: f for f in mock_cm.list_findings()}
            self.assertNotIn("dup-unreferenced", findings)
            self.assertNotIn("twin-dismissed", findings)
            self.assertEqual(findings["dup-patched"].status, "DISMISSED")
            self.assertEqual(
                findings["dup-patched"].dismiss_reason, "cm-ci: duplicate of orig-2"
            )
            self.assertEqual(findings["keep-open"].status, "OPEN")
            self.assertIsNone(findings["keep-open"].dismiss_reason)


if __name__ == "__main__":
    unittest.main()

