"""Unit tests for cm-ci.py."""

from collections.abc import Callable, Iterable
import functools
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

from codemender import ScanMode
from finding import Finding
from mock_codemender import MockCodeMender

_CM_CI_PATH = Path(__file__).resolve().parent.parent / "cm-ci.py"
_SPEC = importlib.util.spec_from_file_location("cm_ci", _CM_CI_PATH)
assert _SPEC is not None and _SPEC.loader is not None
cm_ci = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cm_ci)


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


class TestCmCi(unittest.TestCase):
    """Unit tests for cm-ci.py functions and CLI subcommands."""

    def setUp(self) -> None:
        self._orig_cwd = os.getcwd()

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)

    # ─── norm_rel_path ───────────────────────────────────────────────────────

    @parameterized(
        [
            ("", "", ""),
            ("   ", "", ""),
            ("./src/Main.py", "", "src/main.py"),
            ("src\\utils\\Helper.py", "", "src/utils/helper.py"),
            ("/repo/root/./pkg/Server.go", "/repo/root/", "pkg/server.go"),
            ("/tmp/run123/repo_checkout/lib/Auth.py", "", "lib/auth.py"),
            ("/workspace/proj/internal/Handler.go", "", "internal/handler.go"),
            ("/Users/alice/work/repo/custom/File.c", "", "custom/file.c"),
            (
                "/opt/build/deep/nested/controllers/UserController.py",
                "",
                "controllers/usercontroller.py",
            ),
        ]
    )
    def test_norm_rel_path(self, file_path: str, repo_root: str, expected: str) -> None:
        self.assertEqual(cm_ci.norm_rel_path(file_path, repo_root), expected)

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
        self.assertEqual(cm_ci.code_lines(snippet), expected)

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
                    vuln_type="CWE-79",
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
        self.assertEqual(cm_ci.is_duplicate(a, b), expected)

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
        marker = cm_ci.make_github_marker(finding, repo_root=repo_root)
        self.assertTrue(marker.startswith("<!-- cm-dedup:v1:"))
        self.assertTrue(marker.endswith(" -->"))
        m = cm_ci.GITHUB_MARKER_RE.search(marker)
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
        unpacked = cm_ci.unpack_findings(data)
        self.assertTrue(all(isinstance(f, Finding) for f in unpacked))
        self.assertEqual([f.to_dict() for f in unpacked], expected)

    def test_load_findings_reads_and_unpacks_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "findings.json")
            data = {"findings": [{"finding_id": "f-10", "file_path": "src/main.py"}]}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            loaded = cm_ci.load_findings(path)
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
        self.assertEqual(cm_ci.status_of(finding), expected)

    @parameterized(
        [
            (Finding(finding_id="cm-1", gh_issue_number=9, file_path="a.py"), "cm-1"),
            (Finding(gh_issue_number=9, file_path="a.py"), 9),
            (Finding(file_path="a.py"), "a.py"),
            (Finding(), None),
        ]
    )
    def test_dup_id(self, finding: Finding, expected: Any) -> None:
        self.assertEqual(cm_ci.dup_id(finding), expected)

    # ─── select_findings ─────────────────────────────────────────────────────

    @parameterized(
        [
            (1, ["crit-1"], 1),
            (2, ["crit-1", "high-1"], 1),
            (10, ["crit-1", "high-1", "low-1"], 1),
        ]
    )
    def test_select_findings(
        self, max_n: int, expected_ids: list[str], expected_dups: int
    ) -> None:
        findings = [
            Finding(
                finding_id="low-1",
                status="OPEN",
                severity="LOW",
                file_path="/repo/src/a.py",
                vuln_type="CWE-79",
                snippet="x = 1",
            ),
            Finding(
                finding_id="crit-1",
                status="OPEN",
                severity="CRITICAL",
                file_path="/repo/src/b.py",
                vuln_type="CWE-89",
                snippet="sql_call()",
            ),
            Finding(
                finding_id="crit-dup",
                status="VERIFIED",
                severity="CRITICAL",
                file_path="/repo/src/b.py",
                vuln_id="CWE-89",
                snippet="sql_call()",
            ),
            Finding(
                finding_id="high-1",
                status="REOPENED",
                severity="HIGH",
                file_path="/repo/src/c.py",
                vuln_type="CWE-22",
                snippet="open(p)",
            ),
            Finding(
                finding_id="skipped-venv",
                status="OPEN",
                severity="CRITICAL",
                file_path="/repo/venv/lib/site.py",
                vuln_type="CWE-89",
                snippet="venv_code()",
            ),
            Finding(
                finding_id="skipped-fixed",
                status="FIXED",
                severity="CRITICAL",
                file_path="/repo/src/d.py",
                vuln_type="CWE-89",
                snippet="fixed_code()",
            ),
        ]
        selected, dups = cm_ci.select_findings(findings, "/repo", max_n=max_n)
        self.assertEqual(dups, expected_dups)
        self.assertEqual([f.finding_id for f in selected], expected_ids)

    # ─── remove_duplicates_in_db ─────────────────────────────────────────────

    def test_remove_duplicates_in_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            with patch.object(cm_ci, "CodeMender", return_value=mock_cm):
                ctx = cm_ci.Ctx(tmpdir)
            ctx.db = os.path.join(tmpdir, "state.db")

            self.assertIsNone(cm_ci.remove_duplicates_in_db(ctx, []))

            con = sqlite3.connect(ctx.db)
            con.execute(
                "CREATE TABLE findings ("
                "finding_id TEXT PRIMARY KEY, status TEXT, dismiss_reason TEXT, updated_at TEXT)"
            )
            con.execute("CREATE TABLE patches (finding_id TEXT)")
            con.execute("CREATE TABLE artifacts (finding_id TEXT)")
            con.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?)",
                [
                    ("dup-unreferenced", "OPEN", None, None),
                    ("dup-patched", "OPEN", None, None),
                    ("twin-dismissed", "DISMISSED", cm_ci.CM_TWIN_REASONS[0], None),
                    ("keep-open", "OPEN", None, None),
                ],
            )
            con.execute("INSERT INTO patches VALUES (?)", ("dup-patched",))
            con.commit()
            con.close()

            dups = [
                Finding(finding_id="dup-unreferenced", duplicate_of="orig-1"),
                Finding(finding_id="dup-patched", duplicate_of="orig-2"),
            ]
            res = cm_ci.remove_duplicates_in_db(ctx, dups)
            self.assertEqual(res, (2, 1))

            con = sqlite3.connect(ctx.db)
            rows = {
                r[0]: (r[1], r[2])
                for r in con.execute("SELECT finding_id, status, dismiss_reason FROM findings")
            }
            con.close()
            self.assertNotIn("dup-unreferenced", rows)
            self.assertNotIn("twin-dismissed", rows)
            self.assertEqual(rows["dup-patched"], ("DISMISSED", "cm-ci: duplicate of orig-2"))
            self.assertEqual(rows["keep-open"], ("OPEN", None))

    # ─── cmd_dedup ───────────────────────────────────────────────────────────

    def test_cmd_dedup_deduplicates_cwe_125_and_cwe_129_and_handles_reopened(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            existing_path = os.path.join(tmpdir, "existing.json")
            new_path = os.path.join(tmpdir, "new.json")
            out_path = os.path.join(tmpdir, "out.json")

            existing = [
                {
                    "finding_id": "orig-active",
                    "file_path": "src/buffer.c",
                    "vuln_type": "CWE-125: Out-of-bounds Read",
                    "start_line": 10,
                    "end_line": 20,
                    "status": "OPEN",
                },
                {
                    "finding_id": "orig-fixed",
                    "file_path": "src/auth.c",
                    "vuln_type": "CWE-287",
                    "start_line": 30,
                    "end_line": 40,
                    "status": "FIXED",
                },
            ]
            current = [
                {
                    "finding_id": "cur-dup",
                    "file_path": "src/buffer.c",
                    "vuln_type": "CWE-129: Improper Validation of Array Index",
                    "start_line": 15,
                    "end_line": 25,
                    "status": "OPEN",
                },
                {
                    "finding_id": "cur-reopened",
                    "file_path": "src/auth.c",
                    "vuln_type": "CWE-287",
                    "start_line": 32,
                    "end_line": 38,
                    "status": "OPEN",
                },
                {
                    "finding_id": "cur-new",
                    "file_path": "src/sql.c",
                    "vuln_type": "CWE-89",
                    "start_line": 1,
                    "end_line": 5,
                    "status": "OPEN",
                },
            ]
            with open(existing_path, "w", encoding="utf-8") as fh:
                json.dump(existing, fh)
            with open(new_path, "w", encoding="utf-8") as fh:
                json.dump(current, fh)

            with patch("sys.stdout", new_callable=io.StringIO):
                rc = cm_ci.cmd_dedup(
                    [
                        "--existing",
                        existing_path,
                        "--new",
                        new_path,
                        "--out",
                        out_path,
                        "--repo",
                        tmpdir,
                    ]
                )

            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                out = json.load(fh)
            self.assertEqual([f["finding_id"] for f in out["findings"]], ["cur-new"])
            self.assertEqual([f["finding_id"] for f in out["reopened"]], ["cur-reopened"])
            self.assertEqual(out["reopened"][0]["duplicate_of"], "orig-fixed")
            self.assertEqual([f["finding_id"] for f in out["suppressed_duplicates"]], ["cur-dup"])
            self.assertEqual(out["suppressed_duplicates"][0]["duplicate_of"], "orig-active")

    # ─── Ctx.report & cmd_find ───────────────────────────────────────────────

    def test_ctx_report_uses_codemender_list_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            expected = [Finding(finding_id="cm-10", file_path="src/app.py", status="OPEN")]
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir), initial_findings=expected)
            with patch.object(cm_ci, "CodeMender", return_value=mock_cm):
                ctx = cm_ci.Ctx(tmpdir)
                findings = ctx.report()
                self.assertEqual(mock_cm.list_findings_calls, 1)
                self.assertEqual(findings, expected)

    @parameterized(
        [
            (["--quick"], ScanMode.QUICK, None, 0),
            (["--diff"], ScanMode.DIFF, None, 0),
            (["--fail-on", "CRITICAL", "--deep"], ScanMode.DEEP, None, 4),
            (["--fail-on", "LOW", "--deep"], ScanMode.DEEP, None, 0),
            (["--deep"], ScanMode.DEEP, RuntimeError("cm find failed with exit code 5"), 5),
        ]
    )
    def test_cmd_find_exit_codes_and_dedup(
        self,
        extra_args: list[str],
        expected_mode: ScanMode,
        find_error: Exception | None,
        expected_rc: int,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            initial_findings = [
                Finding(
                    finding_id="cm-old",
                    file_path="src/buf.c",
                    vuln_type="CWE-125",
                    start_line=10,
                    end_line=20,
                    status="OPEN",
                )
            ]
            scheduled_findings = [
                Finding(
                    finding_id="cm-dup",
                    file_path="src/buf.c",
                    vuln_type="CWE-129",
                    start_line=12,
                    end_line=18,
                    severity="HIGH",
                    status="OPEN",
                ),
                Finding(
                    finding_id="cm-new",
                    file_path="src/sql.py",
                    vuln_type="CWE-89",
                    start_line=40,
                    end_line=45,
                    severity="CRITICAL",
                    title="SQL Injection",
                    status="OPEN",
                ),
            ]

            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=initial_findings,
            )
            mock_cm.schedule_findings(scheduled_findings)
            if find_error is not None:
                mock_cm.schedule_find_error(find_error)

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm) as mock_cm_cls,
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, *extra_args])

            self.assertEqual(rc, expected_rc)
            mock_cm_cls.assert_called_once_with(repo_dir=os.path.realpath(tmpdir))
            self.assertEqual(mock_cm.find_calls, [(None, expected_mode)])
            if find_error is None:
                with open(os.path.join(out_dir, "new_findings.json"), encoding="utf-8") as fh:
                    new_findings = json.load(fh)
                self.assertEqual([f["finding_id"] for f in new_findings["findings"]], ["cm-new"])
                self.assertEqual(
                    [f["finding_id"] for f in new_findings["suppressed_duplicates"]], ["cm-dup"]
                )

    # ─── cmd_fix ─────────────────────────────────────────────────────────────

    @parameterized(
        [
            ({"project_paths": False, "reset": True, "exclude_dirs": True},),
            ({"project_paths": True, "reset": False, "exclude_dirs": True},),
        ]
    )
    def test_cmd_fix_requires_config(self, cfg_state: dict[str, bool]) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(cm_ci, "cfg_checks", return_value=cfg_state),
                patch.object(cm_ci, "check_config", return_value=False),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                with self.assertRaises(SystemExit) as cm:
                    cm_ci.cmd_fix(["--repo", tmpdir])
                self.assertEqual(cm.exception.code, 2)

    def test_cmd_fix_selects_commits_and_updates_known_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            known_dir = os.path.join(tmpdir, ".codemender")
            os.makedirs(known_dir, exist_ok=True)
            known_path = os.path.join(known_dir, "known_findings.json")
            with open(known_path, "w", encoding="utf-8") as fh:
                json.dump([{"finding_id": "cm-1", "file_path": "src/app.py", "status": "OPEN"}], fh)

            initial_findings = [
                Finding(
                    finding_id="cm-1",
                    file_path=os.path.join(tmpdir, "src/app.py"),
                    severity="HIGH",
                    title="SQLi",
                    vuln_type="CWE-89",
                    snippet="cursor.execute(q)",
                    status="OPEN",
                )
            ]
            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=initial_findings,
            )

            def fake_cm_fix(cmd: list[str], **_kwargs: Any) -> int:
                mock_cm.mark_status("cm-1", "FIXED")
                return 0

            def fake_sh(
                *cmd: str, check: bool = False, capture: bool = True
            ) -> subprocess.CompletedProcess:
                if cmd[:2] == ("git", "diff") and "--cached" in cmd:
                    return subprocess.CompletedProcess(cmd, 1, "", "")
                if cmd[:3] == ("git", "diff", "--stat"):
                    return subprocess.CompletedProcess(
                        cmd, 0, " 1 file changed, 1 insertion(+)\n", ""
                    )
                if cmd[:3] == ("git", "rev-parse", "--short"):
                    return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
                if cmd[:3] == ("git", "rev-parse", "--git-dir"):
                    return subprocess.CompletedProcess(cmd, 0, ".git\n", "")
                if cmd[:2] == ("git", "ls-files"):
                    return subprocess.CompletedProcess(
                        cmd, 1 if "--error-unmatch" in cmd else 0, "", ""
                    )
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with (
                patch.object(cm_ci, "need"),
                patch.object(
                    cm_ci,
                    "cfg_checks",
                    return_value={"project_paths": True, "reset": True, "exclude_dirs": True},
                ),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(cm_ci, "sh", side_effect=fake_sh) as mock_sh,
                patch("subprocess.call", side_effect=fake_cm_fix) as mock_call,
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_fix(
                    ["--repo", tmpdir, "--known", known_path, "--model", "gemini-pro"]
                )

            self.assertEqual(rc, 0)
            mock_call.assert_called_once_with(
                ["cm", "fix", "cm-1", "-y", "--bypass-warning", "--model", "gemini-pro"],
                stdin=subprocess.DEVNULL,
            )
            commit_calls = [
                c.args for c in mock_sh.call_args_list if c.args[:2] == ("git", "commit")
            ]
            self.assertIn(("git", "commit", "-q", "-m", "codemender: fix cm-1"), commit_calls)

            with open(known_path, encoding="utf-8") as fh:
                updated_known = json.load(fh)
            self.assertEqual(updated_known[0]["status"], "FIXED")

    def test_cmd_fix_aborts_on_nested_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "sub", ".git")
            os.makedirs(nested)
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(
                    cm_ci,
                    "cfg_checks",
                    return_value={"project_paths": True, "reset": True, "exclude_dirs": True},
                ),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_fix(["--repo", tmpdir, "cm-1"])
            self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
