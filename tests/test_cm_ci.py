"""Unit tests for cm-ci.py."""

from collections.abc import Callable, Iterable
import functools
import importlib.util
import io
import json
import os
from pathlib import Path
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
                self.assertEqual(
                    [f.finding_id for f in mock_cm.list_findings()],
                    ["cm-old", "cm-new"],
                )

    def test_cmd_find_complete_calls_run_complete_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(cm_ci, "run_complete_scan") as mock_complete_scan,
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(
                    [
                        "--repo",
                        tmpdir,
                        "--out-dir",
                        out_dir,
                        "--complete",
                        "--complete-runs",
                        "3",
                        "--deep-workers=16",
                    ]
                )
            self.assertEqual(rc, 0)
            mock_complete_scan.assert_called_once_with(
                mock_cm,
                target_or_id=None,
                extra_flags=["--deep-workers", "16"],
                complete_runs=3,
                critical_high_only=True,
            )

    def test_cmd_find_complete_respects_critical_high_only_flag_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(cm_ci, "run_complete_scan") as mock_complete_scan,
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(
                    [
                        "--repo",
                        tmpdir,
                        "--out-dir",
                        out_dir,
                        "--complete",
                        "--critical-high-only=false",
                        "--deep-workers=16",
                    ]
                )
            self.assertEqual(rc, 0)
            mock_complete_scan.assert_called_once_with(
                mock_cm,
                target_or_id=None,
                extra_flags=["--deep-workers", "16"],
                complete_runs=5,
                critical_high_only=False,
            )

    @parameterized(
        [
            (
                "both already in database (CWE-125 then CWE-129)",
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
                "both already in database (CWE-129 then CWE-125)",
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
                "CWE-125 in database and CWE-129 newly found",
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
                "CWE-129 in database and CWE-125 newly found",
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
    def test_cmd_find_always_deduplicates_cwe_125_and_cwe_129(
        self,
        _desc: str,
        initial_findings: list[Finding],
        scheduled_findings: list[Finding],
        expected_new_ids: list[str],
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=initial_findings,
            )
            mock_cm.schedule_findings(scheduled_findings)

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir])

            self.assertEqual(rc, 0)
            with open(os.path.join(out_dir, "new_findings.json"), encoding="utf-8") as fh:
                new_findings = json.load(fh)
            self.assertEqual(
                [f["finding_id"] for f in new_findings["findings"]], expected_new_ids
            )
            self.assertEqual(
                [f["finding_id"] for f in new_findings["suppressed_duplicates"]], ["cm-2"]
            )
            self.assertEqual(new_findings["suppressed_duplicates"][0]["duplicate_of"], "cm-1")
            self.assertEqual([f.finding_id for f in mock_cm.list_findings()], ["cm-1"])

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

    def test_cmd_find_critical_high_mode_filters_summary_counts_and_listed_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            initial_findings = [
                Finding(
                    finding_id="old-fixed-high",
                    file_path="src/reopen_high.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                    severity="HIGH",
                    status="FIXED",
                ),
                Finding(
                    finding_id="old-fixed-low",
                    file_path="src/reopen_low.py",
                    vuln_type="CWE-532",
                    start_line=1,
                    end_line=5,
                    severity="LOW",
                    status="FIXED",
                ),
                Finding(
                    finding_id="old-open-med",
                    file_path="src/existing_med.py",
                    vuln_type="CWE-79",
                    start_line=20,
                    end_line=25,
                    severity="MEDIUM",
                    status="OPEN",
                ),
            ]
            new_batch = [
                Finding(
                    finding_id="new-crit",
                    file_path="src/rce.py",
                    vuln_type="CWE-78",
                    start_line=30,
                    end_line=35,
                    severity="CRITICAL",
                    title="Command Injection",
                    status="OPEN",
                ),
                Finding(
                    finding_id="new-high",
                    file_path="src/ssrf.py",
                    vuln_type="CWE-918",
                    start_line=40,
                    end_line=45,
                    severity="HIGH",
                    title="SSRF Issue",
                    status="OPEN",
                ),
                Finding(
                    finding_id="new-med",
                    file_path="src/xss.js",
                    vuln_type="CWE-79",
                    start_line=50,
                    end_line=55,
                    severity="MEDIUM",
                    title="Stored XSS",
                    status="OPEN",
                ),
                Finding(
                    finding_id="reopen-high",
                    file_path="src/reopen_high.py",
                    vuln_type="CWE-89",
                    start_line=11,
                    end_line=14,
                    severity="HIGH",
                    title="Reopened SQLi",
                    status="OPEN",
                ),
                Finding(
                    finding_id="reopen-low",
                    file_path="src/reopen_low.py",
                    vuln_type="CWE-532",
                    start_line=2,
                    end_line=4,
                    severity="LOW",
                    title="Reopened Log Leak",
                    status="OPEN",
                ),
            ]

            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=initial_findings,
            )

            def _fake_complete_scan(cm: Any, **_kwargs: Any) -> None:
                cm._insert_findings(new_batch)

            stdout_ch = io.StringIO()
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(cm_ci, "run_complete_scan", side_effect=_fake_complete_scan),
                patch("sys.stdout", stdout_ch),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--complete"])

            self.assertEqual(rc, 0)
            out_text = stdout_ch.getvalue()
            self.assertIn(
                "(CRITICAL/HIGH mode) →",
                out_text,
            )
            self.assertIn(
                "(3 CRITICAL/HIGH active finding(s))",
                out_text,
            )
            self.assertIn(
                "CRITICAL/HIGH Summary — Existing: 1 | Current: 3 | Duplicates suppressed: 0"
                " | New to file: 2 (1 CRITICAL, 1 HIGH) | Reopened: 1",
                out_text,
            )
            self.assertIn("(+3 new CRITICAL/HIGH, 5 total entries)", out_text)
            self.assertIn("Command Injection", out_text)
            self.assertIn("SSRF Issue", out_text)
            self.assertIn("Reopened SQLi", out_text)
            self.assertNotIn("Stored XSS", out_text)
            self.assertNotIn("Reopened Log Leak", out_text)

            # Verify --no-critical-high-only restores full all-severity summary and listing
            out_dir_all = os.path.join(tmpdir, ".codemender_all")
            mock_cm_all = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=initial_findings,
            )
            stdout_all = io.StringIO()
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm_all),
                patch.object(cm_ci, "run_complete_scan", side_effect=_fake_complete_scan),
                patch("sys.stdout", stdout_all),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc_all = cm_ci.cmd_find(
                    [
                        "--repo",
                        tmpdir,
                        "--out-dir",
                        out_dir_all,
                        "--complete",
                        "--no-critical-high-only",
                    ]
                )

            self.assertEqual(rc_all, 0)
            out_all_text = stdout_all.getvalue()
            self.assertNotIn("CRITICAL/HIGH Summary", out_all_text)
            self.assertIn(
                "Existing: 3 | Current: 5 | Duplicates suppressed: 0 | New to file: 3 | Reopened: 2",
                out_all_text,
            )
            self.assertIn("Stored XSS", out_all_text)
            self.assertIn("Reopened Log Leak", out_all_text)

    def test_cmd_find_monotonic_severity_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            known_path = os.path.join(out_dir, "known_findings.json")
            os.makedirs(out_dir)

            initial_findings = [
                Finding(
                    finding_id="f-inplace-high",
                    file_path="src/a.py",
                    vuln_type="CWE-89",
                    start_line=10,
                    end_line=15,
                    severity="HIGH",
                    status="OPEN",
                ),
                Finding(
                    finding_id="f-dup-med",
                    file_path="src/b.py",
                    vuln_type="CWE-78",
                    start_line=20,
                    end_line=25,
                    severity="MEDIUM",
                    status="OPEN",
                ),
                Finding(
                    finding_id="f-dup-crit",
                    file_path="src/c.py",
                    vuln_type="CWE-94",
                    start_line=30,
                    end_line=35,
                    severity="CRITICAL",
                    status="OPEN",
                ),
            ]
            with open(known_path, "w", encoding="utf-8") as fh:
                json.dump([f.to_dict() for f in initial_findings], fh)

            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=initial_findings,
            )

            orig_find = mock_cm.find

            def _find_with_wobble(*args: Any, **kwargs: Any) -> Any:
                res = orig_find(*args, **kwargs)
                # Simulate cm overwriting `f-inplace-high` down to MEDIUM in state.db
                mock_cm.db.execute(
                    "UPDATE findings SET severity = 'MEDIUM' WHERE finding_id = 'f-inplace-high'"
                )
                mock_cm.db.commit()
                return res

            mock_cm.schedule_findings(
                [
                    Finding(
                        finding_id="f-dup-med-upgraded",
                        file_path="src/b.py",
                        vuln_type="CWE-78",
                        start_line=21,
                        end_line=24,
                        severity="HIGH",
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="f-dup-crit-downgrade-attempt",
                        file_path="src/c.py",
                        vuln_type="CWE-94",
                        start_line=31,
                        end_line=34,
                        severity="LOW",
                        status="OPEN",
                    ),
                ]
            )

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(mock_cm, "find", side_effect=_find_with_wobble),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--deep"])

            self.assertEqual(rc, 0)
            db_sevs = {f.finding_id: f.severity for f in mock_cm.list_findings()}
            self.assertEqual(db_sevs["f-inplace-high"], "HIGH")
            self.assertEqual(db_sevs["f-dup-med"], "HIGH")
            self.assertEqual(db_sevs["f-dup-crit"], "CRITICAL")

            with open(known_path, encoding="utf-8") as fh:
                known_sevs = {d["finding_id"]: d["severity"] for d in json.load(fh)}
            self.assertEqual(known_sevs["f-inplace-high"], "HIGH")
            self.assertEqual(known_sevs["f-dup-med"], "HIGH")
            self.assertEqual(known_sevs["f-dup-crit"], "CRITICAL")

    @parameterized(
        [
            (
                ["--model", "gemini-2.5-pro", "--deep-workers", "8", "-c", "Check auth"],
                None,
                ScanMode.DEEP,
                ["--model", "gemini-2.5-pro", "--deep-workers", "8", "-c", "Check auth"],
            ),
            (
                ["--model", "gemini-2.5-pro", "src"],
                "src",
                ScanMode.DEEP,
                ["--model", "gemini-2.5-pro"],
            ),
            (
                ["--diff", "main"],
                None,
                ScanMode.DIFF,
                ["--diff=main"],
            ),
            (
                ["--diff=origin/main"],
                None,
                ScanMode.DIFF,
                ["--diff=origin/main"],
            ),
        ]
    )
    def test_cmd_find_space_separated_passthrough_flags_do_not_steal_target(
        self,
        find_args: list[str],
        expected_target: str | None,
        expected_mode: ScanMode,
        expected_extra_flags: list[str],
    ) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
            out_dir = os.path.join(tmpdir, ".codemender")
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            captured_kwargs: list[dict[str, Any]] = []
            orig_find = mock_cm.find

            def _spy_find(**kwargs: Any) -> Any:
                captured_kwargs.append(kwargs)
                return orig_find(**kwargs)

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(mock_cm, "find", side_effect=_spy_find),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, *find_args])

            self.assertEqual(rc, 0)
            self.assertEqual(len(captured_kwargs), 1)
            self.assertEqual(captured_kwargs[0]["target_or_id"], expected_target)
            self.assertEqual(captured_kwargs[0]["scan_mode"], expected_mode)
            self.assertEqual(captured_kwargs[0].get("extra_flags"), expected_extra_flags)

    def test_cmd_find_forwards_context_across_all_scan_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            cm_home = os.path.join(tmpdir, "cm_home")
            os.makedirs(cm_home, exist_ok=True)

            find_cmds: list[list[str]] = []

            def fake_run_command(cmd: list[str], **_kwargs: Any) -> Any:
                if cmd[:2] == ["cm", "report"]:
                    return subprocess.CompletedProcess(cmd, 0, "[]", "")
                if cmd[:2] == ["cm", "find"]:
                    find_cmds.append(cmd)
                    return subprocess.CompletedProcess(cmd, 0, "Success", "")
                raise AssertionError(f"Unexpected command: {cmd}")

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.dict(os.environ, {"CM_HOME": cm_home}),
                patch("codemender.run_command", side_effect=fake_run_command),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                # Without --context: --quick, --diff, --deep omit --context; --complete injects Pass 1 context
                self.assertEqual(cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--quick"]), 0)
                self.assertEqual(cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--diff"]), 0)
                self.assertEqual(cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--deep"]), 0)
                self.assertEqual(
                    cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--complete", "--complete-runs=1"]),
                    0,
                )
                # With --context: every scan mode passes --context to `cm find`
                self.assertEqual(
                    cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--quick", "--context", "Quick ctx"]),
                    0,
                )
                self.assertEqual(
                    cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--diff", "-c", "Diff ctx"]),
                    0,
                )
                self.assertEqual(
                    cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--deep", "--context=Deep ctx"]),
                    0,
                )
                self.assertEqual(
                    cm_ci.cmd_find(
                        [
                            "--repo",
                            tmpdir,
                            "--out-dir",
                            out_dir,
                            "--complete",
                            "--complete-runs=1",
                            "--context",
                            "Complete ctx",
                        ]
                    ),
                    0,
                )

            self.assertEqual(len(find_cmds), 8)
            for cmd in find_cmds[:3]:
                self.assertNotIn("--context", cmd)
            self.assertIn("--context", find_cmds[3])
            base_complete_ctx = find_cmds[3][find_cmds[3].index("--context") + 1]
            self.assertIn("# Audit Strategy", base_complete_ctx)

            self.assertEqual(find_cmds[4][find_cmds[4].index("--context") + 1], "Quick ctx")
            self.assertEqual(find_cmds[5][find_cmds[5].index("--context") + 1], "Diff ctx")
            self.assertEqual(find_cmds[6][find_cmds[6].index("--context") + 1], "Deep ctx")
            self.assertEqual(
                find_cmds[7][find_cmds[7].index("--context") + 1],
                f"{base_complete_ctx}\n\n# Additional Context\nComplete ctx",
            )

    def test_argparse_edge_cases_across_subcommands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "src"), exist_ok=True)
            out_dir = os.path.join(tmpdir, ".codemender")
            mock_cm = MockCodeMender(repo_dir=os.path.realpath(tmpdir))
            captured_kwargs: list[dict[str, Any]] = []
            orig_find = mock_cm.find

            def _spy_find(**kwargs: Any) -> Any:
                captured_kwargs.append(kwargs)
                return orig_find(**kwargs)

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                patch.object(mock_cm, "find", side_effect=_spy_find),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                # `--fail-on-truncation` must pass through to `cm find` (no prefix collision with `--fail-on`)
                self.assertEqual(
                    cm_ci.cmd_find(
                        ["--repo", tmpdir, "--out-dir", out_dir, "--fail-on-truncation", "src"]
                    ),
                    0,
                )
                # `--diff src` where `src` exists on disk sets `target="src"` rather than `--diff=src`
                self.assertEqual(
                    cm_ci.cmd_find(["--repo", tmpdir, "--out-dir", out_dir, "--diff", "src"]),
                    0,
                )
                # `--critical-high-only src` where `src` exists sets `target="src"` and `critical_high_only=True`
                self.assertEqual(
                    cm_ci.cmd_find(
                        ["--repo", tmpdir, "--out-dir", out_dir, "--critical-high-only", "src"]
                    ),
                    0,
                )

            self.assertEqual(
                captured_kwargs,
                [
                    {
                        "target_or_id": "src",
                        "scan_mode": ScanMode.DEEP,
                        "extra_flags": ["--fail-on-truncation"],
                    },
                    {"target_or_id": "src", "scan_mode": ScanMode.DIFF},
                    {"target_or_id": "src", "scan_mode": ScanMode.DEEP},
                ],
            )

            # CLI usage errors exit with code 1 (preserving exit code 2 for missing config)
            with patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as bad_dedup:
                    cm_ci.cmd_dedup(["--existing", "only_one.json"])
                self.assertEqual(bad_dedup.exception.code, 1)

                with self.assertRaises(SystemExit) as bad_cfg:
                    cm_ci.cmd_check_config(["--unknown-flag"])
                self.assertEqual(bad_cfg.exception.code, 1)

    def test_ctx_restores_interrupted_complete_scan_workspace_before_fix(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_dir = os.path.join(tmpdir, "repo")
            cm_home = os.path.join(tmpdir, "cm_home")
            os.makedirs(repo_dir)
            os.makedirs(cm_home)
            cmignore_path = os.path.join(repo_dir, ".cmignore")
            report_path = os.path.join(repo_dir, "_cm_pass_report")
            with open(cmignore_path, "w", encoding="utf-8") as fh:
                fh.write("vendor/\nnode_modules/\nclean_from_killed_pass.py\n")
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write('[{"file_path": "a.py", "snippet": "sink()"}]')

            import complete_scan
            backup_path = complete_scan._workspace_backup_path(repo_dir, cm_home)
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            with open(backup_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "repo_dir": os.path.realpath(repo_dir),
                        "existed": True,
                        "content": "vendor/\nnode_modules/\n",
                    },
                    fh,
                )

            mock_cm = MockCodeMender(repo_dir=os.path.realpath(repo_dir))
            with (
                patch.dict(os.environ, {"CM_HOME": cm_home}),
                patch.object(cm_ci, "CodeMender", return_value=mock_cm),
            ):
                cm_ci.Ctx(repo_dir)

            with open(cmignore_path, "r", encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "vendor/\nnode_modules/\n")
            self.assertFalse(os.path.exists(report_path))
            self.assertFalse(os.path.exists(backup_path))

    def test_repo_inference_from_config_yaml_target_and_cwd(self) -> None:
        restore_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                outside_dir = os.path.join(tmpdir, "outside")
                non_git_repo = os.path.join(tmpdir, "hg_repo")
                non_git_sub = os.path.join(non_git_repo, "pkg")
                second_repo = os.path.join(tmpdir, "second_repo")
                git_repo = os.path.join(tmpdir, "git_repo")
                git_sub = os.path.join(git_repo, "src")
                cm_home = os.path.join(tmpdir, "cm_home")
                for d in (outside_dir, non_git_sub, second_repo, git_sub, cm_home):
                    os.makedirs(d, exist_ok=True)
                with open(os.path.join(git_sub, "app.py"), "w", encoding="utf-8") as fh:
                    fh.write("x = 1\n")

                subprocess.run(["git", "init", "-q", git_repo], check=True)

                cfg_path = os.path.join(cm_home, "config.yaml")

                # 1) Single `project_paths` entry (block YAML) inferred when running from outside any repo
                with open(cfg_path, "w", encoding="utf-8") as fh:
                    fh.write(f'project_paths:\n  # main project\n  - "{non_git_repo}"\nreset: "true"\n')

                os.chdir(outside_dir)
                mock_cm = MockCodeMender(repo_dir=os.path.realpath(non_git_repo))
                with (
                    patch.dict(os.environ, {"CM_HOME": cm_home}),
                    patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                ):
                    ctx_single = cm_ci.Ctx(None)
                self.assertEqual(ctx_single.repo, os.path.realpath(non_git_repo))
                self.assertTrue(cm_ci.cfg_checks(ctx_single)["project_paths"])

                # 2) Multiple `project_paths` entries (flow YAML):
                #    - fails cleanly when outside all of them with no target
                #    - succeeds when cwd is inside a configured non-git project_path
                #    - succeeds when `cmd_find` passes a positional target inside a repo from outside or subdir
                with open(cfg_path, "w", encoding="utf-8") as fh:
                    fh.write(f'project_paths: ["{non_git_repo}", \'{second_repo}\']\n')

                os.chdir(outside_dir)
                with (
                    patch.dict(os.environ, {"CM_HOME": cm_home}),
                    patch("sys.stderr", new_callable=io.StringIO) as err_buf,
                ):
                    with self.assertRaises(SystemExit) as ambig_err:
                        cm_ci.Ctx(None)
                self.assertEqual(ambig_err.exception.code, 1)
                self.assertIn("multiple project_paths", err_buf.getvalue())

                os.chdir(non_git_sub)
                with (
                    patch.dict(os.environ, {"CM_HOME": cm_home}),
                    patch.object(cm_ci, "CodeMender", return_value=mock_cm),
                ):
                    ctx_enclosing = cm_ci.Ctx(None)
                self.assertEqual(ctx_enclosing.repo, os.path.realpath(non_git_repo))

                # 3) Positional target from outside (`../git_repo/src`) and from subdirectory (`app.py` inside `src/`)
                mock_git_cm = MockCodeMender(repo_dir=os.path.realpath(git_repo))
                captured_targets: list[Any] = []
                with (
                    patch.dict(os.environ, {"CM_HOME": cm_home}),
                    patch.object(cm_ci, "need"),
                    patch.object(cm_ci, "check_config", return_value=True),
                    patch.object(cm_ci, "CodeMender", return_value=mock_git_cm),
                    patch.object(
                        cm_ci,
                        "run_complete_scan",
                        side_effect=lambda _cm, **kw: captured_targets.append(kw.get("target_or_id")),
                    ),
                    patch("sys.stdout", new_callable=io.StringIO),
                    patch("sys.stderr", new_callable=io.StringIO),
                ):
                    os.chdir(outside_dir)
                    rc1 = cm_ci.cmd_find(["../git_repo/src", "--complete"])
                    self.assertEqual(rc1, 0)
                    self.assertEqual(os.getcwd(), os.path.realpath(git_repo))

                    os.chdir(git_sub)
                    rc2 = cm_ci.cmd_find(["app.py", "--complete"])
                    self.assertEqual(rc2, 0)
                    self.assertEqual(os.getcwd(), os.path.realpath(git_repo))

                self.assertEqual(captured_targets, ["src", os.path.join("src", "app.py")])

                # 4) `check-config --yes` cleanly merges missing keys into an existing partial `config.yaml` via PyYAML
                with open(cfg_path, "w", encoding="utf-8") as fh:
                    fh.write(
                        f'project_paths:\n  - "{non_git_repo}"\n'
                        'vcs:\n  type: git\n'
                        'scan:\n  exclude_dirs:\n    - "custom_vendor"\n'
                    )
                with (
                    patch.dict(os.environ, {"CM_HOME": cm_home}),
                    patch.object(cm_ci, "CodeMender", return_value=mock_git_cm),
                    patch("sys.stdout", new_callable=io.StringIO),
                ):
                    rc_cfg = cm_ci.cmd_check_config(["--repo", git_repo, "--yes"])
                self.assertEqual(rc_cfg, 0)
                import yaml
                with open(cfg_path, encoding="utf-8") as fh:
                    merged_cfg = yaml.safe_load(fh)
                real_merged_paths = [os.path.realpath(p) for p in merged_cfg["project_paths"]]
                self.assertIn(os.path.realpath(non_git_repo), real_merged_paths)
                self.assertIn(os.path.realpath(git_repo), real_merged_paths)
                self.assertEqual(merged_cfg["vcs"]["commands"]["reset"], "true")
                self.assertIn("custom_vendor", merged_cfg["scan"]["exclude_dirs"])
                self.assertIn("venv", merged_cfg["scan"]["exclude_dirs"])
        finally:
            os.chdir(restore_dir)


if __name__ == "__main__":
    unittest.main()
