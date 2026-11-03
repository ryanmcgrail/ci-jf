"""Unit tests for cm-ci.py."""

import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

_CM_CI_PATH = Path(__file__).resolve().parent.parent / "cm-ci.py"
_SPEC = importlib.util.spec_from_file_location("cm_ci", _CM_CI_PATH)
assert _SPEC is not None and _SPEC.loader is not None
cm_ci = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cm_ci)


class TestCmCi(unittest.TestCase):
    """Unit tests for cm-ci.py functions and CLI subcommands."""

    def setUp(self) -> None:
        self._orig_cwd = os.getcwd()

    def tearDown(self) -> None:
        os.chdir(self._orig_cwd)

    # ─── norm_rel_path ───────────────────────────────────────────────────────

    def test_norm_rel_path_empty_and_relative(self) -> None:
        self.assertEqual(cm_ci.norm_rel_path(""), "")
        self.assertEqual(cm_ci.norm_rel_path("   "), "")
        self.assertEqual(cm_ci.norm_rel_path("./src/Main.py"), "src/main.py")
        self.assertEqual(cm_ci.norm_rel_path("src\\utils\\Helper.py"), "src/utils/helper.py")

    def test_norm_rel_path_with_repo_root(self) -> None:
        self.assertEqual(
            cm_ci.norm_rel_path("/repo/root/./pkg/Server.go", repo_root="/repo/root/"),
            "pkg/server.go",
        )

    def test_norm_rel_path_strips_common_prefixes_and_markers(self) -> None:
        self.assertEqual(
            cm_ci.norm_rel_path("/tmp/run123/repo_checkout/lib/Auth.py"),
            "lib/auth.py",
        )
        self.assertEqual(
            cm_ci.norm_rel_path("/workspace/proj/internal/Handler.go"),
            "internal/handler.go",
        )
        self.assertEqual(
            cm_ci.norm_rel_path("/Users/alice/work/repo/custom/File.c"),
            "custom/file.c",
        )
        self.assertEqual(
            cm_ci.norm_rel_path("/opt/build/deep/nested/controllers/UserController.py"),
            "controllers/usercontroller.py",
        )

    # ─── code_lines ──────────────────────────────────────────────────────────

    def test_code_lines_filters_short_and_comment_lines_and_normalizes_whitespace(self) -> None:
        snippet = (
            "// comment line that is longer than twenty chars\n"
            "# python comment line longer than twenty chars\n"
            "/* block comment start longer than twenty chars */\n"
            "*继续 block comment continuation longer than twenty\n"
            "short = 1\n"
            "result   =   compute_dangerous_query(user_input)  \\n"
            "return   execute_sql_statement(result,   connection)"
        )
        self.assertEqual(
            cm_ci.code_lines(snippet),
            {
                "result = compute_dangerous_query(user_input)",
                "return execute_sql_statement(result, connection)",
            },
        )
        self.assertEqual(cm_ci.code_lines(""), set())

    # ─── is_duplicate ────────────────────────────────────────────────────────

    def test_is_duplicate_overlapping_lines_and_related_cwes(self) -> None:
        a = {
            "file_path": "src/buffer.c",
            "vuln_type": "CWE-125: Out-of-bounds Read",
            "start_line": 10,
            "end_line": 20,
        }
        b = {
            "file_path": "./src/BUFFER.c",
            "vuln_type": "CWE-129: Improper Validation of Array Index",
            "start_line": 18,
            "end_line": 25,
        }
        self.assertTrue(cm_ci.is_duplicate(a, b))

    def test_is_duplicate_subset_code_lines_when_lines_do_not_overlap(self) -> None:
        shared_line = "query = 'SELECT * FROM users WHERE name = ' + user_supplied_name"
        a = {
            "file_path": "src/db.py",
            "vuln_type": "CWE-89",
            "start_line": 10,
            "end_line": 12,
            "snippet": shared_line,
        }
        b = {
            "file_path": "src/db.py",
            "vuln_type": "CWE-89",
            "start_line": 50,
            "end_line": 55,
            "snippet": shared_line + "\ncursor.execute(query, params_tuple_extra)",
        }
        self.assertTrue(cm_ci.is_duplicate(a, b))

    def test_is_duplicate_false_cases(self) -> None:
        base = {
            "file_path": "src/db.py",
            "vuln_type": "CWE-89",
            "start_line": 10,
            "end_line": 15,
            "snippet": "cursor.execute('SELECT * FROM t WHERE id=' + user_id)",
        }
        diff_file = dict(base, file_path="src/other.py")
        diff_cwe = dict(base, vuln_type="CWE-79")
        non_overlapping = dict(
            base,
            start_line=100,
            end_line=105,
            snippet="completely_different_statement_with_long_length(arg1, arg2)",
        )
        missing_path = dict(base, file_path="")

        self.assertFalse(cm_ci.is_duplicate(base, diff_file))
        self.assertFalse(cm_ci.is_duplicate(base, diff_cwe))
        self.assertFalse(cm_ci.is_duplicate(base, non_overlapping))
        self.assertFalse(cm_ci.is_duplicate(base, missing_path))

    # ─── make_github_marker ──────────────────────────────────────────────────

    def test_make_github_marker_with_cwe_and_fallback(self) -> None:
        finding = {
            "file_path": "/repo/src/Auth.py",
            "vuln_type": "CWE-79: Cross-site Scripting",
            "start_line": 12,
            "end_line": 16,
            "snippet": "response.write(untrusted_user_input_string)",
        }
        marker = cm_ci.make_github_marker(finding, repo_root="/repo")
        self.assertTrue(marker.startswith("<!-- cm-dedup:v1:"))
        self.assertTrue(marker.endswith(" -->"))
        m = cm_ci.GITHUB_MARKER_RE.search(marker)
        self.assertIsNotNone(m)
        payload = json.loads(m.group(1))
        self.assertEqual(
            payload,
            {
                "file_path": "src/auth.py",
                "vuln_type": "CWE-79",
                "start_line": 12,
                "end_line": 16,
                "raw_lines": ["response.write(untrusted_user_input_string)"],
            },
        )

        no_cwe_marker = cm_ci.make_github_marker({"file_path": "a.py", "vuln_type": "CustomBug"})
        no_cwe_payload = json.loads(cm_ci.GITHUB_MARKER_RE.search(no_cwe_marker).group(1))
        self.assertEqual(no_cwe_payload["vuln_type"], "CustomBug")

    # ─── unpack_findings & load_findings ─────────────────────────────────────

    def test_unpack_findings_formats(self) -> None:
        self.assertEqual(cm_ci.unpack_findings(None), [])

        direct = [{"finding_id": "f-1", "file_path": "a.py"}, "ignored_non_dict"]
        self.assertEqual(cm_ci.unpack_findings(direct), [{"finding_id": "f-1", "file_path": "a.py"}])

        for wrapper_key in ("findings", "results", "items"):
            wrapped = {wrapper_key: [{"finding_id": "f-2", "file_path": "b.py"}]}
            self.assertEqual(
                cm_ci.unpack_findings(wrapped),
                [{"finding_id": "f-2", "file_path": "b.py"}],
            )

        marker = cm_ci.make_github_marker(
            {"file_path": "src/app.py", "vuln_type": "CWE-89", "start_line": 5, "end_line": 8}
        )
        gh_issues = [
            {"number": 42, "state": "open", "body": f"Issue details\n{marker}"},
            {"number": 43, "state": "open", "body": "Issue without marker"},
        ]
        unpacked_gh = cm_ci.unpack_findings(gh_issues)
        self.assertEqual(len(unpacked_gh), 1)
        self.assertEqual(unpacked_gh[0]["gh_issue_number"], 42)
        self.assertEqual(unpacked_gh[0]["state"], "open")
        self.assertEqual(unpacked_gh[0]["file_path"], "src/app.py")
        self.assertEqual(unpacked_gh[0]["vuln_type"], "CWE-89")

    def test_load_findings_reads_and_unpacks_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "findings.json")
            data = {"findings": [{"finding_id": "f-10", "file_path": "src/main.py"}]}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            loaded = cm_ci.load_findings(path)
            self.assertEqual(loaded, [{"finding_id": "f-10", "file_path": "src/main.py"}])

    # ─── status_of & dup_id ──────────────────────────────────────────────────

    def test_status_of(self) -> None:
        self.assertEqual(cm_ci.status_of({"status": "fixed"}), "FIXED")
        self.assertEqual(cm_ci.status_of({"state": "closed"}), "CLOSED")
        self.assertEqual(cm_ci.status_of({}), "OPEN")
        self.assertEqual(cm_ci.status_of({"status": ""}), "OPEN")

    def test_dup_id(self) -> None:
        self.assertEqual(
            cm_ci.dup_id({"finding_id": "cm-1", "gh_issue_number": 9, "file_path": "a.py"}),
            "cm-1",
        )
        self.assertEqual(cm_ci.dup_id({"gh_issue_number": 9, "file_path": "a.py"}), 9)
        self.assertEqual(cm_ci.dup_id({"file_path": "a.py"}), "a.py")
        self.assertIsNone(cm_ci.dup_id({}))

    # ─── select_findings ─────────────────────────────────────────────────────

    def test_select_findings_filters_sorts_deduplicates_and_caps(self) -> None:
        findings = [
            {
                "finding_id": "low-1",
                "status": "OPEN",
                "severity": "LOW",
                "file_path": "/repo/src/a.py",
                "vuln_type": "CWE-79",
                "snippet": "x = 1",
            },
            {
                "finding_id": "crit-1",
                "status": "OPEN",
                "severity": "CRITICAL",
                "file_path": "/repo/src/b.py",
                "vuln_type": "CWE-89",
                "snippet": "sql_call()",
            },
            {
                "finding_id": "crit-dup",
                "status": "VERIFIED",
                "severity": "CRITICAL",
                "file_path": "/repo/src/b.py",
                "vuln_id": "CWE-89",
                "snippet": "sql_call()",
            },
            {
                "finding_id": "high-1",
                "status": "REOPENED",
                "severity": "HIGH",
                "file_path": "/repo/src/c.py",
                "vuln_type": "CWE-22",
                "snippet": "open(p)",
            },
            {
                "finding_id": "skipped-venv",
                "status": "OPEN",
                "severity": "CRITICAL",
                "file_path": "/repo/venv/lib/site.py",
                "vuln_type": "CWE-89",
                "snippet": "venv_code()",
            },
            {
                "finding_id": "skipped-fixed",
                "status": "FIXED",
                "severity": "CRITICAL",
                "file_path": "/repo/src/d.py",
                "vuln_type": "CWE-89",
                "snippet": "fixed_code()",
            },
        ]
        selected, dups = cm_ci.select_findings(findings, "/repo", max_n=2)
        self.assertEqual(dups, 1)
        self.assertEqual([f["finding_id"] for f in selected], ["crit-1", "high-1"])
        self.assertEqual(selected[0]["_rel"], "src/b.py")
        self.assertEqual(selected[1]["_rel"], "src/c.py")

    # ─── remove_duplicates_in_db ─────────────────────────────────────────────

    def test_remove_duplicates_in_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = cm_ci.Ctx(tmpdir)
            ctx.db = os.path.join(tmpdir, "state.db")

            # Missing DB returns None
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
                {"finding_id": "dup-unreferenced", "duplicate_of": "orig-1"},
                {"finding_id": "dup-patched", "duplicate_of": "orig-2"},
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
                    ["--existing", existing_path, "--new", new_path, "--out", out_path, "--repo", tmpdir]
                )

            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                out = json.load(fh)
            self.assertEqual([f["finding_id"] for f in out["findings"]], ["cur-new"])
            self.assertEqual([f["finding_id"] for f in out["reopened"]], ["cur-reopened"])
            self.assertEqual(out["reopened"][0]["duplicate_of"], "orig-fixed")
            self.assertEqual([f["finding_id"] for f in out["suppressed_duplicates"]], ["cur-dup"])
            self.assertEqual(out["suppressed_duplicates"][0]["duplicate_of"], "orig-active")

    # ─── cmd_find ────────────────────────────────────────────────────────────

    def test_cmd_find_dedup_updates_known_and_respects_fail_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = os.path.join(tmpdir, ".codemender")
            before_report = [
                {
                    "finding_id": "cm-old",
                    "file_path": "src/buf.c",
                    "vuln_type": "CWE-125",
                    "start_line": 10,
                    "end_line": 20,
                    "status": "OPEN",
                }
            ]
            after_report = before_report + [
                {
                    "finding_id": "cm-dup",
                    "file_path": "src/buf.c",
                    "vuln_type": "CWE-129",
                    "start_line": 12,
                    "end_line": 18,
                    "severity": "HIGH",
                    "status": "OPEN",
                },
                {
                    "finding_id": "cm-new",
                    "file_path": "src/sql.py",
                    "vuln_type": "CWE-89",
                    "start_line": 40,
                    "end_line": 45,
                    "severity": "CRITICAL",
                    "title": "SQL Injection",
                    "status": "OPEN",
                },
            ]

            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci.Ctx, "report", side_effect=[before_report, after_report]),
                patch("subprocess.call", return_value=0) as mock_call,
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(
                    ["--repo", tmpdir, "--out-dir", out_dir, "--fail-on", "CRITICAL", "--deep"]
                )

            self.assertEqual(rc, 4)
            mock_call.assert_called_once_with(["cm", "find", "--deep"])

            with open(os.path.join(out_dir, "findings.json"), encoding="utf-8") as fh:
                this_run = json.load(fh)
            self.assertEqual([f["finding_id"] for f in this_run], ["cm-dup", "cm-new"])

            with open(os.path.join(out_dir, "new_findings.json"), encoding="utf-8") as fh:
                new_findings = json.load(fh)
            self.assertEqual([f["finding_id"] for f in new_findings["findings"]], ["cm-new"])
            self.assertEqual(
                [f["finding_id"] for f in new_findings["suppressed_duplicates"]], ["cm-dup"]
            )

            with open(os.path.join(out_dir, "known_findings.json"), encoding="utf-8") as fh:
                known = json.load(fh)
            self.assertEqual([f["finding_id"] for f in known], ["cm-new"])

    def test_cmd_find_propagates_nonzero_cm_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                patch.object(cm_ci, "need"),
                patch.object(cm_ci, "check_config", return_value=True),
                patch.object(cm_ci.Ctx, "report", return_value=[]),
                patch("subprocess.call", return_value=5),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_find(["--repo", tmpdir])
            self.assertEqual(rc, 5)

    # ─── cmd_fix ─────────────────────────────────────────────────────────────

    def test_cmd_fix_requires_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                patch.object(cm_ci, "need"),
                patch.object(
                    cm_ci,
                    "cfg_checks",
                    return_value={"project_paths": False, "reset": True, "exclude_dirs": True},
                ),
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

            initial_report = [
                {
                    "finding_id": "cm-1",
                    "file_path": os.path.join(tmpdir, "src/app.py"),
                    "severity": "HIGH",
                    "title": "SQLi",
                    "vuln_type": "CWE-89",
                    "snippet": "cursor.execute(q)",
                    "status": "OPEN",
                }
            ]
            post_fix_report = [dict(initial_report[0], status="FIXED")]

            def fake_sh(*cmd: str, check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
                if cmd[:2] == ("git", "diff") and "--cached" in cmd:
                    return subprocess.CompletedProcess(cmd, 1, "", "")
                if cmd[:3] == ("git", "diff", "--stat"):
                    return subprocess.CompletedProcess(cmd, 0, " 1 file changed, 1 insertion(+)\n", "")
                if cmd[:3] == ("git", "rev-parse", "--short"):
                    return subprocess.CompletedProcess(cmd, 0, "abc1234\n", "")
                if cmd[:3] == ("git", "rev-parse", "--git-dir"):
                    return subprocess.CompletedProcess(cmd, 0, ".git\n", "")
                if cmd[:2] == ("git", "ls-files"):
                    return subprocess.CompletedProcess(cmd, 1 if "--error-unmatch" in cmd else 0, "", "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with (
                patch.object(cm_ci, "need"),
                patch.object(
                    cm_ci,
                    "cfg_checks",
                    return_value={"project_paths": True, "reset": True, "exclude_dirs": True},
                ),
                patch.object(cm_ci.Ctx, "report", side_effect=[initial_report, post_fix_report]),
                patch.object(cm_ci, "sh", side_effect=fake_sh) as mock_sh,
                patch("subprocess.call", return_value=0) as mock_call,
                patch("sys.stdout", new_callable=io.StringIO),
            ):
                rc = cm_ci.cmd_fix(["--repo", tmpdir, "--known", known_path, "--model", "gemini-pro"])

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
            with (
                patch.object(cm_ci, "need"),
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

