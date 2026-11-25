"""Unit tests for state_db.py."""

import os
import tempfile
import unittest

import deduplication
from finding import Finding
from mock_codemender import MockCodeMender
import state_db


class TestStateDb(unittest.TestCase):
    """Unit tests for SQLite state.db consolidation, severity upgrades, and deduplication."""

    def test_remove_duplicates_in_db_and_severity_upgrades(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=[
                    Finding(finding_id="dup-unreferenced", status="OPEN"),
                    Finding(finding_id="dup-patched", status="OPEN"),
                    Finding(
                        finding_id="twin-dismissed",
                        status="DISMISSED",
                        dismiss_reason=state_db.CM_TWIN_REASONS[0],
                    ),
                    Finding(finding_id="keep-open", severity="MEDIUM", status="OPEN"),
                ],
            )
            mock_cm.db.execute("INSERT INTO patches VALUES (?)", ("dup-patched",))
            mock_cm.db.commit()

            dups = [
                Finding(finding_id="dup-unreferenced", duplicate_of="keep-open", severity="HIGH"),
                Finding(finding_id="dup-patched", duplicate_of="orig-2"),
            ]
            res = state_db.remove_duplicates_in_db(mock_cm, dups)
            self.assertEqual(res, (2, 1))

            findings = {f.finding_id: f for f in mock_cm.list_findings()}
            self.assertNotIn("dup-unreferenced", findings)
            self.assertNotIn("twin-dismissed", findings)
            self.assertEqual(findings["dup-patched"].status, "DISMISSED")
            self.assertEqual(findings["dup-patched"].dismiss_reason, "cm-ci: duplicate of orig-2")
            self.assertEqual(findings["keep-open"].status, "OPEN")
            self.assertEqual(findings["keep-open"].severity, "HIGH")

    def test_deduplicate_db_findings_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_cm = MockCodeMender(
                repo_dir=os.path.realpath(tmpdir),
                initial_findings=[
                    Finding(
                        finding_id="prior-crit",
                        file_path="src/app.py",
                        vuln_type="CWE-94",
                        start_line=10,
                        end_line=14,
                        severity="CRITICAL",
                        snippet="eval(user_supplied_expression_payload)",
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cur-1",
                        file_path="src/app.py",
                        vuln_type="CWE-94",
                        start_line=11,
                        end_line=13,
                        severity="MEDIUM",
                        snippet="eval(user_supplied_expression_payload)",
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cur-2",
                        file_path="src/sql.py",
                        vuln_type="CWE-89",
                        start_line=30,
                        end_line=34,
                        severity="MEDIUM",
                        snippet="cursor.execute('SELECT * FROM u WHERE id=' + uid)",
                        status="OPEN",
                    ),
                    Finding(
                        finding_id="cur-2-dup-high",
                        file_path="src/sql.py",
                        vuln_type="CWE-89",
                        start_line=31,
                        end_line=33,
                        severity="HIGH",
                        snippet="cursor.execute('SELECT * FROM u WHERE id=' + uid)",
                        status="OPEN",
                    ),
                ],
            )
            snap = state_db.snapshot_db_findings(mock_cm)
            self.assertIn("prior-crit", snap)

            state_db.deduplicate_db_findings(mock_cm, exclude_finding_ids={"prior-crit"})
            by_id = {f.finding_id: f for f in mock_cm.list_findings()}
            self.assertEqual(set(by_id.keys()), {"prior-crit", "cur-1", "cur-2"})
            self.assertEqual(by_id["cur-1"].severity, "CRITICAL")
            self.assertEqual(by_id["cur-2"].severity, "HIGH")

            # Also verify cross-run dedup + remove_duplicates_in_db preserves monotonic severity
            res = deduplication.dedup([by_id["prior-crit"]], [by_id["cur-1"]], "")
            state_db.remove_duplicates_in_db(mock_cm, res["suppressed_duplicates"])
            after = {f.finding_id: f.severity for f in mock_cm.list_findings()}
            self.assertEqual(after, {"prior-crit": "CRITICAL", "cur-2": "HIGH"})


if __name__ == "__main__":
    unittest.main()
