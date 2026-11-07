"""In-memory mock of CodeMender for unit tests."""

from collections import deque
from collections.abc import Iterable
import sqlite3
import subprocess
from typing import Any

from codemender import ScanMode
from finding import Finding

_FINDING_COLUMNS = (
    "finding_id",
    "session_id",
    "repository",
    "scan_timestamp",
    "vuln_id",
    "vuln_type",
    "severity",
    "confidence",
    "confidence_level",
    "status",
    "dismiss_reason",
    "file_path",
    "start_line",
    "end_line",
    "title",
    "snippet",
    "analysis",
    "verified",
    "fingerprint",
    "source_stage",
    "updated_at",
    "muted",
    "mute_reason",
    "duplicate_of",
    "gh_issue_number",
    "github_marker",
)


class MockCodeMender:
    """In-memory mock of CodeMender that tracks findings in an sqlite3 database."""

    def __init__(
        self,
        cm_binary: str = "cm",
        repo_dir: str = ".",
        env: dict[str, str] | None = None,
        initial_findings: Iterable[Finding] = (),
    ) -> None:
        self.cm_binary = cm_binary
        self.repo_dir = repo_dir
        self.env = env
        self._db = sqlite3.connect(":memory:")
        self._init_db()
        self._insert_findings(initial_findings)
        self._scheduled_batches: deque[list[Finding]] = deque()
        self._scheduled_error: Exception | None = None
        self.find_calls: list[tuple[str | None, ScanMode]] = []
        self.list_findings_calls: int = 0

    def _init_db(self) -> None:
        self._db.execute(
            "CREATE TABLE findings ("
            "finding_id TEXT PRIMARY KEY, "
            "session_id TEXT, "
            "repository TEXT, "
            "scan_timestamp TEXT, "
            "vuln_id TEXT, "
            "vuln_type TEXT, "
            "severity TEXT, "
            "confidence INTEGER, "
            "confidence_level TEXT, "
            "status TEXT, "
            "dismiss_reason TEXT, "
            "file_path TEXT, "
            "start_line INTEGER, "
            "end_line INTEGER, "
            "title TEXT, "
            "snippet TEXT, "
            "analysis TEXT, "
            "verified INTEGER, "
            "fingerprint TEXT, "
            "source_stage TEXT, "
            "updated_at TEXT, "
            "muted INTEGER, "
            "mute_reason TEXT, "
            "duplicate_of TEXT, "
            "gh_issue_number INTEGER, "
            "github_marker TEXT)"
        )
        self._db.execute("CREATE TABLE patches (finding_id TEXT)")
        self._db.execute("CREATE TABLE artifacts (finding_id TEXT)")
        self._db.commit()

    def _insert_findings(self, findings: Iterable[Finding]) -> None:
        cols_sql = ", ".join(_FINDING_COLUMNS)
        placeholders = ", ".join("?" for _ in _FINDING_COLUMNS)
        rows = [
            tuple(f._get(col) for col in _FINDING_COLUMNS)
            for f in findings
        ]
        if rows:
            self._db.executemany(
                f"INSERT INTO findings ({cols_sql}) VALUES ({placeholders})",
                rows,
            )
            self._db.commit()

    def _query_findings(self) -> list[Finding]:
        cur = self._db.execute("SELECT * FROM findings ORDER BY rowid")
        col_names = [desc[0] for desc in cur.description]
        return [
            Finding.from_dict({col: val for col, val in zip(col_names, row) if val is not None})
            for row in cur.fetchall()
        ]

    @property
    def db(self) -> sqlite3.Connection:
        """Return the in-memory sqlite3 database connection."""
        return self._db

    def schedule_findings(self, findings: Iterable[Finding]) -> None:
        """Schedule findings to be discovered the next time find() is called."""
        self._scheduled_batches.append(list(findings))

    def schedule_find_error(self, error: Exception) -> None:
        """Schedule an exception to be raised the next time find() is called."""
        self._scheduled_error = error

    def mark_status(self, finding_id: str, status: str) -> None:
        """Update the status of a tracked finding by finding_id."""
        self._db.execute(
            "UPDATE findings SET status = ? WHERE finding_id = ?",
            (status, finding_id),
        )
        self._db.commit()

    def find(
        self,
        target_or_id: str | None = None,
        scan_mode: ScanMode = ScanMode.DEEP,
        extra_flags: list[str] | None = None,
        complete_runs: int = 5,
    ) -> Any:
        self.find_calls.append((target_or_id, scan_mode))
        if self._scheduled_error is not None:
            err = self._scheduled_error
            self._scheduled_error = None
            raise err
        if self._scheduled_batches:
            self._insert_findings(self._scheduled_batches.popleft())
        return subprocess.CompletedProcess([self.cm_binary, "find"], 0, "", "")

    def list_findings(self) -> list[Finding]:
        self.list_findings_calls += 1
        return self._query_findings()

    def import_findings(self, findings: Iterable[Finding]) -> list[Finding]:
        before_fingerprints = {f.fingerprint for f in self._query_findings()}
        newly_imported = [f for f in findings if f.fingerprint not in before_fingerprints]
        self._insert_findings(newly_imported)
        return newly_imported

    def __del__(self) -> None:
        if getattr(self, "_db", None) is not None:
            self._db.close()
            self._db = None
