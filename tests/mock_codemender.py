"""In-memory mock of CodeMender for unit tests."""

from collections import deque
from collections.abc import Iterable
import subprocess
from typing import Any

from codemender import ScanMode
from finding import Finding


class MockCodeMender:
    """In-memory mock of CodeMender that tracks findings and schedules future find() results."""

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
        self._findings: list[Finding] = list(initial_findings)
        self._scheduled_batches: deque[list[Finding]] = deque()
        self._scheduled_error: Exception | None = None
        self.find_calls: list[tuple[str | None, ScanMode]] = []
        self.list_findings_calls: int = 0

    def schedule_findings(self, findings: Iterable[Finding]) -> None:
        """Schedule findings to be discovered the next time find() is called."""
        self._scheduled_batches.append(list(findings))

    def schedule_find_error(self, error: Exception) -> None:
        """Schedule an exception to be raised the next time find() is called."""
        self._scheduled_error = error

    def mark_status(self, finding_id: str, status: str) -> None:
        """Update the status of a tracked finding by finding_id."""
        self._findings = [
            Finding(f.to_dict(), status=status) if f.finding_id == finding_id else f
            for f in self._findings
        ]

    def find(
        self,
        target_or_id: str | None = None,
        scan_mode: ScanMode = ScanMode.DEEP,
    ) -> Any:
        self.find_calls.append((target_or_id, scan_mode))
        if self._scheduled_error is not None:
            err = self._scheduled_error
            self._scheduled_error = None
            raise err
        if self._scheduled_batches:
            self._findings.extend(self._scheduled_batches.popleft())
        return subprocess.CompletedProcess([self.cm_binary, "find"], 0, "", "")

    def list_findings(self) -> list[Finding]:
        self.list_findings_calls += 1
        return list(self._findings)

    def import_findings(self, findings: Iterable[Finding]) -> list[Finding]:
        before_fingerprints = {f.fingerprint for f in self._findings}
        newly_imported = [f for f in findings if f.fingerprint not in before_fingerprints]
        self._findings.extend(newly_imported)
        return newly_imported

