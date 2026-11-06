"""CodeMender CLI wrapper class and helpers."""

import enum
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional

from finding import Finding

logger = logging.getLogger("codemender")

_CI_GATE_BLOCKING = re.compile(r"CI Gate Failure:\s*\d+ blocking finding")
_CI_GATE_TRUNCATED = re.compile(r"CI Gate Failure:\s*Impact expansion truncated")
_ADC_REAUTH_ERROR = re.compile(
    r"invalid_grant|invalid_rapt|reauth related error|could not find default credentials",
    re.IGNORECASE,
)
_FIND_CONTEXT = (
    'First, run `jq -r \'.[] | select(.file_path | endswith("<file>")) | .snippet\' {report_file}` '
    "(replacing <file> with the currently scanned file path) to get the "
    "snippets of all preexisting findings for that file; never inspect "
    "`start_line`, `end_line`, `title`, or `analysis`. Treat every line of code "
    "contained in any returned snippet (including any lines in the file "
    "between parts of a snippet separated by `...`) as already having a "
    "finding associated with it—determined solely by the snippet text, never "
    "by `start_line` or `end_line`—and completely skip checking or reporting "
    "vulnerabilities on those lines (never report a finding whose snippet or "
    "sink overlaps any line in a returned snippet, and report at most one "
    "finding per distinct code block/line range). Only check lines of code in "
    "the file that are not covered by any returned snippet; if all executable "
    "code in the file is covered by the returned snippets, stop immediately "
    "and report 0 vulnerabilities. Otherwise, thoroughly and exhaustively "
    "audit every remaining uncovered line in the target file itself (checking "
    "every uncovered function, route, middleware, handler, query, and "
    "statement) and report all distinct vulnerabilities on uncovered lines in "
    "a single pass rather than stopping after the first issue."
)


class ScanMode(str, enum.Enum):
  DEEP = "deep"
  DIFF = "diff"
  QUICK = "quick"


def is_ci_gate_exit(returncode: int, find_stdout: str) -> bool:
  """Whether cm find exited 1 only because CI gate found blocking findings."""
  text = find_stdout or ""
  return (
      returncode == 1
      and bool(_CI_GATE_BLOCKING.search(text))
      and not _CI_GATE_TRUNCATED.search(text)
  )


def is_adc_reauth_error(returncode: int, stdout: str, stderr: str = "") -> bool:
  """Whether a command failed because Google Cloud ADC credentials need login."""
  combined = f"{stdout or ''}\n{stderr or ''}"
  return returncode != 0 and bool(_ADC_REAUTH_ERROR.search(combined))


def build_cm_command(
    cm_binary: str,
    action: str,
    target_or_id: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
) -> List[str]:
  """Centralized command builder for CodeMender CLI invocations."""
  if action == "find" and not target_or_id:
    raise ValueError(f"Action '{action}' requires a valid target or finding ID.")

  if action == "find":
    cmd = [cm_binary, "find", target_or_id]
    if extra_flags:
      cmd.extend(extra_flags)
  elif action == "init":
    cmd = [cm_binary, "init"]
    if extra_flags:
      cmd.extend(extra_flags)
  else:
    cmd = [cm_binary, action]
    if extra_flags:
      cmd.extend(extra_flags)
  return cmd


def run_command(
    cmd: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = True,
    print_to_stdout: bool = False,
) -> subprocess.CompletedProcess:
  """Executes a subprocess command, streaming stdout/stderr in real-time."""
  logger.info("Executing comand: %s", " ".join(cmd))

  process = subprocess.Popen(
      cmd,
      cwd=cwd,
      env=env,
      stdin=subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT if print_to_stdout else subprocess.DEVNULL,
      text=True,
      bufsize=1,
  )

  stdout_lines = []
  for line in process.stdout:
    stdout_lines.append(line)
    if print_to_stdout:
      sys.stdout.write(line)
      sys.stdout.flush()
      if not sys.stdout.isatty():
        sys.stderr.write(line)
        sys.stderr.flush()
  process.stdout.close()

  return_code = process.wait()

  logger.info(f"Command completed with exit code {return_code}")

  if check and return_code != 0:
    logger.error("Command failed with code %d", return_code)
    raise subprocess.CalledProcessError(return_code, cmd, stdout_lines, "")

  return subprocess.CompletedProcess(cmd, return_code, "".join(stdout_lines), "")


def write_import_payload(findings: Iterable[Finding], dest_path: str) -> str:
  """Writes a simple-JSON import payload, keeping only recognized fields."""
  payload = []
  for f in findings:
    payload.append(f.to_cm_import_record())
  os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
  with open(dest_path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2)
  return dest_path


class CodeMender:
  """Encapsulates CodeMender CLI configuration and operations for a repository."""

  def __init__(
      self,
      cm_binary: str = "cm",
      repo_dir: str = ".",
      env: Optional[Dict[str, str]] = None,
  ) -> None:
    self.cm_binary = cm_binary
    self.repo_dir = repo_dir
    self.env = env
    self._db: Optional[sqlite3.Connection] = None

  @property
  def db(self) -> Optional[sqlite3.Connection]:
    """Returns a sqlite3 connection to CodeMender's state.db, or None if not found."""
    if self._db is None:
      cm_dir = (
          (self.env or {}).get("CM_HOME")
          or os.environ.get("CM_HOME")
          or os.path.join(os.path.expanduser("~"), ".codemender")
      )
      db_path = os.path.join(cm_dir, "state.db")
      if not os.path.exists(db_path):
        return None
      self._db = sqlite3.connect(db_path, timeout=10)
    return self._db

  def find(
      self,
      target_or_id: Optional[str] = None,
      scan_mode: ScanMode = ScanMode.DEEP,
  ) -> Any:
    """Runs the CodeMender find command on the target repository directory."""
    target = target_or_id if target_or_id is not None else self.repo_dir
    report_cmd = build_cm_command(
        self.cm_binary,
        "report",
        extra_flags=["--format", "json"],
    )
    report_res = run_command(
        report_cmd,
        cwd=self.repo_dir,
        env=self.env,
        check=False,
    )
    temp_dir = self.repo_dir if os.path.isdir(self.repo_dir) else None
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix="",
        dir=temp_dir,
        delete=False,
        encoding="utf-8",
    ) as tmp_file:
      tmp_file.write(getattr(report_res, "stdout", "") or "")
      report_file = tmp_file.name
      report_ref = os.path.basename(report_file) if temp_dir else report_file

    try:
      extra_flags: List[str] = []
      if scan_mode == ScanMode.QUICK:
        extra_flags.append("--quick")
      if scan_mode == ScanMode.DEEP:
        extra_flags.append("--deep")
      elif scan_mode == ScanMode.DIFF:
        extra_flags.append("--diff")
      extra_flags.extend([
          "--context",
          _FIND_CONTEXT.format(report_file=report_ref),
      ])
      command = build_cm_command(
          self.cm_binary,
          "find",
          target_or_id=target,
          extra_flags=extra_flags,
      )
      result = run_command(command, cwd=self.repo_dir, env=self.env, check=False, print_to_stdout=True)
      returncode = getattr(result, "returncode", 0)
      stdout = getattr(result, "stdout", "")
      stderr = getattr(result, "stderr", "")
      if is_adc_reauth_error(returncode, stdout or "", stderr or ""):
        run_command(
            ["gcloud", "auth", "application-default", "login"],
            cwd=self.repo_dir,
            env=self.env,
            check=True,
            print_to_stdout=True,
        )
        result = run_command(command, cwd=self.repo_dir, env=self.env, check=False, print_to_stdout=True)
        returncode = getattr(result, "returncode", 0)
        stdout = getattr(result, "stdout", "")
    finally:
      if os.path.exists(report_file):
        os.remove(report_file)

    if returncode and not is_ci_gate_exit(returncode, stdout or ""):
      raise RuntimeError(f"cm find failed with exit code {returncode}")
    return result

  def list_findings(
      self,
  ) -> List[Finding]:
    """Returns every finding currently in CodeMender state for this repo."""
    report_cmd = build_cm_command(
        self.cm_binary,
        "report",
        extra_flags=["--format", "json"],
    )
    res = run_command(
        report_cmd,
        cwd=self.repo_dir,
        env=self.env,
        check=False,
    )
    if res.returncode != 0:
      raise RuntimeError(
          f"'cm report --format json' exited {res.returncode}"
      )

    if (res.stdout or "").strip() == "null":
      return []

    json_findings = json.JSONDecoder().decode(res.stdout)

    return [Finding.from_dict(json_finding) for json_finding in json_findings]

  def import_findings(
      self,
      findings: Iterable[Finding],
  ) -> List[Finding]:
    """Imports findings, ignoring the duplicates. Returns the list of newly imported findings."""
    before_findings = self.list_findings()
    before_fingerprints = set([f.fingerprint for f in before_findings])
    findings_not_already_in_cm = [f for f in findings if f.fingerprint not in before_fingerprints]
    if len(findings_not_already_in_cm) == 0:
      return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
      import_file = tmp_file.name

    try:
      write_import_payload(findings_not_already_in_cm, import_file)
      import_cmd = build_cm_command(
          self.cm_binary,
          "report",
          extra_flags=["import", "-f", import_file, "-p", self.repo_dir],
      )
      import_res = run_command(import_cmd, cwd=self.repo_dir, env=self.env, check=False)
    finally:
      if os.path.exists(import_file):
        os.remove(import_file)

    if import_res.returncode != 0:
      raise RuntimeError(
          f"'cm report import' exited {import_res.returncode}"
      )

    return findings_not_already_in_cm

  def __del__(self) -> None:
    if getattr(self, "_db", None) is not None:
      self._db.close()
      self._db = None