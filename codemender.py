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
from typing import Any, Dict, List, Optional

from finding import Finding

logger = logging.getLogger("codemender")

_CI_GATE_BLOCKING = re.compile(r"CI Gate Failure:\s*\d+ blocking finding")
_CI_GATE_TRUNCATED = re.compile(r"CI Gate Failure:\s*Impact expansion truncated")
_ADC_REAUTH_ERROR = re.compile(
    r"invalid_grant|invalid_rapt|reauth related error|could not find default credentials",
    re.IGNORECASE,
)
_DISCOURAGED_CWES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "discouraged_cwes.txt",
)
_ACTIVE_REPORT_STATUSES = frozenset({"OPEN", "VERIFIED", "REOPENED"})
_FIND_CONTEXT_FOR_FIRST_PASS = """\
# File Audit & Cross-File Lookup Strategy
- Audit every uncovered line in the target file itself from top to bottom (cataloguing every uncovered function, route, middleware, handler, secret, cryptographic call, regex, query, and statement) to collect all candidate vulnerabilities across the entire file before making any cross-file tool calls.
- Report at most one finding per distinct code block/line range, and report all distinct vulnerabilities on uncovered lines in a single pass rather than stopping after the first issue.
- Spend at most 2–3 tool turns total on cross-file `grep_search` or `read_file` lookups only when strictly necessary to confirm an external sink or middleware.

# CWE Selection & Validation
- Always assign exactly one CWE ID (`CWE-<number>`) to each finding; it is invalid to omit a CWE ID or to assign multiple CWE IDs to a single finding.
- Select a specific, allowed CWE ID and never report any CWE ID from the following discouraged/prohibited CWE list: {discouraged_cwes}

# Tool & File Restrictions
- Never run git, diff, node, npm, ts-node, tsx, python, or rg commands via `run_command`.
- Never read or search test files, package manifests, dependency directories, challenge metadata (.info.yml, challenges.yml), or .codemender files."""
_FIND_CONTEXT_FOR_LATER_PASSES = f"""\
# Initial Pre-Audit Check
- First, run `grep -Fxq "<file>" {{clean_files_file}} && echo "ALREADY_AUDITED" || jq -r '.[] | select(.file_path | endswith("<file>")) | .snippet' {{report_file}}` (replacing <file> with the currently scanned repo-relative file path) to check if the file was already completely audited or to get the snippets of all preexisting findings for that file.
- Never query {{clean_files_file}} or {{report_file}} for any other file, and use `run_command` only for this single initial check.
- If the command outputs ALREADY_AUDITED, stop immediately and report 0 vulnerabilities.

# Preexisting Snippet & Line Coverage Rules
- Treat every line of code contained in any returned snippet (including any lines in the file between parts of a snippet separated by `...`) as already having a finding associated with it—determined solely by the snippet text, never by `start_line` or `end_line`—and completely skip checking or reporting vulnerabilities on those lines.
- Never report a finding whose snippet or sink overlaps any line in a returned snippet.
- Only check lines of code in the file that are not covered by any returned snippet; if all executable code in the file is covered by the returned snippets, or if the remaining uncovered lines in the file are benign, stop immediately and report 0 vulnerabilities.

{_FIND_CONTEXT_FOR_FIRST_PASS}"""


def _load_discouraged_cwes() -> str:
  """Loads the discouraged CWE IDs from discouraged_cwes.txt as a comma-separated string."""
  if not os.path.exists(_DISCOURAGED_CWES_PATH):
    return ""
  with open(_DISCOURAGED_CWES_PATH, "r", encoding="utf-8") as cwe_f:
    return ", ".join(cwe_f.read().split())


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


def preprocess_report_for_context(raw_report: str) -> str:
  """Filters a raw `cm report --format json` output to OPEN/VERIFIED/REOPENED findings with only file_path and snippet."""
  text = (raw_report or "").strip()
  if not text or text == "null":
    return "[]"
  try:
    items, _ = json.JSONDecoder().raw_decode(text)
  except json.JSONDecodeError:
    return "[]"
  if not isinstance(items, list):
    return "[]"
  filtered = []
  for item in items:
    if not isinstance(item, dict):
      continue
    finding = Finding.from_dict(item)
    if finding.status in _ACTIVE_REPORT_STATUSES:
      filtered.append({
          "file_path": finding.file_path,
          "snippet": finding.snippet,
      })
  return json.dumps(filtered, indent=2)


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
      extra_flags: Optional[List[str]] = None,
      clean_files_file: Optional[str] = None,
      max_turns: int = 8,
      active_files: Optional[List[str]] = None,
      deep_workers: int = 16,
      model: str = "gemini-4-argon",
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
    preprocessed_report = preprocess_report_for_context(
        getattr(report_res, "stdout", "") or ""
    )
    discouraged_cwes = _load_discouraged_cwes()
    has_prior_state = (preprocessed_report != "[]") or (clean_files_file is not None)
    temp_dir = self.repo_dir if os.path.isdir(self.repo_dir) else None
    report_file: Optional[str] = None
    own_clean_files_file = False

    if has_prior_state:
      with tempfile.NamedTemporaryFile(
          mode="w",
          suffix="",
          dir=temp_dir,
          delete=False,
          encoding="utf-8",
      ) as tmp_file:
        tmp_file.write(preprocessed_report)
        report_file = tmp_file.name
        report_ref = os.path.basename(report_file) if temp_dir else report_file

      own_clean_files_file = clean_files_file is None
      if own_clean_files_file:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix="",
            dir=temp_dir,
            delete=False,
            encoding="utf-8",
        ) as clean_tmp_file:
          clean_tmp_file.write("")
          clean_files_file = clean_tmp_file.name
      clean_files_ref = (
          os.path.basename(clean_files_file)
          if temp_dir
          else clean_files_file
      )

    try:
      cmd_flags: List[str] = []
      if scan_mode == ScanMode.QUICK:
        cmd_flags.append("--quick")
      if scan_mode == ScanMode.DEEP:
        cmd_flags.append("--deep")
        cmd_flags.append(f"--deep-workers={deep_workers}")
      elif scan_mode == ScanMode.DIFF:
        cmd_flags.append("--diff")
      if not any(
          f == "--model" or f.startswith("--model=")
          for f in (extra_flags or [])
      ):
        cmd_flags.append(f"--model={model}")
      if extra_flags:
        cmd_flags.extend(extra_flags)
      if has_prior_state:
        context_str = _FIND_CONTEXT_FOR_LATER_PASSES.format(
            report_file=report_ref,
            clean_files_file=clean_files_ref,
            discouraged_cwes=discouraged_cwes,
        )
        cmd_flags.append("--enable-bash")
      else:
        context_str = _FIND_CONTEXT_FOR_FIRST_PASS.format(
            discouraged_cwes=discouraged_cwes,
        )
      if active_files:
        scoped_targets = ", ".join(f"`{f}`" for f in active_files)
        context_str = (
            f"{context_str} Only audit these remaining files: {scoped_targets}."
        )
      cmd_flags.extend([
          "--bypass-warning",
          "--deep-max-turns",
          str(max_turns),
          "--context",
          context_str,
      ])
      command = build_cm_command(
          self.cm_binary,
          "find",
          target_or_id=target,
          extra_flags=cmd_flags,
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
      cleanup_paths = []
      if report_file is not None:
        cleanup_paths.append(report_file)
      if own_clean_files_file and clean_files_file is not None:
        cleanup_paths.append(clean_files_file)
      for tmp_path in cleanup_paths:
        if os.path.exists(tmp_path):
          os.remove(tmp_path)

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

  def __del__(self) -> None:
    if getattr(self, "_db", None) is not None:
      self._db.close()
      self._db = None