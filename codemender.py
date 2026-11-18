"""CodeMender CLI wrapper class and helpers."""

import contextlib
import enum
import json
import logging
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from finding import Finding

logger = logging.getLogger("codemender")

_CI_GATE_BLOCKING = re.compile(r"CI Gate Failure:\s*\d+ blocking finding")
_CI_GATE_TRUNCATED = re.compile(r"CI Gate Failure:\s*Impact expansion truncated")
_ADC_REAUTH_ERROR = re.compile(
    r"invalid_grant|invalid_rapt|reauth related error|could not find default credentials",
    re.IGNORECASE,
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


def _has_flag(flags: Iterable[str], *names: str) -> bool:
  """Returns True if any flag in `flags` matches `name` or `name=...`."""
  for flag in flags:
    for name in names:
      if flag == name or flag.startswith(f"{name}="):
        return True
  return False


def _extract_context_flags(
    extra_flags: Optional[List[str]],
) -> Tuple[List[str], List[str]]:
  """Splits `-c`/`--context` flags out of `extra_flags` so `cm find` receives a single `--context`."""
  if not extra_flags:
    return [], []
  remaining: List[str] = []
  contexts: List[str] = []
  idx = 0
  while idx < len(extra_flags):
    arg = extra_flags[idx]
    if arg in ("-c", "--context"):
      if idx + 1 < len(extra_flags):
        contexts.append(extra_flags[idx + 1])
        idx += 2
        continue
      idx += 1
      continue
    if arg.startswith("--context=") or arg.startswith("-c="):
      contexts.append(arg.split("=", 1)[1])
      idx += 1
      continue
    remaining.append(arg)
    idx += 1
  return remaining, [c.strip() for c in contexts if c and c.strip()]


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


def _raise_signal_exit(signum: int, _frame: Any) -> None:
  raise SystemExit(128 + signum)


@contextlib.contextmanager
def handle_termination_signals() -> Iterator[None]:
  """Converts SIGTERM/SIGHUP into SystemExit so `finally:` cleanup blocks execute."""
  if threading.current_thread() is not threading.main_thread():
    yield
    return
  handled = [signal.SIGTERM]
  if hasattr(signal, "SIGHUP"):
    handled.append(signal.SIGHUP)
  previous: Dict[int, Any] = {}
  try:
    for sig in handled:
      prev = signal.getsignal(sig)
      if prev != signal.SIG_IGN:
        previous[sig] = prev
        signal.signal(sig, _raise_signal_exit)
    yield
  finally:
    for sig, prev in previous.items():
      try:
        signal.signal(sig, prev)
      except (OSError, ValueError):
        pass


def run_command(
    cmd: List[str],
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    check: bool = True,
    print_to_stdout: bool = False,
    interactive: bool = False,
) -> subprocess.CompletedProcess:
  """Executes a subprocess command, streaming stdout/stderr in real-time."""
  logger.info("Executing comand: %s", " ".join(cmd))

  process = subprocess.Popen(
      cmd,
      cwd=cwd,
      env=env,
      stdin=None if interactive else subprocess.DEVNULL,
      stdout=subprocess.PIPE,
      stderr=subprocess.STDOUT if print_to_stdout else subprocess.DEVNULL,
      text=True,
      bufsize=1,
  )

  stdout_lines = []
  try:
    with handle_termination_signals():
      assert process.stdout is not None
      for line in process.stdout:
        stdout_lines.append(line)
        if print_to_stdout:
          sys.stdout.write(line)
          sys.stdout.flush()
      return_code = process.wait()
  finally:
    if process.stdout is not None and not process.stdout.closed:
      process.stdout.close()
    if process.poll() is None:
      process.terminate()
      try:
        process.wait(timeout=3)
      except subprocess.TimeoutExpired:
        process.kill()
        process.wait()

  logger.info(f"Command completed with exit code {return_code}")

  if check and return_code != 0:
    logger.error("Command failed with code %d", return_code)
    raise subprocess.CalledProcessError(return_code, cmd, stdout_lines, "")

  return subprocess.CompletedProcess(cmd, return_code, "".join(stdout_lines), "")


def resolve_cm_home(env: Optional[Dict[str, str]] = None) -> str:
  """Returns the CodeMender state directory (`CM_HOME` or `~/.codemender`)."""
  return (
      (env or {}).get("CM_HOME")
      or os.environ.get("CM_HOME")
      or os.path.join(os.path.expanduser("~"), ".codemender")
  )


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
      cm_dir = resolve_cm_home(self.env)
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
      max_turns: int = 8,
      deep_workers: int = 16,
      model: str = "gemini-4-argon",
      context: Optional[str] = None,
  ) -> Any:
    """Runs the CodeMender find command on the target repository directory."""
    target = target_or_id if target_or_id is not None else self.repo_dir
    cleaned_extra, extra_contexts = _extract_context_flags(extra_flags)
    cmd_flags: List[str] = []
    if scan_mode == ScanMode.QUICK:
      if not _has_flag(cleaned_extra, "--quick"):
        cmd_flags.append("--quick")
    elif scan_mode == ScanMode.DEEP:
      if not _has_flag(cleaned_extra, "--deep"):
        cmd_flags.append("--deep")
      if not _has_flag(cleaned_extra, "--deep-workers"):
        cmd_flags.append(f"--deep-workers={deep_workers}")
    elif scan_mode == ScanMode.DIFF:
      if not _has_flag(cleaned_extra, "--diff"):
        cmd_flags.append("--diff")
    if not _has_flag(cleaned_extra, "--model"):
      cmd_flags.append(f"--model={model}")
    if cleaned_extra:
      cmd_flags.extend(cleaned_extra)
    if not _has_flag(cleaned_extra, "--bypass-warning"):
      cmd_flags.append("--bypass-warning")
    if scan_mode == ScanMode.DEEP and not _has_flag(cleaned_extra, "--deep-max-turns"):
      cmd_flags.extend(["--deep-max-turns", str(max_turns)])
    context_parts: List[str] = []
    if context and context.strip():
      context_parts.append(context.strip())
    context_parts.extend(extra_contexts)
    if context_parts:
      cmd_flags.extend(["--context", "\n\n".join(context_parts)])
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
      if sys.stdin is None or not sys.stdin.isatty():
        raise RuntimeError(
            f"cm find failed with exit code {returncode}: Google Cloud Application"
            " Default Credentials are missing or expired in a non-interactive"
            " session (configure ADC for CI or run"
            " 'gcloud auth application-default login' interactively)"
        )
      run_command(
          ["gcloud", "auth", "application-default", "login"],
          cwd=self.repo_dir,
          env=self.env,
          check=True,
          print_to_stdout=True,
          interactive=True,
      )
      result = run_command(command, cwd=self.repo_dir, env=self.env, check=False, print_to_stdout=True)
      returncode = getattr(result, "returncode", 0)
      stdout = getattr(result, "stdout", "")

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