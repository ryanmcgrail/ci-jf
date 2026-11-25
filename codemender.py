"""CodeMender CLI wrapper class and helpers."""

import contextlib
import dataclasses
import enum
import json
import logging
import os
import re
import shlex
import signal
import sqlite3
import subprocess
import sys
import threading
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple

from finding import Finding

logger = logging.getLogger("codemender")

_STDOUT_SESSION_ID_RE = re.compile(r"^\s*Session:\s+([A-Za-z0-9_-]{4,})\s*$", re.MULTILINE)
_LOG_FILENAME_SESSION_RE = re.compile(r"^\d{8}T\d{6}Z_(.+)\.log$")

# Standard-tier USD pricing per 1,000,000 tokens:
#   (uncached_input_usd, cached_input_usd, output_and_thinking_usd)
MODEL_PRICING_PER_1M: Dict[str, Tuple[float, float, float]] = {
    "gemini-4-hydrogen": (1.50, 0.075, 7.50),
    "gemini-4-neon": (3.00, 0.15, 15.00),
    "gemini-4-argon": (4.00, 0.20, 20.00),
    "gemini-4-carbon": (4.00, 0.20, 20.00),
    "gemini-3.8-flash": (0.50, 0.05, 3.00),
    "gemini-3.7-flash": (0.50, 0.05, 3.00),
    "gemini-3-flash": (0.50, 0.05, 3.00),
    "gemini-3.1-pro": (2.00, 0.20, 12.00),
    "gemini-2.5-pro": (1.25, 0.125, 10.00),
    "gemini-2.5-flash": (0.30, 0.03, 2.50),
}

_CI_GATE_BLOCKING = re.compile(r"CI Gate Failure:\s*\d+ blocking finding")
_CI_GATE_TRUNCATED = re.compile(r"CI Gate Failure:\s*Impact expansion truncated")
_DEEP_PARTIAL_BATCH_FAILURE = re.compile(
    r"deep scan incomplete:\s*\d+\s+of\s+\d+\s+(?:deep scan\s+)?batch\(es\)\s+failed"
    r"|\d+\s+of\s+\d+\s+deep scan batch\(es\)\s+failed\s*\(coverage is incomplete\)",
    re.IGNORECASE,
)
_DEEP_ALL_BATCHES_FAILED = re.compile(
    r"\ball\s+\d+\s+deep scan batch\(es\)\s+failed\b",
    re.IGNORECASE,
)
_SAFETY_BLOCK_ERROR = re.compile(
    r"blocked due to safety|prohibited_content",
    re.IGNORECASE,
)
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


def is_partial_deep_scan_failure(
    returncode: int,
    find_stdout: str,
    allow_all_batches_failed: bool = False,
) -> bool:
  """Whether cm find exited non-zero (1 or 2) because deep scan batch(es) failed in a retryable pass."""
  if returncode not in (1, 2):
    return False
  text = find_stdout or ""
  if _CI_GATE_TRUNCATED.search(text):
    return False
  if _DEEP_PARTIAL_BATCH_FAILURE.search(text):
    return True
  return bool(allow_all_batches_failed and _DEEP_ALL_BATCHES_FAILED.search(text))


def is_safety_block_failure(returncode: int, find_stdout: str) -> bool:
  """Whether cm find exited non-zero (1 or 2) because batches were blocked by a safety/prohibited_content filter."""
  if returncode not in (1, 2):
    return False
  text = find_stdout or ""
  return bool(_SAFETY_BLOCK_ERROR.search(text)) and not _CI_GATE_TRUNCATED.search(text)


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


def _extract_model_flag(
    extra_flags: Optional[List[str]],
    default_model: str = "gemini-4-hydrogen",
) -> Tuple[List[str], str]:
  """Splits `--model` flags out of `extra_flags` and returns `(remaining_flags, resolved_model)`."""
  if not extra_flags:
    return [], default_model
  remaining: List[str] = []
  resolved = default_model
  idx = 0
  while idx < len(extra_flags):
    arg = extra_flags[idx]
    if arg == "--model":
      if idx + 1 < len(extra_flags):
        resolved = extra_flags[idx + 1]
        idx += 2
        continue
      idx += 1
      continue
    if arg.startswith("--model="):
      resolved = arg.split("=", 1)[1]
      idx += 1
      continue
    remaining.append(arg)
    idx += 1
  return remaining, resolved


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
  logger.info("Executing command: %s", shlex.join(cmd))

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


def atomic_write_text(path: str, content: str) -> None:
  """Writes `content` atomically via a sibling `.tmp` file."""
  os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
  tmp_path = f"{path}.tmp"
  with open(tmp_path, "w", encoding="utf-8") as fh:
    fh.write(content)
  os.replace(tmp_path, path)


def resolve_subprocess_env(
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
  """Builds CodeMender's subprocess env, defaulting CM_STALL_DETECTION=on unless overridden."""
  resolved = dict(os.environ)
  if env is not None:
    resolved.update(env)
  if not str(resolved.get("CM_STALL_DETECTION") or "").strip():
    resolved["CM_STALL_DETECTION"] = "on"
  return resolved


def resolve_model_pricing(model: str) -> Optional[Tuple[float, float, float]]:
  """Returns `(uncached_in, cached_in, out_plus_thinking)` USD per 1M tokens for `model`."""
  norm = (model or "").strip().lower()
  if not norm:
    return None
  for prefix in sorted(MODEL_PRICING_PER_1M, key=len, reverse=True):
    if norm == prefix or norm.startswith((f"{prefix}-", f"{prefix}_", f"{prefix}.")):
      return MODEL_PRICING_PER_1M[prefix]
  return None


def estimate_token_cost_usd(
    model: str,
    input_tokens: int,
    cached_tokens: int,
    output_tokens: int,
    thought_tokens: int = 0,
) -> Optional[float]:
  """Estimates Standard-tier USD cost for a turn or session, or None if model pricing is unknown."""
  in_tok = max(0, int(input_tokens or 0))
  cached_tok = max(0, min(int(cached_tokens or 0), in_tok))
  uncached_tok = in_tok - cached_tok
  out_tok = max(0, int(output_tokens or 0)) + max(0, int(thought_tokens or 0))
  if in_tok == 0 and out_tok == 0:
    return 0.0
  rates = resolve_model_pricing(model)
  if rates is None:
    return None
  in_rate, cache_rate, out_rate = rates
  return (
      uncached_tok * in_rate + cached_tok * cache_rate + out_tok * out_rate
  ) / 1_000_000.0


def _format_tokens_short(n: int) -> str:
  if n >= 1_000_000:
    return f"{n / 1_000_000:.2f}M"
  if n >= 1_000:
    return f"{n / 1_000:.1f}k"
  return str(n)


def _format_duration_short(seconds: float) -> str:
  sec = max(0.0, float(seconds or 0.0))
  if 0.0 < sec < 10.0:
    return f"{sec:.1f}s"
  total_sec = int(round(sec))
  h, rem = divmod(total_sec, 3600)
  m, s = divmod(rem, 60)
  if h > 0:
    return f"{h}h {m:02d}m {s:02d}s"
  if m > 0:
    return f"{m}m {s:02d}s"
  return f"{s}s"


def _format_usd(cost: float) -> str:
  if cost <= 0.0:
    return "$0.00"
  if cost < 0.01:
    return f"~${cost:.4f}"
  return f"~${cost:.2f}"


@dataclasses.dataclass
class ScanStats:
  """Aggregated `cm stats --json --session` token, timing, and cost metrics for a scan."""

  session_ids: List[str]
  models: List[str]
  total_turns: int = 0
  tool_turns: int = 0
  input_tokens: int = 0
  cached_tokens: int = 0
  output_tokens: int = 0
  thought_tokens: int = 0
  total_tokens: int = 0
  duration_seconds: float = 0.0
  estimated_cost_usd: Optional[float] = None

  @property
  def uncached_input_tokens(self) -> int:
    return max(0, self.input_tokens - self.cached_tokens)

  @property
  def cache_hit_percent(self) -> float:
    return (self.cached_tokens / self.input_tokens * 100.0) if self.input_tokens > 0 else 0.0

  @property
  def llm_turns(self) -> int:
    return self.total_turns + self.tool_turns

  def format_summary(self) -> str:
    cost_part = (
        f"{_format_usd(self.estimated_cost_usd)} | "
        if self.estimated_cost_usd is not None
        else ""
    )
    models_part = f" | model: {', '.join(self.models)}" if self.models else ""
    return (
        f"cm-ci: scan cost — {cost_part}{_format_tokens_short(self.total_tokens)} tokens "
        f"({_format_tokens_short(self.uncached_input_tokens)} uncached in, "
        f"{_format_tokens_short(self.cached_tokens)} cached [{self.cache_hit_percent:.1f}%], "
        f"{_format_tokens_short(self.output_tokens)} out, "
        f"{_format_tokens_short(self.thought_tokens)} thinking) | "
        f"{self.llm_turns} turn(s) | "
        f"{_format_duration_short(self.duration_seconds)}{models_part}"
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
    self._stdout_session_ids: List[str] = []

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
      model: str = "gemini-4-hydrogen",
      context: Optional[str] = None,
      allow_partial_failure: bool = False,
      allow_all_batches_failed: bool = False,
      allow_safety_block_failure: bool = False,
      env_overrides: Optional[Dict[str, str]] = None,
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
    subproc_env = resolve_subprocess_env(self.env)
    if env_overrides:
      subproc_env.update(env_overrides)
    result = run_command(command, cwd=self.repo_dir, env=subproc_env, check=False, print_to_stdout=True)
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
          env=subproc_env,
          check=True,
          print_to_stdout=True,
          interactive=True,
      )
      result = run_command(command, cwd=self.repo_dir, env=subproc_env, check=False, print_to_stdout=True)
      returncode = getattr(result, "returncode", 0)
      stdout = getattr(result, "stdout", "")

    for sid_match in _STDOUT_SESSION_ID_RE.finditer(stdout or ""):
      sid_val = sid_match.group(1)
      if sid_val not in self._stdout_session_ids:
        self._stdout_session_ids.append(sid_val)

    if (
        returncode
        and not is_ci_gate_exit(returncode, stdout or "")
        and not (
            allow_partial_failure
            and is_partial_deep_scan_failure(
                returncode,
                stdout or "",
                allow_all_batches_failed=allow_all_batches_failed,
            )
        )
        and not (
            allow_safety_block_failure
            and is_safety_block_failure(returncode, stdout or "")
        )
    ):
      raise RuntimeError(f"cm find failed with exit code {returncode}")
    return result

  def _log_dir_session_ids(self) -> List[str]:
    logs_dir = os.path.join(resolve_cm_home(self.env), "logs")
    if not os.path.isdir(logs_dir):
      return []
    out: List[str] = []
    try:
      entries = sorted(os.listdir(logs_dir))
    except OSError:
      return []
    for fname in entries:
      m = _LOG_FILENAME_SESSION_RE.match(fname)
      if m and m.group(1) != "pending" and m.group(1) not in out:
        out.append(m.group(1))
    return out

  def snapshot_session_ids(self) -> Set[str]:
    """Captures all currently known CodeMender session IDs prior to starting a scan."""
    known: Set[str] = set(self._stdout_session_ids)
    known.update(self._log_dir_session_ids())
    con = self.db
    if con is not None:
      try:
        rows = con.execute("SELECT session_id FROM sessions").fetchall()
        known.update(str(r[0]) for r in rows if r and r[0])
      except sqlite3.Error:
        pass
    return known

  def new_scan_session_ids(
      self,
      before_session_ids: Optional[Iterable[str]] = None,
      find_stdout: Optional[str] = None,
  ) -> List[str]:
    """Returns root session IDs created during the scan (excluding preexisting and child sessions)."""
    before_set = {str(s) for s in (before_session_ids or ()) if s}
    ordered: List[str] = []
    new_db_all: Set[str] = set()

    con = self.db
    if con is not None:
      try:
        cols = {
            desc[1] for desc in con.execute("PRAGMA table_info(sessions)").fetchall()
        }
        if "session_id" in cols:
          has_parent = "parent_session_id" in cols
          has_type = "session_type" in cols
          select_parent = "parent_session_id" if has_parent else "''"
          where_type = " WHERE session_type = 'FIND'" if has_type else ""
          rows = con.execute(
              f"SELECT session_id, {select_parent} FROM sessions{where_type} ORDER BY rowid ASC"
          ).fetchall()
          new_rows = [
              (str(r[0]), str(r[1] or ""))
              for r in rows
              if r and r[0] and str(r[0]) not in before_set
          ]
          new_db_all = {sid for sid, _ in new_rows}
          for sid, parent_id in new_rows:
            if (not parent_id or parent_id not in new_db_all) and sid not in ordered:
              ordered.append(sid)
      except sqlite3.Error:
        pass

    for sid in self._log_dir_session_ids():
      if sid not in before_set and sid not in new_db_all and sid not in ordered:
        ordered.append(sid)

    stdout_candidates = list(self._stdout_session_ids)
    if find_stdout:
      for m in _STDOUT_SESSION_ID_RE.finditer(find_stdout):
        stdout_candidates.append(m.group(1))
    for sid in stdout_candidates:
      if sid not in before_set and sid not in new_db_all and sid not in ordered:
        ordered.append(sid)

    return ordered

  def get_session_stats(self, session_id: str) -> Optional[Dict[str, Any]]:
    """Queries `cm stats --json --session <session_id>` and returns the parsed JSON dict."""
    sid = (session_id or "").strip()
    if not sid:
      return None
    stats_cmd = build_cm_command(
        self.cm_binary,
        "stats",
        extra_flags=["--json", "--session", sid],
    )
    res = run_command(
        stats_cmd,
        cwd=self.repo_dir,
        env=resolve_subprocess_env(self.env),
        check=False,
    )
    if getattr(res, "returncode", 1) != 0:
      return None
    raw = (getattr(res, "stdout", "") or "").strip()
    if not raw or raw == "null":
      return None
    try:
      parsed, _ = json.JSONDecoder().raw_decode(raw)
    except json.JSONDecodeError:
      return None
    return parsed if isinstance(parsed, dict) else None

  def get_scan_stats(
      self,
      session_ids: Optional[Iterable[str]] = None,
      *,
      before_session_ids: Optional[Iterable[str]] = None,
      find_stdout: Optional[str] = None,
  ) -> Optional[ScanStats]:
    """Aggregates `cm stats --json --session` metrics across all sessions of a scan."""
    target_sids = (
        [str(s).strip() for s in session_ids if s and str(s).strip()]
        if session_ids is not None
        else self.new_scan_session_ids(
            before_session_ids=before_session_ids,
            find_stdout=find_stdout,
        )
    )
    if not target_sids:
      return None

    included_sessions: List[str] = []
    seen_session_ids: Set[str] = set()
    seen_turn_ids: Set[str] = set()
    models: List[str] = []
    total_turns = 0
    tool_turns = 0
    input_tokens = 0
    cached_tokens = 0
    output_tokens = 0
    thought_tokens = 0
    total_tokens = 0
    duration_seconds = 0.0
    cost_sum = 0.0
    has_unpriced_tokens = False

    def _record_model(m: Any) -> str:
      m_str = str(m or "").strip()
      if m_str and m_str not in models:
        models.append(m_str)
      return m_str

    for sid in target_sids:
      payload = self.get_session_stats(sid)
      if not payload:
        continue
      resp_sid = str(payload.get("session_id") or sid)
      session_model = str(payload.get("model") or "").strip()
      raw_turns = payload.get("turns")

      if isinstance(raw_turns, list) and raw_turns:
        new_turns: List[Dict[str, Any]] = []
        for t in raw_turns:
          if not isinstance(t, dict):
            continue
          tid = str(t.get("interaction_id") or t.get("turn") or "").strip()
          if tid:
            if tid in seen_turn_ids:
              continue
            seen_turn_ids.add(tid)
          new_turns.append(t)
        if not new_turns:
          continue
        if resp_sid not in seen_session_ids:
          seen_session_ids.add(resp_sid)
          included_sessions.append(resp_sid)
        for t in new_turns:
          t_model = _record_model(t.get("model") or session_model)
          t_in = int(t.get("input_tokens") or 0)
          t_ca = int(t.get("cached_tokens") or 0)
          t_out = int(t.get("output_tokens") or 0)
          t_th = int(t.get("thought_tokens") or 0)
          t_tot = int(t.get("total_tokens") or (t_in + t_out + t_th))
          input_tokens += t_in
          cached_tokens += t_ca
          output_tokens += t_out
          thought_tokens += t_th
          total_tokens += t_tot
          t_cost = estimate_token_cost_usd(t_model, t_in, t_ca, t_out, t_th)
          if t_cost is None:
            has_unpriced_tokens = True
          else:
            cost_sum += t_cost

        if len(new_turns) == len(raw_turns):
          total_turns += int(payload.get("total_turns") or len(new_turns))
          tool_turns += int(payload.get("tool_turns") or 0)
          duration_seconds += float(payload.get("duration_seconds") or 0.0)
        else:
          total_turns += len(new_turns)
          duration_seconds += max(
              (float(t.get("duration_seconds") or 0.0) for t in new_turns),
              default=0.0,
          )
      else:
        if resp_sid in seen_session_ids:
          continue
        seen_session_ids.add(resp_sid)
        included_sessions.append(resp_sid)
        s_model = _record_model(session_model)
        s_in = int(payload.get("input_tokens") or 0)
        s_ca = int(payload.get("cached_tokens") or 0)
        s_out = int(payload.get("output_tokens") or 0)
        s_th = int(payload.get("thought_tokens") or 0)
        s_tot = int(payload.get("total_tokens") or (s_in + s_out + s_th))
        input_tokens += s_in
        cached_tokens += s_ca
        output_tokens += s_out
        thought_tokens += s_th
        total_tokens += s_tot
        total_turns += int(payload.get("total_turns") or 0)
        tool_turns += int(payload.get("tool_turns") or 0)
        duration_seconds += float(payload.get("duration_seconds") or 0.0)
        s_cost = estimate_token_cost_usd(s_model, s_in, s_ca, s_out, s_th)
        if s_cost is None:
          has_unpriced_tokens = True
        else:
          cost_sum += s_cost

    if not included_sessions:
      return None

    return ScanStats(
        session_ids=included_sessions,
        models=models,
        total_turns=total_turns,
        tool_turns=tool_turns,
        input_tokens=input_tokens,
        cached_tokens=cached_tokens,
        output_tokens=output_tokens,
        thought_tokens=thought_tokens,
        total_tokens=total_tokens,
        duration_seconds=duration_seconds,
        estimated_cost_usd=None if has_unpriced_tokens else cost_sum,
    )

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
        env=resolve_subprocess_env(self.env),
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