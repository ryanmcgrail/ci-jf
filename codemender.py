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
_DISCOURAGED_CWES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "discouraged_cwes.txt",
)
_COVERED_LINES_SCRIPT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "covered_lines.py",
)
_ACTIVE_REPORT_STATUSES = frozenset({"OPEN", "VERIFIED", "REOPENED"})
_CRITICAL_HIGH_AUDIT_BULLET = (
    "- Audit the entire target file top to bottom and report all distinct"
    " vulnerabilities in a single pass (at most one finding per code block/line"
    " range), focusing on the most critical security issues (CRITICAL and HIGH"
    " severity)."
)
_DEFAULT_AUDIT_BULLET = (
    "- Audit the entire target file top to bottom and report all distinct"
    " vulnerabilities in a single pass (at most one finding per code block/line"
    " range)."
)
_FIND_CONTEXT_FOR_FIRST_PASS = """\
# Audit Strategy
- Audit the entire target file top to bottom and report all distinct vulnerabilities in a single pass (at most one finding per code block/line range).
- Report each distinct vulnerable route, endpoint, or function as its own separate finding rather than grouping multiple endpoints into a single finding; however:
  - When an endpoint or method calls a private/internal helper method within the same file, report the vulnerability once rather than reporting both the caller and its intra-file helper as separate findings.
  - When a controller or route method is a pure pass-through that delegates directly to a service class without adding its own security, auth, or sink logic, report the vulnerability in the service class where the sink/logic resides rather than duplicating it on the pass-through wrapper.
  - When multiple routes in the same file are gated by the exact same shared client-side boolean/state variable, report that shared client-side check once at its definition rather than repeating it for every route that references it (still report routes with distinct authorization flaws, such as missing admin role checks or exposed hidden routes, separately).
- Scope each finding's snippet and line range strictly to the minimal contiguous vulnerable sink lines, never the entire enclosing function or method; never use `...` to bridge non-contiguous lines in a snippet.
- Collect all candidate issues in the target file before making cross-file `grep_search` or `read_file` calls (at most 2-3 turns, and never read files inside `node_modules`); always inspect cross-file consumers when the target file generates/encodes tokens, state, or cookies before concluding 0 vulnerabilities.
- When a handler relies on a repository-local security/auth helper (e.g., `security.*`), always inspect that helper's definition before assuming it enforces authentication, role authorization, or ownership.
- Ignore test files, package manifests, dependency/vendor directories, vendored or minified third-party libraries (stop immediately and report 0 vulnerabilities if the target file is a vendored third-party library), and `.codemender` files.

# Vulnerabilities to Report
- **Secrets, Cryptography & Query/Token Helpers:** Always report hardcoded secrets, passwords, API keys, salts, or cryptographic keys, weak cryptographic/hashing/encoding primitives, and unescaped query/filter builders or insecure token/key processors directly in the target file where they are defined or implemented, rather than deferring the finding to a caller, controller, or consumer file.
- **Frontend (Components, Routers, Guards, Services):**
  - DOM XSS and unsafe rendering sinks (`innerHTML`, `outerHTML`, `document.write`, `bypassSecurityTrust*`, `dangerouslySetInnerHTML`, `v-html`, `eval`), open redirects, and unvalidated `postMessage` or URL handling.
  - Client-side-only authentication, authorization, or rate-limiting/CAPTCHA enforcement (relying on `localStorage`/`sessionStorage`, decoding JWTs without server verification, deriving or verifying credentials/OAuth passwords client-side, or mutating client auth state before server confirmation).
  - Privileged or account-management routes missing guards or guarded only by client-decodeable state, obfuscated/hidden route matchers (security through obscurity), and exposed debug, sandbox, or unreleased routes.
  - Transmitting passwords, tokens, or sensitive credentials in URL query parameters (such as HTTP `GET` requests) or exposing secrets in client-side source files or storage.
- **Backend (Routes, Controllers, Middleware, Models, File/Network Handlers):**
  - Injection (SQL, NoSQL, command, template, XXE, XPath), SSRF, unsafe deserialization, prototype pollution, ReDoS on untrusted input, and path traversal or static file serving with incomplete path sanitization (such as checking only `.includes('/')` or `..` without canonical path containment or null-byte filtering).
  - Missing or bypassable authentication/authorization on endpoints or file/log/key servers, IDOR, mass assignment, privilege escalation (trusting client-supplied user IDs, roles, prices, or wallet addresses without server-side session or cryptographic signature verification), and CSRF on state-changing endpoints.
  - Serialization of database/ORM records into JWTs, sessions, or responses without stripping all sensitive model fields (inspect the model schema for remaining fields like password hashes, TOTP secrets, or security answers even if another field was cleared), and cleartext database storage of authentication secrets or keys.
  - Unbounded resource allocation (such as spawning persistent WebSocket/network providers or event listeners per request without cleanup or rate limiting), overly permissive CORS/security headers, and sensitive error, stack trace, metrics, or directory disclosure.

# CWE Requirements
- Assign exactly one CWE ID (`CWE-<number>`) to each finding; omitting a CWE ID or assigning multiple is invalid.
- Never use any CWE ID from this discouraged/prohibited list: {discouraged_cwes}"""
_FIND_CONTEXT_FOR_LATER_PASSES = f"""\
# Initial Pre-Audit Check
- First, run `python3 {_COVERED_LINES_SCRIPT_PATH} {{report_file}} "<file>"` (replacing `<file>` with the target file's repo-relative path) to check which line ranges and snippets in this file have already been covered.
- Use `run_command` strictly for this single `covered_lines.py` check; never invoke `node`, `sh`, or any other shell command, and never query {{report_file}} for other files.
- Skip every preexisting vulnerability returned for this file (its covered line ranges and sink lines, as well as its enclosing declaration or caller lines) and never report it again; still audit the rest of the file for distinct vulnerabilities on uncovered lines, and if none remain, stop and report 0 vulnerabilities.

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


def _normalize_report_file_path(file_path: str, repo_dir: str = "") -> str:
  """Normalizes a finding file_path to a repo-relative path for exact jq matching."""
  path = (file_path or "").strip().replace("\\", "/")
  if not path:
    return ""
  roots = []
  if repo_dir:
    for candidate in (
        repo_dir,
        os.path.abspath(repo_dir),
        os.path.realpath(repo_dir),
    ):
      norm_root = candidate.strip().replace("\\", "/").rstrip("/")
      if norm_root and norm_root != "." and norm_root not in roots:
        roots.append(norm_root)
  for root in roots:
    prefix = root + "/"
    if path.startswith(prefix):
      return path[len(prefix) :].lstrip("./")
  return path.lstrip("./")


def preprocess_report_for_context(
    raw_report: str,
    repo_dir: str = "",
    exclude_finding_ids: Optional[Iterable[str]] = None,
) -> str:
  """Filters a raw `cm report --format json` output to OPEN/VERIFIED/REOPENED findings with repo-relative file_path and snippet."""
  text = (raw_report or "").strip()
  if not text or text == "null":
    return "[]"
  try:
    items, _ = json.JSONDecoder().raw_decode(text)
  except json.JSONDecodeError:
    return "[]"
  if not isinstance(items, list):
    return "[]"
  excluded = {str(fid) for fid in exclude_finding_ids if fid} if exclude_finding_ids else set()
  filtered = []
  for item in items:
    if not isinstance(item, dict):
      continue
    finding = Finding.from_dict(item)
    if excluded and str(finding.finding_id or "") in excluded:
      continue
    if finding.status in _ACTIVE_REPORT_STATUSES:
      filtered.append({
          "file_path": _normalize_report_file_path(finding.file_path, repo_dir),
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
      max_turns: int = 8,
      active_files: Optional[List[str]] = None,
      deep_workers: int = 16,
      model: str = "gemini-4-argon",
      critical_high_only: bool = False,
      exclude_finding_ids: Optional[Iterable[str]] = None,
      skip_prior_report: bool = False,
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
    if skip_prior_report:
      preprocessed_report = "[]"
    else:
      preprocessed_report = preprocess_report_for_context(
          getattr(report_res, "stdout", "") or "",
          repo_dir=self.repo_dir,
          exclude_finding_ids=exclude_finding_ids,
      )
    discouraged_cwes = _load_discouraged_cwes()
    has_prior_state = (preprocessed_report != "[]") or bool(active_files)
    temp_dir = self.repo_dir if os.path.isdir(self.repo_dir) else None
    report_file: Optional[str] = None

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
            discouraged_cwes=discouraged_cwes,
        )
        cmd_flags.append("--enable-bash")
      else:
        context_str = _FIND_CONTEXT_FOR_FIRST_PASS.format(
            discouraged_cwes=discouraged_cwes,
        )
      if critical_high_only:
        context_str = context_str.replace(
            _DEFAULT_AUDIT_BULLET,
            _CRITICAL_HIGH_AUDIT_BULLET,
            1,
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
      if report_file is not None and os.path.exists(report_file):
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

  def __del__(self) -> None:
    if getattr(self, "_db", None) is not None:
      self._db.close()
      self._db = None