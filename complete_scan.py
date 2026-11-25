"""Multi-pass complete scan orchestration on top of CodeMender deep scans."""

import hashlib
import json
import os
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import codemender
from codemender import CodeMender, ScanMode, atomic_write_text
from deduplication import CWE_DB, strip_dot_slash
from pass_report import PASS_REPORT_REL_PATH, build_covered_lines_report
from state_db import (
    active_preexisting_finding_ids,
    deduplicate_db_findings,
    extract_batch_files_from_stdout,
    extract_failed_batch_files_from_stdout,
    extract_safety_blocked_files,
    get_latest_session_finding_counts,
    inspect_find_sessions,
    normalize_db_finding_cwes,
    reconcile_overwritten_findings,
    snapshot_db_findings,
    snapshot_db_session_ids,
)

_DISCOURAGED_CWES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "discouraged_cwes.txt",
)
_SAFETY_ESCALATION_MODEL = "gemini-4-argon"
_PASS_REPORT_REL_PATH = PASS_REPORT_REL_PATH
_WORKSPACE_BACKUPS_DIR = "workspace_backups"

# Re-exported internal aliases used by unit tests
_atomic_write_text = atomic_write_text
_extract_batch_files_from_stdout = extract_batch_files_from_stdout
_extract_failed_batch_files_from_stdout = extract_failed_batch_files_from_stdout

_FIND_CONTEXT_FOR_FIRST_PASS = """\
# Audit Strategy
- Audit the entire target file in a single pass, reporting each distinct vulnerable endpoint, route, or function separately with at most one finding per vulnerable sink or code block (when multiple impacts share one sink, report a single finding using the most specific root-cause CWE).
- Anchor each finding directly at the sink or security defect—never on pure pass-through wrappers/callers or sinkless intra-file helpers, validators, or sanitizers (and report shared file-level auth/state defects once at their definition rather than per caller).
- Scope each snippet and line range strictly to the minimal contiguous sink lines (never the whole enclosing function, and never bridge non-contiguous lines with `...`).
- Check cross-file callers, routes, or auth helpers only when needed to verify untrusted input reachability or authentication/authorization enforcement; never blanket-skip internal services, workers, or serverless handlers that process untrusted DB, queue, storage, or RPC payloads.
- Grade directly exploitable injection (SQL/NoSQL/LDAP/OS/code/XSS/XXE/SSTI), authentication or token/signature validation bypass, missing authorization/IDOR on sensitive data or state, SSRF, unrestricted file upload, and hardcoded or cleartext credential storage as `HIGH` or `CRITICAL` when reachable without prior privileged access.
- Ignore tests, build/package manifests, developer CLI/deployment scripts, `.codemender` files, and vendored or minified third-party libraries (if the target file is third-party/vendored code, stop immediately and report 0).

# CWE Requirements
- Assign each finding exactly one specific Base/Variant/Class Weakness `CWE-<number>`—never a CWE Category, View, Pillar, Deprecated ID, code-quality metric (`CWE-1041`–`CWE-1127`), or discouraged weakness ({discouraged_cwes})."""

_FIND_CONTEXT_FOR_LATER_PASSES = f"""\
# Initial Pre-Audit Check
- First, run `grep_search` on "{{report_file}}" for this target file's repo-relative path to check its already-covered line ranges/snippets (if any).
- Never re-report a covered vulnerability (its covered/sink lines, enclosing declaration/caller, or any intra-file helper/validator/sanitizer whose caller/sink in this file is already covered, or vice versa); audit the remaining uncovered lines and report 0 if no distinct vulnerabilities remain.

{_FIND_CONTEXT_FOR_FIRST_PASS}"""


def _load_discouraged_cwes() -> str:
  """Returns the concise non-deprecated, non-Pillar discouraged security CWEs for prompt guidance."""
  if CWE_DB.prompt_discouraged_ids:
    return ", ".join(f"CWE-{cid}" for cid in CWE_DB.prompt_discouraged_ids)
  if not os.path.exists(_DISCOURAGED_CWES_PATH):
    return ""
  with open(_DISCOURAGED_CWES_PATH, "r", encoding="utf-8") as cwe_f:
    return ", ".join(cwe_f.read().split())


def _format_cmignore_entry(rel_path: str) -> str:
  """Formats a repo-relative path for `.cmignore` without leading `/` (`cm` matches slashless `relPath`)."""
  entry = strip_dot_slash(rel_path)
  if entry.startswith(("#", "!")):
    entry = "\\" + entry
  if entry.endswith(" "):
    entry = entry[:-1] + "\\ "
  return entry


def _filter_cmignore_entries(
    ignored_files: Iterable[str],
    keep_files: Optional[Iterable[str]] = None,
) -> List[str]:
  """Formats sorted `.cmignore` entries while avoiding root-basename shadowing.

  `cm` matches `.cmignore` patterns containing `/` against the full repo-relative
  path, whereas patterns without `/` are matched against `filepath.Base(relPath)`
  across all subdirectories. If a root-level file (no `/`) is ignored while a
  subdirectory file with the same basename remains active, omit the root-level
  entry so the subdirectory file is still audited.
  """
  protected_basenames_lower = {
      os.path.basename(strip_dot_slash(str(kept or ""))).lower()
      for kept in (keep_files or ())
      if strip_dot_slash(str(kept or ""))
  }
  entries: List[str] = []
  for raw in sorted({strip_dot_slash(str(f or "")) for f in ignored_files}):
    if not raw or ("/" not in raw and raw.lower() in protected_basenames_lower):
      continue
    entries.append(_format_cmignore_entry(raw))
  return entries


def _is_model_fallback_disabled(
    extra_flags: Iterable[str],
    env: Optional[Dict[str, str]] = None,
) -> bool:
  """Returns True if the caller explicitly disabled model fallback via CLI flag or env."""
  for flag in extra_flags:
    if flag == "--no-model-fallback" or (
        flag.startswith("--no-model-fallback=")
        and flag.split("=", 1)[1].strip().lower() not in ("false", "0", "no", "off")
    ):
      return True
  raw_env = (env or {}).get("CM_DISABLE_MODEL_FALLBACK")
  if raw_env is None:
    raw_env = os.environ.get("CM_DISABLE_MODEL_FALLBACK", "")
  return str(raw_env).strip().lower() in ("1", "true", "yes", "on")


def _workspace_backup_path(repo_dir: str, cm_dir: str) -> str:
  """Returns the path in `CM_HOME` storing crash-recovery metadata for `repo_dir`."""
  real_repo = os.path.realpath(repo_dir)
  digest = hashlib.sha256(real_repo.encode("utf-8")).hexdigest()[:24]
  return os.path.join(cm_dir, _WORKSPACE_BACKUPS_DIR, f"{digest}.json")


def _safe_remove(path: str) -> None:
  try:
    if os.path.exists(path):
      os.remove(path)
  except OSError:
    pass


def restore_interrupted_workspace(
    repo_dir: Optional[str],
    cm_dir: Optional[str] = None,
) -> None:
  """Restores `.cmignore` and removes temporary complete-scan scratch files left by SIGTERM/SIGKILL."""
  if not repo_dir or not os.path.isdir(repo_dir):
    return
  resolved_cm_dir = cm_dir or codemender.resolve_cm_home()
  report_path = os.path.join(repo_dir, *PASS_REPORT_REL_PATH.split("/"))
  backup_path = _workspace_backup_path(repo_dir, resolved_cm_dir)
  _safe_remove(report_path)
  _safe_remove(f"{report_path}.tmp")
  _safe_remove(f"{backup_path}.tmp")
  if not os.path.exists(backup_path):
    return
  try:
    with open(backup_path, "r", encoding="utf-8") as fh:
      backup = json.load(fh)
  except (OSError, json.JSONDecodeError):
    _safe_remove(backup_path)
    return

  cmignore_path = os.path.join(repo_dir, ".cmignore")
  if backup.get("existed"):
    orig_content = str(backup.get("content") or "")
    current_content: Optional[str] = None
    if os.path.exists(cmignore_path):
      try:
        with open(cmignore_path, "r", encoding="utf-8") as fh:
          current_content = fh.read()
      except OSError:
        current_content = None
    if current_content != orig_content:
      atomic_write_text(cmignore_path, orig_content)
  else:
    _safe_remove(cmignore_path)

  _safe_remove(backup_path)


def run_complete_scan(
    cm: CodeMender,
    target_or_id: Optional[str] = None,
    extra_flags: Optional[List[str]] = None,
    complete_runs: int = 5,
    critical_high_only: bool = True,
    context: Optional[str] = None,
) -> Any:
  """Runs sequential deep scans, tracking clean files in `.cmignore` and stopping early when converged."""
  has_repo_dir = os.path.isdir(cm.repo_dir)
  cm_dir = codemender.resolve_cm_home(cm.env)
  cmignore_path: Optional[str] = None
  orig_cmignore: Optional[str] = None
  if has_repo_dir:
    restore_interrupted_workspace(cm.repo_dir, cm_dir=cm_dir)
    cmignore_path = os.path.join(cm.repo_dir, ".cmignore")
    cmignore_existed = os.path.exists(cmignore_path)
    if cmignore_existed:
      with open(cmignore_path, "r", encoding="utf-8") as fh:
        orig_cmignore = fh.read()
    backup_path = _workspace_backup_path(cm.repo_dir, cm_dir)
    atomic_write_text(
        backup_path,
        json.dumps({
            "repo_dir": os.path.realpath(cm.repo_dir),
            "existed": cmignore_existed,
            "content": orig_cmignore or "",
        }),
    )

  with codemender.handle_termination_signals():
    try:
      pre_scan_session_ids = snapshot_db_session_ids(cm)
      pre_scan_finding_ids = set(snapshot_db_findings(cm).keys())
      excluded_finding_ids = set(pre_scan_finding_ids)
      discouraged_cwes = _load_discouraged_cwes()
      cleaned_extra_flags, extra_contexts = codemender._extract_context_flags(extra_flags)
      flags_without_model, primary_model = codemender._extract_model_flag(
          cleaned_extra_flags,
          default_model="gemini-4-hydrogen",
      )
      enable_argon_escalation = (
          not primary_model.lower().startswith(("gemini-4-argon", "gemini-4-carbon"))
          and not _is_model_fallback_disabled(cleaned_extra_flags, cm.env)
      )
      user_contexts = [c.strip() for c in ([context] if context else []) + extra_contexts if c and c.strip()]
      additional_context = "\n\n".join(user_contexts)

      all_discovered_files: Set[str] = set()
      escalated_files: Set[str] = set()

      def _write_cmignore(
          ignored_files: Iterable[str],
          keep_files: Optional[Iterable[str]] = None,
      ) -> None:
        if not cmignore_path:
          return
        base = orig_cmignore or ""
        if base and not base.endswith("\n"):
          base += "\n"
        entries = _filter_cmignore_entries(ignored_files, keep_files=keep_files)
        atomic_write_text(cmignore_path, base + "".join(f"{e}\n" for e in entries))

      def _fetch_covered_report(only_files: Optional[Iterable[str]]) -> str:
        report_cmd = codemender.build_cm_command(
            cm.cm_binary, "report", extra_flags=["--format", "json"]
        )
        report_res = codemender.run_command(
            report_cmd,
            cwd=cm.repo_dir,
            env=codemender.resolve_subprocess_env(cm.env),
            check=False,
        )
        return build_covered_lines_report(
            getattr(report_res, "stdout", "") or "",
            repo_dir=cm.repo_dir,
            exclude_finding_ids=excluded_finding_ids or None,
            only_files=only_files,
        )

      def _execute_pass(
          *,
          has_prior_state: bool,
          covered_report: str,
          pass_flags: List[str],
          allow_partial_failure: bool,
          allow_all_batches_failed: bool,
          allow_safety_block_failure: bool = False,
          model_override: Optional[str] = None,
          env_overrides: Optional[Dict[str, str]] = None,
      ) -> Any:
        nonlocal excluded_finding_ids
        report_file: Optional[str] = None
        pass_error: Optional[RuntimeError] = None
        pass_result = None
        report_text = covered_report or "No preexisting findings.\n"
        try:
          if has_prior_state:
            if has_repo_dir:
              report_file = os.path.join(cm.repo_dir, *PASS_REPORT_REL_PATH.split("/"))
              atomic_write_text(report_file, report_text)
              report_ref = PASS_REPORT_REL_PATH
            else:
              with tempfile.NamedTemporaryFile(
                  mode="w", suffix="", delete=False, encoding="utf-8"
              ) as tmp_file:
                tmp_file.write(report_text)
                report_file = tmp_file.name
                report_ref = report_file
            pass_context = _FIND_CONTEXT_FOR_LATER_PASSES.format(
                report_file=report_ref, discouraged_cwes=discouraged_cwes
            )
          else:
            pass_context = _FIND_CONTEXT_FOR_FIRST_PASS.format(
                discouraged_cwes=discouraged_cwes
            )
          if additional_context:
            pass_context = f"{pass_context}\n\n# Additional Context\n{additional_context}"
          pre_pass_rows = snapshot_db_findings(cm)
          find_kwargs: Dict[str, Any] = {
              "target_or_id": target_or_id,
              "scan_mode": ScanMode.DEEP,
              "extra_flags": pass_flags or None,
              "max_turns": 8,
              "context": pass_context,
              "allow_partial_failure": allow_partial_failure,
              "allow_all_batches_failed": allow_all_batches_failed,
              "allow_safety_block_failure": allow_safety_block_failure,
              "env_overrides": env_overrides,
          }
          if model_override is not None:
            find_kwargs["model"] = model_override
          try:
            pass_result = cm.find(**find_kwargs)
          except RuntimeError as exc:
            pass_error = exc
        finally:
          if report_file is not None:
            _safe_remove(report_file)
            _safe_remove(f"{report_file}.tmp")
        reconcile_overwritten_findings(
            cm,
            pre_pass_rows,
            pre_scan_session_ids=pre_scan_session_ids,
            pre_scan_finding_ids=pre_scan_finding_ids,
        )
        excluded_finding_ids = active_preexisting_finding_ids(
            cm, pre_scan_finding_ids, pre_scan_session_ids
        )
        normalize_db_finding_cwes(cm, exclude_finding_ids=excluded_finding_ids or None)
        deduplicate_db_findings(cm, exclude_finding_ids=excluded_finding_ids or None)
        if pass_error is not None:
          raise pass_error
        return pass_result

      def _query_counts(
          prev_files: Optional[List[str]],
          last_res: Any,
      ) -> Dict[str, int]:
        return get_latest_session_finding_counts(
            cm,
            last_pass_files=prev_files,
            last_pass_stdout=getattr(last_res, "stdout", "") or "",
            critical_high_only=critical_high_only,
            exclude_session_ids=pre_scan_session_ids or None,
            exclude_finding_ids=excluded_finding_ids or None,
        )

      def _run_pass_series(
          *,
          pass_flags: List[str],
          model_override: Optional[str] = None,
          env_overrides: Optional[Dict[str, str]] = None,
          scoped_files: Optional[Set[str]] = None,
          excluded_files: Optional[Set[str]] = None,
          prior_cleared_files: Optional[Set[str]] = None,
          collect_safety_blocks: bool = False,
          reset_cmignore_first: bool = False,
      ) -> Tuple[Any, Optional[List[str]], Set[str], bool]:
        series_result = None
        series_prev_active: Optional[List[str]] = None
        series_cleared: Set[str] = set()
        escalate_all = False
        excl = excluded_files if excluded_files is not None else set()

        for pass_idx in range(complete_runs):
          active_files: Optional[List[str]] = None
          covered_report = ""
          has_prior_state = False

          if scoped_files is not None:
            if pass_idx > 0:
              counts = _query_counts(series_prev_active, series_result)
              all_discovered_files.update(counts.keys())
              series_cleared.update(f for f in scoped_files if counts.get(f, 1) == 0)
            active_files = sorted(scoped_files - series_cleared)
            if not active_files:
              break
            ignored = (
                (all_discovered_files - set(active_files))
                | (prior_cleared_files or set())
                | series_cleared
            )
            _write_cmignore(ignored, keep_files=active_files)
            covered_report = _fetch_covered_report(active_files)
            has_prior_state = bool(covered_report) or (pass_idx > 0)
          elif pass_idx > 0:
            counts = _query_counts(series_prev_active, series_result)
            all_discovered_files.update(counts.keys())
            for cleared in series_cleared:
              counts[cleared] = 0
            series_cleared.update(
                t for t, c in counts.items() if c == 0 and t not in excl
            )
            clean_files = sorted(
                t for t, c in counts.items() if c == 0 and t not in excl
            )
            active_files = sorted(
                t for t, c in counts.items() if c > 0 and t not in excl
            )
            if counts and not active_files:
              break
            _write_cmignore(set(clean_files) | excl, keep_files=active_files)
            covered_report = _fetch_covered_report(active_files or None)
            has_prior_state = bool(covered_report) or bool(active_files)
          elif reset_cmignore_first:
            _write_cmignore([])

          pass_pre_sessions = snapshot_db_session_ids(cm) if collect_safety_blocks else set()
          is_non_final = pass_idx < complete_runs - 1
          series_result = _execute_pass(
              has_prior_state=has_prior_state,
              covered_report=covered_report,
              pass_flags=pass_flags,
              allow_partial_failure=is_non_final,
              allow_all_batches_failed=(pass_idx > 0 and has_prior_state),
              allow_safety_block_failure=collect_safety_blocks,
              model_override=model_override,
              env_overrides=env_overrides,
          )
          series_prev_active = active_files
          if collect_safety_blocks:
            new_blocked, all_safety_blocked = extract_safety_blocked_files(
                cm,
                getattr(series_result, "stdout", "") or "",
                pass_pre_sessions,
                primary_model,
            )
            if new_blocked:
              excl.update(new_blocked)
              series_cleared.difference_update(new_blocked)
            elif pass_idx == 0 and all_safety_blocked:
              escalate_all = True
              break

        return series_result, series_prev_active, series_cleared, escalate_all

      primary_env_overrides = (
          {"CM_DISABLE_MODEL_FALLBACK": "true"} if enable_argon_escalation else None
      )
      result, prev_active_files, cleared_files, escalate_entire_repo = _run_pass_series(
          pass_flags=cleaned_extra_flags,
          env_overrides=primary_env_overrides,
          excluded_files=escalated_files,
          collect_safety_blocks=enable_argon_escalation,
      )

      if enable_argon_escalation and (escalated_files or escalate_entire_repo):
        if result is not None and not escalate_entire_repo:
          counts = _query_counts(prev_active_files, result)
          all_discovered_files.update(counts.keys())
          cleared_files.update(
              t for t, c in counts.items() if c == 0 and t not in escalated_files
          )
        argon_res, prev_active_files, _, _ = _run_pass_series(
            pass_flags=flags_without_model,
            model_override=_SAFETY_ESCALATION_MODEL,
            scoped_files=None if escalate_entire_repo else escalated_files,
            prior_cleared_files=cleared_files,
            reset_cmignore_first=escalate_entire_repo,
        )
        if argon_res is not None:
          result = argon_res

      if result is not None:
        final_stdout = getattr(result, "stdout", "") or ""
        _, unresolved_list = inspect_find_sessions(
            cm,
            last_pass_files=prev_active_files,
            last_pass_stdout=final_stdout,
            critical_high_only=critical_high_only,
            exclude_session_ids=pre_scan_session_ids or None,
            exclude_finding_ids=excluded_finding_ids or None,
        )
        unresolved_failed = set(unresolved_list)
        if getattr(result, "returncode", 0) != 0:
          unresolved_failed.update(extract_failed_batch_files_from_stdout(final_stdout))
        if unresolved_failed:
          failed_list = ", ".join(sorted(unresolved_failed))
          raise RuntimeError(
              "cm find failed with exit code 1: deep scan incomplete"
              f" (unresolved failed batch(es): {failed_list})"
          )
      return result
    finally:
      if has_repo_dir:
        restore_interrupted_workspace(cm.repo_dir, cm_dir=cm_dir)
