#!/usr/bin/env python3
"""cm-ci.py {version} — CodeMender wrapper for CI: run correlation and safe batch fixing.

Requires cm {min_cm} or later. Single file, standard library only (python3 >= 3.8).
Needs `cm` and `git` on PATH.

  cm-ci.py check-config                         report the config CodeMender needs in CI
                                                and print the YAML to add; exit 2 if
                                                incomplete (never modifies config.yaml)
  cm-ci.py find [wrapper opts] <cm find args>   run `cm find` (every cm flag passes
                                                through: --deep, --diff, --format,
                                                --model, -y, ...), report what the scan
                                                newly surfaced, and write
                                                .codemender/run_manifest.json
  cm-ci.py fix [options] [FINDING_ID ...]       run `cm fix` for several findings safely:
                                                one commit per fix, abort if the working
                                                tree was reset, record which session
                                                produced each commit

find options:
  --repo DIR        repository root (default: git toplevel)
  --out-dir DIR     where to write run_manifest.json (default .codemender)
  --fail-on SEVS    exit 4 if a NEW or REOPENED finding has one of these severities,
                    e.g. CRITICAL,HIGH. "NONE" or omitted disables the gate
  --ci-build-id ID  record your CI build ID in the manifest (also $CM_CI_BUILD_ID)
  --no-manifest     skip run_manifest.json (no reading of CodeMender's session logs)
fix options:
  --repo DIR  --model M  --max N (default 10)  --out-dir DIR
  --include-new-files  --dry-run  --ci-build-id ID  --no-manifest

Deduplication is NOT done here. cm {min_cm} fingerprints findings on canonical CWE plus a
comment-insensitive snippet and matches them across runs, so a repeated scan updates the
existing row instead of adding a second one, and a fixed bug that comes back returns as
REOPENED. That is why this wrapper refuses to run on anything older.

New / reopened / already-known IS done here, by comparing `cm report` before and after the
scan. It relies on cm's stable finding IDs, not on re-deriving identity. `cm report` cannot
answer it alone: --status OPEN is everything ever found, and --status REOPENED is sticky.
`cm find --fail-on` cannot be used for CI gating either — it is only evaluated on --diff
scans, so on a plain or --deep scan it is silently a no-op. See the README.

Exit codes: 0 ok · 1 usage / tool missing · 2 config missing or cm too old ·
            3 workspace reset detected during fix · 4 --fail-on matched ·
            otherwise the exit code of `cm`
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# Version of this wrapper (not of CodeMender). Recorded in both manifests so a support
# ticket identifies which build produced them. Bump on any behaviour change.
CM_CI_VERSION = "2.0.0"
# Cross-run finding dedup landed in cm 0.13.0. This wrapper no longer dedups, so running
# it against an older CLI would silently reintroduce the duplicates it used to remove.
CM_MIN_VERSION = (0, 13, 0)
CM_MIN_VERSION_STR = ".".join(str(n) for n in CM_MIN_VERSION)
__doc__ = (__doc__ or "").replace("{version}", CM_CI_VERSION).replace("{min_cm}", CM_MIN_VERSION_STR)

ACTIVE = {"OPEN", "REOPENED", "VERIFIED", ""}
SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ─── helpers ─────────────────────────────────────────────────────────────────

def die(msg: str, code: int = 1) -> None:
    print(f"cm-ci: {msg}", file=sys.stderr)
    sys.exit(code)


def need(tool: str) -> None:
    if shutil.which(tool) is None:
        die(f"'{tool}' not found on PATH")


def sh(*cmd: str, check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(cmd), text=True, capture_output=capture, stdin=subprocess.DEVNULL, check=check)


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _version_tuple(v: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", str(v or ""))
    return tuple(int(p) for p in parts[:3]) if parts else ()


def cm_version() -> Tuple[int, ...]:
    """Version of the `cm` on PATH, from `cm --version` ("cm version 0.13.0"). () if unknown."""
    r = sh("cm", "--version")
    return _version_tuple(r.stdout or r.stderr) if r.returncode == 0 else ()


def require_cm(min_version: Tuple[int, ...] = CM_MIN_VERSION) -> Tuple[int, ...]:
    need("cm")
    v = cm_version()
    want = ".".join(str(n) for n in min_version)
    if not v:
        die(f"could not read `cm --version`; this wrapper needs cm {want} or later", 2)
    if v < min_version:
        die(f"cm {'.'.join(str(n) for n in v)} is too old — this wrapper needs {want} or later. "
            f"Cross-run finding deduplication is done by cm itself from {want}; on an older CLI "
            "a repeated scan files the same bug again. Run `cm update`.", 2)
    return v


def unpack_findings(data: Any) -> List[dict]:
    """`cm report --format json` (array, or an object with a findings list) → findings."""
    if data is None:
        return []
    items = data if isinstance(data, list) else next(
        (data.get(k) for k in ("findings", "results", "items") if isinstance(data.get(k), list)), [])
    return [it for it in items or [] if isinstance(it, dict)]


def status_of(f: dict) -> str:
    return str(f.get("status") or "OPEN").upper()


def sev_of(f: dict) -> str:
    return str(f.get("severity") or "").upper()


def classify_lifecycle(before: List[dict], after: List[dict]) -> Dict[str, List[dict]]:
    """Split this run's active findings into new / reopened / existing.

    From 0.13.0 a finding keeps the same `finding_id` when a later scan sees it again, so
    comparing `cm report` before and after the scan is enough to say what the run actually
    surfaced. This is NOT the old client-side dedup: identity comes from cm, we only read it.

    Needed because `cm report` alone cannot answer it. `--status OPEN` is everything ever
    found, not this run's delta, and `--status REOPENED` is sticky — it stays set, so it
    does not identify the run that caused the regression.
    """
    prev = {str(f.get("finding_id")): f for f in before if f.get("finding_id")}
    out: Dict[str, List[dict]] = {"new": [], "reopened": [], "existing": []}
    for f in after:
        fid = str(f.get("finding_id") or "")
        if not fid or status_of(f) not in ACTIVE:
            continue
        was = prev.get(fid)
        if was is None:
            out["new"].append(f)
        elif status_of(was) not in ACTIVE:
            # resolved last time we looked, active now: a regression or an incomplete fix
            out["reopened"].append(f)
        else:
            out["existing"].append(f)
    return out


def gate_hits(findings: List[dict], fail_on: Optional[str]) -> List[dict]:
    """Findings whose severity is listed in `fail_on`. Empty or "NONE" disables the gate."""
    spec = (fail_on or "").strip()
    if not spec or spec.upper() == "NONE":
        return []
    want = {s.strip().upper() for s in spec.split(",") if s.strip()}
    return [f for f in findings if sev_of(f) in want]



class Ctx:
    def __init__(self, repo: Optional[str]):
        if not repo:
            r = sh("git", "rev-parse", "--show-toplevel")
            if r.returncode != 0:
                die("not inside a git repo (use --repo DIR)")
            repo = r.stdout.strip()
        self.repo = os.path.realpath(repo)
        os.chdir(self.repo)
        self.cm_dir = os.environ.get("CM_HOME") or os.path.join(os.path.expanduser("~"), ".codemender")
        self.cfg = os.path.join(self.cm_dir, "config.yaml")
        self.db = os.path.join(self.cm_dir, "state.db")

    def report(self) -> List[dict]:
        r = sh("cm", "report", "--format", "json")
        if r.returncode != 0 or not r.stdout.strip():
            return []
        try:
            return unpack_findings(json.loads(r.stdout))
        except json.JSONDecodeError:
            return []


def write_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def git_head(short: bool = False) -> Optional[str]:
    r = sh("git", "rev-parse", *(["--short"] if short else []), "HEAD")
    return r.stdout.strip() or None if r.returncode == 0 else None


# ─── run correlation ─────────────────────────────────────────────────────────
#
# `cm find --deep` / `--diff` start one agent session per source file and print no
# overarching ID. CodeMender does mint one per invocation — `command_id`, stamped on
# every record of every session it spawns — but never shows it. We read it back out
# of the session logs: snapshot $CM_HOME/logs/sessions/ around the `cm` call, parse
# what appeared, group by command_id. Token totals replicate `cm stats` arithmetic so
# a run's numbers reconcile with the command-type row rather than disagreeing with it.

SESSIONS_SCHEMA_VERSION = "1"          # sessions.SchemaVersion
TOKEN_KEYS = ("input", "output", "cached", "thought", "tool_use", "total")

_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})"
                    r"(?:\.(\d+))?(Z|z|[+-]\d{2}:?\d{2})?$")


def fmt_duration(seconds: Optional[float]) -> str:
    """cm's formatDuration: "%02dm %02ds", with zero and negatives as 00m 00s."""
    if not seconds or seconds <= 0:
        return "00m 00s"
    total = int(seconds + 0.5)  # Go rounds half away from zero; round() does not
    return f"{total // 60:02d}m {total % 60:02d}s"


def human_count(n: Any) -> str:
    """cm's humanCount: k/M/B suffixes, thresholds half a rounding unit low."""
    n = _int(n)
    if n >= 999_950_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 999_950:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}k"
    return str(n)


def _pct(part: int, whole: int) -> float:
    return 0.0 if whole <= 0 else part / whole * 100.0


def _parse_ts(value: Any) -> Optional[float]:
    """RFC3339 (nanosecond precision) → epoch seconds. None when unparseable."""
    m = _TS_RE.match(str(value or ""))
    if not m:
        return None
    y, mo, d, h, mi, s, frac, off = m.groups()
    import calendar
    secs = float(calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0)))
    if frac:
        secs += float("0." + frac)
    if off and off not in ("Z", "z"):
        digits = off[1:].replace(":", "")
        delta = int(digits[:2]) * 3600 + int(digits[2:4] or 0) * 60
        secs -= delta if off[0] == "+" else -delta
    return secs


def sessions_root(ctx: "Ctx") -> str:
    return os.path.join(ctx.cm_dir, "logs", "sessions")


def list_session_logs(root: str) -> Dict[str, int]:
    """abs path → size for every <root>/<cm_project_id>/*.jsonl. Missing root → {}."""
    out: Dict[str, int] = {}
    try:
        projects = sorted(os.listdir(root))
    except OSError:
        return out
    for proj in projects:
        pdir = os.path.join(root, proj)
        try:
            names = sorted(os.listdir(pdir))
        except OSError:
            continue
        for name in names:
            if not name.endswith(".jsonl"):
                continue
            path = os.path.join(pdir, name)
            try:
                out[path] = os.path.getsize(path)
            except OSError:
                continue
    return out


def _new_invocation() -> dict:
    return {"command_type": "", "cli_version": "", "argv": None, "project": "",
            "files": [], "schemas": set(), "sessions": {}, "duration_ms": 0,
            "first_ts": None, "last_ts": None, "any_ts": None}


def _fold_log(path: str, acc: Dict[str, dict]) -> None:
    """Fold one session log into acc, keyed by command_id. Malformed lines are skipped,
    matching the reader in CodeMender itself."""
    project = os.path.basename(os.path.dirname(path))
    name = os.path.basename(path)
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict):
                continue
            cid = str(r.get("command_id") or "")
            if not cid:
                continue
            e = acc.get(cid)
            if e is None:
                e = acc[cid] = _new_invocation()
            e["schemas"].add(str(r.get("schema_version") or ""))
            if not e["project"]:
                e["project"] = project
            if name not in e["files"]:
                e["files"].append(name)
            if r.get("cli_version"):
                e["cli_version"] = str(r["cli_version"])
            ts = _parse_ts(r.get("ts"))
            if ts is not None:
                e["any_ts"] = ts if e["any_ts"] is None else max(e["any_ts"], ts)
            rtype = str(r.get("type") or "")
            sid = str(r.get("session_id") or "")
            if rtype == "command_start":
                if r.get("command_type"):
                    e["command_type"] = str(r["command_type"])
                if e["argv"] is None and isinstance(r.get("args"), list):
                    e["argv"] = [str(a) for a in r["args"]]
            elif rtype == "interaction":
                s = e["sessions"].setdefault(sid, {"usage": None, "requests": 0, "polls": 0})
                s["requests"] += 1
                usage = {k: _int(r.get(k)) for k in TOKEN_KEYS}
                # Records carry *cumulative* totals, so the highest wins — summing them
                # would multiply the bill. Ties keep the later record, as cm does.
                if s["usage"] is None or usage["total"] >= s["usage"]["total"]:
                    s["usage"] = usage
                if ts is not None:
                    # cm measures an un-finished run by the span of its interactions.
                    e["first_ts"] = ts if e["first_ts"] is None else min(e["first_ts"], ts)
                    e["last_ts"] = ts if e["last_ts"] is None else max(e["last_ts"], ts)
            elif rtype == "session_summary":
                s = e["sessions"].setdefault(sid, {"usage": None, "requests": 0, "polls": 0})
                s["polls"] += _int(r.get("poll_count"))
            elif rtype == "command_finish":
                e["duration_ms"] = max(e["duration_ms"], _int(r.get("duration_ms")))


def _aggregate_usage(e: dict) -> dict:
    """Token totals for one invocation, by the same arithmetic as `cm stats`."""
    totals = {k: 0 for k in TOKEN_KEYS}
    requests = polls = 0
    for s in e["sessions"].values():
        requests += s["requests"]
        polls += s["polls"]
        if s["usage"]:
            for k in TOKEN_KEYS:
                totals[k] += s["usage"][k]
    if e["duration_ms"] > 0:
        secs = e["duration_ms"] / 1000.0
    elif e["first_ts"] is not None and e["last_ts"] is not None and e["last_ts"] > e["first_ts"]:
        # Sessions run concurrently, so this is the wall clock of the run, not a sum.
        secs = e["last_ts"] - e["first_ts"]
    else:
        secs = 0.0
    return {
        "requests": requests,
        "polls": polls,
        "input_tokens": totals["input"],
        "output_tokens": totals["output"],
        "cached_tokens": totals["cached"],
        "thought_tokens": totals["thought"],
        "tool_calls": totals["tool_use"],
        "total_tokens": totals["total"],
        # Vertex formulas: input already includes cached (cmd/deps.go EnableVertexCacheHit).
        "cache_hit_percent": _pct(totals["cached"], totals["input"]),
        "think_ratio_percent": _pct(totals["thought"], totals["thought"] + totals["output"]),
        "duration_seconds": round(secs, 3),
        "duration_formatted": fmt_duration(secs),
    }


def collect_run(root: str, before: Dict[str, int], want_prefix: str) -> dict:
    """Identify the `want_prefix` invocation whose session logs appeared under `root`
    since the `before` snapshot. Never raises and never fails a build: on anything
    unexpected it returns run_id None / usage None and says why in warnings."""
    out: Dict[str, Any] = {"run_id": None, "command_type": None, "cli_version": None,
                           "cm_project_id": None, "argv": None, "session_ids": [],
                           "session_log_files": [], "usage": None, "warnings": []}
    fresh = [p for p, size in list_session_logs(root).items() if size > before.get(p, -1)]
    if not fresh:
        out["warnings"].append(
            f"no session log was written under {root} during this run, so the run ID and "
            "session list are unavailable (a different $CM_HOME, or session logging disabled)")
        return out
    acc: Dict[str, dict] = {}
    for path in sorted(fresh):
        _fold_log(path, acc)
    candidates = [(cid, e) for cid, e in acc.items()
                  if (e["command_type"] or "").startswith(want_prefix)]
    if not candidates:
        out["warnings"].append(
            f"no session log for a '{want_prefix}' command was written during this run, so "
            "the run ID and session list are unavailable")
        return out
    # Several can match when a previous step is still flushing; the newest is ours.
    cid, e = max(candidates, key=lambda kv: (kv[1]["any_ts"] or 0.0, kv[0]))
    out["run_id"] = cid
    out["command_type"] = e["command_type"] or None
    out["cli_version"] = e["cli_version"] or None
    out["cm_project_id"] = e["project"] or None
    out["argv"] = e["argv"]
    out["session_ids"] = sorted(sid for sid in e["sessions"] if sid)
    out["session_log_files"] = list(e["files"])

    schemas = {s for s in e["schemas"] if s}
    if schemas and schemas != {SESSIONS_SCHEMA_VERSION}:
        out["warnings"].append(
            f"session log schema_version {sorted(schemas)} is not "
            f"{SESSIONS_SCHEMA_VERSION}; this wrapper cannot read it, so token totals are "
            "omitted rather than reported wrong")
        return out
    out["usage"] = _aggregate_usage(e)
    return out


def run_summary_line(run: dict) -> str:
    bits = [f"cm-ci: run {run.get('run_id') or 'unknown'}"]
    if run.get("session_ids"):
        bits.append(f"{len(run['session_ids'])} session(s)")
    usage = run.get("usage")
    if usage:
        bits.append(f"{human_count(usage['total_tokens'])} tokens")
        bits.append(usage["duration_formatted"])
    if run.get("command_type"):
        bits.append(run["command_type"])
    return " · ".join(bits)


def report_lifecycle(lc: Dict[str, List[dict]], repo: str) -> None:
    """One summary line, then a line per finding this run actually surfaced. Existing
    findings are counted but not listed — they are in `cm report`, and reprinting them
    every night is what makes CI output unreadable."""
    new, reop, exist = lc["new"], lc["reopened"], lc["existing"]
    print(f"cm-ci: new {len(new)} · reopened {len(reop)} · already known {len(exist)} "
          f"· active {len(new) + len(reop) + len(exist)}")
    for tag, rows in (("REOPENED", reop), ("NEW", new)):
        for f in rows:
            loc = rel_path(str(f.get("file_path") or ""), repo)
            line = f.get("start_line")
            print(f"  {tag:<8} {sev_of(f):<8} {loc}{':' + str(line) if line else ''} "
                  f"{f.get('title') or ''}".rstrip())
    # stdout is block-buffered under a pipe while stderr is not, so without this the
    # "failing (exit 4)" line lands above the findings it is talking about in a CI log.
    sys.stdout.flush()


def ci_build_id(flag: Optional[str]) -> Optional[str]:
    """Recorded verbatim; nothing is generated when the caller supplies nothing."""
    return flag or os.environ.get("CM_CI_BUILD_ID") or None


def build_run_manifest(run: dict, ci_build_id: Optional[str], repo: str,
                       git_commit: Optional[str], started_at: str, finished_at: str,
                       exit_code: int, argv: Optional[List[str]] = None,
                       lifecycle: Optional[Dict[str, List[dict]]] = None) -> dict:
    m = {
        "cm_ci_version": CM_CI_VERSION,
        "run_id": run.get("run_id"),
        "ci_build_id": ci_build_id,
        "command_type": run.get("command_type"),
        "cli_version": run.get("cli_version"),
        "cm_project_id": run.get("cm_project_id"),
        # CodeMender's command_start logs only the positional target, so prefer the
        # arguments we actually passed; the log is the fallback.
        "argv": argv if argv is not None else run.get("argv"),
        "repo": repo,
        "git_commit": git_commit,
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": exit_code,
        "session_count": len(run.get("session_ids") or []),
        "session_ids": run.get("session_ids") or [],
        "session_log_files": run.get("session_log_files") or [],
    }
    # What this run actually surfaced. Only the IDs: the finding bodies are in
    # `cm report --format json`, and duplicating them here would just go stale.
    if lifecycle is not None:
        m["lifecycle"] = {
            "new": len(lifecycle.get("new") or []),
            "reopened": len(lifecycle.get("reopened") or []),
            "existing": len(lifecycle.get("existing") or []),
            "active_total": sum(len(lifecycle.get(k) or [])
                                for k in ("new", "reopened", "existing")),
        }
        m["new_finding_ids"] = [str(f.get("finding_id")) for f in lifecycle.get("new") or []]
        m["reopened_finding_ids"] = [str(f.get("finding_id"))
                                     for f in lifecycle.get("reopened") or []]
    # Omitted rather than wrong: a missing field is a bug report, a bad cost number is a
    # bad decision. `warnings` always says why.
    if run.get("usage"):
        m["usage"] = run["usage"]
    m["warnings"] = list(run.get("warnings") or [])
    return m


def build_fix_manifest(ci_build_id: Optional[str], repo: str, head_before: Optional[str],
                       head_after: Optional[str], started_at: str, finished_at: str,
                       fixes: List[dict], warnings: List[str]) -> dict:
    """One `cm fix` pass is several `cm` invocations, so there is no single run ID for it.
    The per-fix run IDs and sessions live in `fixes`; `ci_build_id` is what joins the pass
    back to the scan that found the bugs."""
    return {
        "cm_ci_version": CM_CI_VERSION,
        "ci_build_id": ci_build_id,
        "command": "fix",
        "repo": repo,
        "head_before": head_before,
        "head_after": head_after,
        "started_at": started_at,
        "finished_at": finished_at,
        "fixes": fixes,
        "warnings": warnings,
    }


def report_run(run: Optional[dict]) -> None:
    if run is None:
        return
    print(run_summary_line(run), flush=True)
    for w in run.get("warnings") or []:
        print(f"cm-ci: warning — {w}", file=sys.stderr)


# ─── option parsing ──────────────────────────────────────────────────────────

FIND_VALUE_OPTS = ("--repo", "--out-dir", "--ci-build-id", "--fail-on")
FIND_FLAGS = ("--no-manifest",)
FIX_VALUE_OPTS = ("--repo", "--model", "--max", "--out-dir", "--ci-build-id")
FIX_FLAGS = ("--include-new-files", "--dry-run", "--no-manifest")


def parse_opts(argv: List[str], with_value: Tuple[str, ...], flags: Tuple[str, ...], passthrough: bool):
    opts: Dict[str, Any] = {f: False for f in flags}
    rest: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("--") and "=" in a and a.split("=", 1)[0] in with_value:
            k, v = a.split("=", 1)
            opts[k] = v; i += 1
        elif a in with_value:
            if i + 1 >= len(argv):
                die(f"option {a} needs a value")
            opts[a] = argv[i + 1]; i += 2
        elif a in flags:
            opts[a] = True; i += 1
        elif a in ("-h", "--help"):
            print(__doc__); sys.exit(0)
        elif a.startswith("--") and not passthrough:
            die(f"unknown option {a}")
        else:
            rest.append(a); i += 1
    return opts, rest


# ─── config check ────────────────────────────────────────────────────────────

EXCLUDE_DIRS = '["venv", ".venv", "env", "site-packages", "__pycache__", "node_modules", "vendor", "dist", "bin", "target", "obj", "build", ".gradle"]'


def _cfg_text(ctx: Ctx) -> str:
    try:
        with open(ctx.cfg, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def cfg_checks(ctx: Ctx) -> Dict[str, bool]:
    t = _cfg_text(ctx)
    return {
        "project_paths": bool(re.search(r"^\s*project_paths:.*[\"']?" + re.escape(ctx.repo) + r"[\"']?", t, re.M)),
        "reset": bool(re.search(r"^\s*reset:\s*[\"']?true[\"']?\s*$", t, re.M)),
        "exclude_dirs": bool(re.search(r"^\s*exclude_dirs:", t, re.M) and re.search(r"(^|[\"' ,\[-])\.?venv([\]\"' ,]|$)", t, re.M)),
    }


def cfg_has_section(ctx: Ctx, name: str) -> bool:
    return bool(re.search(rf"^{name}:", _cfg_text(ctx), re.M))


def check_config(ctx: Ctx) -> bool:
    """Report which CI settings CodeMender has and which are missing, print the YAML to add,
    and return True when the config is complete.

    This never writes to config.yaml. `cm init` ships a template that already defines
    `server:`, `vcs:` and `scan:`, so appending either duplicates a top-level key — which
    cm then refuses to load — or needs a real YAML merge. Silently rewriting someone's
    config is worse than telling them what to add. Treat config.yaml as part of the runner
    image and this command as the gate that proves it is right.
    """
    ok = cfg_checks(ctx)
    print(f"cm-ci: config check — {ctx.cfg}")
    why = {
        "project_paths": "cm fix/verify resolve the real repo root (no nested temp repo)",
        "reset": "vcs.commands.reset=\"true\" — no 'git checkout HEAD -- . && git clean -fd' before each fix",
        "exclude_dirs": "scan.exclude_dirs lists venv/.venv (cm's default list has neither)",
    }
    for k in ("project_paths", "reset", "exclude_dirs"):
        print(f"{k:<15} {'OK' if ok[k] else 'MISSING'}\n    {why[k]}")
    if all(ok.values()):
        print("cm-ci: config complete")
        return True
    add = ""
    if not ok["project_paths"]:
        add += f'project_paths: ["{ctx.repo}"]\n'
    if not ok["reset"]:
        add += 'vcs:\n  type: git\n  commands:\n    reset: "true"\n'
    if not ok["exclude_dirs"]:
        add += f"scan:\n  exclude_dirs: {EXCLUDE_DIRS}\n"
    print(f"\nAdd to {ctx.cfg}:\n\n{add}", flush=True)
    merge = [n for n in ("project_paths", "vcs", "scan") if cfg_has_section(ctx, n)]
    if merge:
        print(f"cm-ci: {ctx.cfg} already defines {', '.join(merge)} — merge the keys above into "
              "the existing section(s). Appending would create a duplicate top-level key and cm "
              "will refuse to load the file.", file=sys.stderr)
    return False


def cmd_check_config(argv: List[str]) -> int:
    opts, rest = parse_opts(argv, ("--repo",), ("--yes", "--apply"), passthrough=False)
    if rest:
        die(f"check-config: unexpected argument {rest[0]}")
    ctx = Ctx(opts.get("--repo"))
    complete = check_config(ctx)
    if opts["--yes"] or opts["--apply"]:
        print("cm-ci: note — check-config only reports; --yes/--apply have no effect.", file=sys.stderr)
    return 0 if complete else 2


# ─── find ────────────────────────────────────────────────────────────────────

def cmd_find(argv: List[str]) -> int:
    opts, cm_args = parse_opts(argv, FIND_VALUE_OPTS, FIND_FLAGS, passthrough=True)
    require_cm()
    ctx = Ctx(opts.get("--repo"))
    out_dir = opts.get("--out-dir") or ".codemender"
    build_id = ci_build_id(opts.get("--ci-build-id"))
    fail_on = opts.get("--fail-on")
    manifest_path = os.path.join(out_dir, "run_manifest.json")
    if not check_config(ctx):
        print("cm-ci: warning — config incomplete; findings under venv/ will be reported and "
              f"'cm fix' would revert earlier fixes. Add the YAML above to {ctx.cfg}", file=sys.stderr)

    before = ctx.report()
    print(f"cm-ci: cm find {' '.join(cm_args)}", flush=True)
    logs_before = {} if opts["--no-manifest"] else list_session_logs(sessions_root(ctx))
    started_at = now_rfc3339()
    rc = subprocess.call(["cm", "find", *cm_args])
    finished_at = now_rfc3339()
    run = None if opts["--no-manifest"] else collect_run(sessions_root(ctx), logs_before, "find")
    report_run(run)

    lifecycle = classify_lifecycle(before, ctx.report())
    report_lifecycle(lifecycle, ctx.repo)
    if run is not None:
        write_json(manifest_path, build_run_manifest(
            run, build_id, ctx.repo, git_head(), started_at, finished_at,
            rc, argv=["find", *cm_args], lifecycle=lifecycle))
        print(f"cm-ci: → {manifest_path} (run ID, sessions, and what this scan surfaced)")
    if rc != 0:
        # The manifest is written either way: the session IDs of a failed scan are exactly
        # what a support ticket needs.
        print(f"cm-ci: cm find exited {rc}", file=sys.stderr)
        return rc

    # Gate on what this run surfaced, not on the whole database — otherwise a repo with one
    # accepted CRITICAL fails every build forever. `cm find --fail-on` cannot be used for
    # this: it is only evaluated on --diff scans (cmd/find.go evaluateCIGate), so on a plain
    # or --deep scan it is silently a no-op.
    hits = gate_hits(lifecycle["new"] + lifecycle["reopened"], fail_on)
    if hits:
        worst = sorted({sev_of(f) for f in hits}, key=lambda s: SEV_RANK.get(s, 9))
        print(f"cm-ci: {len(hits)} new or reopened finding(s) at {', '.join(worst)} "
              f"— failing (exit 4)", file=sys.stderr)
        return 4
    return 0


# ─── fix ─────────────────────────────────────────────────────────────────────

SKIP_DIRS = ("venv/", ".venv/", "site-packages/", "node_modules/")


def rel_path(p: str, root: str) -> str:
    p = str(p or "")
    return p[len(root) + 1:] if p.startswith(root + "/") else p


def select_findings(findings: List[dict], root: str, max_n: int) -> List[dict]:
    """Open findings worth fixing, worst first, capped at max_n. Anything under a
    virtual-env directory is skipped: it is third-party code the repo does not own."""
    rows = []
    for f in findings:
        if status_of(f) not in ACTIVE:
            continue
        rel = rel_path(f.get("file_path", ""), root)
        if any(s in rel + "/" for s in SKIP_DIRS):
            continue
        rows.append((SEV_RANK.get(str(f.get("severity", "")).upper(), 9), dict(f, _rel=rel)))
    rows.sort(key=lambda r: r[0])
    return [f for _, f in rows][:max_n]


def nested_git(root: str) -> List[str]:
    hits = []
    for dirpath, dirnames, _ in os.walk(root):
        depth = dirpath[len(root):].count(os.sep)
        if depth > 6:
            dirnames[:] = []
            continue
        if ".git" in dirnames or os.path.islink(os.path.join(dirpath, ".git")):
            if dirpath != root:
                hits.append(os.path.relpath(os.path.join(dirpath, ".git"), root))
            if ".git" in dirnames:
                dirnames.remove(".git")
    return sorted(hits)


CM_MARKER = ".cm_project"


def exclude_cm_marker(repo: str) -> None:
    """cm writes a `.cm_project` marker at the repo root. Keep it out of git via the
    repo-local exclude file (does not touch the project's own .gitignore)."""
    git_dir = sh("git", "rev-parse", "--git-dir").stdout.strip()
    if not git_dir:
        return
    path = os.path.join(repo, git_dir, "info", "exclude") if not os.path.isabs(git_dir) else os.path.join(git_dir, "info", "exclude")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []
        if CM_MARKER not in lines:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(("" if not lines or lines[-1] == "" else "\n") + CM_MARKER + "\n")
    except OSError:
        pass
    if sh("git", "ls-files", "--error-unmatch", CM_MARKER).returncode == 0:
        sh("git", "rm", "-q", "--cached", CM_MARKER)  # was staged/tracked by cm; untrack, keep on disk


def cmd_fix(argv: List[str]) -> int:
    opts, ids = parse_opts(argv, FIX_VALUE_OPTS, FIX_FLAGS, passthrough=False)
    require_cm()
    ctx = Ctx(opts.get("--repo"))
    max_n = int(opts.get("--max") or 10)
    out_dir = opts.get("--out-dir") or ".codemender"
    build_id = ci_build_id(opts.get("--ci-build-id"))
    want_manifest = not opts["--no-manifest"]
    manifest_path = os.path.join(out_dir, "fix_manifest.json")

    ok = cfg_checks(ctx)
    if not (ok["project_paths"] and ok["reset"]):
        real_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            check_config(ctx)
        finally:
            sys.stdout = real_stdout
        die("refusing to fix — without project_paths + reset:\"true\" every 'cm fix' reverts earlier fixes. Add the YAML above to " + ctx.cfg, 2)

    if not ids:
        sel = select_findings(ctx.report(), ctx.repo, max_n)
        ids = [str(f["finding_id"]) for f in sel]
        print(f"cm-ci: selected {len(ids)} finding(s) (cap {max_n}):")
        for f in sel:
            print(f"  {f['finding_id']}  {f.get('severity', '')}  {f['_rel']}  {f.get('title', '')}")
    else:
        print(f"cm-ci: fixing {len(ids)} finding(s):")
        for i in ids:
            print(f"  {i}")
    if not ids:
        print("cm-ci: nothing to fix")
        return 0
    if opts["--dry-run"]:
        return 0

    pre = nested_git(ctx.repo)
    if pre:
        print("cm-ci: nested .git already present — remove before running:\n  " + "\n  ".join(pre), file=sys.stderr)
        return 3

    # There is no single run ID for the whole pass: `cm-ci.py fix` calls `cm fix` once
    # per finding, so each one is its own invocation. The manifest maps commit → session.
    fixes: List[dict] = []
    warnings: List[str] = []
    started_at = now_rfc3339()
    head_before = git_head(short=True)

    def save_fix_manifest() -> None:
        if not want_manifest:
            return
        os.makedirs(out_dir, exist_ok=True)
        write_json(manifest_path, build_fix_manifest(
            ci_build_id=build_id, repo=ctx.repo, head_before=head_before,
            head_after=git_head(short=True), started_at=started_at,
            finished_at=now_rfc3339(), fixes=fixes, warnings=warnings))
        print(f"cm-ci: → {manifest_path} (which session produced each commit)")

    fixed = failed = 0
    for fid in ids:
        print(f"\n── cm fix {fid} ──", flush=True)
        cmd = ["cm", "fix", fid, "-y", "--bypass-warning"] + (["--model", opts["--model"]] if opts.get("--model") else [])
        logs_before = list_session_logs(sessions_root(ctx)) if want_manifest else {}
        rc = subprocess.call(cmd, stdin=subprocess.DEVNULL)
        # Read the logs rather than scraping stdout: `cm fix` keeps streaming to the CI
        # console, and stdout does not carry the run ID at all. startSession retries on
        # AlreadyExists, so one invocation can own more than one session.
        run = collect_run(sessions_root(ctx), logs_before, "fix") if want_manifest else None
        entry = {"finding_id": fid,
                 "run_id": run["run_id"] if run else None,
                 "session_ids": run["session_ids"] if run else [],
                 "commit": None,
                 "status": "committed"}
        for w in (run or {}).get("warnings") or []:
            if w not in warnings:
                warnings.append(w)
        if run is not None:
            fixes.append(entry)

        n = nested_git(ctx.repo)
        if n:
            entry["status"] = "aborted_nested_git"
            save_fix_manifest()
            print("cm-ci: cm fix created a nested git repo — config not honoured:\n  " + "\n  ".join(n) +
                  f"\naborting; remove the .git link(s) above, check {ctx.cfg}, and inspect 'git status'.", file=sys.stderr)
            return 3
        if rc != 0:
            entry["status"] = "failed"
            entry["exit_code"] = rc
            print(f"cm-ci: cm fix {fid} exited {rc} — not committing")
            failed += 1
            continue
        exclude_cm_marker(ctx.repo)
        sh("git", "reset", "-q")  # drop whatever cm staged itself (e.g. its .cm_project marker)
        sh("git", "add", "-A" if opts["--include-new-files"] else "-u")
        if sh("git", "diff", "--cached", "--quiet").returncode == 0:
            entry["status"] = "no_tracked_changes"
            print(f"cm-ci: {fid} produced no tracked changes")
        else:
            sh("git", "commit", "-q", "-m", f"codemender: fix {fid}")
            entry["commit"] = git_head(short=True)
            fixed += 1
            print("cm-ci: committed " + sh("git", "diff", "--stat", "HEAD~1").stdout.strip().splitlines()[-1])
        untracked = sh("git", "ls-files", "--others", "--exclude-standard").stdout.strip()
        if untracked:
            print("cm-ci: untracked files left by the agent (review; --include-new-files to commit):\n  " + "\n  ".join(untracked.splitlines()))

    save_fix_manifest()
    head = sh("git", "rev-parse", "--short", "HEAD").stdout.strip()
    print(f"\ncm-ci: done — committed {fixed} fix(es), {failed} failed, HEAD={head}")
    return 0


# ─── main ────────────────────────────────────────────────────────────────────

def main(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 1
    if argv[0] in ("-V", "--version", "version"):
        print(f"cm-ci.py {CM_CI_VERSION} (requires cm {CM_MIN_VERSION_STR} or later)")
        return 0
    sub, rest = argv[0], argv[1:]
    cmds = {"check-config": cmd_check_config, "find": cmd_find, "fix": cmd_fix}
    if sub not in cmds:
        print(f"cm-ci: unknown subcommand '{sub}'\n{__doc__}", file=sys.stderr)
        return 1
    return cmds[sub](rest)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
