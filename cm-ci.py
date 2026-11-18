#!/usr/bin/env python3
"""cm-ci.py — CodeMender wrapper for CI: no duplicate findings across runs, no lost fixes.

Single file, standard library only (python3 >= 3.8). Needs `cm` and `git` on PATH.

  cm-ci.py check-config [--yes]                 detect the config CodeMender needs in CI,
                                                print the YAML to add, apply it (--yes / prompt)
  cm-ci.py find [wrapper opts] <cm find args>   run `cm find` (every cm flag passes through:
                                                --deep, --context, --diff, --model, -y, ...),
                                                export this run, drop cross-run duplicates and
                                                DISMISS them in CodeMender's own database so
                                                `cm report` stays consolidated
  cm-ci.py fix [options] [FINDING_ID ...]       run `cm fix` safely: one commit per fix, abort
                                                if the tree was reset, refresh known findings
  cm-ci.py dedup --existing A --new B [--out F] standalone dedup of two exports

find wrapper options (everything else is forwarded to `cm find` unchanged):
  --repo DIR        repo root (default: git toplevel of cwd)
  --existing FILE   previous `cm report --format json` export OR
                    `gh issue list --state all --json number,title,state,body` output
  --known FILE      running list of known findings (default .codemender/known_findings.json)
  --out-dir DIR     where findings.json / new_findings.json go (default .codemender)
  --fail-on SEVS    exit 4 if a new or reopened finding has one of these severities
  --critical-high-only[=BOOL]  focus on CRITICAL/HIGH issues (default: true for --complete, false otherwise)
  --no-update       do not append this run's new findings to --known
  --no-dedup        only run cm find + export
fix options:
  --repo DIR  --model M  --max N (default 10)  --known FILE  --include-new-files  --dry-run

Exit codes: 0 ok · 1 usage/tool missing · 2 config missing · 3 workspace reset detected ·
            4 --fail-on hit · otherwise the exit code of `cm find`

Duplicate rule (same as is_duplicate.py / .sh, validated on a 60-repo corpus): same
repository-relative file, same CWE family, and (line ranges overlap OR every code line of
the shorter snippet appears verbatim in the longer one).
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from codemender import CodeMender, ScanMode
from complete_scan import (
    _reconcile_overwritten_findings,
    _snapshot_db_findings,
    restore_interrupted_workspace,
    run_complete_scan,
)
from deduplication import (
    ACTIVE,
    dedup,
    higher_severity,
    is_critical_high,
    load_findings,
    remove_duplicates_in_db,
    severity_rank,
    status_of,
    summary_line,
    upgrade_finding_severity_in_db,
)
from finding import Finding

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
        restore_interrupted_workspace(self.repo, cm_dir=self.cm_dir)
        self.cfg = os.path.join(self.cm_dir, "config.yaml")
        self.cm = CodeMender(repo_dir=self.repo)

    def report(self) -> List[Finding]:
        try:
            return self.cm.list_findings()
        except (RuntimeError, json.JSONDecodeError):
            return []


def write_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(
            payload,
            fh,
            indent=2,
            default=lambda o: o.to_dict() if isinstance(o, Finding) else o,
        )
        fh.write("\n")
    os.replace(tmp, path)


class _ArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that disables prefix abbreviation and exits 1 (via die) on CLI errors."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(**kwargs)

    def print_help(self, file: Any = None) -> None:
        print(__doc__, file=file or sys.stdout)

    def error(self, message: str) -> None:
        die(message, 1)


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


def check_config(ctx: Ctx, mode: str) -> bool:
    """mode: report (exit 2 if incomplete) | apply | warn (never exits). Returns True when complete."""
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
    add, manual = "", False
    if not ok["project_paths"]:
        manual |= cfg_has_section(ctx, "project_paths")
        add += f'project_paths: ["{ctx.repo}"]\n'
    if not ok["reset"]:
        manual |= cfg_has_section(ctx, "vcs")
        add += 'vcs:\n  type: git\n  commands:\n    reset: "true"\n'
    if not ok["exclude_dirs"]:
        manual |= cfg_has_section(ctx, "scan")
        add += f"scan:\n  exclude_dirs: {EXCLUDE_DIRS}\n"
    print(f"\nAdd to {ctx.cfg}:\n\n{add}")
    if manual:
        print(f"cm-ci: {ctx.cfg} already has one of these sections — merge the keys above manually (not rewriting your file).", file=sys.stderr)
        if mode == "warn":
            return False
        sys.exit(2)
    ans = "n"
    if mode == "apply":
        ans = "y"
    elif mode == "report" and sys.stdin.isatty() and sys.stdout.isatty():
        ans = input(f"Apply to {ctx.cfg} now? [y/N] ").strip()
    if ans.lower() in ("y", "yes"):
        os.makedirs(ctx.cm_dir, exist_ok=True)
        existing = _cfg_text(ctx)
        with open(ctx.cfg, "a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            if existing.strip():
                fh.write("\n")
            fh.write(f"# added by cm-ci.py {datetime.now().date()} — CodeMender CI settings (fix persistence, venv noise)\n{add}")
        print(f"cm-ci: wrote {ctx.cfg}")
        if not all(cfg_checks(ctx).values()):
            die(f"config still incomplete after writing {ctx.cfg}")
        return True
    if mode == "warn":
        print("cm-ci: warning — config incomplete; run 'cm-ci.py check-config --yes' "
              "(findings under venv/ will be reported; cm fix would revert earlier fixes)", file=sys.stderr)
        return False
    die("config incomplete — re-run with --yes to apply", 2)
    return False


def cmd_check_config(argv: List[str]) -> int:
    parser = _ArgumentParser(prog="cm-ci.py check-config")
    parser.add_argument("--repo")
    parser.add_argument("--yes", "--apply", dest="apply", action="store_true")
    args = parser.parse_args(argv)
    ctx = Ctx(args.repo)
    check_config(ctx, "apply" if args.apply else "report")
    return 0


# ─── find ────────────────────────────────────────────────────────────────────

_BOOL_LITERALS = {
    "true": True,
    "1": True,
    "yes": True,
    "y": True,
    "on": True,
    "false": False,
    "0": False,
    "no": False,
    "n": False,
    "off": False,
}

# `cm find` and global `cm` options that take a value argument; registered on the
# `find` parser so space-separated forms (e.g. `--model gemini-2.5-pro`) don't steal `target`.
_CM_FIND_VALUE_FLAGS = (
    ("-c", "--context"),
    ("--deep-max-turns",),
    ("--deep-workers",),
    ("--diff-job-timeout",),
    ("--diff-max-neighbors",),
    ("--diff-workers",),
    ("--format",),
    ("--model",),
    ("--output",),
    ("--team-id",),
)


def _parse_bool_flag(flag: str, raw: str) -> bool:
    val = _BOOL_LITERALS.get(raw.strip().lower())
    if val is None:
        die(f"option {flag} expects true or false (got {raw!r})")
    return bool(val)


class _ForwardValueAction(argparse.Action):
    """Appends `[option_string, value]` to `namespace.passthrough` for forwarding to `cm find`."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        items = list(getattr(namespace, self.dest, None) or ())
        if option_string:
            items.append(option_string)
        items.append(str(values))
        setattr(namespace, self.dest, items)


class _DiffAction(argparse.Action):
    """Switches scan mode to `diff` and captures an optional git ref."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        namespace.mode = "diff"
        namespace.diff_ref = values


def _build_find_parser() -> _ArgumentParser:
    parser = _ArgumentParser(prog="cm-ci.py find")
    parser.set_defaults(mode="deep", diff_ref=None, passthrough=None)
    parser.add_argument("--repo")
    parser.add_argument("--existing")
    parser.add_argument("--known")
    parser.add_argument("--out-dir", default=".codemender")
    parser.add_argument("--fail-on")
    parser.add_argument("--no-update", action="store_true")
    parser.add_argument("--no-dedup", action="store_true")
    parser.add_argument("--complete-runs", type=int, default=5)
    parser.add_argument("--quick", dest="mode", action="store_const", const="quick")
    parser.add_argument("--deep", dest="mode", action="store_const", const="deep")
    parser.add_argument("--complete", dest="mode", action="store_const", const="complete")
    parser.add_argument("--diff", action=_DiffAction, nargs="?", const="")
    parser.add_argument("--critical-high-only", dest="critical_high_only", nargs="?", const="true", default=None)
    parser.add_argument("--no-critical-high-only", dest="critical_high_only", action="store_const", const="false")
    for flag_names in _CM_FIND_VALUE_FLAGS:
        parser.add_argument(*flag_names, dest="passthrough", action=_ForwardValueAction)
    parser.add_argument("target", nargs="?")
    return parser


def cmd_find(argv: List[str]) -> int:
    args, unknown = _build_find_parser().parse_known_args(argv)
    need("cm")
    ctx = Ctx(args.repo)
    out_dir = args.out_dir or ".codemender"
    known_path = args.known or os.path.join(out_dir, "known_findings.json")
    existing_path = args.existing
    check_config(ctx, "warn")
    os.makedirs(out_dir, exist_ok=True)

    before = ctx.report()
    before_ids = {str(f.finding_id or "") for f in before}
    pre_find_rows = _snapshot_db_findings(ctx.cm)

    target: Optional[str] = args.target
    extra_cm_flags: List[str] = []
    if args.mode == "diff" and args.diff_ref:
        if target is None and os.path.exists(args.diff_ref):
            target = args.diff_ref
        else:
            extra_cm_flags.append(f"--diff={args.diff_ref}")

    critical_high_flag: Optional[bool] = None
    if args.critical_high_only is not None:
        raw_ch = args.critical_high_only
        if raw_ch.strip().lower() not in _BOOL_LITERALS and target is None and os.path.exists(raw_ch):
            target = raw_ch
            critical_high_flag = True
        else:
            critical_high_flag = _parse_bool_flag("--critical-high-only", raw_ch)

    if args.passthrough:
        extra_cm_flags.extend(args.passthrough)
    extra_cm_flags.extend(unknown)

    is_complete_scan = args.mode == "complete"
    scan_mode = ScanMode.DEEP if is_complete_scan else ScanMode(args.mode)
    critical_high_only = critical_high_flag if critical_high_flag is not None else is_complete_scan
    preview_parts = ([target] if target else []) + [f"--{args.mode}"] + extra_cm_flags
    print(f"cm-ci: cm find {' '.join(preview_parts)}".rstrip(), flush=True)
    try:
        if is_complete_scan:
            run_complete_scan(
                ctx.cm,
                target_or_id=target,
                extra_flags=extra_cm_flags or None,
                complete_runs=args.complete_runs,
                critical_high_only=critical_high_only,
            )
        else:
            find_kwargs: Dict[str, Any] = {
                "target_or_id": target,
                "scan_mode": scan_mode,
            }
            if extra_cm_flags:
                find_kwargs["extra_flags"] = extra_cm_flags
            ctx.cm.find(**find_kwargs)
            _reconcile_overwritten_findings(ctx.cm, pre_find_rows, restore_session_id=False)
    except RuntimeError as e:
        print(f"cm-ci: {e}", file=sys.stderr)
        m = re.search(r"exit code (\d+)", str(e))
        return int(m.group(1)) if m else 1

    after = ctx.report()
    this_run = [f for f in after if str(f.finding_id or "") not in before_ids and status_of(f) in ACTIVE]
    this_run_shown = [f for f in this_run if is_critical_high(f)] if critical_high_only else this_run
    findings_path = os.path.join(out_dir, "findings.json")
    write_json(findings_path, this_run)
    if critical_high_only:
        print(f"cm-ci: this run (CRITICAL/HIGH mode) → {findings_path} ({len(this_run_shown)} CRITICAL/HIGH active finding(s))")
    else:
        print(f"cm-ci: this run → {findings_path} ({len(this_run)} active finding(s))")
    if args.no_dedup:
        return 0

    # Pool = what CodeMender already knows on this machine (previous sessions in its DB),
    # plus the repo's known list, plus an explicit export / issue list.
    pool: List[Finding] = []
    seen: set = set()
    sources = [("cm database (previous sessions)", before)]
    known: List[Finding] = []
    if os.path.exists(known_path):
        known = load_findings(known_path)
        sources.append((known_path, known))
    if existing_path:
        sources.append((existing_path, load_findings(existing_path)))
    for name, items in sources:
        for f in items:
            key = str(f.finding_id or f.gh_issue_number or id(f))
            if key in seen:
                continue
            seen.add(key); pool.append(f)
    if critical_high_only:
        print("cm-ci: dedup against " + ", ".join(f"{name} ({sum(1 for f in items if is_critical_high(f))} CRITICAL/HIGH)" for name, items in sources))
    else:
        print("cm-ci: dedup against " + ", ".join(f"{name} ({len(items)})" for name, items in sources))
    res = dedup(pool, this_run, ctx.repo)
    if critical_high_only:
        existing_ch_n = sum(1 for f in pool if is_critical_high(f))
        print(summary_line(existing_ch_n, len(this_run_shown), res, critical_high_only=True))
    else:
        print(summary_line(len(pool), len(this_run), res))
    new_path = os.path.join(out_dir, "new_findings.json")
    write_json(new_path, res)
    print(f"cm-ci: → {new_path} (findings = file these; reopened = fixed before, back again; suppressed_duplicates = already known)")

    r = remove_duplicates_in_db(ctx, res["suppressed_duplicates"])
    if ctx.cm.db is not None:
        try:
            db_cols = {row[1] for row in ctx.cm.db.execute("PRAGMA table_info(findings)")}
            upgraded_any = False
            for f in res["findings"] + res["reopened"]:
                if f.finding_id and f.severity:
                    upgraded_any |= upgrade_finding_severity_in_db(ctx.cm.db, db_cols, f.finding_id, f.severity)
            if upgraded_any:
                ctx.cm.db.commit()
        except Exception:
            pass
    if r is not None:
        removed, marked = r
        extra = f" ({marked} referenced by a patch kept as DISMISSED)" if marked else ""
        print(f"cm-ci: removed {removed} duplicate row(s) from state.db{extra} — `cm report` now shows each bug once")
    elif res["suppressed_duplicates"]:
        print(f"cm-ci: note — state.db not found, duplicates only recorded in {new_path}")

    if not existing_path and not args.no_update:
        after_by_id = {str(f.finding_id): f for f in ctx.report() if f.finding_id}
        upgraded_known: List[Finding] = []
        for kf in known:
            best_sev = kf.severity
            cur_db = after_by_id.get(str(kf.finding_id))
            if cur_db is not None:
                best_sev = higher_severity(best_sev, cur_db.severity)
            for d in res["suppressed_duplicates"]:
                if str(d.duplicate_of or "") == str(kf.finding_id) or (
                    kf.gh_issue_number is not None and str(d.duplicate_of or "") == str(kf.gh_issue_number)
                ):
                    best_sev = higher_severity(best_sev, d.severity)
            if best_sev and severity_rank(best_sev) < severity_rank(kf.severity):
                kf = Finding(kf.to_dict(), severity=best_sev)
            upgraded_known.append(kf)
        known_ids = {str(f.finding_id) for f in upgraded_known}
        added = [f for f in res["findings"] + res["reopened"] if str(f.finding_id) not in known_ids]
        write_json(known_path, upgraded_known + added)
        if critical_high_only:
            added_ch = [f for f in added if is_critical_high(f)]
            print(f"cm-ci: updated {known_path} (+{len(added_ch)} new CRITICAL/HIGH, {len(upgraded_known) + len(added)} total entries) — commit it so the next run knows these")
        else:
            print(f"cm-ci: updated {known_path} ({len(upgraded_known) + len(added)} entries) — commit it so the next run knows these")

    shown_reopened = [f for f in res["reopened"] if is_critical_high(f)] if critical_high_only else res["reopened"]
    shown_findings = [f for f in res["findings"] if is_critical_high(f)] if critical_high_only else res["findings"]
    for f in shown_reopened:
        print(f"  ♻ REOPENED {f.severity or ''} {f.file_path}:{f.start_line or ''} {f.title or ''} (was {f.duplicate_of})")
    for f in shown_findings:
        print(f"  🆕 NEW      {f.severity or ''} {f.file_path}:{f.start_line or ''} {f.title or ''}")

    fail_on = args.fail_on
    if fail_on:
        sevs = {s.strip().upper() for s in fail_on.split(",") if s.strip()}
        hits = [f for f in shown_findings + shown_reopened if str(f.severity or "").upper() in sevs]
        if hits:
            print(f"cm-ci: {len(hits)} new/reopened finding(s) at severity {fail_on} — failing", file=sys.stderr)
            return 4
    return 0


# ─── fix ─────────────────────────────────────────────────────────────────────

SKIP_DIRS = ("venv/", ".venv/", "site-packages/", "node_modules/")


def rel_path(p: str, root: str) -> str:
    p = str(p or "")
    return p[len(root) + 1:] if p.startswith(root + "/") else p


def vclass(f: Finding) -> str:
    s = f"{f.vuln_id or ''} {f.vuln_type or ''}"
    m = re.search(r"cwe-?\s*(\d+)", s, re.I)
    return f"cwe-{m.group(1)}" if m else re.sub(r"\s+", " ", str(f.vuln_type or "")).strip().lower()


def select_findings(findings: List[Finding], root: str, max_n: int) -> Tuple[List[Finding], int]:
    rows = []
    for f in findings:
        if status_of(f) not in ACTIVE:
            continue
        rel = rel_path(f.file_path or "", root)
        if any(s in rel + "/" for s in SKIP_DIRS):
            continue
        rows.append((SEV_RANK.get(str(f.severity or "").upper(), 9), rel, f))
    rows.sort(key=lambda r: r[0])
    seen, dups, out = set(), 0, []
    for _, rel, f in rows:
        key = (rel, vclass(f), re.sub(r"\s+", " ", str(f.snippet or "")).strip())
        if key in seen:
            dups += 1
            continue
        seen.add(key); out.append(Finding(f.to_dict(), _rel=rel))
    return out[:max_n], dups


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
    parser = _ArgumentParser(prog="cm-ci.py fix")
    parser.add_argument("--repo")
    parser.add_argument("--model")
    parser.add_argument("--max", dest="max_n", type=int, default=10)
    parser.add_argument("--known")
    parser.add_argument("--include-new-files", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("ids", nargs="*")
    args = parser.parse_intermixed_args(argv)
    need("cm")
    ctx = Ctx(args.repo)
    max_n = args.max_n
    ids = list(args.ids)
    known_path = args.known or os.path.join(".codemender", "known_findings.json")

    ok = cfg_checks(ctx)
    if not (ok["project_paths"] and ok["reset"]):
        real_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            check_config(ctx, "warn")
        finally:
            sys.stdout = real_stdout
        die("refusing to fix — without project_paths + reset:\"true\" every 'cm fix' reverts earlier fixes. Run: cm-ci.py check-config --yes", 2)

    if not ids:
        sel, dups = select_findings(ctx.report(), ctx.repo, max_n)
        ids = [str(f.finding_id) for f in sel]
        note = f"; {dups} duplicate(s) collapsed (same file/class/snippet)" if dups else ""
        print(f"cm-ci: selected {len(ids)} finding(s) (cap {max_n}){note}:")
        for f in sel:
            rel = f._get("_rel") or rel_path(f.file_path or "", ctx.repo)
            print(f"  {f.finding_id}  {f.severity or ''}  {rel}  {f.title or ''}")
    else:
        print(f"cm-ci: fixing {len(ids)} finding(s):")
        for i in ids:
            print(f"  {i}")
    if not ids:
        print("cm-ci: nothing to fix")
        return 0
    if args.dry_run:
        return 0

    pre = nested_git(ctx.repo)
    if pre:
        print("cm-ci: nested .git already present — remove before running:\n  " + "\n  ".join(pre), file=sys.stderr)
        return 3
    fixed = failed = 0
    for fid in ids:
        print(f"\n── cm fix {fid} ──", flush=True)
        cmd = ["cm", "fix", fid, "-y", "--bypass-warning"] + (["--model", args.model] if args.model else [])
        rc = subprocess.call(cmd, stdin=subprocess.DEVNULL)
        n = nested_git(ctx.repo)
        if n:
            print("cm-ci: cm fix created a nested git repo — config not honoured:\n  " + "\n  ".join(n) +
                  f"\naborting; remove the .git link(s) above, check {ctx.cfg}, and inspect 'git status'.", file=sys.stderr)
            return 3
        if rc != 0:
            print(f"cm-ci: cm fix {fid} exited {rc} — not committing")
            failed += 1
            continue
        exclude_cm_marker(ctx.repo)
        sh("git", "reset", "-q")  # drop whatever cm staged itself (e.g. its .cm_project marker)
        sh("git", "add", "-A" if args.include_new_files else "-u")
        if sh("git", "diff", "--cached", "--quiet").returncode == 0:
            print(f"cm-ci: {fid} produced no tracked changes")
        else:
            sh("git", "commit", "-q", "-m", f"codemender: fix {fid}")
            fixed += 1
            print("cm-ci: committed " + sh("git", "diff", "--stat", "HEAD~1").stdout.strip().splitlines()[-1])
        untracked = sh("git", "ls-files", "--others", "--exclude-standard").stdout.strip()
        if untracked:
            print("cm-ci: untracked files left by the agent (review; --include-new-files to commit):\n  " + "\n  ".join(untracked.splitlines()))

    if os.path.exists(known_path):
        by_id = {str(f.finding_id): f for f in ctx.report()}
        known = load_findings(known_path)
        updated_known = []
        for f in known:
            cur = by_id.get(str(f.finding_id))
            if cur is not None:
                best_sev = higher_severity(f.severity, cur.severity)
                updates: Dict[str, Any] = {"status": cur.status}
                if best_sev:
                    updates["severity"] = best_sev
                f = Finding(f.to_dict(), **updates)
            updated_known.append(f)
        write_json(known_path, updated_known)
        sh("git", "add", known_path)
        if sh("git", "diff", "--cached", "--quiet").returncode != 0:
            sh("git", "commit", "-q", "-m", f"codemender: update known_findings ({fixed} fix(es))")
    head = sh("git", "rev-parse", "--short", "HEAD").stdout.strip()
    print(f"\ncm-ci: done — committed {fixed} fix(es), {failed} failed, HEAD={head}")
    return 0


# ─── dedup (standalone) ──────────────────────────────────────────────────────

def cmd_dedup(argv: List[str]) -> int:
    parser = _ArgumentParser(prog="cm-ci.py dedup")
    parser.add_argument("--existing", required=True)
    parser.add_argument("--new", required=True)
    parser.add_argument("--out")
    parser.add_argument("--repo", "--repo-root", dest="repo")
    args = parser.parse_args(argv)
    root = os.path.realpath(args.repo) if args.repo else ""
    existing = load_findings(args.existing)
    current = load_findings(args.new)
    res = dedup(existing, current, root)
    print(summary_line(len(existing), len(current), res))
    if args.out:
        write_json(args.out, res)
    return 0


# ─── main ────────────────────────────────────────────────────────────────────

def main(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 1
    sub, rest = argv[0], argv[1:]
    cmds = {"check-config": cmd_check_config, "find": cmd_find, "fix": cmd_fix, "dedup": cmd_dedup}
    if sub not in cmds:
        print(f"cm-ci: unknown subcommand '{sub}'\n{__doc__}", file=sys.stderr)
        return 1
    return cmds[sub](rest)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
