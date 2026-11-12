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
  --critical-high-only[=BOOL]  whether --complete focuses only on CRITICAL/HIGH issues (default: true)
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

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from codemender import CodeMender, ScanMode
from complete_scan import run_complete_scan
from deduplication import (
    ACTIVE,
    dedup,
    load_findings,
    remove_duplicates_in_db,
    status_of,
    summary_line,
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


def parse_opts(argv: List[str], with_value: Tuple[str, ...], flags: Tuple[str, ...], passthrough: bool):
    """Tiny option parser. Unknown args → positionals (or forwarded verbatim when passthrough)."""
    opts: Dict[str, Any] = {f: False for f in flags}
    rest: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in with_value:
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
    opts, rest = parse_opts(argv, ("--repo",), ("--yes", "--apply"), passthrough=False)
    if rest:
        die(f"check-config: unexpected argument {rest[0]}")
    ctx = Ctx(opts.get("--repo"))
    check_config(ctx, "apply" if (opts["--yes"] or opts["--apply"]) else "report")
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


def _parse_bool_flag(flag: str, raw: str) -> bool:
    val = _BOOL_LITERALS.get(raw.strip().lower())
    if val is None:
        die(f"option {flag} expects true or false (got {raw!r})")
    return bool(val)


def cmd_find(argv: List[str]) -> int:
    opts, cm_args = parse_opts(argv, ("--repo", "--existing", "--known", "--out-dir", "--fail-on", "--complete-runs"),
                               ("--no-update", "--no-dedup"), passthrough=True)
    need("cm")
    ctx = Ctx(opts.get("--repo"))
    out_dir = opts.get("--out-dir") or ".codemender"
    known_path = opts.get("--known") or os.path.join(out_dir, "known_findings.json")
    existing_path = opts.get("--existing")
    check_config(ctx, "warn")
    os.makedirs(out_dir, exist_ok=True)

    before = ctx.report()
    before_ids = {str(f.finding_id or "") for f in before}
    scan_mode = ScanMode.DEEP
    is_complete_scan = False
    target: Optional[str] = None
    extra_cm_flags: List[str] = []
    complete_runs = int(opts["--complete-runs"]) if opts.get("--complete-runs") is not None else 5
    critical_high_only = True
    idx = 0
    while idx < len(cm_args):
        arg = cm_args[idx]
        if arg == "--quick":
            scan_mode = ScanMode.QUICK
            is_complete_scan = False
        elif arg == "--diff":
            scan_mode = ScanMode.DIFF
            is_complete_scan = False
        elif arg == "--deep":
            scan_mode = ScanMode.DEEP
            is_complete_scan = False
        elif arg == "--complete":
            is_complete_scan = True
        elif arg.startswith("--complete-runs="):
            complete_runs = int(arg.split("=", 1)[1])
        elif arg == "--critical-high-only":
            if idx + 1 < len(cm_args) and cm_args[idx + 1].strip().lower() in _BOOL_LITERALS:
                critical_high_only = _parse_bool_flag(arg, cm_args[idx + 1])
                idx += 1
            else:
                critical_high_only = True
        elif arg.startswith("--critical-high-only="):
            critical_high_only = _parse_bool_flag("--critical-high-only", arg.split("=", 1)[1])
        elif arg == "--no-critical-high-only":
            critical_high_only = False
        elif not arg.startswith("-") and target is None:
            target = arg
        else:
            extra_cm_flags.append(arg)
        idx += 1
    print(f"cm-ci: cm find {' '.join(cm_args)}".rstrip(), flush=True)
    try:
        if is_complete_scan:
            run_complete_scan(
                ctx.cm,
                target_or_id=target,
                extra_flags=extra_cm_flags or None,
                complete_runs=complete_runs,
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
    except RuntimeError as e:
        print(f"cm-ci: {e}", file=sys.stderr)
        m = re.search(r"exit code (\d+)", str(e))
        return int(m.group(1)) if m else 1

    after = ctx.report()
    this_run = [f for f in after if str(f.finding_id or "") not in before_ids and status_of(f) in ACTIVE]
    findings_path = os.path.join(out_dir, "findings.json")
    write_json(findings_path, this_run)
    print(f"cm-ci: this run → {findings_path} ({len(this_run)} active finding(s))")
    if opts["--no-dedup"]:
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
    print("cm-ci: dedup against " + ", ".join(f"{name} ({len(items)})" for name, items in sources))
    res = dedup(pool, this_run, ctx.repo)
    print(summary_line(len(pool), len(this_run), res))
    new_path = os.path.join(out_dir, "new_findings.json")
    write_json(new_path, res)
    print(f"cm-ci: → {new_path} (findings = file these; reopened = fixed before, back again; suppressed_duplicates = already known)")

    r = remove_duplicates_in_db(ctx, res["suppressed_duplicates"])
    if r is not None:
        removed, marked = r
        extra = f" ({marked} referenced by a patch kept as DISMISSED)" if marked else ""
        print(f"cm-ci: removed {removed} duplicate row(s) from state.db{extra} — `cm report` now shows each bug once")
    elif res["suppressed_duplicates"]:
        print(f"cm-ci: note — state.db not found, duplicates only recorded in {new_path}")

    if not existing_path and not opts["--no-update"]:
        known_ids = {str(f.finding_id) for f in known}
        added = [f for f in res["findings"] + res["reopened"] if str(f.finding_id) not in known_ids]
        write_json(known_path, known + added)
        print(f"cm-ci: updated {known_path} ({len(known) + len(added)} entries) — commit it so the next run knows these")

    for f in res["reopened"]:
        print(f"  ♻ REOPENED {f.severity or ''} {f.file_path}:{f.start_line or ''} {f.title or ''} (was {f.duplicate_of})")
    for f in res["findings"]:
        print(f"  🆕 NEW      {f.severity or ''} {f.file_path}:{f.start_line or ''} {f.title or ''}")

    fail_on = opts.get("--fail-on")
    if fail_on:
        sevs = {s.strip().upper() for s in fail_on.split(",") if s.strip()}
        hits = [f for f in res["findings"] + res["reopened"] if str(f.severity or "").upper() in sevs]
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
    opts, ids = parse_opts(argv, ("--repo", "--model", "--max", "--known"), ("--include-new-files", "--dry-run"), passthrough=False)
    need("cm")
    ctx = Ctx(opts.get("--repo"))
    max_n = int(opts.get("--max") or 10)
    known_path = opts.get("--known") or os.path.join(".codemender", "known_findings.json")

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
    if opts["--dry-run"]:
        return 0

    pre = nested_git(ctx.repo)
    if pre:
        print("cm-ci: nested .git already present — remove before running:\n  " + "\n  ".join(pre), file=sys.stderr)
        return 3
    fixed = failed = 0
    for fid in ids:
        print(f"\n── cm fix {fid} ──", flush=True)
        cmd = ["cm", "fix", fid, "-y", "--bypass-warning"] + (["--model", opts["--model"]] if opts.get("--model") else [])
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
        sh("git", "add", "-A" if opts["--include-new-files"] else "-u")
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
                f = Finding(f.to_dict(), status=cur.status)
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
    opts, rest = parse_opts(argv, ("--existing", "--new", "--out", "--repo", "--repo-root"), (), passthrough=False)
    if rest or not opts.get("--existing") or not opts.get("--new"):
        die("dedup: --existing and --new are required")
    root = opts.get("--repo") or opts.get("--repo-root") or ""
    root = os.path.realpath(root) if root else ""
    existing = load_findings(opts["--existing"])
    current = load_findings(opts["--new"])
    res = dedup(existing, current, root)
    print(summary_line(len(existing), len(current), res))
    if opts.get("--out"):
        write_json(opts["--out"], res)
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
