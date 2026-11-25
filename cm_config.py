"""CodeMender `config.yaml` validation, YAML merging, and repository root inference."""

from datetime import datetime
import os
import subprocess
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
import yaml

from codemender import atomic_write_text

DEFAULT_EXCLUDE_DIRS: List[str] = [
    "venv",
    ".venv",
    "env",
    "site-packages",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "bin",
    "target",
    "obj",
    "build",
    ".gradle",
]


def _default_die(msg: str, code: int = 1) -> None:
    print(f"cm-ci: {msg}", file=sys.stderr)
    sys.exit(code)


def safe_getcwd() -> Optional[str]:
    try:
        return os.path.realpath(os.getcwd())
    except OSError:
        return None


def load_cm_config(cfg_path: str) -> Tuple[Dict[str, Any], bool]:
    """Loads `config.yaml` via PyYAML, returning `(parsed_dict, is_valid_yaml)`."""
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        return {}, True
    if not raw.strip():
        return {}, True
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError:
        return {}, False
    if parsed is None:
        return {}, True
    if isinstance(parsed, dict):
        return parsed, True
    return {}, False


def _raw_project_path_entries(cfg: Mapping[str, Any]) -> List[str]:
    raw = cfg.get("project_paths")
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = [str(x) for x in raw if x is not None and str(x).strip()]
    else:
        return []
    return [os.path.expanduser(item.strip()) for item in items if item.strip()]


def parse_project_paths(cfg: Mapping[str, Any]) -> List[str]:
    """Extracts existing real directories from `project_paths` in a parsed `config.yaml`."""
    resolved: List[str] = []
    seen: set = set()
    for p in _raw_project_path_entries(cfg):
        if not os.path.isabs(p):
            continue
        real_p = os.path.realpath(p)
        if real_p not in seen and os.path.isdir(real_p):
            seen.add(real_p)
            resolved.append(real_p)
    return resolved


def _enclosing_project_path(probe_dir: str, project_paths: List[str]) -> Optional[str]:
    matches = [
        p for p in project_paths
        if probe_dir == p or probe_dir.startswith(p + os.sep)
    ]
    return max(matches, key=len) if matches else None


def _git_toplevel(probe_dir: str) -> Optional[str]:
    if not probe_dir or not os.path.isdir(probe_dir):
        return None
    r = subprocess.run(
        ["git", "-C", probe_dir, "rev-parse", "--show-toplevel"],
        text=True,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=False,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return None
    top = os.path.realpath(r.stdout.strip())
    return top if os.path.isdir(top) else None


def _resolve_probe_dir(probe_dir: str, project_paths: List[str]) -> Optional[str]:
    cfg_match = _enclosing_project_path(probe_dir, project_paths)
    git_match = _git_toplevel(probe_dir)
    if cfg_match and git_match:
        return git_match if git_match.startswith(cfg_match + os.sep) else cfg_match
    return cfg_match or git_match


def infer_repo_dir(
    cm_dir: str,
    target_hint: Optional[str] = None,
    required: bool = True,
    die_fn: Callable[[str, int], None] = _default_die,
) -> Optional[str]:
    """Infers the repository root from `target_hint`, `cwd`, or `$CM_HOME/config.yaml`."""
    cfg_path = os.path.join(cm_dir, "config.yaml")
    cfg, _ = load_cm_config(cfg_path)
    cfg_paths = parse_project_paths(cfg)

    orig_cwd = safe_getcwd()
    if target_hint and target_hint not in (".", "./"):
        cand_raw = (
            target_hint
            if os.path.isabs(target_hint)
            else (os.path.join(orig_cwd, target_hint) if orig_cwd else None)
        )
        if cand_raw:
            cand = os.path.realpath(cand_raw)
            if os.path.exists(cand):
                probe = cand if os.path.isdir(cand) else os.path.dirname(cand)
                resolved = _resolve_probe_dir(probe, cfg_paths)
                if resolved:
                    return resolved

    if orig_cwd:
        resolved_cwd = _resolve_probe_dir(orig_cwd, cfg_paths)
        if resolved_cwd:
            return resolved_cwd

    if len(cfg_paths) == 1:
        return cfg_paths[0]

    if not required:
        return None
    if len(cfg_paths) > 1:
        die_fn(
            f"not inside a git repo and {cfg_path} lists multiple project_paths"
            f" ({len(cfg_paths)}) — use --repo DIR",
            1,
        )
    die_fn("not inside a git repo (use --repo DIR)", 1)
    return None


def cfg_checks(ctx: Any) -> Dict[str, bool]:
    """Validates `project_paths`, `vcs.commands.reset`, and `scan.exclude_dirs` in `ctx.cfg`."""
    cfg, valid = load_cm_config(ctx.cfg)
    if not valid:
        return {"project_paths": False, "reset": False, "exclude_dirs": False}

    real_repo = os.path.realpath(ctx.repo)
    raw_entries = _raw_project_path_entries(cfg)
    has_proj = (
        real_repo in parse_project_paths(cfg)
        or ctx.repo in raw_entries
        or real_repo in {os.path.realpath(p) for p in raw_entries if os.path.isabs(p)}
    )

    vcs = cfg.get("vcs")
    commands = vcs.get("commands") if isinstance(vcs, dict) else None
    reset_val = commands.get("reset") if isinstance(commands, dict) else cfg.get("reset")
    has_reset = reset_val is True or str(reset_val or "").strip().lower() == "true"

    scan = cfg.get("scan")
    excl_val = scan.get("exclude_dirs") if isinstance(scan, dict) else cfg.get("exclude_dirs")
    has_excl = isinstance(excl_val, list) and any(
        str(x).strip().rstrip("/") in ("venv", ".venv") for x in excl_val
    )
    return {
        "project_paths": has_proj,
        "reset": has_reset,
        "exclude_dirs": has_excl,
    }


def merge_required_config(
    cfg: Mapping[str, Any],
    repo: str,
    ok: Optional[Mapping[str, bool]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Merges missing CI config keys into `cfg`, returning `(merged_cfg, patch_preview)`."""
    merged: Dict[str, Any] = dict(cfg)
    preview: Dict[str, Any] = {}
    checks = dict(ok) if ok is not None else {"project_paths": False, "reset": False, "exclude_dirs": False}

    if not checks.get("project_paths"):
        existing_paths = _raw_project_path_entries(merged)
        if repo not in existing_paths:
            existing_paths.append(repo)
        merged["project_paths"] = existing_paths
        preview["project_paths"] = existing_paths

    if not checks.get("reset"):
        vcs_raw = merged.get("vcs")
        vcs_dict = dict(vcs_raw) if isinstance(vcs_raw, dict) else {}
        vcs_dict.setdefault("type", "git")
        cmds_raw = vcs_dict.get("commands")
        cmds_dict = dict(cmds_raw) if isinstance(cmds_raw, dict) else {}
        cmds_dict["reset"] = "true"
        vcs_dict["commands"] = cmds_dict
        merged["vcs"] = vcs_dict
        preview["vcs"] = {"type": vcs_dict["type"], "commands": {"reset": "true"}}

    if not checks.get("exclude_dirs"):
        scan_raw = merged.get("scan")
        scan_dict = dict(scan_raw) if isinstance(scan_raw, dict) else {}
        cur_excl = scan_dict.get("exclude_dirs")
        excl_list = [str(x) for x in cur_excl] if isinstance(cur_excl, list) else []
        for d in DEFAULT_EXCLUDE_DIRS:
            if d not in excl_list:
                excl_list.append(d)
        scan_dict["exclude_dirs"] = excl_list
        merged["scan"] = scan_dict
        preview["scan"] = {"exclude_dirs": excl_list}

    return merged, preview


def check_config(
    ctx: Any,
    mode: str,
    die_fn: Callable[[str, int], None] = _default_die,
) -> bool:
    """mode: report (exit 2 if incomplete) | apply | warn (never exits). Returns True when complete."""
    cfg, valid = load_cm_config(ctx.cfg)
    if not valid:
        print(f"cm-ci: {ctx.cfg} contains invalid YAML — fix syntax before applying CI settings.", file=sys.stderr)
        if mode == "warn":
            return False
        sys.exit(2)

    ok = cfg_checks(ctx)
    print(f"cm-ci: config check — {ctx.cfg}")
    why = {
        "project_paths": "cm fix/verify resolve the real repo root (no nested temp repo)",
        "reset": 'vcs.commands.reset="true" — no \'git checkout HEAD -- . && git clean -fd\' before each fix',
        "exclude_dirs": "scan.exclude_dirs lists venv/.venv (cm's default list has neither)",
    }
    for k in ("project_paths", "reset", "exclude_dirs"):
        print(f"{k:<15} {'OK' if ok[k] else 'MISSING'}\n    {why[k]}")
    if all(ok.values()):
        print("cm-ci: config complete")
        return True

    merged, preview = merge_required_config(cfg, ctx.repo, ok=ok)
    preview_yaml = yaml.safe_dump(preview, sort_keys=False, default_flow_style=False)
    print(f"\nSettings to merge into {ctx.cfg}:\n\n{preview_yaml}")

    ans = "n"
    if mode == "apply":
        ans = "y"
    elif mode == "report" and sys.stdin.isatty() and sys.stdout.isatty():
        ans = input(f"Apply to {ctx.cfg} now? [y/N] ").strip()

    if ans.lower() in ("y", "yes"):
        header = f"# updated by cm-ci.py {datetime.now().date()} — CodeMender CI settings (fix persistence, venv noise)\n"
        dumped = yaml.safe_dump(merged, sort_keys=False, default_flow_style=False)
        atomic_write_text(ctx.cfg, header + dumped)
        print(f"cm-ci: wrote {ctx.cfg}")
        if not all(cfg_checks(ctx).values()):
            die_fn(f"config still incomplete after writing {ctx.cfg}", 1)
        return True

    if mode == "warn":
        print(
            "cm-ci: warning — config incomplete; run 'cm-ci.py check-config --yes' "
            "(findings under venv/ will be reported; cm fix would revert earlier fixes)",
            file=sys.stderr,
        )
        return False
    die_fn("config incomplete — re-run with --yes to apply", 2)
    return False
