# `cm-ci.py` — CodeMender wrapper for CI: duplicate findings and fix persistence

A single script that wraps the CodeMender CLI (`cm`) for use in CI pipelines. It addresses three things:

1. **Duplicate findings across runs** — every `cm find` reports the same bugs again under new IDs. `cm-ci.py find` recognises findings you already know about (earlier runs in CodeMender's own database, a previous export, your GitHub issues, or a file kept in the repo), removes the duplicates from CodeMender's database so `cm report` shows each bug once, and flags any that were fixed but came back.
2. **Fixes being undone** — running `cm fix` for several findings in a row can silently revert earlier fixes in the same directory. `cm-ci.py fix` applies the required configuration, commits after every fix and stops if the problem is detected.
3. **Noise from virtual environments** — findings under `venv/`, `.venv/`, `node_modules/` etc. are excluded from scans and skipped when fixing.

**Requirements:** `python3` (3.8 or later, standard library only), `git`, and `cm` on `PATH`.
**Package contents:** `README.md`, `cm-ci.py`

---

## 1. One-time setup

```bash
chmod +x cm-ci.py
cd /path/to/your/repo
./cm-ci.py check-config          # shows OK / MISSING per setting and the YAML to add; asks before writing
./cm-ci.py check-config --yes    # CI: apply without asking
```

This adds three settings to `~/.codemender/config.yaml` (or `$CM_HOME/config.yaml`):

```yaml
project_paths: ["/abs/path/to/your/repo"]
vcs:
  type: git
  commands:
    reset: "true"
scan:
  exclude_dirs: ["venv", ".venv", "env", "site-packages", "__pycache__", "node_modules", "vendor", "dist", "bin", "target", "obj", "build", ".gradle"]
```

- `project_paths` is the absolute path of the checkout on that machine/runner.
- The script only appends when the file has no `project_paths:` / `vcs:` / `scan:` section yet. If it does, it prints the settings and asks you to merge them by hand (exit 2); it never rewrites your file.
- Run `cm fix` only on a clean working tree (no uncommitted changes).

## 2. Scan: `cm-ci.py find`

Any argument that is not a wrapper option is passed to `cm find` unchanged, so all CodeMender flags work:

```bash
./cm-ci.py find -y .
./cm-ci.py find --deep --deep-workers 8 -y .
./cm-ci.py find --context "focus on the auth module" -y src/
./cm-ci.py find --diff origin/main -y .
./cm-ci.py find --existing existing.json --fail-on CRITICAL,HIGH -y .
```

Output in `.codemender/` (change with `--out-dir`):

| file | content |
|---|---|
| `findings.json` | this run's findings, same format as `cm report --format json` |
| `new_findings.json` | `findings` — not seen before, file these (each has a `github_marker` to put in the issue body)<br>`reopened` — duplicate of a finding that was fixed / closed: a regression, reopen it<br>`suppressed_duplicates` — already known (`duplicate_of` says which) |

Console summary: `Existing: N | Current: N | Duplicates suppressed: N | New to file: N | Reopened: N`.

**Pool** = the set of already-known findings this run is compared against. It is the union of:

| source | always? | notes |
|---|---|---|
| CodeMender's own database on this machine (findings from earlier sessions) | yes | so repeated `cm find` runs on the same machine never produce duplicates |
| `.codemender/known_findings.json` in the repo | if present | created on the first run, extended with each run's new findings; commit it so a fresh runner sees it (`--no-update` to leave it untouched) |
| `--existing FILE` | if given | either format is auto-detected:<br>• a previous `cm report --format json` export<br>• a GitHub issue export, `gh issue list --state all --json number,title,state,body`, for issues whose body contains the `github_marker` from an earlier `new_findings.json` |

Suppressed duplicates are **removed from CodeMender's database** (together with the duplicate rows the CLI itself writes in `--deep` mode), so `cm report` lists each bug exactly once. The full record of every removed duplicate is kept in `new_findings.json → suppressed_duplicates`. Reopened findings stay OPEN — they are real.

Two findings are the same bug when they are in the same file, have the same vulnerability class, and their line ranges overlap or one snippet's code lines are contained in the other's — the same rule as the `is_duplicate` script shared earlier, built in. This also collapses findings the CLI lists twice within one report.

Wrapper options:

| option | meaning |
|---|---|
| `--existing FILE` | add a previous export / GitHub issue list to the pool (see above) |
| `--fail-on SEVS` | comma-separated severities, e.g. `CRITICAL,HIGH`. Exit **4** if any **new or reopened** finding has one of them — suppressed duplicates never trigger it. Use it to fail the CI job only on things that need action |
| `--known FILE` | alternative path for `known_findings.json` |
| `--out-dir DIR` | where to write the output files (default `.codemender/`) |
| `--repo DIR` | repo root (default: the git toplevel of the current directory) |
| `--no-update` | do not extend `known_findings.json` |
| `--no-dedup` | run `cm find` and export `findings.json` only |

## 3. Fix: `cm-ci.py fix`

```bash
./cm-ci.py fix --dry-run                  # show what would be fixed
./cm-ci.py fix                            # open findings, worst severity first, at most 10
./cm-ci.py fix --max 3                    # same, at most 3
./cm-ci.py fix <finding-id> ...           # exactly these
./cm-ci.py fix --model <model> <finding-id>
```

For each finding: `cm fix <id> -y --bypass-warning`, then `git commit -m "codemender: fix <id>"` with the tracked changes only. Files the fix agent created (e.g. scratch tests) are listed but not committed unless you pass `--include-new-files`. The `.cm_project` marker that CodeMender writes at the repo root is kept out of git (via `.git/info/exclude`, your `.gitignore` is not touched). Afterwards the statuses in `known_findings.json` are refreshed so a fixed bug that comes back is reported as `reopened` by the next `find`.

The command refuses to run (exit 2) until `check-config` has been applied, and stops with exit 3 if it detects that a fix reset the working tree anyway — in that case nothing further is committed and the path to inspect is printed.

| option | meaning |
|---|---|
| `--max N` | when no ids are given: fix at most N open findings, ordered CRITICAL → HIGH → MEDIUM → LOW (default 10). Findings under virtual-env directories and same-file/same-class twins are skipped |
| `--model M` | passed to `cm fix --model` |
| `--include-new-files` | also commit files the fix agent created |
| `--dry-run` | print the selection, change nothing |
| `--known FILE`, `--repo DIR` | as for `find` |

## 4. Standalone dedup: `cm-ci.py dedup`

Compare two exports without running a scan:

```bash
./cm-ci.py dedup --existing prev.json --new current.json --out new_issues.json [--repo /abs/repo]
```

## 5. CI checklist

1. Runner image has `python3`, `git`, `cm`. First step: `./cm-ci.py check-config --yes`.
2. Clean working tree on a branch.
3. `./cm-ci.py find [--existing existing.json] [--fail-on CRITICAL,HIGH] <cm flags> .`
4. File issues from `new_findings.json → findings`; reopen those in `reopened`.
5. Optional: `./cm-ci.py fix --max N`, then push the branch / open a PR (one commit per finding).
6. If you rely on `known_findings.json` rather than `--existing`, commit `.codemender/known_findings.json` so the next runner knows what was already found.
7. Treat exit 3 as a job failure.

**Exit codes:** `0` ok · `1` usage / tool missing · `2` configuration missing · `3` fix reset detected · `4` `--fail-on` hit · otherwise the exit code of `cm find`.

## 6. Notes

- `findings.json` and `new_findings.json` are overwritten on each `find`; archive them as CI artifacts if you need history.
- `reopened` means the scanner reports the same weakness again on code that was fixed. In practice this is either a regression or an incomplete fix — review it like any other finding; it is never dismissed automatically.
- Repeated scans of unchanged code can still surface a few *genuinely new* findings (the scanner is not fully deterministic). These are new locations or new weakness classes, not duplicates; they land in `findings`, and once filed they are recognised by every later run.

