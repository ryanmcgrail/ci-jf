# `cm-ci.py` — CodeMender wrapper for CI

A single script that wraps the CodeMender CLI (`cm`) for use in CI pipelines. It addresses four things:

1. **No handle on a multi-session scan** — `cm find --deep` and `cm find --diff` split the work across many agent sessions (one per file), and the CLI does not print anything that ties them together. `cm-ci.py find` gives each scan one ID, lists every session it spawned, and totals what the scan cost. See [section 3](#3-run-correlation-one-id-for-a-multi-session-scan).
2. **No way to tell what a scan actually surfaced, or to gate CI on it** — `cm report --status OPEN` is everything ever found, not this run's delta, and `cm find --fail-on` is only evaluated on `--diff` scans, so on a plain or `--deep` scan it silently does nothing. `cm-ci.py find` reports new / reopened / already-known and fails the build on the first two only. See [section 2](#2-scan-cm-cipy-find).
3. **Fixes being undone** — running `cm fix` for several findings in a row can silently revert earlier fixes in the same directory. `cm-ci.py fix` checks the required configuration up front, commits after every fix, and stops if the problem is detected.
4. **Noise from virtual environments** — findings under `venv/`, `.venv/`, `node_modules/` etc. are excluded from scans (via config) and skipped when fixing.

> [!IMPORTANT]
> **Duplicate findings are no longer this script's job.** Up to `cm` 0.12.0, repeated scans filed the
> same bug again under a new ID, and version 1.x of this wrapper removed those duplicates itself.
> `cm` 0.13.0 matches findings across runs natively: a repeated scan updates the existing finding
> instead of adding a second one, and a bug that was fixed and came back returns as `REOPENED`.
> Version 2.0.0 therefore **requires `cm` 0.13.0 or later and refuses to start on anything older**,
> and all the dedup options are gone. See [upgrading from 1.x](#7-upgrading-from-1x).

**Version:** `cm-ci.py` 2.0.0 (`./cm-ci.py --version`). Recorded in both manifests, so an archived build says which wrapper produced it.
**CodeMender CLI:** **`cm` 0.13.0 or later.** The wrapper checks `cm --version` first and exits 2 if it is older. Run `cm update`.
**Requirements:** `python3` (3.8 or later, standard library only), `git`, and `cm` on `PATH`.
**Package contents:** `README.md`, `cm-ci.py`

---

## 1. One-time setup

CodeMender needs three settings in `~/.codemender/config.yaml` (or `$CM_HOME/config.yaml`). Add them once, on the machine or in the runner image:

```yaml
project_paths: ["/abs/path/to/your/repo"]
vcs:
  type: git
  commands:
    reset: "true"
scan:
  exclude_dirs: ["venv", ".venv", "env", "site-packages", "__pycache__", "node_modules", "vendor", "dist", "bin", "target", "obj", "build", ".gradle"]
```

| setting | why |
| --- | --- |
| `project_paths` | `cm fix` / `cm verify` resolve the real repo root instead of a nested temp copy. Absolute path of the checkout on that runner. |
| `vcs.commands.reset: "true"` | stops CodeMender running `git checkout HEAD -- . && git clean -fd` before each fix, which would revert everything fixed earlier in the run. |
| `scan.exclude_dirs` | CodeMender's default has neither `venv` nor `.venv`, so a Python repo gets findings reported inside its installed third-party packages. |

### About `exclude_dirs`

CodeMender's default, which is also what `cm init` writes, is:

```yaml
exclude_dirs: ["node_modules", "vendor", "dist", "bin", "target", "obj", "build", ".gradle"]
```

The list above is that default plus five Python entries: `venv`, `.venv`, `env`, `site-packages`, `__pycache__`.

Two things to know:

- **Setting the key replaces the list, it does not extend it.** Whatever you write is the whole list, so keep CodeMender's eight entries unless you mean to drop them.
- **This is a starting point, not a complete list.** Add whatever else your repo carries that you do not own or do not want fixed: generated code, test fixtures and sample payloads, vendored third-party checkouts, submodules, build caches, language-specific directories the default misses (`.tox`, `.eggs`, `Pods`, `.next`, `coverage`, `third_party`). Every directory left in scope costs tokens and produces findings nobody will action.

`cm init` already writes a `scan:` and a `vcs:` section. Merge the keys above into those sections rather than adding a second one; a duplicate top-level key makes `cm` refuse to load the file.

Then verify:

```bash
chmod +x cm-ci.py
cd /path/to/your/repo
./cm-ci.py check-config
```

It prints OK / MISSING per setting and, if anything is missing, the exact YAML to add. Exit code `0` = complete, `2` = incomplete. It only reports; it never modifies `config.yaml`.

Run `cm fix` only on a clean working tree (no uncommitted changes).

## 2. Scan: `cm-ci.py find`

Any argument that is not a wrapper option is passed to `cm find` unchanged, so all CodeMender flags work:

```bash
./cm-ci.py find -y .
./cm-ci.py find --deep --deep-workers 8 -y .
./cm-ci.py find --context "focus on the auth module" -y src/
./cm-ci.py find --diff origin/main -y .
./cm-ci.py find --fail-on CRITICAL,HIGH -y .
```

The scan itself, its console output and its exit code are CodeMender's. The wrapper adds one file:

| file | content |
|---|---|
| `.codemender/run_manifest.json` | one ID for this scan, every CodeMender session it spawned, and what it cost — see [section 3](#3-run-correlation-one-id-for-a-multi-session-scan) |

Change the directory with `--out-dir`.

### What this scan surfaced

After the scan, the wrapper compares `cm report` with the snapshot it took before and prints the
delta:

```
cm-ci: new 2 · reopened 1 · already known 14 · active 17
  REOPENED HIGH     src/auth/session.py:88 Session fixation on login
  NEW      CRITICAL src/api/exec.py:42 OS Command Injection in run_job via os.system
  NEW      HIGH     src/db/query.py:17 SQL Injection in lookup_user
```

| bucket | meaning |
|---|---|
| **new** | CodeMender had never recorded this finding before. File it. |
| **reopened** | it was FIXED, CLOSED or DISMISSED, and this scan found it active again. A regression or an incomplete fix. |
| **already known** | active and unchanged since the last scan. Counted, not listed. |

This works because from 0.13.0 a finding keeps the same ID when a later scan sees it again, so the
wrapper only reads identity, it does not compute it. The counts and the ID lists go into
`run_manifest.json` as `lifecycle`, `new_finding_ids` and `reopened_finding_ids`; join them against
`cm report --format json` by `finding_id` to get the full records.

### Failing the build

```bash
./cm-ci.py find --fail-on CRITICAL,HIGH -y .
```

Exit **4** if any **new or reopened** finding has one of those severities. Already-known findings
never trigger it, so a repo with one accepted CRITICAL does not fail every build forever. `NONE`, or
omitting the flag, disables the gate.

> [!WARNING]
> **Do not use `cm find --fail-on` for this.** Despite the help text and its `CRITICAL,HIGH` default,
> CodeMender only evaluates that flag on `--diff` scans. On a plain or `--deep` scan it is silently a
> no-op: `cm find -y .` will report CRITICAL findings and still exit 0. This is reported to the
> CodeMender team. Use the wrapper's `--fail-on` instead.

### Reading the findings

```bash
cm report --format json                      # everything, machine readable
cm report --status OPEN --severity CRITICAL  # what to act on now
cm report --status REOPENED                  # every regression ever, not just this run's
```

Wrapper options:

| option | meaning |
|---|---|
| `--fail-on SEVS` | exit 4 if a new or reopened finding has one of these severities, e.g. `CRITICAL,HIGH`. `NONE` or omitted disables the gate |
| `--out-dir DIR` | where to write `run_manifest.json` (default `.codemender/`) |
| `--repo DIR` | repo root (default: the git toplevel of the current directory) |
| `--ci-build-id ID` | record your CI build ID in the manifest, so a scan can be joined back to the build that ran it. Also read from `$CM_CI_BUILD_ID`. The scan's own run ID always comes from CodeMender |
| `--no-manifest` | skip `run_manifest.json` (no reading of CodeMender's session logs at all) |

## 3. Run correlation: one ID for a multi-session scan

### Why

A plain `cm find .` runs as one agent session and prints its ID:

```
   Session: ChA2NTkyNjFiYmJiMGI5OTU5EAgaATAqBG1haW4
```

`--deep` and `--diff` do not work that way. They split the repository up and run **one agent session
per unit of work**:

| mode | one session per | concurrency |
|---|---|---|
| `--deep` | **source file** (the batcher caps a batch at 1 file / 96 KB) | `--deep-workers`, 1–16, default 8 |
| `--diff` | changed file, plus its 1-hop neighbours | `--diff-workers` |

Both then run extra sessions for the post-triage critic pass. A 400-file `--deep` scan is 400+
sessions. The CLI prints a per-file progress line for each but **no overarching ID**, and nothing in
`cm report`, `cm session list` or `state.db` records that those sessions belong together.

So there is no answer to "which scan produced this finding" beyond naming one arbitrary session.

### What the wrapper does

CodeMender already mints a UUID for every `cm` invocation and stamps it on every session that
invocation spawns. `cm-ci.py find` reads it back out and writes
`.codemender/run_manifest.json`:

```json
{
  "cm_ci_version": "2.0.0",
  "run_id": "22e1838d-eddc-425b-a476-9dcea472e06d",
  "ci_build_id": "gh-actions-8412",
  "command_type": "find",
  "cli_version": "0.13.0",
  "cm_project_id": "05b1db4e-429d-4b24-abc1-f5be5cad2e8d",
  "argv": ["find", "--deep", "--deep-workers", "8", "-y", "."],
  "repo": "/home/runner/work/acme/acme",
  "git_commit": "4c1f9ab...",
  "started_at": "2026-10-07T15:22:30Z",
  "finished_at": "2026-10-07T15:51:04Z",
  "exit_code": 0,
  "session_count": 412,
  "session_ids": ["ChA2NTky...", "ChBmNjA4...", "..."],
  "session_log_files": ["session-20261007T152230Z-ChA2NTky.jsonl", "..."],
  "lifecycle": {"new": 2, "reopened": 1, "existing": 14, "active_total": 17},
  "new_finding_ids": ["9b50167f-...", "477448b7-..."],
  "reopened_finding_ids": ["dd31c61d-..."],
  "usage": {
    "requests": 1934,
    "polls": 2210,
    "input_tokens": 41837221,
    "output_tokens": 882014,
    "cached_tokens": 30119544,
    "thought_tokens": 511903,
    "tool_calls": 1402,
    "total_tokens": 43231138,
    "cache_hit_percent": 71.99,
    "think_ratio_percent": 58.04,
    "duration_seconds": 1714.0,
    "duration_formatted": "28m 34s"
  },
  "warnings": []
}
```

- **`run_id`** — **CodeMender's own ID for this scan**, not something the wrapper invents. It is the
  `command_id` the CLI generates per invocation and writes into every session it starts. This is the
  ID to put in the PR comment and to quote when raising an issue with the CodeMender team — it means
  the same thing on both sides.
- **`ci_build_id`** — whatever you passed in `--ci-build-id` / `$CM_CI_BUILD_ID`, recorded verbatim.
  Nothing is generated: if you do not pass one, the field is `null`. Use it to join a scan back to
  your own build system.
- **`session_ids`** — every agent session this one scan spawned.
- **`usage`** — what this one scan cost. See [per-run totals](#per-run-totals).

One console line is printed as soon as the scan finishes:

```
cm-ci: run 22e1838d-eddc-425b-a476-9dcea472e06d · 412 session(s) · 43.2M tokens · 28m 34s · find --deep
```

### How it is obtained

CodeMender writes one JSONL log per agent session under
`$CM_HOME/logs/sessions/<project-id>/` (default `~/.codemender/logs/sessions/...`), named
`session-<timestamp>-<session-id-prefix>.jsonl`. Every line of every one of those files carries the
`command_id` of the CLI invocation that produced it:

```json
{"schema_version":"1","type":"command_start","command_id":"22e1838d-...","command_type":"find",
 "session_id":"ChA2NTky...","cli_version":"0.13.0","args":["find","--deep","."], ...}
```

The wrapper lists that directory before running `cm find`, lists it again immediately afterwards,
and groups the new files by `command_id`. It reads only these fields: `command_id`, `command_type`,
`session_id`, `cli_version`, `schema_version`, `args`.

### Per-run totals

`cm stats` groups by command type over a time window, so the `cm find --deep` row is **every deep
run in the last 7 days added together**, and `cm stats --session <id>` is one session out of the
412 a deep scan spawns. Neither answers "what did this scan cost".

The `usage` block in the manifest does. It covers exactly one run:

| field | what it is |
|---|---|
| `requests` | model turns across the whole scan |
| `polls` | poll calls made while waiting on the agent |
| `input_tokens` | prompt tokens sent |
| `output_tokens` | tokens generated |
| `cached_tokens` | input tokens served from cache (already included in `input_tokens`) |
| `thought_tokens` | thinking tokens (already included in `output_tokens`) |
| `tool_calls` | tokens spent on tool calls |
| `total_tokens` | **the number to bill against** |
| `cache_hit_percent` | share of input served from cache — higher is cheaper |
| `think_ratio_percent` | share of output spent thinking |
| `duration_seconds` | wall-clock time for the scan |
| `duration_formatted` | the same, as `28m 34s` |

Field names and meanings match `cm stats --json`, so a run's numbers add up to the matching
`cm stats` row rather than disagreeing with it.

### Caveats

- **This reads an internal log format.** It is schema-versioned (`schema_version: "1"`) and the
  wrapper checks the version, but it is not a public interface. A feature request is open with the
  CodeMender team to print the run ID on screen and expose it in `cm report`; once that ships the
  wrapper will read it from there and stop touching the logs.
- **Degraded mode never fails the build.** If the logs directory is missing, unreadable, or carries
  an unexpected `schema_version`, the manifest is still written with `run_id: null`, an empty
  `session_ids`, no `usage`, and an explanation in `warnings`. The scan result and the exit code are
  unaffected. Use `--no-manifest` to turn the feature off entirely.
- **One scan per checkout at a time.** The before/after directory comparison assumes no other `cm`
  process is writing to the same `$CM_HOME` concurrently. Give parallel CI jobs their own `$CM_HOME`
  (or their own runner), which you want anyway so they do not share `state.db`.
- **An interrupted `--deep` / `--diff` run cannot be resumed, and the manifest does not change
  that.** `cm session resume` works on a single session, and CodeMender only treats a session as
  resumable for about 5 minutes after its last activity. A deep scan is hundreds of sessions, so a
  run killed at minute 80 of 90 is a total loss — the only option is to re-run and pay again. Size
  your CI job timeout with headroom accordingly. A feature request is open for run-level resume.

## 4. Fix: `cm-ci.py fix`

```bash
./cm-ci.py fix --dry-run                  # show what would be fixed
./cm-ci.py fix                            # open findings, worst severity first, at most 10
./cm-ci.py fix --max 3                    # same, at most 3
./cm-ci.py fix <finding-id> ...           # exactly these
./cm-ci.py fix --model <model> <finding-id>
```

For each finding: `cm fix <id> -y --bypass-warning`, then `git commit -m "codemender: fix <id>"` with the tracked changes only. Files the fix agent created (e.g. scratch tests) are listed but not committed unless you pass `--include-new-files`. The `.cm_project` marker that CodeMender writes at the repo root is kept out of git (via `.git/info/exclude`, your `.gitignore` is not touched).

The command refuses to run (exit 2) while `project_paths` or `vcs.commands.reset` is missing — it prints the same report as `check-config` so you can see what to add — and stops with exit 3 if it detects that a fix reset the working tree anyway; in that case nothing further is committed and the path to inspect is printed.

**Run correlation.** `cm fix` is one agent session per invocation, and it already prints it:

```
   Session: ChBmNjA4ZTQ0YjAyYzE5OTU5...
   Operation: projects/.../operations/...
```

Since `cm-ci.py fix` calls `cm fix` once per finding, a `--max 10` run is 10 separate invocations,
each with its own run ID and session. The wrapper records the mapping in
`.codemender/fix_manifest.json`, so every commit in the PR can be traced back to the session that
produced it:

```json
{
  "cm_ci_version": "2.0.0",
  "ci_build_id": "gh-actions-8412",
  "command": "fix",
  "repo": "/home/runner/work/acme/acme",
  "head_before": "4c1f9ab",
  "head_after": "e07b312",
  "started_at": "2026-10-07T16:02:11Z",
  "finished_at": "2026-10-07T16:29:48Z",
  "fixes": [
    {"finding_id": "f-1a2b", "run_id": "7c40...", "session_ids": ["ChBmNjA4..."],
     "commit": "9ab3f10", "status": "committed"},
    {"finding_id": "f-3c4d", "run_id": "91ea...", "session_ids": ["ChBjYTcw..."],
     "commit": null, "status": "no_tracked_changes"},
    {"finding_id": "f-5e6f", "run_id": null, "session_ids": [],
     "commit": null, "status": "failed", "exit_code": 1}
  ],
  "warnings": []
}
```

There is no single run ID for the whole `fix` pass, because there is no single `cm` invocation —
pass `--ci-build-id` to both `find` and `fix` if you want to join them. The same caveats as
[section 3](#caveats) apply, and `--no-manifest` disables it.

| option | meaning |
|---|---|
| `--max N` | when no ids are given: fix at most N open findings, ordered CRITICAL → HIGH → MEDIUM → LOW (default 10). Findings under virtual-env directories are skipped |
| `--model M` | passed to `cm fix --model` |
| `--include-new-files` | also commit files the fix agent created |
| `--dry-run` | print the selection, change nothing |
| `--ci-build-id ID` | record your CI build ID, same as for `find` (also `$CM_CI_BUILD_ID`) |
| `--no-manifest` | skip `fix_manifest.json` |
| `--repo DIR`, `--out-dir DIR` | as for `find` |

## 5. CI checklist

1. Runner image has `python3`, `git`, `cm` (**0.13.0 or later**) and the `config.yaml` from [section 1](#1-one-time-setup). First step: `./cm-ci.py check-config` — it exits 2 if a setting is missing, so the job fails before burning tokens on a scan that cannot be fixed.
2. Clean working tree on a branch.
3. `export CM_CI_BUILD_ID="$CI_BUILD_ID"` once, so both manifests record which build produced them.
4. `./cm-ci.py find --fail-on CRITICAL,HIGH <cm flags> .` — exit 4 means this scan surfaced something that needs action.
5. File issues for `new_finding_ids`, reopen for `reopened_finding_ids`; `cm report --format json` has the full records, joined on `finding_id`.
6. Optional: `./cm-ci.py fix --max N`, then push the branch / open a PR (one commit per finding).
7. Archive `.codemender/run_manifest.json` and `.codemender/fix_manifest.json` as build artifacts — they are the only record of which CodeMender sessions the job used, and the logs they point at are local to the runner.
8. Treat exit 3 as a job failure.

**Exit codes:** `0` ok · `1` usage / tool missing · `2` configuration missing, or `cm` older than 0.13.0 · `3` fix reset detected · `4` `--fail-on` matched a new or reopened finding · otherwise the exit code of `cm`.

## 6. Notes

- `run_manifest.json` is overwritten on each `find` and `fix_manifest.json` on each `fix`; archive them as CI artifacts if you need history.
- `REOPENED` means CodeMender reports the same weakness again on code that was fixed. In practice this is either a regression or an incomplete fix — review it like any other finding; it is never dismissed automatically. It does not show up in `cm find` output.
- Repeated scans of unchanged code can still surface a few *genuinely new* findings. CodeMender is an LLM-based scanner and is not fully deterministic, so a second pass — and `--deep` in particular — can reach a weakness the first pass missed. These are new locations or new weakness classes, not duplicates, and they will show up as `NEW`.
- The before/after comparison assumes no other `cm` process is writing to the same `$CM_HOME` while the scan runs. Give parallel CI jobs their own `$CM_HOME`.
- The session logs the manifest points at stay on the runner under `$CM_HOME/logs/sessions/`. If you need them beyond the job, archive that directory too — the manifest records file names, not contents.

## 7. Upgrading from 1.x

Drop in the new `cm-ci.py`, upgrade `cm` to 0.13.0, and remove the dedup flags from your pipeline. `--fail-on` is unchanged, so a pipeline that only uses it needs no edit.

**Requires `cm` 0.13.0.** The wrapper checks `cm --version` before doing anything and exits 2 with a message if it is older. If any of your teams are pinned to an older CLI, keep them on `cm-ci.py` 1.1.0 until they upgrade.

**Removed from `find`:** `--existing`, `--known`, `--no-dedup`, `--no-update`.
**Removed from `fix`:** `--known`.
**Removed entirely:** the `cm-ci.py dedup` subcommand.

**No longer written:** `findings.json`, `new_findings.json`, `known_findings.json`. You can delete a committed `.codemender/known_findings.json`; nothing reads it any more.

| what you did in 1.x | what to do now |
|---|---|
| `--fail-on CRITICAL,HIGH` | unchanged, still exit 4. It now gates on new and reopened findings only, instead of on whatever the wrapper's own dedup classified as new |
| read `findings.json` | `cm report --format json` |
| read `new_findings.json → findings` | `new_finding_ids` in `run_manifest.json`, joined on `finding_id` |
| read `new_findings.json → reopened` | `reopened_finding_ids` in `run_manifest.json` |
| `--existing prev.json` to carry findings between runners | give the job a persistent `$CM_HOME`, or `cm report --format json` on one side and `cm report import` on the other |
| `github_marker` in an issue body | the finding ID is now stable across runs; put that in the issue |
| `cm-ci.py dedup a.json b.json` | gone — `cm` does not produce the duplicates any more |

**Unchanged:** exit `4` still means `--fail-on` matched. Exit `2` now also means "`cm` is too old".

