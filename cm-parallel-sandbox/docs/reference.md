# cm-parallel-sandbox reference

Detailed flags, result layouts, and behavior notes. Start with the [README](../README.md).

- [Command examples](#command-examples)
- [Checking a run](#checking-a-run)
- [Results layout](#results-layout)
- [`summary.json` fields](#summaryjson-fields)
- [Flags](#flags)
- [Diff-case manifest](#diff-case-manifest-configrepos_with_difftsv)
- [Diff mode](#diff-mode)
- [cm 0.10.0 notes](#cm-0100-notes)
- [Known limitations](#known-limitations)

## Command examples

Run find stage only:
```bash
python3 run.py --operation find --repos o04-vampi --experiment-id smoke --project $PROJECT
```

Run verify stage against an explicit find run ID:
```bash
python3 run.py --operation verify --from-find-run 20260927_002112_find_v0.9.0_gemini-3.8-flash --repos o04-vampi --experiment-id smoke --project $PROJECT
```

Run standalone fix stage from a verify run (default: verified findings only):
```bash
python3 run.py --operation fix --from-verify-run smoke/<verify_run_id> --repos o04-vampi --experiment-id smoke --fix-limit 1 --project $PROJECT
```

Run standalone fix stage from a verify run including unverified findings:
```bash
python3 run.py --operation fix --from-verify-run smoke/<verify_run_id> --repos o04-vampi --include-unverified --project $PROJECT
```

Run standalone fix stage directly from a find run:
```bash
python3 run.py --operation fix --from-find-run smoke/<find_run_id> --repos o04-vampi --severity CRITICAL --fix-limit 1 --project $PROJECT
```

Run fix targeted to specific finding ID(s) or prefixes:
```bash
python3 run.py --operation fix --from-find-run smoke/<find_run_id> --repos o04-vampi --finding-ids 2c72497a --project $PROJECT
```

Run chained 2-stage verify-fix:
```bash
python3 run.py --operation verify-fix --from-find-run smoke/<find_run_id> --repos o04-vampi --verify-limit 1 --fix-limit 1 --project $PROJECT
```

Run chained 2-stage find-fix:
```bash
python3 run.py --operation find-fix --repos o04-vampi --severity CRITICAL --fix-limit 1 --project $PROJECT
```

Run full 3-stage find-verify-fix:
```bash
python3 run.py --operation find-verify-fix --repos o04-vampi --severity CRITICAL --verify-limit 1 --fix-limit 1 --project $PROJECT
```

Simulate dispatch without modifying cloud resources:
```bash
python3 run.py --operation find-verify-fix --repos o04-vampi --dry-run --project $PROJECT
```

Pre-stage repository source tarballs manually:
```bash
python3 stage_repos.py --repos o04-vampi --bucket $PROJECT-cm-payload
```
`stage_repos.py` flags: `--repos-tsv`, `--repos`, `--bucket`, `--force`.

## Checking a run

When `run.py` dispatches a job, it outputs phase banners, tracking identifiers, and logging pointers:
- Phase banners: `[stage]`, `[dispatch]`, `[progress]`, `[summary]` provide structured feedback for every phase.
- `run_id`: The run identifier string (`<YYYYMMDD_HHMMSS>_<operation>_v<cm_version>_<model>`).
- `results`: The Cloud Storage path prefix where task outputs land (`gs://<bucket>/<experiment_id>/<run_id>/`).
- `execution`: The Cloud Run job execution resource name (`cm-find-runner-<suffix>` or `cm-verify-runner-<suffix>`).
- `status: gcloud run jobs executions describe ...`: The gcloud command to check execution status and task details.
- `logs: gcloud logging read ...`: Direct CLI filter query to inspect execution logs in Cloud Logging.
- `console`: Direct Cloud Logging Console URL formatted for the execution.

`--wait` behavior:
- Without `--wait`: `run.py` writes task manifests to GCS, updates job configuration, dispatches the Cloud Run execution asynchronously (`--async`), and exits immediately after printing tracking and logging pointers.
- With `--wait`: `run.py` dispatches asynchronously and runs an interactive polling loop against `gcloud run jobs executions describe` every 5 minutes (default 300s, configurable via `--poll-interval`). In interactive terminals, it updates in-place via carriage return (`\r\033[K`); in CI/non-TTY, it logs line-by-line. Output shows elapsed time (`[MM:SS]`) and live task breakdown (`<running> running, <succeeded> succeeded, <failed> failed / <total> total`). On completion, it reports terminal status condition, overall duration, and exit code.
- In multi-stage operations (`find-verify`, `verify-fix`, `find-fix`, `find-verify-fix`): `run.py` waits on earlier phases before dispatching subsequent phases. When an upstream phase completes, it displays summary breakdowns before dispatching the downstream phase. If an upstream phase fails, the downstream phase is skipped and `run.py` outputs a resumption command.

Exit codes:
- `0`: Execution dispatched (asynchronous mode) or completed successfully (synchronous `--wait` mode).
- `1`: Cloud Run job execution failed or gcloud dispatch returned an error.
- `2`: No tasks to run (no matching findings for severity or finding ID filter), invalid CLI arguments (`argparse` error), or run ID collision in GCS (`tasks.json` already present).

## Results layout

```
gs://<proj>-cm-find-results/<experiment_id>/<run_id>/<repo_id>/
  findings.json             # CodeMender findings report in JSON format
  findings_table.txt        # Text table of findings
  state.db                  # CodeMender SQLite state database (if created)
  cm_api_token_stats.json   # Token usage metrics for the find phase
  cm_stats.json             # `cm stats --json` for the find phase (cm's local log accounting)
  summary.json              # Task execution summary and status
  repo_commit.txt           # Pinned commit SHA of the analyzed repository
  logs/
    cm_init.log             # stdout and stderr from cm init
    execution.log           # stdout and stderr from cm find
    token_stats.log         # stdout and stderr from cm-api-token-stats
    cm_stats.log            # stderr from cm stats
    cm_logs.tar.gz          # cm's per-session logs from $CM_HOME/logs

gs://<proj>-cm-verify-results/<experiment_id>/<run_id>/<repo_id>/
  post_verify_report.json   # CodeMender report after verification loop
  source_findings.json      # Findings input copied from find results
  imported_findings.json    # Filtered findings imported into repository
  matching_finding_ids.txt  # Ordered list of finding IDs matching severity filter
  tool_inventory.txt        # Available local compiler and runtime tool inventory
  state.db                  # CodeMender SQLite state database (if created)
  summary.json              # Verification summary and status
  repo_commit.txt           # Pinned commit SHA of the analyzed repository
  logs/
    cm_init.log             # stdout and stderr from cm init
    import.log              # stdout and stderr from import_findings.py
  findings/<finding_id>/
    context.txt             # Rendered exploit context provided to cm verify
    verify.log              # stdout and stderr from cm verify execution
    exit_code               # Exit code (integer) or "deadline" if skipped
    token_stats.json        # Token usage metrics for this finding verification
    cm_stats.json           # `cm stats --json` for this finding verification
    exploit/                # Generated exploit files (if created by cm verify)

gs://<proj>-cm-fix-results/<experiment_id>/<run_id>/<repo_id>/
  post_fix_report.json      # CodeMender report after patching loop
  source_findings.json      # Findings input copied from verify or find results
  imported_findings.json    # Target findings imported into repository for fixing
  matching_finding_ids.txt  # Ordered list of finding IDs targeted for patching
  patch.diff                # Combined unified git diff of all applied patches
  state.db                  # CodeMender SQLite state database (if created)
  summary.json              # Patching summary and status
  repo_commit.txt           # Pinned commit SHA of the analyzed repository
  logs/
    cm_init.log             # stdout and stderr from cm init
    import.log              # stdout and stderr from import_findings.py
  findings/<finding_id>/
    patch.diff              # Unified diff patch for this finding (if generated)
    fix.log                 # stdout and stderr from cm fix execution
    exit_code               # Exit code (integer) or "deadline" if skipped
    token_stats.json        # Token usage metrics for this finding patch
    cm_stats.json           # `cm stats --json` for this finding patch
    summary.json            # Individual finding patch status and metadata

gs://<proj>-cm-payload/
  repos/<repo_id>.tar.gz    # Repository source tarball archive
  bin/cm/<version>/cm-linux-amd64.zip          # Cached cm executable archive
  bin/cm/<version>/cm-linux-amd64.zip.sha256   # SHA-256 sidecar checksum
  runs/<experiment_id>/<run_id>/
    tasks.json              # Task definitions indexed by CLOUD_RUN_TASK_INDEX
    run_manifest.json       # Execution manifest and dispatch metadata
```

## `summary.json` fields

Common fields:
- `operation`: `"find"`, `"verify"`, or `"fix"`
- `repo_id`: Repository identifier
- `run_id`: Run identifier string
- `experiment_id`: Experiment identifier
- `model`: Model name passed to `cm`
- `mode`: Mode name (`"shallow"`, `"deep"` or `"diff"`)
- `cm_version`: Version string of `cm`
- `exit_code`: Process exit code
- `start_epoch`: Task start timestamp in epoch seconds
- `end_epoch`: Task end timestamp in epoch seconds
- `wall_clock_seconds`: Total runtime in seconds
- `status`: Overall task status (`"ok"`, `"timeout"`, or `"failed"`)

Find fields:
- `findings_count`: Total findings reported
- `severity_counts`: Dictionary mapping severity level to finding count
- `tokens`: Dictionary of token metrics (`input_tokens`, `output_tokens`, `cached_tokens`, `thought_tokens`, `tool_calls`, `total_tokens`, `total_turns`)
- cm >= 0.10.0 only (0.9.0 summaries are unchanged):
  - `deep_workers`: `--deep-workers` sent to `cm find`, or `null` for shallow runs
  - `sessions`: `state_db` (rows in `state.db`), `logs` (session logs in `cm_logs.tar.gz`), `union`, and `dropped_from_db` (sessions that have a log but no `state.db` row; cm can lose rows to `SQLITE_BUSY` under concurrent deep workers)
  - `token_stats_status`: `"ok"`, `"failed"`, or `"timeout"` (the token-stats run hit `TOKEN_STATS_TIMEOUT`). A session that cm stopped mid-step (for example at the 5-minute diff ceiling) is counted up to that step and recorded as an `incomplete` turn instead of being retried until the timeout
- `mode: "diff"` only (shallow and deep summaries are unchanged):
  - `pinned_ref` / `diff_ref`: the checkout `HEAD` and the ref passed to `cm find --diff=`
  - `changed_files` / `changed_lines`: code-only diff size from `container/scripts/diff_stats.py` (also uploaded as `diff_stats.json`; the counted paths are in `diff_files.txt`)
  - `cm_exit_code`: cm's raw exit code. cm's default `--fail-on CRITICAL,HIGH` gate exits 1 when it reports such findings; that counts as success (`exit_code` 0) when `findings.json` is non-empty. cm's 5-minute delta-scan ceiling also exits 1 and also counts as success (see `diff_timed_out`)
  - `diff_workers`: `--diff-workers` sent to cm, or `null` when cm used its default (4)
  - `diff_timed_out`: `true` when cm stopped the PR delta scan at its hard-coded 5-minute ceiling. Tokens up to that point are still counted; findings from unfinished jobs are lost
  - `diff_jobs_total` / `diff_jobs_completed` / `diff_jobs_failed`: delta-scan job counts parsed from `logs/execution.log` (`PR Delta Scan Complete: …` or `timed out … (k/n jobs completed)`); `null` when cm printed none (`diff_jobs_failed` is unknown on a timeout)

Verify fields:
- `findings_expected`: Count of findings matching severity filter
- `findings_attempted`: Count of findings where verification ran
- `status_counts`: Verification status breakdown (`VERIFIED`, `DISMISSED`, `OTHER:<status>`)
- `timeout_count`: Count of findings that timed out (exit code 124 or 137)
- `nonzero_exit_count`: Count of findings with non-zero exit code (excluding null)
- `exit_codes`: Mapping of `finding_id` to its exit code
- `tokens`: Aggregate token usage across all verified findings in this task
- `severity`: Severity filter string used for this run
- `source_find_run`: Find run identifier used as findings input
- `source_find_mode`: `mode` of the source find run (from its `run_manifest.json`), when known

Fix fields:
- `findings_expected`: Count of findings targeted for patching
- `findings_attempted`: Count of findings where patching ran
- `patches_generated`: Total count of patches generated and applied
- `status_counts`: Patch status breakdown (`FIXED`, `FAILED`, `SKIPPED`, `OTHER:<status>`)
- `timeout_count`: Count of findings that timed out
- `nonzero_exit_count`: Count of findings with non-zero exit code
- `exit_codes`: Mapping of `finding_id` to its exit code
- `tokens`: Aggregate token usage across all patched findings in this task
- `source_verify_run` / `source_find_run`: Upstream run identifier used as findings input
- `source_find_mode`: `mode` of the find run behind the source, when known

Status values:
- Find: `"ok"` when `exit_code == 0`, `tokens.total_tokens > 0`, and `findings.json` is valid JSON (diff mode: `exit_code` is 0 for a cm exit 1 with findings or at the 5-minute ceiling, see `cm_exit_code` and `diff_timed_out`). `"timeout"` when `exit_code` is 124 or 137. `"failed"` otherwise.
- Verify: `"ok"` when `post_verify_report.json` exists, all expected findings were attempted, `exit_code == 0`, and `timeout_count == 0`. `"timeout"` when `timeout_count > 0` or task `exit_code` is 124 or 137. `"failed"` otherwise.
- Fix: `"ok"` when `post_fix_report.json` exists, all expected findings were attempted, `exit_code == 0`, and `timeout_count == 0`. `"timeout"` when `timeout_count > 0` or task `exit_code` is 124 or 137. `"failed"` otherwise.

## Flags

| Flag | Default | Notes |
|---|---|---|
| `--operation` | `find` | Execution mode: `find`, `verify`, `find-verify`, `fix`, `verify-fix`, `find-fix`, `find-verify-fix` |
| `--repos-tsv` | `config/repos.tsv` | Benchmark manifest path. `--mode diff` has no default and needs a diff manifest (`config/repos_with_diff.tsv`) |
| `--repos` | all | Space-separated list of `repo_id`s to run |
| `--project` | gcloud config | Target GCP project ID |
| `--region` | `us-central1` | Deployment GCP region |
| `--cm-version` | `0.11.0` | CodeMender CLI version; pass `0.10.0` or `0.9.0` to use a previous release. On first use the zip is fetched with `gcloud artifacts generic download` and cached in the payload bucket; `run.py` exits 1 with a credentials hint if the download fails |
| `--model` | `gemini-3.8-flash` | Model passed to `cm --model` |
| `--mode` | `shallow` | `--mode deep` adds `--deep` to `cm find`; `--mode diff` runs `cm find --diff=<diff_ref>` on a `pinned_ref` checkout per case (see [Diff mode](#diff-mode)). Both require `--cm-version >= 0.10.0`. Find only: chained and standalone verify/fix always run with `MODE=shallow`, and record the find's mode as `source_find_mode` |
| `--extra-cm-args` | `""` | Additional arguments appended to `cm` commands (sent as `EXTRA_CM_ARGS`) |
| `--from-find-run` | none | Source find run (`run_id`, `<exp>/<run_id>`, or `latest` = run with the newest `summary.json`); required for `verify`, `verify-fix`; optional for `fix` |
| `--from-verify-run` | none | Source verify run (`run_id`, `<exp>/<run_id>`, or `latest` = run with the newest `summary.json`); optional for `fix` |
| `--severity` | `CRITICAL,HIGH` | Comma-separated severities filtered (used in verify, find-verify, fix, etc.) |
| `--verify-limit` | `0` (all) | Max findings verified per task; highest severity first |
| `--fix-limit` | `0` (all) | Max findings patched per task; highest severity first |
| `--include-unverified` | off | Fix stage: include unverified findings (`status!=DISMISSED`) when fixing from verify run |
| `--finding-ids` | none | Specific finding IDs or prefixes (bypasses severity, verify-limit, and fix-limit) |
| `--experiment-id` | `default` | Experiment directory prefix |
| `--run-id` | generated | Run identifier (`<YYYYMMDD_HHMMSS>_<operation>_v<cm_version>_<model>`) |
| `--deep-workers` | `8` with `--mode deep` (same as cm) | `cm find --deep-workers` per repo (1–16); only with `--mode deep`. Repos × workers must be ≤ 900 concurrent model calls (`DEEP_CALL_BUDGET`), or `run.py` exits 2 before staging with a `--deep-workers`/`--repos` hint. Not allowed inside `--extra-cm-args` |
| `--diff-workers` | unset (cm default 4) | `cm find --diff-workers` per case (1–16); only with `--mode diff`. Unset means the flag is not passed to cm. Cases × effective workers must be ≤ 900. Not allowed inside `--extra-cm-args` |
| `--token-stats-workers` | `8` (same as `cm-api-token-stats`) | Sessions fetched concurrently by each `cm-api-token-stats` run (≥ 1), for every operation. Sent as `TOKEN_STATS_WORKERS` and recorded as `token_stats_workers` in `run_manifest.json` |
| `--container-timeout` | `172800` | Cloud Run container task timeout in seconds (`> 300`, `<= 604800`) |
| `--fix-timeout` | `10800` | Max seconds per finding in fix stage (`<= container-timeout - 300`) |
| `--wait` | off | Block until execution finishes |
| `--poll-interval` | `300` | Polling interval in seconds under `--wait` |
| `--dry-run` | off | Print task manifest and execution plan without modifying cloud resources |

## Diff-case manifest (`config/repos_with_diff.tsv`)

`config/repos_with_diff.tsv` lists diff-scan cases for `cm find --diff=<diff_ref>` on a checkout of `pinned_ref`, which is what a PR's CI runs. `config/repos.tsv` is unchanged. Columns (tab-separated, LF line endings):

| Column | Meaning |
|---|---|
| `repo_id` | Case id: `<source_repo_id>--<pinned_ref[:7]>-<diff_ref[:7]>` (e.g. `o04-vampi--f16052d-beca461`); matches `^[a-z0-9][a-z0-9-]*$` |
| `pinned_ref` | 40-hex commit checked out as `HEAD`. Defaults to the `repos.tsv` ref resolved to a SHA; can be edited per row |
| `diff_ref` | 40-hex commit passed to `--diff=`. Must be an ancestor of `pinned_ref` (cm diffs `merge-base(diff_ref, HEAD)`) |
| `diff_bucket` | `S`/`M`/`L`/`XL`: the band the row was mined for. Informational only |
| `source_repo_id` | The `repos.tsv` row this case comes from; metadata columns are copied from it |
| `evidence` | `k=<n>; changed_files=<n>; changed_lines=<n>` (`diff_ref` = `pinned_ref~k`, first-parent) |

`changed_files` and `changed_lines` count code files only, using `container/scripts/diff_stats.py`: `git diff --numstat --no-renames <diff_ref> <pinned_ref>`, minus binary files, minus paths outside `config/cm_config.yaml`'s `scan.extensions` include list (or in its exclude list), minus paths with a `scan.exclude_dirs` directory component.

Up to 4 cases per repo, one per band of `changed_files`: **S** 1–3, **M** 4–15, **L** 16–49, **XL** 50–150. `scripts/fetch_diff_repos.py` walks `pinned_ref~k` (k = 1, 2, …), stopping at the first k with more than 150 changed code files, at k = 500, or at the root commit, and picks the largest k in each band. Bands a repo can't fill are skipped.

```bash
scripts/fetch_diff_repos.py                    # (re)mine all repos; mirrors and walk caches in ~/.cache/cm-diff-mining
scripts/fetch_diff_repos.py --repos p13-gin    # re-mine one repo, keep other rows
scripts/validate_diff_tsv.py --report /tmp/diff_tsv_report.tsv   # static + git checks per row
```

The miner reuses each repo's existing `pinned_ref` from the TSV (so hand edits stick); pass `--reresolve` to re-resolve from `repos.tsv`. If a ref can't be found upstream, that repo fails with `pinned ref '<ref>' for <id> can't be found in <url>; update <id>'s ref in config/repos.tsv …` and the other repos still run; fix the ref in `config/repos.tsv` and re-run with `--repos <id>`.

Exceptions in the checked-in TSV:

- `o09-benchmarkjava` is in `XL_OVERFLOW` (also `--xl-overflow ID`). Its first 75 first-parent commits touch no code files and k = 76 jumps to 635 files, so no band fits; for repos in `XL_OVERFLOW` with no XL candidate, the stop k is used as the XL case. Its only row has 635 changed files, above the 150-file XL limit.
- `h04-svelte` and `p32-wireguard`: their old `repos.tsv` refs (`v4.2.17`, `master`) don't exist upstream, so `repos.tsv` now pins the commits they resolve to (`a8deae9`, the `svelte@4.2.17` tag; `abba013`, the `stable` branch tip when mined).

## Diff mode

`--mode diff` reproduces a PR's CI scan: each task checks out `pinned_ref` and runs `cm find --diff=<diff_ref> . --model … -y --bypass-warning` (plus `--diff-workers N` only when set, then `EXTRA_CM_ARGS`). cm diffs `merge-base(diff_ref, HEAD)` against the working tree, so `diff_ref` must be an ancestor of `pinned_ref`.

- **Manifest:** `--repos-tsv` is required and every row is validated before staging (required columns, 40-hex refs, `diff_ref != pinned_ref`, case id ↔ refs). `diff_bucket` is optional metadata and is not passed to tasks.
- **Staging:** one tarball per case at `gs://<payload>/repos/<case_id>.tar.gz`. `stage_repos.stage_one_diff` fetches the commit graph only (`--filter=tree:0`) to check ancestry and count `N = rev-list --count diff_ref..pinned_ref`, then makes a full (non-partial) depth-`N+1` clone so cm finds the merge-base without network. Existing tarballs are reused (the name embeds both SHAs); `stage_repos.py --force` restages.
- **Entrypoint:** asserts `HEAD == pinned_ref` and that `diff_ref` is an ancestor (else the task dies before cm runs), writes `diff_stats.json` / `diff_files.txt`, and does not pass `--fail-on`. A cm exit 1 with non-empty findings is the default gate tripping and counts as success. cm also caps every PR delta scan at a hard-coded 5 minutes (no flag or config in 0.10.0/0.11.0); a cm exit 1 at that ceiling counts as success with `diff_timed_out: true`. Any other exit 1, and any other non-zero exit, fail. `--fail-on` may still be passed through `--extra-cm-args`; `--diff`, `--diff-workers`, `--staged` and `--deep` may not.
- **Budget:** cases × effective `--diff-workers` (4 when unset) ≤ 900 concurrent model calls. Diff finds use the deep soft-timeout reserve (`SOFT_TIMEOUT_RESERVE_DEEP`).
- **Chaining:** `find-verify`/`find-fix`/`find-verify-fix` work with `--mode diff`; later phases run with `MODE=shallow` on the same case tarball and record `source_find_mode: diff`.
- **Standalone verify/fix of a diff find run:** pass `--repos-tsv config/repos_with_diff.tsv --repos <case ids>`. With the default `config/repos.tsv` the case ids are unknown and no tasks are built; without `--repos`, every case in the manifest would be staged.

## cm 0.10.0 notes

cm 0.11.0 (the default) keeps the 0.10.0 `cm find` flags, scan config and `CM_HOME` layout; these notes apply to both.

- `CM_HOME`: the entrypoint exports `CM_HOME` and keeps `state.db`, `config.yaml` and session logs there. `state.db` is in WAL mode, so it is snapshotted with SQLite's backup API rather than copied, and the session logs are archived as `logs/cm_logs.tar.gz`.
- Scan config: `config/cm_config.yaml` follows the 0.10.0 `scan:` schema (`exclude_dirs` replaces `exclude_paths`; `.tsx`, `.jsx`, `.mjs`, `.cjs`, `.sol`, `.tf` and `.hcl` are included).
- `--fail-on`: cm 0.10.0 applies its CI gate only to `--diff` scans, and full-repo `cm find` exits 0 even with CRITICAL findings. The runner does not inject `--fail-on`; pass it through `--extra-cm-args` (`EXTRA_CM_ARGS`) if you run diff scans.
- Token stats: `cm-api-token-stats` runs with `--since` scoped to the task, `--workers $TOKEN_STATS_WORKERS` (unset: the script's default, 8), and under `TOKEN_STATS_TIMEOUT` seconds (default: soft-timeout reserve minus 120, so 180 s shallow and 780 s deep or diff). Deep and diff finds reserve `SOFT_TIMEOUT_RESERVE_DEEP` seconds (default 900) of the job timeout for token stats and uploads. Each run logs `cm-api-token-stats (limit <N>s, workers <W>)`.
- cm stats: right before each `cm-api-token-stats` run, the entrypoint also runs `cm stats --json --since <N>s` over the same window (the whole task for find, `t0` for each verify or fix finding). It writes the output to `cm_stats.json` (find) or `findings/<id>/cm_stats.json` (verify and fix) so you can compare it with the API numbers. `cm stats` counts cm's own local session logs; `cm-api-token-stats` counts the billing turns it fetches from the API. The keys match (`input_tokens`, `output_tokens`, `cached_tokens`, `thought_tokens`, `tool_calls`, `total_tokens`, `total_turns`). The capture is best-effort and is not used in `summary.json`. It is capped at `CM_STATS_TIMEOUT` seconds (default 30, and never past the soft deadline). A timeout writes `{"error":"timeout"}`, any other failure writes `{"error":"failed","exit_code":N}`, and neither changes the task exit code. Each `cm stats` run leaves an empty `<ts>_pending.log`. For find it runs after `cm_logs.tar.gz` is built, so `sessions` is unaffected.

## Known limitations

- Verify task `status: ok` with non-zero finding exits: A verify `summary.json` can record `status: ok` even when individual finding verifications exit with non-zero return codes without timing out. The count of such exits is recorded in `nonzero_exit_count`.
- `deploy.sh` empty image line: `deploy.sh` outputs an empty `image:` line at completion due to the gcloud describe format path. Verify the image using:
  ```bash
  gcloud run jobs describe cm-verify-runner --project $PROJECT --region us-central1 --format="value(spec.template.spec.template.spec.containers[0].image)"
  ```
- Find failure skips verify in `find-verify`: If the find phase fails during `--operation find-verify`, verification is skipped and `run.py` prints the resume command:
  ```bash
  python3 run.py --operation verify --from-find-run <experiment_id>/<find_run_id>
  ```
- Exit code `2` scope: Exit code `2` is returned when no tasks match the filter, when CLI arguments fail validation, or when a run ID collision occurs in GCS (`tasks.json` already present). Because generated run IDs have 1-second resolution, multiple dispatches within the same second with identical parameters collide.
- Shared selftest namespace: Passing `--experiment-id selftest` writes results under `gs://<bucket>/selftest/`, which is the same prefix used by `scripts/selftest.sh`.
- Vendored `cm-api-token-stats`: `container/scripts/cm-api-token-stats` is a byte-for-byte copy of [`fde-security-aigis@61338ff`](https://github.com/cloud-gtm/fde-security-aigis/blob/61338fffc3fb376ca7cc4beb5e48f4bae4d4a6e4/cm-api-token-stats/cm-api-token-stats). To re-sync, copy the upstream file (keep the exec bit), update `UPSTREAM_COMMIT` and `UPSTREAM_SHA256` in `tests/test_token_stats_vendor.py`, run `./scripts/check.sh`, and rebuild the image with `deploy.sh`.
