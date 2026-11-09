#!/usr/bin/env bash
# Entrypoint shared by cm-find-runner, cm-verify-runner, and cm-fix-runner.
#
# Reads tasks[CLOUD_RUN_TASK_INDEX] from
# gs://$PAYLOAD_BUCKET/runs/$EXPERIMENT_ID/$RUN_ID/tasks.json, installs the
# SHA-256-pinned cm binary from the payload bucket, extracts the repo tarball,
# runs `cm find` (MODE=diff: `cm find --diff=<diff_ref>` on a pinned_ref
# checkout), the sequential air-gapped `cm verify` loop, or the sequential
# `cm fix` loop, and uploads the results create-only to the stage's results bucket.
#
# No `set -e`: cm failures and best-effort steps must not skip the summary and
# upload; fatal steps call die explicitly.
set -uo pipefail

OPERATION="${OPERATION:?OPERATION must be set}"
CM_OPT_DIR="${CM_OPT_DIR:-/opt/cm}"
SCRIPTS_DIR="$CM_OPT_DIR/scripts"
CONFIG_DIR="$CM_OPT_DIR/config"
CM_CI_DIR="${CM_CI_DIR:-$CM_OPT_DIR/cm-ci}"
if [ ! -f "$CM_CI_DIR/cm-ci.py" ] && [ -f "$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd)/cm-ci.py" ]; then
  CM_CI_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
fi
CM_CI="${CM_CI:-$CM_CI_DIR/cm-ci.py}"
TASK_INDEX="${CLOUD_RUN_TASK_INDEX:-0}"
JOB_TIMEOUT="${JOB_TIMEOUT:-172800}"
SOFT_TIMEOUT_RESERVE="${SOFT_TIMEOUT_RESERVE:-300}"
SOFT_TIMEOUT_RESERVE_DEEP="${SOFT_TIMEOUT_RESERVE_DEEP:-900}"
VERIFY_FINDING_TIMEOUT="${VERIFY_FINDING_TIMEOUT:-2400}"
FIX_FINDING_TIMEOUT="${FIX_FINDING_TIMEOUT:-10800}"
MODEL="${MODEL:-gemini-4-argon}"
MODE="${MODE:-shallow}"
DEEP_WORKERS="${DEEP_WORKERS:-}"  # cm find --deep-workers; empty = cm default
DIFF_WORKERS="${DIFF_WORKERS:-}"  # cm find --diff-workers; empty = not passed
TOKEN_STATS_WORKERS="${TOKEN_STATS_WORKERS:-}"  # cm-api-token-stats --workers; empty = upstream default
CM_STATS_TIMEOUT="${CM_STATS_TIMEOUT:-30}"  # seconds per best-effort `cm stats --json`
SEVERITY="${SEVERITY:-CRITICAL,HIGH}"
VERIFY_LIMIT="${VERIFY_LIMIT:-0}"  # max findings verified per task; 0 = all
FIX_LIMIT="${FIX_LIMIT:-0}"        # max findings fixed per task; 0 = all
EXTRA_CM_ARGS="${EXTRA_CM_ARGS:-}"
FROM_FIND_RUN="${FROM_FIND_RUN:-}"
FROM_VERIFY_RUN="${FROM_VERIFY_RUN:-}"
INCLUDE_UNVERIFIED="${INCLUDE_UNVERIFIED:-0}"
FINDING_IDS="${FINDING_IDS:-}"
export CLOUDSDK_STORAGE_PARALLEL_COMPOSITE_UPLOAD_ENABLED=False

# Deep, complete, and diff finds collect stats one session at a time over many sessions.
case "$MODE" in deep|diff|complete) SOFT_TIMEOUT_RESERVE="$SOFT_TIMEOUT_RESERVE_DEEP" ;; esac
# Leave 120s of the reserve for summary and upload after token stats.
TOKEN_STATS_TIMEOUT="${TOKEN_STATS_TIMEOUT:-$(( SOFT_TIMEOUT_RESERVE > 121 ? SOFT_TIMEOUT_RESERVE - 120 : 1 ))}"
START_EPOCH="$(date +%s)"
DEADLINE=$(( START_EPOCH + JOB_TIMEOUT - SOFT_TIMEOUT_RESERVE ))
export CM_HOME="${CM_HOME:-$HOME/.codemender}"
CM_STATE_DB="$CM_HOME/state.db"
MIN_FINDING_SECONDS=60  # don't start a finding with less time than this left
IMPORT_ARGS=()
MATCHING_IDS=()

log() { echo "[entrypoint $(date -u +%FT%TZ)] $*" >&2; }
die() { log "FATAL: $*"; exit 1; }

require_count() {  # $1 = variable name; (( )) would mis-evaluate other values
  [[ "${!1}" =~ ^(0|[1-9][0-9]*)$ ]] || die "$1 must be a non-negative integer, got '${!1}'"
}
require_count VERIFY_LIMIT
require_count FIX_LIMIT
if [ -n "$DEEP_WORKERS" ] && ! [[ "$DEEP_WORKERS" =~ ^([1-9]|1[0-6])$ ]]; then
  die "DEEP_WORKERS must be empty or 1-16, got '$DEEP_WORKERS'"
fi
if [ -n "$DIFF_WORKERS" ] && ! [[ "$DIFF_WORKERS" =~ ^([1-9]|1[0-6])$ ]]; then
  die "DIFF_WORKERS must be empty or 1-16, got '$DIFF_WORKERS'"
fi
if [ -n "$TOKEN_STATS_WORKERS" ] && ! [[ "$TOKEN_STATS_WORKERS" =~ ^[1-9][0-9]*$ ]]; then
  die "TOKEN_STATS_WORKERS must be empty or an integer >= 1, got '$TOKEN_STATS_WORKERS'"
fi
[[ "$CM_STATS_TIMEOUT" =~ ^[1-9][0-9]*$ ]] \
  || die "CM_STATS_TIMEOUT must be an integer >= 1, got '$CM_STATS_TIMEOUT'"
PINNED_REF=""
DIFF_REF=""
CM_EXIT_CODE=""

soft_remaining() {
  local r=$(( DEADLINE - $(date +%s) ))
  (( r < 1 )) && r=1
  echo "$r"
}

prune_broken_links() { find "$1" -xtype l -delete 2>/dev/null || true; }

fetch() {  # $1 = gs:// source, $2 = local destination
  gcloud storage cp "$1" "$2" || die "cannot read $1"
}

task_field() {
  python3 -c 'import json,sys; t=json.load(open(sys.argv[1]))[int(sys.argv[2])]; print(t.get(sys.argv[3], ""))' \
    "$WORK/tasks.json" "$TASK_INDEX" "$1"
}

setup_task() {
  : "${PAYLOAD_BUCKET:?}" "${EXPERIMENT_ID:?}" "${RUN_ID:?}" "${CM_VERSION:?}" "${EXPECTED_CM_SHA256:?}"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/cmtask.XXXXXX")"
  gcloud storage cat "gs://$PAYLOAD_BUCKET/runs/$EXPERIMENT_ID/$RUN_ID/tasks.json" > "$WORK/tasks.json" \
    || die "cannot read tasks.json"
  REPO_ID="$(task_field repo_id)"
  LANGUAGE="$(task_field language)"
  FINDINGS_URI="$(task_field findings_gcs_uri)"
  VERIFY_REPORT_URI="$(task_field verify_report_gcs_uri)"
  VERIFY_IDS_URI="$(task_field verify_ids_gcs_uri)"
  VERIFY_REPO_PREFIX="$(task_field verify_repo_prefix)"
  SOURCE_FIND_MODE="$(task_field source_find_mode)"
  [ -n "$REPO_ID" ] || die "task $TASK_INDEX has no repo_id"
  case "$OPERATION" in
    find)   RESULTS_BUCKET="${FIND_RESULTS_BUCKET:?}" ;;
    verify) RESULTS_BUCKET="${VERIFY_RESULTS_BUCKET:?}" ;;
    fix)    RESULTS_BUCKET="${FIX_RESULTS_BUCKET:?}" ;;
  esac
  DEST="gs://$RESULTS_BUCKET/$EXPERIMENT_ID/$RUN_ID/$REPO_ID/"
  RESULTS_DIR="$WORK/results"
  IDS_FILE="$RESULTS_DIR/matching_finding_ids.txt"
  INVENTORY="$RESULTS_DIR/tool_inventory.txt"
  REPO_DIR="$HOME/workspace/$REPO_ID"
  mkdir -p "$RESULTS_DIR/logs" "$HOME/bin" "$REPO_DIR"
  log "task $TASK_INDEX: $OPERATION $REPO_ID -> $DEST"
}

install_cm() {
  local zip="$WORK/cm-linux-amd64.zip" actual
  gcloud storage cp "gs://$PAYLOAD_BUCKET/bin/cm/$CM_VERSION/cm-linux-amd64.zip" "$zip" \
    || die "cannot download cm $CM_VERSION"
  actual="$(sha256sum "$zip" | cut -d' ' -f1)"
  [ "$actual" = "$EXPECTED_CM_SHA256" ] \
    || die "cm SHA-256 mismatch: expected $EXPECTED_CM_SHA256 got $actual"
  unzip -o -q "$zip" -d "$HOME/bin" || die "cannot unzip cm"
  chmod +x "$HOME/bin/cm"
  export PATH="$HOME/bin:$PATH"
  cm --version >&2 || true
}

extract_repo() {
  gcloud storage cp "gs://$PAYLOAD_BUCKET/repos/$REPO_ID.tar.gz" "$WORK/repo.tar.gz" \
    || die "cannot download repo tarball"
  # Tarballs are depth-1 clones at pinned_ref under <repo_id>/: never git checkout.
  tar -xzf "$WORK/repo.tar.gz" --strip-components=1 -C "$REPO_DIR" || die "cannot extract repo"
  git config --global --add safe.directory "$REPO_DIR"
  git -C "$REPO_DIR" rev-parse HEAD > "$RESULTS_DIR/repo_commit.txt" 2>/dev/null || true
}

init_cm_state() {
  (cd "$REPO_DIR" && cm init -y </dev/null >> "$RESULTS_DIR/logs/cm_init.log" 2>&1) || true
  mkdir -p "$CM_HOME"
  cp "$CONFIG_DIR/cm_config.yaml" "$CM_HOME/config.yaml"
  printf '\nproject_paths:\n  - "%s"\n' "$REPO_DIR" >> "$CM_HOME/config.yaml"
}

# MODE=diff: the tarball is a pinned_ref checkout deep enough to contain
# diff_ref, so cm diffs merge-base(diff_ref, HEAD) as in CI.
prepare_diff() {
  local head
  PINNED_REF="$(task_field pinned_ref)"
  DIFF_REF="$(task_field diff_ref)"
  [[ "$PINNED_REF" =~ ^[0-9a-f]{40}$ ]] || die "diff task has no 40-hex pinned_ref: '$PINNED_REF'"
  [[ "$DIFF_REF" =~ ^[0-9a-f]{40}$ ]] || die "diff task has no 40-hex diff_ref: '$DIFF_REF'"
  head="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)"
  [ "$head" = "$PINNED_REF" ] || die "checkout HEAD '$head' != pinned_ref $PINNED_REF"
  git -C "$REPO_DIR" merge-base --is-ancestor "$DIFF_REF" HEAD 2>/dev/null \
    || die "diff_ref $DIFF_REF is not an ancestor of HEAD in the staged checkout"
  python3 "$SCRIPTS_DIR/diff_stats.py" --repo "$REPO_DIR" \
    --config "$CONFIG_DIR/cm_config.yaml" --base "$DIFF_REF" \
    > "$RESULTS_DIR/diff_stats.json" || die "diff_stats.py failed"
  python3 "$SCRIPTS_DIR/diff_stats.py" --repo "$REPO_DIR" \
    --config "$CONFIG_DIR/cm_config.yaml" --base "$DIFF_REF" --list \
    > "$RESULTS_DIR/diff_files.txt" || die "diff_stats.py --list failed"
  log "diff $DIFF_REF..$PINNED_REF: $(cat "$RESULTS_DIR/diff_stats.json")"
}

prepare_task() {
  setup_task
  install_cm
  extract_repo
  if [ "$OPERATION" = find ] && [ "$MODE" = diff ]; then
    prepare_diff
  fi
  init_cm_state
}

token_stats() {  # $1 = output file, $2 = optional start epoch
  local since_args=() worker_args=() limit="$TOKEN_STATS_TIMEOUT" left code=0
  [ -n "$TOKEN_STATS_WORKERS" ] && worker_args=(--workers "$TOKEN_STATS_WORKERS")
  if [ -n "${2:-}" ]; then
    # Upstream reads --since 0s as 168h, so the window is at least 1s.
    since_args=(--since "$(( $(date +%s) - $2 + 1 ))s")
    left="$(soft_remaining)"
    (( left < limit )) && limit="$left"
  fi
  log "cm-api-token-stats (limit ${limit}s, workers ${TOKEN_STATS_WORKERS:-default})"
  timeout --kill-after=5s "$limit" \
    cm-api-token-stats --project "${PROJECT_ID:-}" "${since_args[@]}" "${worker_args[@]}" \
    --json > "$1" \
    2>> "$RESULTS_DIR/logs/token_stats.log" || code=$?
  if (( code == 124 || code == 137 )); then
    echo '{"error":"timeout"}' > "$1"
    log "cm-api-token-stats timed out after ${limit}s"
  elif (( code != 0 )); then
    log "cm-api-token-stats failed (see logs)"
  fi
}

# cm's own local token accounting (it reads $CM_HOME/logs), uploaded next to
# the cm-api-token-stats output so the two can be compared. Best-effort: never
# changes the task exit code. Each run writes an empty <ts>_pending.log.
cm_stats() {  # $1 = output file, $2 = start epoch
  local limit="$CM_STATS_TIMEOUT" left code=0
  left="$(soft_remaining)"
  (( left < limit )) && limit="$left"
  timeout --kill-after=5s "$limit" \
    cm stats --json --since "$(( $(date +%s) - $2 + 1 ))s" </dev/null \
    > "$1" 2>> "$RESULTS_DIR/logs/cm_stats.log" || code=$?
  if (( code == 124 || code == 137 )); then
    echo '{"error":"timeout"}' > "$1"
    log "cm stats timed out after ${limit}s"
  elif (( code != 0 )) || ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" 2>/dev/null; then
    echo "{\"error\":\"failed\",\"exit_code\":$code}" > "$1"
    log "cm stats failed (see logs)"
  fi
}

# Create-only upload via the GCS JSON API with ifGenerationMatch=0. `gcloud
# storage cp` first GETs the destination, which objectCreator cannot do.
gcs_put() {  # $1 = local file, $2 = gs://bucket/object
  local rest="${2#gs://}" token name
  token="$(gcloud auth print-access-token)" || return 1
  name="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "${rest#*/}")"
  curl -sS -f -m 600 -o /dev/null -X POST -H "Authorization: Bearer $token" \
    -H "Content-Type: application/octet-stream" --data-binary @"$1" \
    "https://storage.googleapis.com/upload/storage/v1/b/${rest%%/*}/o?uploadType=media&ifGenerationMatch=0&name=$name"
}

gcs_put_tree() {  # $1 = local dir, $2 = gs://bucket/prefix
  local f
  while IFS= read -r -d '' f; do
    gcs_put "$f" "${2%/}/${f#"$1"/}" || return 1
  done < <(cd / && python3 -c 'import os,sys
for r,_,fs in os.walk(sys.argv[1]):
  for x in sorted(fs):
    p = os.path.join(r, x)
    if os.path.isfile(p):
      sys.stdout.write(p + "\0")' "$1")
}

upload_results() {
  # curl cannot read broken symlinks.
  prune_broken_links "$RESULTS_DIR"
  gcs_put_tree "$RESULTS_DIR" "$DEST" || die "upload to $DEST failed"
  log "uploaded results to $DEST"
}

summarize() {  # $1 = exit code, extra args passed through
  local code="$1"; shift
  python3 "$SCRIPTS_DIR/build_summary.py" --operation "$OPERATION" \
    --results-dir "$RESULTS_DIR" --repo-id "$REPO_ID" \
    --run-id "$RUN_ID" --experiment-id "$EXPERIMENT_ID" --model "$MODEL" \
    --mode "$MODE" --cm-version "$CM_VERSION" --severity "$SEVERITY" \
    --from-find-run "$FROM_FIND_RUN" --from-verify-run "$FROM_VERIFY_RUN" \
    --deep-workers "$DEEP_WORKERS" --source-find-mode "$SOURCE_FIND_MODE" \
    --pinned-ref "$PINNED_REF" --diff-ref "$DIFF_REF" \
    --diff-workers "$DIFF_WORKERS" --cm-exit-code "$CM_EXIT_CODE" \
    --exit-code "$code" \
    --start-epoch "$START_EPOCH" --end-epoch "$(date +%s)" "$@" \
    || log "build_summary failed"
}

# cm keeps state.db in WAL mode, so a plain cp can miss committed rows; the
# sqlite backup API reads through the WAL. Session logs are the only record of
# sessions whose state.db rows were lost to SQLITE_BUSY under --deep.
copy_state_db() {
  if [ -f "$CM_STATE_DB" ]; then
    python3 -c 'import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()' \
      "$CM_STATE_DB" "$RESULTS_DIR/state.db" || log "state.db snapshot failed"
  fi
  if compgen -G "$CM_HOME/logs/*.log" > /dev/null; then
    (cd "$CM_HOME/logs" && tar -czf "$RESULTS_DIR/logs/cm_logs.tar.gz" -- *.log) \
      || log "cm log archive failed"
  fi
}

cm_report_json() {  # $1 = output file; "[]" when the report fails or is empty
  (cd "$REPO_DIR" && cm report --format json </dev/null 2>/dev/null) > "$1" || echo "[]" > "$1"
  [ -s "$1" ] || echo "[]" > "$1"
}

# cm stops a PR delta scan at a hard-coded 5-minute ceiling and exits 1.
# Same messages as build_summary.py's DELTA_TIMEOUT_RE / DELTA_CEILING_RE.
diff_timed_out() {
  grep -Eq 'PR delta scan timed out after|PR Delta Scan (reached|terminated: reached).*ceiling' \
    "$RESULTS_DIR/logs/execution.log" 2>/dev/null
}

# MODE=diff: cm's default --fail-on gate (CRITICAL,HIGH) exits 1 when it
# reports such findings, and its 5-minute ceiling exits 1 too. Both are
# measured outcomes: exit 1 with findings or at the ceiling maps to 0
# (summary.json records diff_timed_out); exit 1 otherwise and any other
# non-zero exit stay failures. Any non-empty findings list counts (severity
# and DISMISSED status are not checked): the gate is cm's default or a
# pass-through --fail-on, and the raw code is kept as cm_exit_code.
diff_task_code() {  # $1 = raw cm exit code
  if [ "$1" = 1 ] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if (d if isinstance(d, list) else (d or {}).get("findings") or []) else 1)' \
      "$RESULTS_DIR/findings.json" 2>/dev/null; then
    log "cm find exit 1 with findings: --fail-on gate tripped; counted as success"
    echo 0
  elif [ "$1" = 1 ] && diff_timed_out; then
    log "cm find exit 1 at cm's 5-minute PR delta scan ceiling; counted as success (diff_timed_out)"
    echo 0
  else
    echo "$1"
  fi
}

run_find() {
  local deep=() code
  if [ "$MODE" = "complete" ]; then
    deep=(--complete)
    [ -n "$DEEP_WORKERS" ] && [ "$DEEP_WORKERS" != "16" ] && deep+=("--deep-workers=$DEEP_WORKERS")
  elif [ "$MODE" = "deep" ]; then
    deep=(--deep)
    [ -n "$DEEP_WORKERS" ] && [ "$DEEP_WORKERS" != "16" ] && deep+=("--deep-workers=$DEEP_WORKERS")
  elif [ "$MODE" = "diff" ]; then
    deep=(--diff "--diff=$DIFF_REF")
    [ -n "$DIFF_WORKERS" ] && deep+=("--diff-workers=$DIFF_WORKERS")
  elif [ "$MODE" = "shallow" ]; then
    deep=(--quick)
  fi
  log "cm find (mode=$MODE, soft timeout $(soft_remaining)s)"
  # shellcheck disable=SC2086  # EXTRA_CM_ARGS is intentionally word-split.
  (cd "$REPO_DIR" && timeout --kill-after=15s "$(soft_remaining)" \
    python3 "$CM_CI" find . --repo "$REPO_DIR" ${deep[@]+"${deep[@]}"} "--model=$MODEL" -y $EXTRA_CM_ARGS \
    </dev/null 2>&1) | tee "$RESULTS_DIR/logs/execution.log"
  code=$?
  log "cm find exit code $code"
  (cd "$REPO_DIR" && cm report --format json </dev/null 2>/dev/null) > "$RESULTS_DIR/findings.json.tmp"
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); json.dump(d if d is not None else [], open(sys.argv[2],"w"), indent=2)' \
      "$RESULTS_DIR/findings.json.tmp" "$RESULTS_DIR/findings.json" 2>/dev/null; then :; else
    echo "[]" > "$RESULTS_DIR/findings.json"
  fi
  rm -f "$RESULTS_DIR/findings.json.tmp"
  if [ "$MODE" = "diff" ]; then
    CM_EXIT_CODE="$code"
    code="$(diff_task_code "$code")"
  fi
  (cd "$REPO_DIR" && cm report </dev/null > "$RESULTS_DIR/findings_table.txt" 2>/dev/null) || true
  copy_state_db
  cm_stats "$RESULTS_DIR/cm_stats.json" "$START_EPOCH"
  token_stats "$RESULTS_DIR/cm_api_token_stats.json"
  summarize "$code"
  upload_results
  return "$code"
}

# ------------------------------------------------------------------------------
# verify / fix: import the source findings into cm's state, then run cm on each
# matching finding sequentially, resetting the repo in between.
# ------------------------------------------------------------------------------
fetch_source_findings() {
  [ -n "$FINDINGS_URI" ] || die "$OPERATION task has no findings_gcs_uri"
  fetch "$FINDINGS_URI" "$RESULTS_DIR/source_findings.json"
}

# `cm report` creates the state.db schema that import_findings.py writes into.
ensure_cm_schema() {
  (cd "$REPO_DIR" && cm report --format json </dev/null >/dev/null 2>&1) || true
}

init_import_args() {
  IMPORT_ARGS=(
    --findings "$RESULTS_DIR/source_findings.json"
    --repo-dir "$REPO_DIR"
    --repo-id "$REPO_ID"
    --severity "$SEVERITY"
    --ids-out "$IDS_FILE"
    --filtered-out "$RESULTS_DIR/imported_findings.json"
  )
}

import_findings() {  # $1 = error message, extra args appended to IMPORT_ARGS
  local msg="$1"; shift
  python3 "$SCRIPTS_DIR/import_findings.py" "${IMPORT_ARGS[@]}" "$@" \
    >> "$RESULTS_DIR/logs/import.log" 2>&1 || die "$msg"
}

write_inventory() {
  python3 "$SCRIPTS_DIR/render_verify_context.py" --inventory-only > "$INVENTORY"
}

load_matching_ids() {  # $1 = limit variable name, $2 = verb for the log line
  local limit="${!1}"
  mapfile -t MATCHING_IDS < "$IDS_FILE"
  if (( limit > 0 && ${#MATCHING_IDS[@]} > limit )); then
    MATCHING_IDS=("${MATCHING_IDS[@]:0:limit}")
    printf '%s\n' "${MATCHING_IDS[@]}" > "$IDS_FILE"  # summary counts the capped set
    log "$1=$limit: $2 the first $limit by severity"
  fi
}

# Runs `cm <verb>` on each of MATCHING_IDS within the soft deadline.
# $1 = verb, $2 = per-finding timeout, $3 = hook run before the repo reset
# (gets finding id and dir), rest = extra cm flags. Returns 124 if any finding
# was skipped for the deadline, else 0.
process_findings() {
  local verb="$1" max_seconds="$2" hook="$3"; shift 3
  local loop_code=0 fid fdir remaining t t0 code
  for fid in "${MATCHING_IDS[@]}"; do
    fdir="$RESULTS_DIR/findings/$fid"; mkdir -p "$fdir"
    remaining=$(( DEADLINE - $(date +%s) ))
    if (( remaining < MIN_FINDING_SECONDS )); then
      log "soft deadline reached; skipping $fid"
      echo "deadline" > "$fdir/exit_code"; loop_code=124; continue
    fi
    t=$(( remaining < max_seconds ? remaining : max_seconds ))
    python3 "$SCRIPTS_DIR/render_verify_context.py" --template "$CONFIG_DIR/verify_context.md" \
      --repo-dir "$REPO_DIR" --repo-id "$REPO_ID" --language "$LANGUAGE" \
      --finding-id "$fid" --inventory-file "$INVENTORY" > "$fdir/context.txt"
    t0=$(date +%s)
    # shellcheck disable=SC2086  # EXTRA_CM_ARGS is intentionally word-split.
    (cd "$REPO_DIR" && timeout --kill-after=15s "$t" \
      cm "$verb" "$fid" --model "$MODEL" -y --bypass-warning --unrestricted "$@" \
      -c "$(cat "$fdir/context.txt")" $EXTRA_CM_ARGS </dev/null 2>&1) | tee "$fdir/$verb.log"
    code=$?
    echo "$code" > "$fdir/exit_code"
    log "finding $fid exit code $code"
    "$hook" "$fid" "$fdir"
    cm_stats "$fdir/cm_stats.json" "$t0"
    token_stats "$fdir/token_stats.json" "$t0"
    git -C "$REPO_DIR" reset --hard -q && git -C "$REPO_DIR" clean -fdxq
  done
  return "$loop_code"
}

finish_findings_run() {  # $1 = post-run report file name, $2 = loop exit code
  cm_report_json "$RESULTS_DIR/$1"
  copy_state_db
  summarize "$2" --ids-file "$IDS_FILE"
  upload_results
  return "$2"
}

archive_exploit() {  # $1 = finding id, $2 = finding dir
  local src=""
  if [ -d "$REPO_DIR/.exploit" ]; then
    src="$REPO_DIR/.exploit"
  else
    src="$(find "$REPO_DIR" -maxdepth 4 -name ".exploit" -type d 2>/dev/null | head -n 1)"
  fi
  [ -n "$src" ] || return 0
  cp -rL "$src" "$2/exploit" 2>/dev/null || cp -a "$src" "$2/exploit" 2>/dev/null || true
  prune_broken_links "$2/exploit"
}

run_verify() {
  local loop_code
  fetch_source_findings
  ensure_cm_schema
  init_import_args
  if [ -n "$FINDING_IDS" ]; then
    IMPORT_ARGS+=(--finding-ids "$FINDING_IDS")
  fi
  import_findings "import_findings failed"
  write_inventory
  load_matching_ids VERIFY_LIMIT verifying
  log "verifying ${#MATCHING_IDS[@]} finding(s) sequentially"
  process_findings verify "$VERIFY_FINDING_TIMEOUT" archive_exploit --no-reset
  loop_code=$?
  finish_findings_run post_verify_report.json "$loop_code"
}

# Downloads each matching finding's verify-run exploit, archives a copy with
# the results, and re-imports the findings with --exploits-dir.
stage_exploits() {
  local exp_dir="$WORK/exploits" fid remote dst
  mkdir -p "$exp_dir"
  for fid in "${MATCHING_IDS[@]}"; do
    remote="${VERIFY_REPO_PREFIX%/}/findings/$fid/exploit"
    gcloud storage ls "$remote/" >/dev/null 2>&1 || continue
    dst="$exp_dir/$fid"
    mkdir -p "$dst"
    gcloud storage cp -r "$remote"/* "$dst/" >/dev/null 2>&1 \
      || gcloud storage cp -r "$remote" "$dst/" >/dev/null 2>&1 || true
    if [ -d "$dst/exploit" ] && [ ! -f "$dst/poc.txt" ] && [ ! -f "$dst/exploit.sh" ]; then
      cp -rL "$dst/exploit/." "$dst/" 2>/dev/null || true
      rm -rf "$dst/exploit"
    fi
    prune_broken_links "$dst"
    mkdir -p "$RESULTS_DIR/findings/$fid/exploit"
    cp -rL "$dst/." "$RESULTS_DIR/findings/$fid/exploit/" 2>/dev/null || true
    prune_broken_links "$RESULTS_DIR/findings/$fid/exploit"
  done
  import_findings "import_findings with exploits failed" --exploits-dir "$exp_dir"
  # The re-import rewrites --ids-out uncapped; restore the FIX_LIMIT-capped set.
  printf '%s\n' "${MATCHING_IDS[@]}" > "$IDS_FILE"
}

capture_patch() {  # $1 = finding id, $2 = finding dir
  git -C "$REPO_DIR" add -N . 2>/dev/null || true
  git -C "$REPO_DIR" diff HEAD -- . ':!.exploit' > "$2/patch.diff" 2>/dev/null || true
  # cm may leave no working-tree edit; fall back to its latest stored patch.
  if [ ! -s "$2/patch.diff" ] && [ -f "$CM_STATE_DB" ]; then
    python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute("SELECT diff FROM patches WHERE finding_id=? ORDER BY created_at DESC LIMIT 1",(sys.argv[2],)).fetchone(); sys.stdout.write(r[0] if r and r[0] else "")' \
      "$CM_STATE_DB" "$1" > "$2/patch.diff" 2>/dev/null || true
  fi
}

concat_patches() {
  local p
  for p in "$RESULTS_DIR"/findings/*/patch.diff; do
    if [ -s "$p" ]; then
      cat "$p" >> "$RESULTS_DIR/patch.diff"
    fi
  done
}

run_fix() {
  local loop_code
  fetch_source_findings
  init_import_args
  if [ -n "$VERIFY_REPORT_URI" ]; then
    fetch "$VERIFY_REPORT_URI" "$RESULTS_DIR/source_verify_report.json"
    IMPORT_ARGS+=(--verify-report "$RESULTS_DIR/source_verify_report.json")
    if [ "$INCLUDE_UNVERIFIED" != "1" ]; then
      IMPORT_ARGS+=(--only-verified)
    fi
  fi
  if [ -n "$VERIFY_IDS_URI" ]; then
    fetch "$VERIFY_IDS_URI" "$RESULTS_DIR/source_verify_ids.txt"
    IMPORT_ARGS+=(--attempted-ids "$RESULTS_DIR/source_verify_ids.txt")
  fi
  if [ -n "$FINDING_IDS" ]; then
    IMPORT_ARGS+=(--finding-ids "$FINDING_IDS")
  fi
  ensure_cm_schema
  import_findings "import_findings failed"
  load_matching_ids FIX_LIMIT fixing
  if [ -n "$VERIFY_REPO_PREFIX" ] && (( ${#MATCHING_IDS[@]} > 0 )); then
    stage_exploits
  fi
  write_inventory
  log "fixing ${#MATCHING_IDS[@]} finding(s) sequentially"
  process_findings fix "$FIX_FINDING_TIMEOUT" capture_patch
  loop_code=$?
  concat_patches
  finish_findings_run post_fix_report.json "$loop_code"
}

# ------------------------------------------------------------------------------
# Hidden OPERATION=selftest (run by scripts/selftest.sh, not exposed in run.py).
# Proves DNS/egress isolation, the bucket data diode, and the offline toolbox,
# then writes gs://<own results bucket>/selftest/<execution>/result.json.
# ------------------------------------------------------------------------------
ST_RESULTS="${TMPDIR:-/tmp}/selftest_checks.jsonl"

st_record() {  # name pass(true|false) detail
  python3 -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "pass": sys.argv[2] == "true", "detail": sys.argv[3][-400:]}))' \
    "$1" "$2" "$3" >> "$ST_RESULTS"
}

st_expect_ok() {  # name cmd...
  local name="$1" out; shift
  if out="$("$@" 2>&1)"; then st_record "$name" true "$out"; else st_record "$name" false "$out"; fi
}

st_expect_fail() {  # name max_seconds cmd...  (must fail, within max_seconds)
  local name="$1" max="$2" out rc t0 dt; shift 2
  t0=$(date +%s)
  out="$("$@" 2>&1)"; rc=$?
  dt=$(( $(date +%s) - t0 ))
  if (( rc != 0 && dt <= max )); then
    st_record "$name" true "rc=$rc ${dt}s: $out"
  else
    st_record "$name" false "rc=$rc ${dt}s: $out"
  fi
}

run_selftest() {
  local job="${CLOUD_RUN_JOB:-}" role own exec_id prefix probe ip out code
  case "$job" in
    *fix*) role="fix"; own="${FIX_RESULTS_BUCKET:?}" ;;
    *verify*) role="verify"; own="${VERIFY_RESULTS_BUCKET:?}" ;;
    *find*) role="find"; own="${FIND_RESULTS_BUCKET:?}" ;;
    *) die "selftest: cannot infer role from CLOUD_RUN_JOB='$job'" ;;
  esac
  exec_id="${CLOUD_RUN_EXECUTION:-manual-$START_EPOCH}"
  prefix="gs://$own/selftest/$exec_id"
  : > "$ST_RESULTS"
  log "selftest role=$role own=$own"

  # 1. DNS resolves googleapis into the private VIP.
  ip="$(getent hosts aiplatform.googleapis.com | awk '{print $1; exit}')"
  if [[ "$ip" =~ ^199\.36\.153\.(8|9|10|11)$ ]]; then
    st_record dns_private_vip true "aiplatform.googleapis.com -> $ip"
  else
    st_record dns_private_vip false "aiplatform.googleapis.com -> '${ip}'"
  fi
  # 2. Google APIs answer over HTTPS; 3/4. the internet does not.
  code="$(curl -m10 -s -o /dev/null -w '%{http_code}' https://aiplatform.googleapis.com/ 2>&1)"
  if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
    st_record googleapis_https true "HTTP $code"
  else
    st_record googleapis_https false "curl: '$code'"
  fi
  st_expect_fail egress_github_blocked 20 curl -m5 -sS -o /dev/null https://github.com
  st_expect_fail egress_1111_blocked 20 curl -m5 -sS -o /dev/null https://1.1.1.1

  # 5-8. Bucket data diode.
  probe="$(mktemp)"; echo "selftest $role $exec_id" > "$probe"
  st_expect_ok own_bucket_create gcs_put "$probe" "$prefix/probe.txt"
  st_expect_fail own_bucket_overwrite_denied 120 gcs_put "$probe" "$prefix/probe.txt"
  st_expect_fail payload_write_denied 120 gcs_put "$probe" "gs://${PAYLOAD_BUCKET:?}/selftest/$role-$exec_id.txt"
  if [ "$role" = find ]; then
    st_expect_fail find_sa_read_verify_results_denied 120 gcloud storage ls "gs://${VERIFY_RESULTS_BUCKET:?}/"
    if [ -n "${FIX_RESULTS_BUCKET:-}" ]; then
      st_expect_fail find_sa_read_fix_results_denied 120 gcloud storage ls "gs://$FIX_RESULTS_BUCKET/"
    fi
  elif [ "$role" = verify ]; then
    st_expect_fail verify_sa_write_find_results_denied 120 gcs_put "$probe" "gs://${FIND_RESULTS_BUCKET:?}/selftest/$role-$exec_id.txt"
    st_expect_ok verify_sa_read_find_results gcloud storage ls "gs://${FIND_RESULTS_BUCKET:?}/"
    if [ -n "${FIX_RESULTS_BUCKET:-}" ]; then
      st_expect_fail verify_sa_read_fix_results_denied 120 gcloud storage ls "gs://$FIX_RESULTS_BUCKET/"
    fi
  elif [ "$role" = fix ]; then
    st_expect_fail fix_sa_write_find_results_denied 120 gcs_put "$probe" "gs://${FIND_RESULTS_BUCKET:?}/selftest/$role-$exec_id.txt"
    st_expect_fail fix_sa_write_verify_results_denied 120 gcs_put "$probe" "gs://${VERIFY_RESULTS_BUCKET:?}/selftest/$role-$exec_id.txt"
    st_expect_ok fix_sa_read_find_results gcloud storage ls "gs://${FIND_RESULTS_BUCKET:?}/"
    st_expect_ok fix_sa_read_verify_results gcloud storage ls "gs://${VERIFY_RESULTS_BUCKET:?}/"
  fi
  st_expect_ok payload_read gcloud storage ls "gs://$PAYLOAD_BUCKET/"

  # 9. Offline exploit toolbox (VERIFY_AIRGAP.md §5), verify and fix jobs.
  if [ "$role" = verify ] || [ "$role" = fix ]; then
    local tdir; tdir="$(mktemp -d)"
    printf 'int main(void){return 0;}\n' > "$tdir/a.c"
    printf 'int main(){return 0;}\n' > "$tdir/b.cc"
    printf 'class T{public static void main(String[] a){}}\n' > "$tdir/T.java"
    st_expect_ok toolbox_python_libs python3 -c 'import flask, sqlalchemy, jwt, yaml, lxml'
    st_expect_ok toolbox_node_express env NODE_PATH="$(npm root -g 2>/dev/null)" node -e 'require("express")'
    st_expect_ok toolbox_gcc gcc -o "$tdir/a" "$tdir/a.c"
    st_expect_ok toolbox_gxx_asan g++ -fsanitize=address -o "$tdir/b" "$tdir/b.cc"
    st_expect_ok toolbox_javac javac -d "$tdir" "$tdir/T.java"
    st_expect_ok toolbox_go go version
    st_expect_ok toolbox_php php -v
    st_expect_ok toolbox_ruby ruby -v
    st_expect_fail airgap_pip_install_fails 21 timeout 20 pip install --index-url https://pypi.org/simple six
    st_expect_fail airgap_npm_view_fails 21 timeout 20 npm view left-pad
    st_expect_fail airgap_git_ls_remote_fails 21 timeout 20 git ls-remote https://github.com/erev0s/VAmPI.git
    out="$(python3 "$SCRIPTS_DIR/render_verify_context.py" --template "$CONFIG_DIR/verify_context.md" \
      --repo-dir /home/runner/workspace/selftest --repo-id selftest --language python 2>&1)"
    if [[ "$out" == *"   - python3: "* && "$out" != *'$'* ]]; then
      st_record render_verify_context true "$(echo "$out" | tail -3)"
    else
      st_record render_verify_context false "$out"
    fi
  fi

  python3 - "$ST_RESULTS" "$role" "$exec_id" "$job" > "$probe.result.json" <<'PY'
import json, sys
checks = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
print(json.dumps({"role": sys.argv[2], "execution": sys.argv[3], "job": sys.argv[4],
                  "all_pass": bool(checks) and all(c["pass"] for c in checks),
                  "checks": checks}, indent=2))
PY
  gcs_put "$probe.result.json" "$prefix/result.json" || die "cannot upload selftest result"
  log "selftest result: $prefix/result.json"
  cat "$probe.result.json"
}

main() {
  case "$OPERATION" in
    selftest) run_selftest; return 0 ;;
    find) prepare_task; run_find ;;
    verify) prepare_task; run_verify ;;
    fix) prepare_task; run_fix ;;
    *) die "unknown OPERATION '$OPERATION'" ;;
  esac
}

main "$@"
