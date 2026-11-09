#!/usr/bin/env bash
# Live data-diode selftest: runs OPERATION=selftest on both Cloud Run jobs,
# fetches each result.json, and exits non-zero if any check failed.
#
# Usage: scripts/selftest.sh [--project <project>] [--region us-central1] [--out out/selftest]
set -euo pipefail

PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
REGION="us-central1"
OUT="out/selftest"

while (( $# )); do
  case "$1" in
    --project) PROJECT="${2:?}"; shift 2 ;;
    --region) REGION="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done
[ -n "$PROJECT" ] || { echo "--project is required" >&2; exit 2; }
mkdir -p "$OUT"

rc=0
for role in find verify fix; do
  job="cm-$role-runner"
  bucket="$PROJECT-cm-$role-results"
  echo "==> selftest $job"
  exec_json="$(gcloud run jobs execute "$job" --project="$PROJECT" --region="$REGION" \
    --update-env-vars=OPERATION=selftest --tasks=1 --wait --format=json)" \
    || { echo "execution of $job failed" >&2; rc=1; continue; }
  exec_name="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"]["name"])' <<<"$exec_json")"
  gcloud storage cat "gs://$bucket/selftest/$exec_name/result.json" > "$OUT/$role.json" \
    || { echo "missing result.json for $exec_name" >&2; rc=1; continue; }
  python3 - "$OUT/$role.json" <<'PY' || rc=1
import json, sys
r = json.load(open(sys.argv[1]))
for c in r["checks"]:
  print(f"  {'PASS' if c['pass'] else 'FAIL'}  {c['name']}")
print(f"  role={r['role']} execution={r['execution']} all_pass={r['all_pass']}")
sys.exit(0 if r["all_pass"] else 1)
PY
done
exit "$rc"
