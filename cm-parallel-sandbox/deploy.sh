#!/usr/bin/env bash
# Builds the shared runner image with Cloud Build and rolls it into find, verify, and fix jobs.
#
# Usage: ./deploy.sh --project <project> [--region us-central1] [--tag <tag>]
#
# Enables no APIs and runs no Terraform: the AR repo and jobs come from the
# cm-parallel-sandbox Terraform module.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROJECT=""
REGION="us-central1"
TAG=""
FIND_JOB="cm-find-runner"
VERIFY_JOB="cm-verify-runner"
FIX_JOB="cm-fix-runner"

usage() { sed -n '2,4p' "$0" >&2; exit 2; }

while (( $# )); do
  case "$1" in
    --project) PROJECT="${2:?}"; shift 2 ;;
    --region) REGION="${2:?}"; shift 2 ;;
    --tag) TAG="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
done
[ -n "$PROJECT" ] || { echo "--project is required" >&2; usage; }

if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
  echo "refusing to deploy from a dirty tree; commit or stash first:" >&2
  git -C "$ROOT" status --short >&2
  exit 1
fi
[ -n "$TAG" ] || TAG="$(git -C "$ROOT" rev-parse --short HEAD)"

IMAGE="$REGION-docker.pkg.dev/$PROJECT/cm-parallel-sandbox/cm-sandbox-runner:$TAG"

# run.py never writes job parallelism; a pinned value would silently throttle
# every execution. Read-only: fail before building, never fix it here.
for job in "$FIND_JOB" "$VERIFY_JOB" "$FIX_JOB"; do
  par="$(gcloud run jobs describe "$job" --project="$PROJECT" --region="$REGION" \
    --format='value(spec.template.spec.parallelism)')"
  if [ -n "$par" ] && [ "$par" != "0" ]; then
    echo "deploy.sh: $job has parallelism=$par pinned; run.py expects it unset." >&2
    echo "  one-time reset: gcloud run jobs update $job --parallelism=0" \
      "--project=$PROJECT --region=$REGION" >&2
    exit 1
  fi
done

# Build context = container/ plus the runtime config and cm-ci wrapper the image bakes in.
CTX="$(mktemp -d "${TMPDIR:-/tmp}/cm_build.XXXXXX")"
trap 'rm -rf "$CTX"' EXIT
cp -a "$ROOT/container/." "$CTX/"
mkdir -p "$CTX/config" "$CTX/cm-ci"
cp "$ROOT/config/cm_config.yaml" "$ROOT/config/verify_context.md" "$CTX/config/"
for f in cm-ci.py codemender.py complete_scan.py deduplication.py finding.py cwe_database.py cwec_v4.20.xml discouraged_cwes.txt; do
  if [ -f "$ROOT/../$f" ]; then
    cp "$ROOT/../$f" "$CTX/cm-ci/"
  fi
done

echo "==> Building $IMAGE"
# Submit async and poll status: streaming logs needs project Viewer.
BUILD_ID="$(gcloud builds submit "$CTX" --project="$PROJECT" --tag="$IMAGE" \
  --machine-type=e2-highcpu-8 --timeout=3600s --async --format='value(id)')"
echo "==> Build $BUILD_ID submitted"
while :; do
  STATUS="$(gcloud builds describe "$BUILD_ID" --project="$PROJECT" \
    --format='value(status)')"
  case "$STATUS" in
    SUCCESS) break ;;
    QUEUED|PENDING|WORKING) sleep "${DEPLOY_POLL_SECONDS:-20}" ;;
    *) echo "deploy.sh: build $BUILD_ID status $STATUS" >&2; exit 1 ;;
  esac
done

for job in "$FIND_JOB" "$VERIFY_JOB" "$FIX_JOB"; do
  echo "==> Updating $job"
  gcloud run jobs update "$job" --project="$PROJECT" --region="$REGION" \
    --image="$IMAGE" --quiet
done

# Read back each job's image (Job resource path) and fail on any mismatch.
for job in "$FIND_JOB" "$VERIFY_JOB" "$FIX_JOB"; do
  deployed="$(gcloud run jobs describe "$job" --project="$PROJECT" \
    --region="$REGION" \
    --format='value(spec.template.spec.template.spec.containers[0].image)')"
  echo "$job image: ${deployed:-<none>}"
  if [[ "$deployed" != "$IMAGE" ]]; then
    echo "deploy.sh: $job image is '${deployed}', expected '$IMAGE'" >&2
    exit 1
  fi
done
