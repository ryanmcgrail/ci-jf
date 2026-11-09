#!/usr/bin/env bash
# Provisions sandbox infrastructure, builds the runner container image, and runs
# the data diode self-test.
#
# Usage: ./bootstrap.sh --project <project> [--region us-central1] [--no-enable-apis] [--config-dir <dir>] [--var-file <path>]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_ROOT="$(cd "$(dirname "$0")" && pwd)"
PROJECT=""
REGION="us-central1"
ENABLE_APIS="true"
CONFIG_DIR="$TF_ROOT/examples/dev-sandbox"
VAR_FILE=""

usage() {
  sed -n '2,5p' "$0" >&2
  exit 2
}

while (( $# )); do
  case "$1" in
    --project) PROJECT="${2:?}"; shift 2 ;;
    --region) REGION="${2:?}"; shift 2 ;;
    --no-enable-apis) ENABLE_APIS="false"; shift 1 ;;
    --config-dir) CONFIG_DIR="${2:?}"; shift 2 ;;
    --var-file) VAR_FILE="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
done

[ -n "$PROJECT" ] || { echo "--project is required" >&2; usage; }

command -v terraform >/dev/null || { echo "error: terraform is required on PATH" >&2; exit 1; }
command -v gcloud >/dev/null || { echo "error: gcloud is required on PATH" >&2; exit 1; }

# Resolve --var-file before changing directory so relative paths work.
var_file_args=()
if [ -n "$VAR_FILE" ]; then
  [ -f "$VAR_FILE" ] || { echo "error: --var-file not found: $VAR_FILE" >&2; exit 1; }
  var_file_args=("-var-file=$(cd "$(dirname "$VAR_FILE")" && pwd)/$(basename "$VAR_FILE")")
fi

echo "==> [1/3] Applying Terraform infrastructure in $CONFIG_DIR"
(
  cd "$CONFIG_DIR"
  terraform init -input=false
  terraform apply -auto-approve -input=false \
    ${var_file_args[@]+"${var_file_args[@]}"} \
    -var="project_id=$PROJECT" \
    -var="region=$REGION" \
    -var="enable_apis=$ENABLE_APIS"
)

echo "==> [2/3] Building runner image and updating Cloud Run jobs"
ALLOW_DIRTY=1 "$ROOT/deploy.sh" --project "$PROJECT" --region "$REGION"

echo "==> [3/3] Running data-diode self-test across all stages"
"$ROOT/scripts/selftest.sh" --project "$PROJECT" --region "$REGION"

echo "==> Sandbox bootstrap completed successfully."
echo "    To run your first pipeline execution, run:"
echo "    python3 run.py --operation find-verify-fix --repos o04-vampi --experiment-id smoke --verify-limit 1 --fix-limit 1 --wait --project $PROJECT"
