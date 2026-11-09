#!/usr/bin/env bash
# Local gate: compile, unit tests, shell syntax (and shellcheck when available).
set -euo pipefail
cd "$(dirname "$0")/.."
targets=()
for t in cmrun stage_repos.py run.py container/scripts tests; do [ -e "$t" ] && targets+=("$t"); done
python3 -m compileall -q "${targets[@]}"
python3 -m unittest discover -s tests -v
for f in deploy.sh container/entrypoint.sh scripts/*.sh terraform/*.sh; do [ -f "$f" ] && bash -n "$f"; done
if command -v shellcheck >/dev/null; then
  sc=()
  for f in container/entrypoint.sh deploy.sh scripts/*.sh terraform/*.sh; do [ -f "$f" ] && sc+=("$f"); done
  shellcheck -S warning "${sc[@]}"
fi
if command -v terraform >/dev/null; then
  terraform fmt -check -recursive terraform
  for d in terraform/modules/cm-parallel-sandbox terraform/examples/dev-sandbox terraform/examples/complete; do
    terraform -chdir="$d" init -backend=false -input=false >/dev/null
    terraform -chdir="$d" validate >/dev/null
  done
fi
echo "check.sh: OK"
