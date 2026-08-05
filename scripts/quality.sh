#!/usr/bin/env bash
set -euo pipefail

project_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mode="${1:---local}"
[[ "${mode}" == "--local" || "${mode}" == "--ci" ]] || { echo "usage: scripts/quality.sh [--local|--ci]" >&2; exit 64; }
cd "${project_root}"
export UV_CACHE_DIR="${project_root}/.cache/uv"
# FAST_EQUIVALENCE_BOUNDARY: this non-recursive entry point preserves the
# canonical Fast foundation/canary coverage through the complete pytest gate,
# then adds the pre-existing lock, policy, static, typing, and shell gates.
# Fast itself must never invoke this script.
"${project_root}/.tools/uv/uv" --config-file uv.toml --project "${project_root}" lock --check
"${project_root}/scripts/run.sh" mojoattention privacy --json -
"${project_root}/scripts/run.sh" mojoattention authority --json -
"${project_root}/scripts/run.sh" python scripts/validate_governance_contracts.py
"${project_root}/scripts/run.sh" mojoattention contract validate \
  --contract contracts/acceptance/1-3.example.json \
  --source-revision 1111111111111111111111111111111111111111 \
  --trusted-base-revision 2222222222222222222222222222222222222222 \
  --json -
if [[ "${mode}" == "--ci" ]]; then
  "${project_root}/scripts/run.sh" pytest -q -m 'not host_integration'
else
  "${project_root}/scripts/run.sh" pytest -q
fi
"${project_root}/scripts/run.sh" ruff check .
"${project_root}/scripts/run.sh" ruff format --check .
"${project_root}/scripts/run.sh" mypy
bash -n scripts/*.sh
