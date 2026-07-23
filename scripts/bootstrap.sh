#!/usr/bin/env bash
set -euo pipefail

project_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
uv_bin="${project_root}/.tools/uv/uv"
expected_uv="0.11.29"

required_paths=(
  pyproject.toml uv.toml uv.lock .python-version README.md docs/setup.md
  src/mojoattention/config.py src/mojoattention/validation/preflight.py
  contracts/README.md schemas/README.md fixtures/README.md reports/README.md
)

fail() { echo "bootstrap: $1" >&2; exit "${2:-3}"; }
require_local_path() {
  local candidate="$1"
  [[ ! -L "${candidate}" ]] || fail "refusing symlinked project path: ${candidate}"
  [[ "$(realpath -m -- "${candidate}")" == "${project_root}"/* ]] || fail "path escapes project root: ${candidate}"
}
verify_structure() {
  local relative
  for relative in "${required_paths[@]}"; do
    [[ -e "${project_root}/${relative}" ]] || fail "required project path is missing: ${relative}"
  done
}

[[ $# -eq 1 ]] || fail "usage: scripts/bootstrap.sh [--check|--sync]" 64
command -v python3 >/dev/null || fail "Python 3.14.4 is required; python3 was not found" 2
[[ "$(python3 -c 'import platform; print(platform.python_version())')" == "3.14.4" ]] || fail "Python 3.14.4 is required" 2
[[ -x "${uv_bin}" ]] || fail "pinned uv is missing; run scripts/install-uv.sh" 2
[[ "$("${uv_bin}" --version | awk '{print $2}')" == "${expected_uv}" ]] || fail "project tool must be uv ${expected_uv}" 3
verify_structure

for path in "${project_root}/.venv" "${project_root}/.cache" "${project_root}/.cache/modular"; do
  require_local_path "${path}"
done

unset PYTHONHOME PYTHONPATH UV_CONFIG_FILE UV_PROJECT UV_WORKSPACE UV_INDEX UV_DEFAULT_INDEX
unset UV_EXTRA_INDEX_URL UV_INDEX_URL UV_FIND_LINKS UV_NO_INDEX UV_INDEX_STRATEGY UV_INSECURE_HOST
unset UV_OFFLINE UV_FROZEN UV_LOCKED UV_NO_SYNC UV_PYTHON UV_PYTHON_DOWNLOADS UV_LINK_MODE
export UV_PROJECT_ENVIRONMENT="${project_root}/.venv"
export UV_CACHE_DIR="${project_root}/.cache/uv"
export MODULAR_CACHE_DIR="${project_root}/.cache/modular"
export MODULAR_MAX_CACHE_DIR="${project_root}/.cache/modular"
export XDG_CACHE_HOME="${project_root}/.cache"
export XDG_DATA_HOME="${project_root}/.cache/xdg-data"
export MOJOATTENTION_PROJECT_ROOT="${project_root}"
export MOJOATTENTION_UV_BIN="${uv_bin}"
export PATH="${project_root}/.venv/bin:${PATH}"

case "$1" in
  --check)
    [[ -x "${project_root}/.venv/bin/python" ]] || fail "project .venv is missing; run scripts/bootstrap.sh --sync" 2
    [[ -d "${project_root}/.cache/modular" ]] || fail "project Modular cache is missing; run scripts/bootstrap.sh --sync" 2
    "${project_root}/.venv/bin/mojoattention" environment --json - >/dev/null
    printf 'bootstrap-ok root=%s environment=.venv modular-cache=.cache/modular uv=%s\n' "${project_root}" "${expected_uv}"
    ;;
  --sync)
    mkdir -p "${project_root}/.cache/modular" "${project_root}/.cache/xdg-data" "${project_root}/.cache/uv"
    PYTHONPATH="${project_root}/src" python3 -m mojoattention.cli.main preflight --mode broad --json - >/dev/null
    cd "${project_root}"
    "${uv_bin}" --config-file "${project_root}/uv.toml" --project "${project_root}" lock --check
    "${uv_bin}" --config-file "${project_root}/uv.toml" --project "${project_root}" sync --locked --all-groups
    "${project_root}/.venv/bin/mojoattention" environment --json - >/dev/null
    ;;
  *) fail "usage: scripts/bootstrap.sh [--check|--sync]" 64 ;;
esac
