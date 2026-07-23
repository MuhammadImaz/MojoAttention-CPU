#!/usr/bin/env bash
set -euo pipefail

project_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${project_root}/.venv/bin:${PATH}"
export UV_PROJECT_ENVIRONMENT="${project_root}/.venv"
export UV_CACHE_DIR="${project_root}/.cache/uv"
export UV_TOOL_DIR="${project_root}/.cache/uv-tools"
export MODULAR_CACHE_DIR="${project_root}/.cache/modular"
export MODULAR_MAX_CACHE_DIR="${project_root}/.cache/modular"
export XDG_CACHE_HOME="${project_root}/.cache"
export XDG_DATA_HOME="${project_root}/.cache/xdg-data"
export MOJOATTENTION_PROJECT_ROOT="${project_root}"
export MOJOATTENTION_UV_BIN="${project_root}/.tools/uv/uv"
unset PYTHONHOME PYTHONPATH

if [[ ! -x "${project_root}/.venv/bin/python" ]]; then
  echo "run: project environment is missing; execute scripts/bootstrap.sh --sync" >&2
  exit 2
fi
if [[ -L "${project_root}/.venv" || -L "${project_root}/.cache" || -L "${project_root}/.cache/modular" ]]; then
  echo "run: refusing symlinked project environment or cache paths" >&2
  exit 3
fi
if [[ "$#" -eq 0 ]]; then
  echo "usage: scripts/run.sh <project-command> [args...]" >&2
  exit 64
fi

cd "${project_root}"
command_path="$(command -v -- "$1" || true)"
if [[ -z "${command_path}" || "${command_path}" != "${project_root}/.venv/bin/"* ]]; then
  echo "run: command must resolve inside the project .venv: $1" >&2
  exit 3
fi
exec "$@"
