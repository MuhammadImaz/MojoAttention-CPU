#!/usr/bin/env bash
set -euo pipefail

project_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
uv_version="0.11.29"
uv_wheel="uv-${uv_version}-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
uv_url="https://files.pythonhosted.org/packages/0d/28/3fa1c2061d588184840e3e4ab17e6d318c744bb2fcb15ddb0c29b5bc0bb3/${uv_wheel}"
uv_sha256="eec03a8b63d55915694db3af4e91324b39ced49e2aeac7af37851c7eb3f470ea"
install_dir="${project_root}/.tools/uv"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "install-uv: this pinned artifact supports Linux x86_64 only" >&2
  exit 2
fi
if [[ -L "${project_root}/.tools" || -L "${install_dir}" ]]; then
  echo "install-uv: refusing symlinked project tool paths" >&2
  exit 3
fi
command -v curl >/dev/null || { echo "install-uv: curl is required" >&2; exit 2; }
command -v unzip >/dev/null || { echo "install-uv: unzip is required" >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "install-uv: sha256sum is required" >&2; exit 2; }

mkdir -p "${install_dir}"
temporary_dir="$(mktemp -d "${project_root}/.tools/uv-install.XXXXXX")"
trap 'rm -rf -- "${temporary_dir}"' EXIT
curl --disable --proto '=https' --tlsv1.2 --fail --location --silent --show-error "${uv_url}" --output "${temporary_dir}/${uv_wheel}"
printf '%s  %s\n' "${uv_sha256}" "${temporary_dir}/${uv_wheel}" | sha256sum --check --status
unzip -qq "${temporary_dir}/${uv_wheel}" 'uv-0.11.29.data/scripts/uv' -d "${temporary_dir}/extract"
install -m 0755 "${temporary_dir}/extract/uv-0.11.29.data/scripts/uv" "${install_dir}/uv.tmp"
mv -f "${install_dir}/uv.tmp" "${install_dir}/uv"
"${install_dir}/uv" --version
