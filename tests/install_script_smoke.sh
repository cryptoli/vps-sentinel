#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary_path="${BINARY_PATH:-${repo_root}/target/release/vps-sentinel}"

if [ ! -x "${binary_path}" ]; then
  cargo build --release --locked
fi

tmp_dir="$(mktemp -d)"
as_root=()
if [ "$(id -u)" -ne 0 ]; then
  as_root=(sudo)
fi

cleanup() {
  if [ "${#as_root[@]}" -gt 0 ]; then
    "${as_root[@]}" rm -rf "${tmp_dir}"
  else
    rm -rf "${tmp_dir}"
  fi
}
trap cleanup EXIT

package_dir="${tmp_dir}/package"
mkdir -p "${package_dir}/packaging/systemd"
cp "${binary_path}" "${package_dir}/vps-sentinel"
cp "${repo_root}/config/config.example.toml" "${package_dir}/config.example.toml"
cp "${repo_root}/install.sh" \
  "${repo_root}/update.sh" \
  "${repo_root}/stop.sh" \
  "${package_dir}/"
cp "${repo_root}/packaging/systemd/vps-sentinel.service" \
  "${package_dir}/packaging/systemd/vps-sentinel.service"
chmod 0755 "${package_dir}/vps-sentinel" "${package_dir}"/*.sh

archive="${tmp_dir}/vps-sentinel-test.tar.gz"
tar -czf "${archive}" -C "${package_dir}" .

install_root="${tmp_dir}/install-root"
"${as_root[@]}" env \
  INSTALL_METHOD=release \
  RELEASE_ARTIFACT_URL="file://${archive}" \
  INSTALL_DEPS=no \
  INSTALL_SYSTEMD=no \
  ENABLE_SERVICE=no \
  RUN_DOCTOR=no \
  BOOTSTRAP_BASELINE=no \
  RUN_FIRST_SCAN=no \
  RUN_NOTIFY_TEST=no \
  PREFIX="${install_root}/usr/local" \
  CONFIG_DIR="${install_root}/etc/vps-sentinel" \
  DATA_DIR="${install_root}/var/lib/vps-sentinel" \
  LOG_DIR="${install_root}/var/log/vps-sentinel" \
  sh "${repo_root}/install.sh"

"${as_root[@]}" test -x "${install_root}/usr/local/bin/vps-sentinel"
"${as_root[@]}" test -x "${install_root}/usr/local/bin/vs"
"${as_root[@]}" test -x "${install_root}/usr/local/bin/vps-sentinel-update"
"${as_root[@]}" test -x "${install_root}/usr/local/bin/vps-sentinel-stop"
"${as_root[@]}" test -f "${install_root}/etc/vps-sentinel/config.toml"
"${as_root[@]}" "${install_root}/usr/local/bin/vs" --version
"${as_root[@]}" "${install_root}/usr/local/bin/vps-sentinel" \
  --config "${install_root}/etc/vps-sentinel/config.toml" \
  config validate

echo "install script smoke test passed"
