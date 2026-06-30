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

panel_env="${tmp_dir}/panel.env"
env \
  PANEL_ENV_FILE="${panel_env}" \
  PANEL_BIND="100.64.0.10:8860" \
  PANEL_DB_BACKEND="postgres" \
  PANEL_DATABASE_URL="postgres://vps_sentinel:sec'ret@100.64.0.1:5432/vps_sentinel" \
  PANEL_WEB_DIR="/srv/vps-sentinel/panel/web" \
  PANEL_PUBLIC_PAGES="overview,nodes" \
  PANEL_NODE_SECRETS='{"node-a":"secret-a"}' \
  PANEL_PUBLIC_ENABLED="true" \
  PANEL_THEME="default" \
  PANEL_THEMES="default:Default,blue:Blue" \
  PANEL_MAX_BODY_BYTES="1048576" \
  PANEL_WRITE_MAX_BODY_BYTES="65536" \
  PANEL_GEOIP_CITY_DB="/opt/geoip/GeoLite2-City.mmdb" \
  PANEL_SHARED_SECRET="shared-secret" \
  PANEL_TOKEN="browser-token" \
  PANEL_ADMIN_PATH="/private-entry" \
  sh "${repo_root}/scripts/create-panel-env.sh"
env PANEL_ENV_FILE="${panel_env}" sh "${repo_root}/scripts/create-panel-env.sh"
# shellcheck disable=SC1090
. "${panel_env}"
[ "${PANEL_BIND}" = "100.64.0.10:8860" ]
[ "${PANEL_DB_BACKEND}" = "postgres" ]
[ "${PANEL_DATABASE_URL}" = "postgres://vps_sentinel:sec'ret@100.64.0.1:5432/vps_sentinel" ]
[ "${PANEL_WEB_DIR}" = "/srv/vps-sentinel/panel/web" ]
[ "${PANEL_PUBLIC_PAGES}" = "overview,nodes" ]
[ "${PANEL_NODE_SECRETS}" = '{"node-a":"secret-a"}' ]
[ "${PANEL_PUBLIC_ENABLED}" = "true" ]
[ "${PANEL_THEME}" = "default" ]
[ "${PANEL_THEMES}" = "default:Default,blue:Blue" ]
[ "${PANEL_MAX_BODY_BYTES}" = "1048576" ]
[ "${PANEL_WRITE_MAX_BODY_BYTES}" = "65536" ]
[ "${PANEL_GEOIP_CITY_DB}" = "/opt/geoip/GeoLite2-City.mmdb" ]
env PANEL_ENV_FILE="${panel_env}" PANEL_BIND="127.0.0.1:9000" sh "${repo_root}/scripts/create-panel-env.sh"
# shellcheck disable=SC1090
. "${panel_env}"
[ "${PANEL_BIND}" = "127.0.0.1:9000" ]
env \
  PANEL_ENV_FILE="${panel_env}" \
  PANEL_PUBLIC_PAGES="" \
  PANEL_NODE_SECRETS="" \
  PANEL_GEOIP_CITY_DB="" \
  sh "${repo_root}/scripts/create-panel-env.sh"
grep -qx "PANEL_PUBLIC_PAGES=''" "${panel_env}"
! grep -q "^PANEL_NODE_SECRETS=" "${panel_env}"
! grep -q "^PANEL_GEOIP_CITY_DB=" "${panel_env}"
env PANEL_ENV_FILE="${panel_env}" sh "${repo_root}/scripts/create-panel-env.sh"
grep -qx "PANEL_PUBLIC_PAGES=''" "${panel_env}"

package_dir="${tmp_dir}/package"
mkdir -p "${package_dir}/packaging/systemd" "${package_dir}/scripts"
cp "${binary_path}" "${package_dir}/vps-sentinel"
cp "${repo_root}/config/config.example.toml" "${package_dir}/config.example.toml"
cp "${repo_root}/install.sh" \
  "${repo_root}/update.sh" \
  "${repo_root}/stop.sh" \
  "${package_dir}/"
cp "${repo_root}/scripts/create-panel-env.sh" "${package_dir}/scripts/create-panel-env.sh"
cp "${repo_root}/packaging/systemd/vps-sentinel.service" \
  "${package_dir}/packaging/systemd/vps-sentinel.service"
chmod 0755 "${package_dir}/vps-sentinel" "${package_dir}"/*.sh "${package_dir}/scripts"/*.sh

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
"${as_root[@]}" test -x "${install_root}/usr/local/bin/vps-sentinel-panel-env"
"${as_root[@]}" test -f "${install_root}/etc/vps-sentinel/config.toml"
"${as_root[@]}" "${install_root}/usr/local/bin/vs" --version
"${as_root[@]}" "${install_root}/usr/local/bin/vps-sentinel" \
  --config "${install_root}/etc/vps-sentinel/config.toml" \
  config validate

echo "install script smoke test passed"
