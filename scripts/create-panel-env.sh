#!/usr/bin/env sh
set -eu

SCRIPT_NAME="create-panel-env"

log() {
  printf '%s\n' "[$SCRIPT_NAME] $*"
}

fail() {
  printf '%s\n' "[$SCRIPT_NAME] error: $*" >&2
  exit 1
}

random_hex() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
    return
  fi
  if command -v od >/dev/null 2>&1 && [ -r /dev/urandom ]; then
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
    return
  fi
  if command -v node >/dev/null 2>&1; then
    node -e "process.stdout.write(require('crypto').randomBytes(Number(process.argv[1])).toString('hex'))" "$bytes"
    return
  fi
  fail "missing random source: install openssl, provide /dev/urandom+od, or set PANEL_* values explicitly"
}

random_token() {
  random_hex 32
}

random_admin_path() {
  printf '/%s\n' "$(random_hex 6)"
}

shell_quote_value() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
}

credential_value() {
  file="$1"
  key="$2"
  [ -f "$file" ] || return 0
  sed -n "s/^${key}='\\([^']*\\)'$/\\1/p" "$file" | tail -n 1
}

main() {
  output="${PANEL_ENV_FILE:-/etc/vps-sentinel-panel/panel.env}"
  database_backend="${PANEL_DB_BACKEND:-sqlite}"
  database_url="${PANEL_DATABASE_URL:-sqlite:///var/lib/vps-sentinel-panel/panel.db}"
  bind="${PANEL_BIND:-127.0.0.1:8858}"
  web_dir="${PANEL_WEB_DIR:-/usr/local/share/vps-sentinel/panel/web}"
  public_pages="${PANEL_PUBLIC_PAGES:-overview,probe_sources,nodes}"
  shared_secret="${PANEL_SHARED_SECRET:-$(credential_value "$output" PANEL_SHARED_SECRET)}"
  operator_token="${PANEL_OPERATOR_TOKEN:-$(credential_value "$output" PANEL_OPERATOR_TOKEN)}"
  admin_token="${PANEL_ADMIN_TOKEN:-$(credential_value "$output" PANEL_ADMIN_TOKEN)}"
  admin_path="${PANEL_ADMIN_PATH:-$(credential_value "$output" PANEL_ADMIN_PATH)}"

  [ -n "$shared_secret" ] || shared_secret="$(random_token)"
  [ -n "$operator_token" ] || operator_token="$(random_token)"
  [ -n "$admin_token" ] || admin_token="$(random_token)"
  [ -n "$admin_path" ] || admin_path="$(random_admin_path)"

  dir="$(dirname "$output")"
  if [ ! -d "$dir" ]; then
    install -d -m 0750 "$dir"
  fi
  tmp="${output}.$$"
  {
    printf '%s\n' '# vps-sentinel self-hosted panel environment'
    printf '%s\n' '# Keep this file private. Agents must use PANEL_SHARED_SECRET as [panel].secret.'
    printf "PANEL_BIND='%s'\n" "$(shell_quote_value "$bind")"
    printf "PANEL_DB_BACKEND='%s'\n" "$(shell_quote_value "$database_backend")"
    printf "PANEL_DATABASE_URL='%s'\n" "$(shell_quote_value "$database_url")"
    printf "PANEL_WEB_DIR='%s'\n" "$(shell_quote_value "$web_dir")"
    printf "PANEL_SHARED_SECRET='%s'\n" "$(shell_quote_value "$shared_secret")"
    printf "PANEL_OPERATOR_TOKEN='%s'\n" "$(shell_quote_value "$operator_token")"
    printf "PANEL_ADMIN_TOKEN='%s'\n" "$(shell_quote_value "$admin_token")"
    printf "PANEL_ADMIN_PATH='%s'\n" "$(shell_quote_value "$admin_path")"
    printf "PANEL_PUBLIC_PAGES='%s'\n" "$(shell_quote_value "$public_pages")"
  } >"$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$output"

  log "panel environment written to $output"
  log "management path: $admin_path"
  log "read $output as root to configure agent panel.secret and browser tokens"
}

main "$@"
