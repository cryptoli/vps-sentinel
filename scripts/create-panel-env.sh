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
  line="$(grep "^${key}='" "$file" 2>/dev/null | tail -n 1 || true)"
  [ -n "$line" ] || return 0
  value="${line#"$key='"}"
  value="${value%"'"}"
  unescape_shell_quote_value "$value"
}

credential_key_exists() {
  file="$1"
  key="$2"
  [ -f "$file" ] || return 1
  grep -q "^${key}='" "$file" 2>/dev/null
}

unescape_shell_quote_value() {
  value="$1"
  quote_escape="'\\''"
  while :; do
    case "$value" in
      *"$quote_escape"*)
        prefix="${value%%"$quote_escape"*}"
        suffix="${value#*"$quote_escape"}"
        value="${prefix}'${suffix}"
        ;;
      *)
        printf '%s\n' "$value"
        return
        ;;
    esac
  done
}

env_value_is_set() {
  eval "[ \"\${$1+x}\" = x ]"
}

env_value() {
  eval "printf '%s\n' \"\${$1}\""
}

browser_token_value() {
  file="$1"
  if [ -n "${PANEL_TOKEN:-}" ]; then
    printf '%s\n' "$PANEL_TOKEN"
    return
  fi
  for key in PANEL_TOKEN PANEL_ADMIN_TOKEN PANEL_OPERATOR_TOKEN PANEL_VIEW_TOKEN; do
    value="$(credential_value "$file" "$key")"
    if [ -n "$value" ]; then
      printf '%s\n' "$value"
      return
    fi
  done
}

env_or_existing() {
  key="$1"
  default_value="$2"
  eval "override=\${$key:-}"
  if [ -n "$override" ]; then
    printf '%s\n' "$override"
    return
  fi
  existing="$(credential_value "$output" "$key")"
  if [ -n "$existing" ]; then
    printf '%s\n' "$existing"
    return
  fi
  printf '%s\n' "$default_value"
}

env_or_existing_allow_empty() {
  key="$1"
  default_value="$2"
  if env_value_is_set "$key"; then
    env_value "$key"
    return
  fi
  if credential_key_exists "$output" "$key"; then
    credential_value "$output" "$key"
    return
  fi
  printf '%s\n' "$default_value"
}

optional_env_or_existing() {
  key="$1"
  if env_value_is_set "$key"; then
    env_value "$key"
    return
  fi
  credential_value "$output" "$key"
}

main() {
  output="${PANEL_ENV_FILE:-/etc/vps-sentinel-panel/panel.env}"
  script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
  repo_root="$(CDPATH= cd -- "${script_dir}/.." && pwd)"
  contract_env="${repo_root}/panel/shared/contract.env"
  [ -f "$contract_env" ] && . "$contract_env"
  database_backend="$(env_or_existing PANEL_DB_BACKEND sqlite)"
  database_url="$(env_or_existing PANEL_DATABASE_URL sqlite:///var/lib/vps-sentinel-panel/panel.db)"
  bind="$(env_or_existing PANEL_BIND 127.0.0.1:8858)"
  web_dir="$(env_or_existing PANEL_WEB_DIR /usr/local/share/vps-sentinel/panel/web)"
  public_pages="$(env_or_existing_allow_empty PANEL_PUBLIC_PAGES "${PANEL_CONTRACT_DEFAULT_PUBLIC_PAGES:-overview,probe_sources,nodes}")"
  node_secrets="$(optional_env_or_existing PANEL_NODE_SECRETS)"
  public_enabled="$(optional_env_or_existing PANEL_PUBLIC_ENABLED)"
  panel_theme="$(optional_env_or_existing PANEL_THEME)"
  panel_themes="$(optional_env_or_existing PANEL_THEMES)"
  max_body_bytes="$(optional_env_or_existing PANEL_MAX_BODY_BYTES)"
  write_max_body_bytes="$(optional_env_or_existing PANEL_WRITE_MAX_BODY_BYTES)"
  geoip_city_db="$(optional_env_or_existing PANEL_GEOIP_CITY_DB)"
  geoip_asn_db="$(optional_env_or_existing PANEL_GEOIP_ASN_DB)"
  shared_secret="${PANEL_SHARED_SECRET:-$(credential_value "$output" PANEL_SHARED_SECRET)}"
  panel_token="$(browser_token_value "$output")"
  admin_path="${PANEL_ADMIN_PATH:-$(credential_value "$output" PANEL_ADMIN_PATH)}"

  [ -n "$shared_secret" ] || shared_secret="$(random_token)"
  [ -n "$panel_token" ] || panel_token="$(random_token)"
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
    if [ -n "$node_secrets" ]; then
      printf "PANEL_NODE_SECRETS='%s'\n" "$(shell_quote_value "$node_secrets")"
    fi
    printf "PANEL_TOKEN='%s'\n" "$(shell_quote_value "$panel_token")"
    printf "PANEL_ADMIN_PATH='%s'\n" "$(shell_quote_value "$admin_path")"
    printf "PANEL_PUBLIC_PAGES='%s'\n" "$(shell_quote_value "$public_pages")"
    if [ -n "$public_enabled" ]; then
      printf "PANEL_PUBLIC_ENABLED='%s'\n" "$(shell_quote_value "$public_enabled")"
    fi
    if [ -n "$panel_theme" ]; then
      printf "PANEL_THEME='%s'\n" "$(shell_quote_value "$panel_theme")"
    fi
    if [ -n "$panel_themes" ]; then
      printf "PANEL_THEMES='%s'\n" "$(shell_quote_value "$panel_themes")"
    fi
    if [ -n "$max_body_bytes" ]; then
      printf "PANEL_MAX_BODY_BYTES='%s'\n" "$(shell_quote_value "$max_body_bytes")"
    fi
    if [ -n "$write_max_body_bytes" ]; then
      printf "PANEL_WRITE_MAX_BODY_BYTES='%s'\n" "$(shell_quote_value "$write_max_body_bytes")"
    fi
    if [ -n "$geoip_city_db" ]; then
      printf "PANEL_GEOIP_CITY_DB='%s'\n" "$(shell_quote_value "$geoip_city_db")"
    fi
    if [ -n "$geoip_asn_db" ]; then
      printf "PANEL_GEOIP_ASN_DB='%s'\n" "$(shell_quote_value "$geoip_asn_db")"
    fi
  } >"$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$output"

  log "panel environment written to $output"
  log "management path: $admin_path"
  log "read $output as root to configure agent panel.secret, PANEL_TOKEN, and the management path"
}

main "$@"
