#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/vps-sentinel}"
LOG_DIR="${LOG_DIR:-/var/log/vps-sentinel}"
BIN_PATH="${BIN_PATH:-target/release/vps-sentinel}"
SERVICE_NAME="${SERVICE_NAME:-vps-sentinel}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
SYSTEMD_TEMPLATE="${SYSTEMD_TEMPLATE:-packaging/systemd/vps-sentinel.service}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
ENABLE_SERVICE="${ENABLE_SERVICE:-no}"
RUN_DOCTOR="${RUN_DOCTOR:-yes}"
BOOTSTRAP_BASELINE="${BOOTSTRAP_BASELINE:-yes}"
RUN_FIRST_SCAN="${RUN_FIRST_SCAN:-yes}"
STORAGE_MAX_DATABASE_SIZE_MB="${STORAGE_MAX_DATABASE_SIZE_MB:-}"
ACTIVE_RESPONSE_ENABLED="${ACTIVE_RESPONSE_ENABLED:-}"
ACTIVE_RESPONSE_FIREWALL_BACKEND="${ACTIVE_RESPONSE_FIREWALL_BACKEND:-}"
ACTIVE_RESPONSE_BLOCK_TTL_SECONDS="${ACTIVE_RESPONSE_BLOCK_TTL_SECONDS:-}"
ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN="${ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN:-}"
ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD="${ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD:-}"
ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD="${ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD:-}"
ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD="${ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD:-}"
SYSTEMD_UNIT_INSTALLED=0

if [ ! -f "$BIN_PATH" ]; then
  echo "binary not found at $BIN_PATH; run cargo build --release first" >&2
  exit 1
fi

install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
install -m 0755 "$BIN_PATH" "$PREFIX/bin/vps-sentinel"
ln -sf vps-sentinel "$PREFIX/bin/vs"
rm -f "$PREFIX/bin/vps-sentinel-reload"
if [ -f stop.sh ]; then
  install -m 0755 stop.sh "$PREFIX/bin/vps-sentinel-stop"
fi
if [ -f update.sh ]; then
  install -m 0755 update.sh "$PREFIX/bin/vps-sentinel-update"
fi
if [ -f install.sh ]; then
  install -m 0755 install.sh "$PREFIX/bin/vps-sentinel-install"
fi

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
  echo "created $CONFIG_DIR/config.toml"
else
  echo "kept existing $CONFIG_DIR/config.toml"
fi

toml_string() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/'
}

toml_bool() {
  case "$1" in
    yes|true|1) printf '%s\n' "true" ;;
    no|false|0) printf '%s\n' "false" ;;
    *)
      echo "invalid boolean value: $1" >&2
      exit 1
      ;;
  esac
}

set_toml_value() {
  file="$1"
  section="$2"
  key="$3"
  value="$4"
  tmp="${file}.tmp.$$"
  awk -v section="$section" -v key="$key" -v value="$value" '
    BEGIN { header = "[" section "]"; in_section = 0; written = 0; seen = 0 }
    /^\[.*\]$/ {
      if (in_section && !written) {
        print key " = " value
        written = 1
      }
      in_section = ($0 == header)
      if (in_section) {
        seen = 1
      }
    }
    in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      if (!written) {
        print key " = " value
        written = 1
      }
      next
    }
    { print }
    END {
      if (!written) {
        if (!seen) {
          print ""
          print header
        }
        print key " = " value
      }
    }
  ' "$file" > "$tmp"
  mv "$tmp" "$file"
}

configure_storage_limits() {
  if [ -z "$STORAGE_MAX_DATABASE_SIZE_MB" ]; then
    return
  fi
  config_path="$CONFIG_DIR/config.toml"
  set_toml_value "$config_path" "storage" "max_database_size_mb" "$STORAGE_MAX_DATABASE_SIZE_MB"
  chmod 0600 "$config_path"
  echo "configured storage size limit in $config_path"
}

configure_active_response() {
  if [ -z "$ACTIVE_RESPONSE_ENABLED" ] \
    && [ -z "$ACTIVE_RESPONSE_FIREWALL_BACKEND" ] \
    && [ -z "$ACTIVE_RESPONSE_BLOCK_TTL_SECONDS" ] \
    && [ -z "$ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN" ] \
    && [ -z "$ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD" ] \
    && [ -z "$ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD" ] \
    && [ -z "$ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD" ]; then
    return
  fi
  config_path="$CONFIG_DIR/config.toml"
  if [ -n "$ACTIVE_RESPONSE_ENABLED" ]; then
    set_toml_value "$config_path" "active_response" "enabled" "$(toml_bool "$ACTIVE_RESPONSE_ENABLED")"
  fi
  if [ -n "$ACTIVE_RESPONSE_FIREWALL_BACKEND" ]; then
    set_toml_value "$config_path" "active_response" "firewall_backend" "$(toml_string "$ACTIVE_RESPONSE_FIREWALL_BACKEND")"
  fi
  if [ -n "$ACTIVE_RESPONSE_BLOCK_TTL_SECONDS" ]; then
    set_toml_value "$config_path" "active_response" "block_ttl_seconds" "$ACTIVE_RESPONSE_BLOCK_TTL_SECONDS"
  fi
  if [ -n "$ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN" ]; then
    set_toml_value "$config_path" "active_response" "max_blocks_per_scan" "$ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN"
  fi
  if [ -n "$ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD" ]; then
    set_toml_value "$config_path" "active_response" "web_probe_block_threshold" "$ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD"
  fi
  if [ -n "$ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD" ]; then
    set_toml_value "$config_path" "active_response" "web_exploit_block_threshold" "$ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD"
  fi
  if [ -n "$ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD" ]; then
    set_toml_value "$config_path" "active_response" "ssh_failed_login_block_threshold" "$ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD"
  fi
  chmod 0600 "$config_path"
  echo "configured active response in $config_path"
}

configure_storage_limits
configure_active_response

systemd_available() {
  [ -d /etc/systemd/system ] \
    && [ -d /run/systemd/system ] \
    && command -v systemctl >/dev/null 2>&1
}

should_install_systemd() {
  case "$INSTALL_SYSTEMD" in
    yes|true|1)
      if systemd_available; then
        return 0
      fi
      echo "systemd was requested but is not available" >&2
      exit 1
      ;;
    no|false|0)
      return 1
      ;;
    auto)
      systemd_available
      ;;
    *)
      echo "invalid INSTALL_SYSTEMD value: $INSTALL_SYSTEMD" >&2
      exit 1
      ;;
  esac
}

escape_sed_replacement() {
  printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

yes_enabled() {
  case "$1" in
    yes|true|1) return 0 ;;
    no|false|0) return 1 ;;
    *)
      echo "invalid boolean value: $1" >&2
      exit 1
      ;;
  esac
}

post_install_setup() {
  config_path="$CONFIG_DIR/config.toml"
  "$PREFIX/bin/vps-sentinel" --config "$config_path" config validate
  if yes_enabled "$RUN_DOCTOR"; then
    "$PREFIX/bin/vps-sentinel" --config "$config_path" doctor
  fi
  if yes_enabled "$BOOTSTRAP_BASELINE"; then
    if "$PREFIX/bin/vps-sentinel" --config "$config_path" baseline show >/dev/null 2>&1; then
      echo "kept existing baseline"
    else
      "$PREFIX/bin/vps-sentinel" --config "$config_path" baseline create
    fi
  fi
  if yes_enabled "$RUN_FIRST_SCAN"; then
    first_scan_log="$LOG_DIR/first-scan.log"
    if "$PREFIX/bin/vps-sentinel" --config "$config_path" scan --no-notify > "$first_scan_log" 2>&1; then
      sed -n '1p' "$first_scan_log"
      echo "first scan details: $first_scan_log"
    else
      cat "$first_scan_log" >&2
      exit 1
    fi
  fi
}

write_systemd_unit() {
  if [ ! -f "$SYSTEMD_TEMPLATE" ]; then
    echo "systemd template not found: $SYSTEMD_TEMPLATE" >&2
    exit 1
  fi

  install -d "$(dirname "$SERVICE_PATH")"
  tmp="${SERVICE_PATH}.tmp.$$"
  sed \
    -e "s|@BIN_PATH@|$(escape_sed_replacement "$PREFIX/bin/vps-sentinel")|g" \
    -e "s|@CONFIG_PATH@|$(escape_sed_replacement "$CONFIG_DIR/config.toml")|g" \
    -e "s|@DATA_DIR@|$(escape_sed_replacement "$DATA_DIR")|g" \
    -e "s|@LOG_DIR@|$(escape_sed_replacement "$LOG_DIR")|g" \
    "$SYSTEMD_TEMPLATE" > "$tmp"
  if [ -f "$SERVICE_PATH" ] && cmp -s "$tmp" "$SERVICE_PATH"; then
    rm -f "$tmp"
    echo "kept existing systemd unit"
  else
    mv "$tmp" "$SERVICE_PATH"
    echo "installed systemd unit at $SERVICE_PATH"
  fi
  chmod 0644 "$SERVICE_PATH"
}

install_systemd_unit_file() {
  if ! should_install_systemd; then
    echo "skipped systemd service installation"
    return
  fi
  write_systemd_unit
  systemctl daemon-reload
  SYSTEMD_UNIT_INSTALLED=1
}

activate_systemd_service() {
  if [ "$SYSTEMD_UNIT_INSTALLED" -ne 1 ]; then
    return
  fi
  case "$ENABLE_SERVICE" in
    yes|true|1)
      systemctl enable "$SERVICE_NAME"
      if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        systemctl restart "$SERVICE_NAME"
      else
        systemctl start "$SERVICE_NAME"
      fi
      ;;
    no|false|0)
      echo "installed systemd unit; enable with: systemctl enable --now $SERVICE_NAME"
      ;;
    *)
      echo "invalid ENABLE_SERVICE value: $ENABLE_SERVICE" >&2
      exit 1
      ;;
  esac
}

install_systemd_unit_file
post_install_setup
activate_systemd_service
