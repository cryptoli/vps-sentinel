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

if [ ! -f "$BIN_PATH" ]; then
  echo "binary not found at $BIN_PATH; run cargo build --release first" >&2
  exit 1
fi

install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
install -m 0755 "$BIN_PATH" "$PREFIX/bin/vps-sentinel"
if [ -f reload.sh ]; then
  install -m 0755 reload.sh "$PREFIX/bin/vps-sentinel-reload"
fi

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
  echo "created $CONFIG_DIR/config.toml"
else
  echo "kept existing $CONFIG_DIR/config.toml"
fi

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
  sed \
    -e "s|@BIN_PATH@|$(escape_sed_replacement "$PREFIX/bin/vps-sentinel")|g" \
    -e "s|@CONFIG_PATH@|$(escape_sed_replacement "$CONFIG_DIR/config.toml")|g" \
    -e "s|@DATA_DIR@|$(escape_sed_replacement "$DATA_DIR")|g" \
    -e "s|@LOG_DIR@|$(escape_sed_replacement "$LOG_DIR")|g" \
    "$SYSTEMD_TEMPLATE" > "$SERVICE_PATH"
  chmod 0644 "$SERVICE_PATH"
}

post_install_setup

if should_install_systemd; then
  write_systemd_unit
  systemctl daemon-reload
  case "$ENABLE_SERVICE" in
    yes|true|1)
      systemctl enable "$SERVICE_NAME"
      if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        systemctl reload-or-restart "$SERVICE_NAME"
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
else
  echo "skipped systemd service installation"
fi
