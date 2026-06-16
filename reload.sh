#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
CONFIG_PATH="${CONFIG_PATH:-$CONFIG_DIR/config.toml}"
SERVICE_NAME="${SERVICE_NAME:-vps-sentinel}"
BIN_PATH="${BIN_PATH:-$PREFIX/bin/vps-sentinel}"

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root, for example: sudo sh reload.sh" >&2
  exit 1
fi

if [ ! -x "$BIN_PATH" ]; then
  echo "vps-sentinel binary not found: $BIN_PATH" >&2
  exit 1
fi

"$BIN_PATH" --config "$CONFIG_PATH" config validate

if command -v systemctl >/dev/null 2>&1 && systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
  if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl reload "$SERVICE_NAME"
    echo "reloaded $SERVICE_NAME with $CONFIG_PATH"
  else
    echo "$SERVICE_NAME is not active; configuration is valid"
  fi
else
  echo "systemd service not found; configuration is valid"
fi
