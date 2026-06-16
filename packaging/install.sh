#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/vps-sentinel}"
LOG_DIR="${LOG_DIR:-/var/log/vps-sentinel}"
BIN_PATH="${BIN_PATH:-target/release/vps-sentinel}"

if [ ! -f "$BIN_PATH" ]; then
  echo "binary not found at $BIN_PATH; run cargo build --release first" >&2
  exit 1
fi

install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
install -m 0755 "$BIN_PATH" "$PREFIX/bin/vps-sentinel"

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
  echo "created $CONFIG_DIR/config.toml"
else
  echo "kept existing $CONFIG_DIR/config.toml"
fi

if [ -d /etc/systemd/system ]; then
  install -m 0644 packaging/systemd/vps-sentinel.service /etc/systemd/system/vps-sentinel.service
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    echo "installed systemd unit; enable with: systemctl enable --now vps-sentinel"
  fi
fi
