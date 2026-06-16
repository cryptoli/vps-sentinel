#!/usr/bin/env sh
set -eu

SERVICE_NAME="${SERVICE_NAME:-vps-sentinel}"

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root, for example: sudo sh stop.sh" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required to stop the service" >&2
  exit 1
fi

if ! systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
  echo "systemd service not found: $SERVICE_NAME" >&2
  exit 1
fi

if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
  systemctl stop "$SERVICE_NAME"
  echo "stopped $SERVICE_NAME"
else
  echo "$SERVICE_NAME is already stopped"
fi
