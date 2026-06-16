#!/usr/bin/env sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/cryptoli/vps-sentinel.git}"
BRANCH="${BRANCH:-main}"
WORK_DIR="${WORK_DIR:-/opt/vps-sentinel-src}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/vps-sentinel}"
LOG_DIR="${LOG_DIR:-/var/log/vps-sentinel}"
SERVICE_NAME="${SERVICE_NAME:-vps-sentinel}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
SYSTEMD_TEMPLATE="${SYSTEMD_TEMPLATE:-packaging/systemd/vps-sentinel.service}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
RESTART_SERVICE="${RESTART_SERVICE:-auto}"
VALIDATE_CONFIG="${VALIDATE_CONFIG:-yes}"
REFRESH_BASELINE="${REFRESH_BASELINE:-auto}"
SYSTEMD_UNIT_INSTALLED=0

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root, for example: sudo sh update.sh" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required for update" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    echo "cargo is required; run install.sh first" >&2
    exit 1
  fi
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
    echo "updated systemd unit at $SERVICE_PATH"
  fi
  chmod 0644 "$SERVICE_PATH"
}

install_systemd_unit_file() {
  if ! should_install_systemd; then
    echo "skipped systemd service update"
    return
  fi

  write_systemd_unit
  systemctl daemon-reload
  SYSTEMD_UNIT_INSTALLED=1
}

reload_updated_service() {
  if [ "$SYSTEMD_UNIT_INSTALLED" -ne 1 ]; then
    return
  fi

  case "$RESTART_SERVICE" in
    auto)
      if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        systemctl reload-or-restart "$SERVICE_NAME"
      else
        echo "updated systemd unit; service is not enabled"
      fi
      ;;
    yes|true|1)
      systemctl enable --now "$SERVICE_NAME"
      ;;
    no|false|0)
      echo "updated systemd unit; skipped service restart"
      ;;
    *)
      echo "invalid RESTART_SERVICE value: $RESTART_SERVICE" >&2
      exit 1
      ;;
  esac
}

refresh_baseline() {
  case "$REFRESH_BASELINE" in
    auto)
      if "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" baseline show >/dev/null 2>&1; then
        "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" baseline create
      else
        echo "skipped baseline refresh; no existing baseline"
      fi
      ;;
    yes|true|1)
      "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" baseline create
      ;;
    no|false|0) ;;
    *)
      echo "invalid REFRESH_BASELINE value: $REFRESH_BASELINE" >&2
      exit 1
      ;;
  esac
}

if [ -d "$WORK_DIR/.git" ]; then
  git -C "$WORK_DIR" fetch origin "$BRANCH"
  git -C "$WORK_DIR" checkout "$BRANCH"
  git -C "$WORK_DIR" pull --ff-only origin "$BRANCH"
else
  install -d "$(dirname "$WORK_DIR")"
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$WORK_DIR"
fi

cd "$WORK_DIR"
cargo build --release --locked
install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
install -m 0755 target/release/vps-sentinel "$PREFIX/bin/vps-sentinel"
if [ -f reload.sh ]; then
  install -m 0755 reload.sh "$PREFIX/bin/vps-sentinel-reload"
fi

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
fi

case "$VALIDATE_CONFIG" in
  yes|true|1)
    "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" config validate
    ;;
  no|false|0) ;;
  *)
    echo "invalid VALIDATE_CONFIG value: $VALIDATE_CONFIG" >&2
    exit 1
    ;;
esac

install_systemd_unit_file
refresh_baseline
reload_updated_service

echo "vps-sentinel updated from $REPO_URL ($BRANCH)"
