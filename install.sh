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
INSTALL_DEPS="${INSTALL_DEPS:-yes}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
ENABLE_SERVICE="${ENABLE_SERVICE:-yes}"

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root, for example: sudo sh install.sh" >&2
  exit 1
fi

install_deps() {
  case "$INSTALL_DEPS" in
    yes|true|1) ;;
    no|false|0)
      echo "skipped dependency installation"
      return
      ;;
    *)
      echo "invalid INSTALL_DEPS value: $INSTALL_DEPS" >&2
      exit 1
      ;;
  esac

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y ca-certificates curl git build-essential pkg-config
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl git gcc gcc-c++ make pkgconf-pkg-config
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl git gcc gcc-c++ make pkgconfig
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates curl git build-base pkgconfig
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ca-certificates curl git base-devel pkgconf
  else
    echo "unsupported package manager; install curl, git, C compiler, make, and pkg-config manually" >&2
    exit 1
  fi
}

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

ensure_rust() {
  if command -v cargo >/dev/null 2>&1; then
    return
  fi
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    return
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
}

checkout_or_update() {
  if [ -d "$WORK_DIR/.git" ]; then
    git -C "$WORK_DIR" fetch origin "$BRANCH"
    git -C "$WORK_DIR" checkout "$BRANCH"
    git -C "$WORK_DIR" pull --ff-only origin "$BRANCH"
  else
    install -d "$(dirname "$WORK_DIR")"
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$WORK_DIR"
  fi
}

build_and_install() {
  cd "$WORK_DIR"
  cargo build --release --locked
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  install -m 0755 target/release/vps-sentinel "$PREFIX/bin/vps-sentinel"

  if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
    echo "created $CONFIG_DIR/config.toml"
  else
    echo "kept existing $CONFIG_DIR/config.toml"
  fi

  install_systemd_unit
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

install_systemd_unit() {
  if ! should_install_systemd; then
    echo "skipped systemd service installation"
    return
  fi

  write_systemd_unit
  systemctl daemon-reload
  case "$ENABLE_SERVICE" in
    yes|true|1)
      systemctl enable --now "$SERVICE_NAME"
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

install_deps
ensure_rust
checkout_or_update
build_and_install

echo "vps-sentinel installed"
echo "config: $CONFIG_DIR/config.toml"
echo "database: $DATA_DIR/sentinel.db"
