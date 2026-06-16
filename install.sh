#!/usr/bin/env sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/cryptoli/vps-sentinel.git}"
BRANCH="${BRANCH:-main}"
WORK_DIR="${WORK_DIR:-/opt/vps-sentinel-src}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/vps-sentinel}"
LOG_DIR="${LOG_DIR:-/var/log/vps-sentinel}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/vps-sentinel.service}"

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root, for example: sudo sh install.sh" >&2
  exit 1
fi

install_deps() {
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

ensure_rust() {
  if command -v cargo >/dev/null 2>&1; then
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

  if [ -d /etc/systemd/system ]; then
    install -m 0644 packaging/systemd/vps-sentinel.service "$SERVICE_PATH"
    systemctl daemon-reload
    systemctl enable --now vps-sentinel
  fi
}

install_deps
ensure_rust
checkout_or_update
build_and_install

echo "vps-sentinel installed"
echo "config: $CONFIG_DIR/config.toml"
echo "database: $DATA_DIR/sentinel.db"
