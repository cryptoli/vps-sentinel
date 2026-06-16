#!/usr/bin/env sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/cryptoli/vps-sentinel.git}"
BRANCH="${BRANCH:-main}"
WORK_DIR="${WORK_DIR:-/opt/vps-sentinel-src}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
SERVICE_NAME="${SERVICE_NAME:-vps-sentinel}"

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
install -d "$PREFIX/bin" "$CONFIG_DIR"
install -m 0755 target/release/vps-sentinel "$PREFIX/bin/vps-sentinel"

if [ ! -f "$CONFIG_DIR/config.toml" ]; then
  install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
    systemctl restart "$SERVICE_NAME"
  fi
fi

echo "vps-sentinel updated from $REPO_URL ($BRANCH)"
