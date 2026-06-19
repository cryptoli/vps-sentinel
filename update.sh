#!/usr/bin/env sh
set -eu

REPO_URL="${REPO_URL:-https://github.com/cryptoli/vps-sentinel.git}"
BRANCH="${BRANCH:-main}"
WORK_DIR="${WORK_DIR:-/opt/vps-sentinel-src}"
PREFIX="${PREFIX:-/usr/local}"
SHARE_DIR="${SHARE_DIR:-$PREFIX/share/vps-sentinel}"
CONFIG_DIR="${CONFIG_DIR:-/etc/vps-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/vps-sentinel}"
LOG_DIR="${LOG_DIR:-/var/log/vps-sentinel}"
SERVICE_NAME="${SERVICE_NAME:-vps-sentinel}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/${SERVICE_NAME}.service}"
SYSTEMD_TEMPLATE="${SYSTEMD_TEMPLATE:-packaging/systemd/vps-sentinel.service}"
INSTALL_DEPS="${INSTALL_DEPS:-yes}"
INSTALL_METHOD="${INSTALL_METHOD:-auto}"
RELEASE_VERSION="${RELEASE_VERSION:-latest}"
RELEASE_ARTIFACT_URL="${RELEASE_ARTIFACT_URL:-}"
TARGET_TRIPLE="${TARGET_TRIPLE:-}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
RESTART_SERVICE="${RESTART_SERVICE:-auto}"
VALIDATE_CONFIG="${VALIDATE_CONFIG:-yes}"
MIGRATE_CONFIG="${MIGRATE_CONFIG:-yes}"
SYNC_CONFIG_DEFAULTS="${SYNC_CONFIG_DEFAULTS:-yes}"
REFRESH_BASELINE="${REFRESH_BASELINE:-no}"
POST_UPDATE_SCAN="${POST_UPDATE_SCAN:-yes}"
UPDATE_MAINTENANCE_SECONDS="${UPDATE_MAINTENANCE_SECONDS:-600}"
SYSTEMD_UNIT_INSTALLED=0
SERVICE_WAS_ACTIVE=0
SERVICE_STOPPED_FOR_UPDATE=0

cleanup_on_exit() {
  status=$?
  if [ "$status" -ne 0 ] && [ "$SERVICE_STOPPED_FOR_UPDATE" -eq 1 ] && systemd_available; then
    echo "update failed; attempting to restart existing $SERVICE_NAME service" >&2
    systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
}

trap cleanup_on_exit EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root, for example: sudo sh update.sh" >&2
  exit 1
fi

install_deps() {
  mode="${1:-source}"
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

  case "$mode" in
    release|source) ;;
    *)
      echo "invalid dependency mode: $mode" >&2
      exit 1
      ;;
  esac

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    if [ "$mode" = "release" ]; then
      apt-get install -y ca-certificates curl tar
    else
      apt-get install -y ca-certificates curl git build-essential pkg-config
    fi
  elif command -v dnf >/dev/null 2>&1; then
    if [ "$mode" = "release" ]; then
      dnf install -y ca-certificates curl tar
    else
      dnf install -y ca-certificates curl git gcc gcc-c++ make pkgconf-pkg-config
    fi
  elif command -v yum >/dev/null 2>&1; then
    if [ "$mode" = "release" ]; then
      yum install -y ca-certificates curl tar
    else
      yum install -y ca-certificates curl git gcc gcc-c++ make pkgconfig
    fi
  elif command -v apk >/dev/null 2>&1; then
    if [ "$mode" = "release" ]; then
      apk add --no-cache ca-certificates curl tar
    else
      apk add --no-cache ca-certificates curl git build-base pkgconfig
    fi
  elif command -v pacman >/dev/null 2>&1; then
    if [ "$mode" = "release" ]; then
      pacman -Sy --noconfirm ca-certificates curl tar
    else
      pacman -Sy --noconfirm ca-certificates curl git base-devel pkgconf
    fi
  else
    if [ "$mode" = "release" ]; then
      echo "unsupported package manager; install curl, tar, and ca-certificates manually" >&2
    else
      echo "unsupported package manager; install curl, git, C compiler, make, and pkg-config manually" >&2
    fi
    exit 1
  fi
}

command_available() {
  command -v "$1" >/dev/null 2>&1
}

ensure_release_tools() {
  if command_available curl && command_available tar; then
    return
  fi
  install_deps release
  if ! command_available curl || ! command_available tar; then
    echo "curl and tar are required for release update" >&2
    exit 1
  fi
}

cargo_works() {
  command_available cargo && cargo --version >/dev/null 2>&1
}

ensure_rust() {
  if cargo_works; then
    return
  fi
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    if cargo_works; then
      return
    fi
  fi
  if command_available rustup; then
    rustup default stable
    if cargo_works; then
      return
    fi
  elif [ -x "$HOME/.cargo/bin/rustup" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
    rustup default stable
    if cargo_works; then
      return
    fi
  else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain stable
    export PATH="$HOME/.cargo/bin:$PATH"
  fi

  if ! cargo_works; then
    echo "cargo is installed but cannot run; check the Rust toolchain before source update" >&2
    exit 1
  fi
}

ensure_source_tools() {
  if ! command_available git; then
    echo "git is required for source update" >&2
    exit 1
  fi
  ensure_rust
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

stop_service_before_update() {
  case "$INSTALL_SYSTEMD" in
    no|false|0) return ;;
    yes|true|1|auto) ;;
    *)
      echo "invalid INSTALL_SYSTEMD value: $INSTALL_SYSTEMD" >&2
      exit 1
      ;;
  esac

  case "$RESTART_SERVICE" in
    auto|yes|true|1) ;;
    no|false|0) return ;;
    *)
      echo "invalid RESTART_SERVICE value: $RESTART_SERVICE" >&2
      exit 1
      ;;
  esac

  if ! systemd_available; then
    return
  fi

  if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    SERVICE_WAS_ACTIVE=1
    systemctl stop "$SERVICE_NAME"
    SERVICE_STOPPED_FOR_UPDATE=1
  fi
}

restart_updated_service() {
  if [ "$SYSTEMD_UNIT_INSTALLED" -ne 1 ]; then
    return
  fi

  case "$RESTART_SERVICE" in
    auto)
      if [ "$SERVICE_WAS_ACTIVE" -eq 1 ] || systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
        systemctl start "$SERVICE_NAME"
        SERVICE_STOPPED_FOR_UPDATE=0
      else
        echo "updated systemd unit; service is not active or enabled"
      fi
      ;;
    yes|true|1)
      systemctl enable "$SERVICE_NAME"
      systemctl restart "$SERVICE_NAME"
      SERVICE_STOPPED_FOR_UPDATE=0
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

start_update_maintenance() {
  case "$UPDATE_MAINTENANCE_SECONDS" in
    ''|*[!0-9]*)
      echo "invalid UPDATE_MAINTENANCE_SECONDS value: $UPDATE_MAINTENANCE_SECONDS" >&2
      exit 1
      ;;
  esac
  if [ "$UPDATE_MAINTENANCE_SECONDS" -eq 0 ]; then
    return
  fi
  if [ ! -x "$PREFIX/bin/vps-sentinel" ] || [ ! -f "$CONFIG_DIR/config.toml" ]; then
    return
  fi
  if "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" maintenance start \
    --duration-seconds "$UPDATE_MAINTENANCE_SECONDS" \
    --reason "vps-sentinel update" >/dev/null 2>&1; then
    echo "started update maintenance window for ${UPDATE_MAINTENANCE_SECONDS}s"
  else
    echo "could not start update maintenance window; continuing update" >&2
  fi
}

post_update_scan() {
  case "$POST_UPDATE_SCAN" in
    yes|true|1)
      log="$LOG_DIR/post-update-scan.log"
      if "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" scan --no-notify > "$log" 2>&1; then
        sed -n '1p' "$log"
        echo "post-update scan details: $log"
      else
        echo "post-update no-notify scan failed; service restart continues" >&2
        cat "$log" >&2
      fi
      ;;
    no|false|0) ;;
    *)
      echo "invalid POST_UPDATE_SCAN value: $POST_UPDATE_SCAN" >&2
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

migrate_config() {
  if yes_enabled "$MIGRATE_CONFIG"; then
    "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" config migrate
  fi
}

sync_config_defaults() {
  if yes_enabled "$SYNC_CONFIG_DEFAULTS"; then
    "$PREFIX/bin/vps-sentinel" --config "$CONFIG_DIR/config.toml" config sync-defaults
  fi
}

install_binary_aliases() {
  ln -sf vps-sentinel "$PREFIX/bin/vs"
  rm -f "$PREFIX/bin/vps-sentinel-reload"
}

detect_target_triple() {
  if [ -n "$TARGET_TRIPLE" ]; then
    printf '%s\n' "$TARGET_TRIPLE"
    return
  fi

  arch="$(uname -m)"
  libc="gnu"
  if ldd --version 2>&1 | grep -qi musl; then
    libc="musl"
  fi

  case "$arch" in
    x86_64|amd64) printf 'x86_64-unknown-linux-%s\n' "$libc" ;;
    aarch64|arm64) printf 'aarch64-unknown-linux-%s\n' "$libc" ;;
    *)
      echo "unsupported release artifact architecture: $arch" >&2
      return 1
      ;;
  esac
}

repo_release_base() {
  case "$REPO_URL" in
    git@github.com:*)
      repo_path="${REPO_URL#git@github.com:}"
      printf 'https://github.com/%s\n' "${repo_path%.git}"
      ;;
    ssh://git@github.com/*)
      repo_path="${REPO_URL#ssh://git@github.com/}"
      printf 'https://github.com/%s\n' "${repo_path%.git}"
      ;;
    *)
      printf '%s\n' "${REPO_URL%.git}"
      ;;
  esac
}

release_url() {
  if [ -n "$RELEASE_ARTIFACT_URL" ]; then
    printf '%s\n' "$RELEASE_ARTIFACT_URL"
    return
  fi

  triple="$(detect_target_triple)"
  artifact="vps-sentinel-${triple}.tar.gz"
  base_url="$(repo_release_base)"
  if [ "$RELEASE_VERSION" = "latest" ]; then
    printf '%s/releases/latest/download/%s\n' "$base_url" "$artifact"
  else
    printf '%s/releases/download/%s/%s\n' "$base_url" "$RELEASE_VERSION" "$artifact"
  fi
}

release_binary_works() {
  binary="$1"
  [ -x "$binary" ] || chmod 0755 "$binary" 2>/dev/null || return 1
  "$binary" --version >/dev/null 2>&1
}

install_optional_panel() {
  source_dir="$1"
  panel_bin=""
  if [ -f "$source_dir/vps-sentinel-panel" ]; then
    panel_bin="$source_dir/vps-sentinel-panel"
  elif [ -f "$source_dir/target/release/vps-sentinel-panel" ]; then
    panel_bin="$source_dir/target/release/vps-sentinel-panel"
  fi
  if [ -n "$panel_bin" ]; then
    install -m 0755 "$panel_bin" "$PREFIX/bin/vps-sentinel-panel"
    echo "installed optional Rust panel binary to $PREFIX/bin/vps-sentinel-panel"
  fi
  if [ -d "$source_dir/panel" ]; then
    install -d "$SHARE_DIR"
    rm -rf "$SHARE_DIR/panel"
    cp -R "$source_dir/panel" "$SHARE_DIR/panel"
    echo "installed optional panel assets to $SHARE_DIR/panel"
  fi
}

install_helper_scripts() {
  source_dir="$1"
  for script in stop update install; do
    if [ -f "$source_dir/${script}.sh" ]; then
      install -m 0755 "$source_dir/${script}.sh" "$PREFIX/bin/vps-sentinel-${script}"
    fi
  done
}

ensure_config_exists() {
  source_config="$1"
  if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    install -m 0600 "$source_config" "$CONFIG_DIR/config.toml"
    echo "created $CONFIG_DIR/config.toml"
  else
    echo "kept existing $CONFIG_DIR/config.toml"
  fi
}

post_update() {
  migrate_config
  sync_config_defaults

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
  post_update_scan
  restart_updated_service
}

checkout_or_update() {
  if [ -d "$WORK_DIR/.git" ]; then
    git -C "$WORK_DIR" fetch origin "$BRANCH:refs/remotes/origin/$BRANCH"
    if git -C "$WORK_DIR" show-ref --verify --quiet "refs/heads/$BRANCH"; then
      git -C "$WORK_DIR" checkout "$BRANCH"
    else
      git -C "$WORK_DIR" checkout -b "$BRANCH" "origin/$BRANCH"
    fi
    git -C "$WORK_DIR" pull --ff-only origin "$BRANCH"
  else
    install -d "$(dirname "$WORK_DIR")"
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$WORK_DIR"
  fi
}

install_from_release() {
  ensure_release_tools
  url="$(release_url)" || return 1
  tmp_dir="$(mktemp -d)"
  archive="$tmp_dir/vps-sentinel.tar.gz"
  echo "downloading release artifact: $url"
  if ! curl -fsSL "$url" -o "$archive"; then
    rm -rf "$tmp_dir"
    return 1
  fi
  if ! tar -xzf "$archive" -C "$tmp_dir"; then
    rm -rf "$tmp_dir"
    return 1
  fi
  if ! release_binary_works "$tmp_dir/vps-sentinel"; then
    echo "release artifact binary cannot execute on this host; falling back to source build"
    rm -rf "$tmp_dir"
    return 1
  fi

  install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  start_update_maintenance
  stop_service_before_update
  install -m 0755 "$tmp_dir/vps-sentinel" "$PREFIX/bin/vps-sentinel"
  install_optional_panel "$tmp_dir"
  install_binary_aliases
  install_helper_scripts "$tmp_dir"
  ensure_config_exists "$tmp_dir/config.example.toml"

  if [ -f "$tmp_dir/packaging/systemd/vps-sentinel.service" ]; then
    SYSTEMD_TEMPLATE="$tmp_dir/packaging/systemd/vps-sentinel.service"
  fi

  post_update
  rm -rf "$tmp_dir"
  echo "vps-sentinel updated from release artifact"
}

build_and_install_from_source() {
  install_deps source
  ensure_source_tools
  checkout_or_update
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  start_update_maintenance
  stop_service_before_update
  cd "$WORK_DIR"
  cargo build --release --locked
  install -m 0755 target/release/vps-sentinel "$PREFIX/bin/vps-sentinel"
  install_optional_panel "$WORK_DIR"
  install_binary_aliases
  install_helper_scripts "$WORK_DIR"
  ensure_config_exists "$WORK_DIR/config/config.example.toml"
  SYSTEMD_TEMPLATE="$WORK_DIR/packaging/systemd/vps-sentinel.service"
  post_update
  echo "vps-sentinel updated from $REPO_URL ($BRANCH)"
}

case "$INSTALL_METHOD" in
  release)
    if ! install_from_release; then
      echo "release update failed; falling back to source build"
      build_and_install_from_source
    fi
    ;;
  auto)
    if ! install_from_release; then
      echo "release artifact unavailable; falling back to source build"
      build_and_install_from_source
    fi
    ;;
  source)
    build_and_install_from_source
    ;;
  *)
    echo "invalid INSTALL_METHOD value: $INSTALL_METHOD" >&2
    exit 1
    ;;
esac
