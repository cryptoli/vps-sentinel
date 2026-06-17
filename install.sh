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
INSTALL_METHOD="${INSTALL_METHOD:-auto}"
RELEASE_VERSION="${RELEASE_VERSION:-latest}"
TARGET_TRIPLE="${TARGET_TRIPLE:-}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
ENABLE_SERVICE="${ENABLE_SERVICE:-yes}"
RUN_DOCTOR="${RUN_DOCTOR:-yes}"
BOOTSTRAP_BASELINE="${BOOTSTRAP_BASELINE:-yes}"
RUN_FIRST_SCAN="${RUN_FIRST_SCAN:-yes}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
TELEGRAM_MIN_SEVERITY="${TELEGRAM_MIN_SEVERITY:-Medium}"
RUN_NOTIFY_TEST="${RUN_NOTIFY_TEST:-auto}"
VPS_NAME="${VPS_NAME:-}"
CONFIG_CREATED=0
SYSTEMD_UNIT_INSTALLED=0

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

toml_string() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/'
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

configure_telegram() {
  if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ -z "$TELEGRAM_CHAT_ID" ]; then
    return
  fi
  if [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    echo "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be provided together" >&2
    exit 1
  fi
  config_path="$CONFIG_DIR/config.toml"
  set_toml_value "$config_path" "notifications.telegram" "enabled" "true"
  set_toml_value "$config_path" "notifications.telegram" "bot_token" "$(toml_string "$TELEGRAM_BOT_TOKEN")"
  set_toml_value "$config_path" "notifications.telegram" "chat_id" "$(toml_string "$TELEGRAM_CHAT_ID")"
  set_toml_value "$config_path" "notifications.telegram" "min_severity" "$(toml_string "$TELEGRAM_MIN_SEVERITY")"
  chmod 0600 "$config_path"
  echo "configured Telegram notifications in $config_path"
}

detect_hostname() {
  hostname -f 2>/dev/null || hostname 2>/dev/null || printf '%s\n' "local-host"
}

configure_agent_identity() {
  config_path="$CONFIG_DIR/config.toml"
  detected_hostname="$(detect_hostname)"
  if [ "$CONFIG_CREATED" -eq 1 ] && [ -n "$detected_hostname" ]; then
    set_toml_value "$config_path" "agent" "hostname" "$(toml_string "$detected_hostname")"
  fi
  if [ -n "$VPS_NAME" ]; then
    set_toml_value "$config_path" "agent" "display_name" "$(toml_string "$VPS_NAME")"
  elif [ "$CONFIG_CREATED" -eq 1 ] && [ -n "$detected_hostname" ]; then
    set_toml_value "$config_path" "agent" "display_name" "$(toml_string "$detected_hostname")"
  fi
  chmod 0600 "$config_path"
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

release_url() {
  triple="$(detect_target_triple)"
  artifact="vps-sentinel-${triple}.tar.gz"
  if [ "$RELEASE_VERSION" = "latest" ]; then
    printf '%s/releases/latest/download/%s\n' "${REPO_URL%.git}" "$artifact"
  else
    printf '%s/releases/download/%s/%s\n' "${REPO_URL%.git}" "$RELEASE_VERSION" "$artifact"
  fi
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

install_from_release() {
  url="$(release_url)" || return 1
  tmp_dir="$(mktemp -d)"
  archive="$tmp_dir/vps-sentinel.tar.gz"
  echo "downloading release artifact: $url"
  if ! curl -fsSL "$url" -o "$archive"; then
    rm -rf "$tmp_dir"
    return 1
  fi
  tar -xzf "$archive" -C "$tmp_dir"
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  install -m 0755 "$tmp_dir/vps-sentinel" "$PREFIX/bin/vps-sentinel"
  for script in reload stop update install; do
    if [ -f "$tmp_dir/${script}.sh" ]; then
      install -m 0755 "$tmp_dir/${script}.sh" "$PREFIX/bin/vps-sentinel-${script}"
    fi
  done
  if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    install -m 0600 "$tmp_dir/config.example.toml" "$CONFIG_DIR/config.toml"
    CONFIG_CREATED=1
    echo "created $CONFIG_DIR/config.toml"
  else
    echo "kept existing $CONFIG_DIR/config.toml"
  fi
  if [ -f "$tmp_dir/packaging/systemd/vps-sentinel.service" ]; then
    SYSTEMD_TEMPLATE="$tmp_dir/packaging/systemd/vps-sentinel.service"
  fi
  configure_agent_identity
  configure_telegram
  install_systemd_unit_file
  post_install_setup
  activate_systemd_service
  rm -rf "$tmp_dir"
}

build_and_install() {
  cd "$WORK_DIR"
  cargo build --release --locked
  install -d "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
  install -m 0755 target/release/vps-sentinel "$PREFIX/bin/vps-sentinel"
  if [ -f reload.sh ]; then
    install -m 0755 reload.sh "$PREFIX/bin/vps-sentinel-reload"
  fi
  if [ -f stop.sh ]; then
    install -m 0755 stop.sh "$PREFIX/bin/vps-sentinel-stop"
  fi

  if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    install -m 0600 config/config.example.toml "$CONFIG_DIR/config.toml"
    CONFIG_CREATED=1
    echo "created $CONFIG_DIR/config.toml"
  else
    echo "kept existing $CONFIG_DIR/config.toml"
  fi

  configure_agent_identity
  configure_telegram
  install_systemd_unit_file
  post_install_setup
  activate_systemd_service
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
  case "$RUN_NOTIFY_TEST" in
    auto)
      if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
        "$PREFIX/bin/vps-sentinel" --config "$config_path" notify test
      fi
      ;;
    yes|true|1)
      "$PREFIX/bin/vps-sentinel" --config "$config_path" notify test
      ;;
    no|false|0) ;;
    *)
      echo "invalid RUN_NOTIFY_TEST value: $RUN_NOTIFY_TEST" >&2
      exit 1
      ;;
  esac
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

install_deps
case "$INSTALL_METHOD" in
  release)
    install_from_release || {
      echo "release installation failed" >&2
      exit 1
    }
    ;;
  auto)
    if ! install_from_release; then
      echo "release artifact unavailable; falling back to source build"
      ensure_rust
      checkout_or_update
      build_and_install
    fi
    ;;
  source)
    ensure_rust
    checkout_or_update
    build_and_install
    ;;
  *)
    echo "invalid INSTALL_METHOD value: $INSTALL_METHOD" >&2
    exit 1
    ;;
esac

echo "vps-sentinel installed"
echo "config: $CONFIG_DIR/config.toml"
echo "database: $DATA_DIR/sentinel.db"
