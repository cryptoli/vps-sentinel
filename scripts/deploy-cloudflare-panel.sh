#!/usr/bin/env sh
set -eu

SCRIPT_NAME="deploy-cloudflare-panel"

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy-cloudflare-panel.sh [--dry-run] [--skip-verify]

Required for real deploy:
  CLOUDFLARE_API_TOKEN or an existing wrangler login session
  CLOUDFLARE_ACCOUNT_ID or CF_ACCOUNT_ID

Generated automatically when omitted:
  PANEL_SHARED_SECRET, unless PANEL_NODE_SECRETS is set
  PANEL_TOKEN
  PANEL_ADMIN_PATH

Common configuration:
  PANEL_WORKER_NAME             default: vps-sentinel-panel
  PANEL_D1_NAME                 default: ${PANEL_WORKER_NAME}-db
  PANEL_D1_ID                   optional, reused when set
  PANEL_COMPATIBILITY_DATE      default: 2026-06-22
  PANEL_PUBLIC_ENABLED          default: false
  PANEL_PUBLIC_PAGES            default: overview,probe_sources,nodes
  PANEL_ADMIN_PATH              generated once and reused from the local credential file
  PANEL_THEME                   default: default
  PANEL_THEMES                  default: default:Default
  PANEL_CORS_ORIGIN             optional exact origin for cross-origin agent/UI calls
  PANEL_MAX_BODY_BYTES          default: 1048576
  PANEL_VERIFY_URL              optional URL used for /api/v1/settings verification
  PANEL_CREDENTIAL_FILE         default: ~/.config/vps-sentinel/cloudflare-panel.env
  WRANGLER_BIN                  optional path to wrangler; otherwise wrangler or npx is used

Examples:
  CLOUDFLARE_ACCOUNT_ID=... \
  scripts/deploy-cloudflare-panel.sh

  PANEL_DEPLOY_DRY_RUN=1 scripts/deploy-cloudflare-panel.sh
EOF
}

log() {
  printf '%s\n' "[$SCRIPT_NAME] $*"
}

warn() {
  printf '%s\n' "[$SCRIPT_NAME] warning: $*" >&2
}

fail() {
  printf '%s\n' "[$SCRIPT_NAME] error: $*" >&2
  exit 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

run_wrangler() {
  if [ -n "${WRANGLER_BIN:-}" ]; then
    "$WRANGLER_BIN" "$@"
  elif command -v wrangler >/dev/null 2>&1; then
    wrangler "$@"
  elif command -v npx >/dev/null 2>&1; then
    npx --yes wrangler@latest "$@"
  else
    fail "wrangler is not installed and npx is unavailable"
  fi
}

parse_args() {
  PANEL_DEPLOY_VERIFY="${PANEL_DEPLOY_VERIFY:-1}"
  PANEL_DEPLOY_DRY_RUN="${PANEL_DEPLOY_DRY_RUN:-0}"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run)
        PANEL_DEPLOY_DRY_RUN=1
        ;;
      --skip-verify)
        PANEL_DEPLOY_VERIFY=0
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
    shift
  done
  export PANEL_DEPLOY_VERIFY PANEL_DEPLOY_DRY_RUN
}

validate_name() {
  value="$1"
  label="$2"
  case "$value" in
    *[!A-Za-z0-9_-]*|'')
      fail "$label must contain only letters, numbers, underscore, or dash"
      ;;
  esac
}

is_enabled() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

credential_file_path() {
  if [ -n "${PANEL_CREDENTIAL_FILE:-}" ]; then
    printf '%s\n' "$PANEL_CREDENTIAL_FILE"
    return
  fi
  if [ "${PANEL_DEPLOY_DRY_RUN:-0}" = "1" ]; then
    printf '%s\n' "${TMPDIR:-/tmp}/vps-sentinel-cloudflare-panel-dry-run.$$"
    return
  fi
  home_dir="${HOME:-}"
  [ -n "$home_dir" ] || home_dir="$(pwd)"
  printf '%s\n' "${home_dir}/.config/vps-sentinel/cloudflare-panel.env"
}

credential_value() {
  file="$1"
  key="$2"
  [ -f "$file" ] || return 0
  line="$(grep "^${key}='" "$file" 2>/dev/null | tail -n 1 || true)"
  [ -n "$line" ] || return 0
  value="${line#"$key='"}"
  value="${value%"'"}"
  unescape_shell_quote_value "$value"
}

unescape_shell_quote_value() {
  value="$1"
  quote_escape="'\\''"
  while :; do
    case "$value" in
      *"$quote_escape"*)
        prefix="${value%%"$quote_escape"*}"
        suffix="${value#*"$quote_escape"}"
        value="${prefix}'${suffix}"
        ;;
      *)
        printf '%s\n' "$value"
        return
        ;;
    esac
  done
}

shell_quote_value() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
}

random_hex() {
  bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
    return
  fi
  if command -v od >/dev/null 2>&1 && [ -r /dev/urandom ]; then
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
    return
  fi
  if command -v node >/dev/null 2>&1; then
    node -e "process.stdout.write(require('crypto').randomBytes(Number(process.argv[1])).toString('hex'))" "$bytes"
    return
  fi
  fail "missing random source: install openssl, provide /dev/urandom+od, or set PANEL_* values explicitly"
}

random_token() {
  random_hex 32
}

random_admin_path() {
  printf '/%s\n' "$(random_hex 6)"
}

load_or_generate_panel_secret() {
  key="$1"
  generator="$2"
  file="$3"
  current="$(eval "printf '%s' \"\${${key}:-}\"")"
  if [ -n "$current" ]; then
    printf '%s\n' "$current"
    return
  fi
  stored="$(credential_value "$file" "$key")"
  if [ -n "$stored" ]; then
    printf '%s\n' "$stored"
    return
  fi
  "$generator"
}

load_or_generate_browser_token() {
  file="$1"
  if [ -n "${PANEL_TOKEN:-}" ]; then
    printf '%s\n' "$PANEL_TOKEN"
    return
  fi
  for key in PANEL_TOKEN PANEL_ADMIN_TOKEN PANEL_OPERATOR_TOKEN PANEL_VIEW_TOKEN; do
    stored="$(credential_value "$file" "$key")"
    if [ -n "$stored" ]; then
      printf '%s\n' "$stored"
      return
    fi
  done
  random_token
}

write_credential_file() {
  file="$1"
  dir="$(dirname "$file")"
  if [ ! -d "$dir" ]; then
    install -d -m 0700 "$dir"
  fi
  tmp="${file}.$$"
  {
    printf '%s\n' '# vps-sentinel Cloudflare panel credentials'
    printf '%s\n' '# Keep this file private. Reuse these values when rotating or redeploying agents.'
    printf "PANEL_SHARED_SECRET='%s'\n" "$(shell_quote_value "${PANEL_SHARED_SECRET:-}")"
    printf "PANEL_TOKEN='%s'\n" "$(shell_quote_value "${PANEL_TOKEN:-}")"
    printf "PANEL_ADMIN_PATH='%s'\n" "$(shell_quote_value "${PANEL_ADMIN_PATH:-}")"
  } >"$tmp"
  chmod 0600 "$tmp"
  mv "$tmp" "$file"
}

ensure_panel_credentials() {
  PANEL_CREDENTIAL_FILE="$(credential_file_path)"
  export PANEL_CREDENTIAL_FILE
  if [ -z "${PANEL_SHARED_SECRET:-}" ] && [ -z "${PANEL_NODE_SECRETS:-}" ]; then
    PANEL_SHARED_SECRET="$(load_or_generate_panel_secret PANEL_SHARED_SECRET random_token "$PANEL_CREDENTIAL_FILE")"
    export PANEL_SHARED_SECRET
  fi
  PANEL_TOKEN="$(load_or_generate_browser_token "$PANEL_CREDENTIAL_FILE")"
  PANEL_ADMIN_PATH="$(load_or_generate_panel_secret PANEL_ADMIN_PATH random_admin_path "$PANEL_CREDENTIAL_FILE")"
  export PANEL_TOKEN PANEL_ADMIN_PATH
  write_credential_file "$PANEL_CREDENTIAL_FILE"
}

find_d1_id() {
  database_name="$1"
  run_wrangler d1 list --json | node -e '
const fs = require("fs");
const name = process.argv[1];
const input = fs.readFileSync(0, "utf8").trim();
if (!input) process.exit(0);
const parsed = JSON.parse(input);
const list = Array.isArray(parsed) ? parsed : (parsed.result || parsed.databases || []);
const found = list.find((item) => item.name === name || item.database_name === name);
process.stdout.write(found ? String(found.uuid || found.id || found.database_id || "") : "");
' "$database_name"
}

parse_created_d1_id() {
  node -e '
const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim();
if (!input) process.exit(0);
function scan(value) {
  if (!value || typeof value !== "object") return "";
  for (const key of ["uuid", "id", "database_id"]) {
    if (typeof value[key] === "string" && value[key]) return value[key];
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const hit = scan(item);
      if (hit) return hit;
    }
  } else {
    for (const item of Object.values(value)) {
      const hit = scan(item);
      if (hit) return hit;
    }
  }
  return "";
}
try {
  const parsed = JSON.parse(input);
  const id = scan(parsed);
  if (id) {
    process.stdout.write(id);
    process.exit(0);
  }
} catch (_) {
}
const match = input.match(/database_id\s*=\s*"([^"]+)"/) || input.match(/\bid\s*[:=]\s*"?([0-9a-f-]{20,})"?/i);
process.stdout.write(match ? match[1] : "");
'
}

ensure_d1_database() {
  if [ -n "${PANEL_D1_ID:-}" ]; then
    log "using configured D1 database id for ${PANEL_D1_NAME}"
    return
  fi

  log "looking for D1 database ${PANEL_D1_NAME}"
  PANEL_D1_ID="$(find_d1_id "$PANEL_D1_NAME" || true)"
  if [ -n "$PANEL_D1_ID" ]; then
    export PANEL_D1_ID
    log "reusing existing D1 database ${PANEL_D1_NAME}"
    return
  fi

  log "creating D1 database ${PANEL_D1_NAME}"
  create_output="$(run_wrangler d1 create "$PANEL_D1_NAME")"
  PANEL_D1_ID="$(printf '%s' "$create_output" | parse_created_d1_id)"
  [ -n "$PANEL_D1_ID" ] || fail "could not parse D1 database id from wrangler output"
  export PANEL_D1_ID
}

ignore_d1_compat_error() {
  output="$1"
  normalized="$(printf '%s' "$output" | tr '[:upper:]' '[:lower:]')"
  case "$normalized" in
    *"duplicate column"*|*"already exists"*|*"no such table"*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

apply_d1_compat_migrations() {
  log "applying D1 compatibility migrations"
  while IFS='|' read -r table column definition; do
    [ -n "$table" ] || continue
    command="ALTER TABLE ${table} ADD COLUMN ${column} ${definition}"
    set +e
    output="$(run_wrangler d1 execute "$PANEL_D1_NAME" --remote --command "$command" 2>&1)"
    status="$?"
    set -e
    if [ "$status" -ne 0 ]; then
      if ignore_d1_compat_error "$output"; then
        continue
      fi
      printf '%s\n' "$output" >&2
      fail "D1 compatibility migration failed for ${table}.${column}"
    fi
  done <<'EOF'
nodes|metrics_json|TEXT NOT NULL DEFAULT '{}'
findings|review_signature|TEXT NOT NULL DEFAULT ''
incidents|review_signature|TEXT NOT NULL DEFAULT ''
baseline_drifts|category|TEXT NOT NULL DEFAULT 'system'
baseline_drifts|review_signature|TEXT NOT NULL DEFAULT ''
panel_reviews|review_signature|TEXT NOT NULL DEFAULT ''
EOF
}

write_config() {
  TMP_CONFIG="$1"
  export TMP_CONFIG
  node <<'NODE'
const fs = require("fs");

const vars = {
  PANEL_MAX_BODY_BYTES: process.env.PANEL_MAX_BODY_BYTES || "1048576",
  PANEL_PUBLIC_ENABLED: process.env.PANEL_PUBLIC_ENABLED || "false",
  PANEL_PUBLIC_PAGES: Object.prototype.hasOwnProperty.call(process.env, "PANEL_PUBLIC_PAGES")
    ? process.env.PANEL_PUBLIC_PAGES
    : (process.env.PANEL_CONTRACT_DEFAULT_PUBLIC_PAGES || "overview,probe_sources,nodes"),
  PANEL_THEME: process.env.PANEL_THEME || "default",
  PANEL_THEMES: process.env.PANEL_THEMES || process.env.PANEL_CONTRACT_DEFAULT_THEMES || "default:Default",
  PANEL_ADMIN_PATH: process.env.PANEL_ADMIN_PATH,
};
if (process.env.PANEL_CORS_ORIGIN) {
  vars.PANEL_CORS_ORIGIN = process.env.PANEL_CORS_ORIGIN;
}

const config = {
  name: process.env.PANEL_WORKER_NAME,
  main: "worker.js",
  compatibility_date: process.env.PANEL_COMPATIBILITY_DATE || "2026-06-22",
  assets: {
    directory: "./web",
    binding: "ASSETS",
    not_found_handling: "single-page-application",
    run_worker_first: ["/*"],
  },
  d1_databases: [
    {
      binding: "DB",
      database_name: process.env.PANEL_D1_NAME,
      database_id: process.env.PANEL_D1_ID,
    },
  ],
  vars,
};

fs.writeFileSync(process.env.TMP_CONFIG, `${JSON.stringify(config, null, 2)}\n`);
NODE
}

put_secret() {
  secret_name="$1"
  secret_value="$2"
  [ -n "$secret_value" ] || return 0
  log "setting Worker secret ${secret_name}"
  printf '%s' "$secret_value" | run_wrangler secret put "$secret_name" --config "$TMP_CONFIG"
}

delete_legacy_secret() {
  secret_name="$1"
  log "removing legacy Worker secret ${secret_name} if present"
  printf 'y\n' | run_wrangler secret delete "$secret_name" --config "$TMP_CONFIG" >/dev/null 2>&1 || true
}

verify_deploy() {
  deploy_output="$1"
  verify_url="${PANEL_VERIFY_URL:-}"
  if [ -z "$verify_url" ]; then
    verify_url="$(printf '%s\n' "$deploy_output" | sed -n 's#.*\(https://[^[:space:]]*workers.dev\).*#\1#p' | head -n 1)"
  fi
  if [ "${PANEL_DEPLOY_VERIFY}" != "1" ]; then
    warn "deployment verification skipped"
    return
  fi
  if [ -z "$verify_url" ]; then
    warn "could not infer Worker URL; set PANEL_VERIFY_URL to enable verification"
    return
  fi
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl is unavailable; skipping ${verify_url}/api/v1/settings verification"
    return
  fi
  log "verifying ${verify_url}/api/v1/settings"
  curl -fsS "${verify_url%/}/api/v1/settings" >/dev/null
  log "verification passed: ${verify_url}"
}

main() {
  parse_args "$@"

  SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
  REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
  CONTRACT_ENV="${REPO_ROOT}/panel/shared/contract.env"
  [ -f "$CONTRACT_ENV" ] && . "$CONTRACT_ENV"
  export PANEL_CONTRACT_DEFAULT_PUBLIC_PAGES PANEL_CONTRACT_DEFAULT_THEMES
  WORKER_FILE="${REPO_ROOT}/panel/cloudflare/worker.js"
  WORKER_CONTRACT_FILE="${REPO_ROOT}/panel/cloudflare/panel-contract.generated.js"
  SCHEMA_FILE="${REPO_ROOT}/panel/cloudflare/schema.sql"
  WEB_DIR="${REPO_ROOT}/panel/web"

  [ -f "$WORKER_FILE" ] || fail "missing ${WORKER_FILE}"
  [ -f "$WORKER_CONTRACT_FILE" ] || fail "missing ${WORKER_CONTRACT_FILE}; run node scripts/generate-panel-contract.mjs"
  [ -f "$SCHEMA_FILE" ] || fail "missing ${SCHEMA_FILE}"
  [ -d "$WEB_DIR" ] || fail "missing ${WEB_DIR}"

  need_command node
  if [ -n "${CF_ACCOUNT_ID:-}" ] && [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    export CLOUDFLARE_ACCOUNT_ID="$CF_ACCOUNT_ID"
  fi

  PANEL_WORKER_NAME="${PANEL_WORKER_NAME:-vps-sentinel-panel}"
  PANEL_D1_NAME="${PANEL_D1_NAME:-${PANEL_WORKER_NAME}-db}"
  PANEL_COMPATIBILITY_DATE="${PANEL_COMPATIBILITY_DATE:-2026-06-22}"
  PANEL_PUBLIC_ENABLED="${PANEL_PUBLIC_ENABLED:-false}"
  if [ "${PANEL_PUBLIC_PAGES+x}" != "x" ]; then
    PANEL_PUBLIC_PAGES="${PANEL_CONTRACT_DEFAULT_PUBLIC_PAGES:-overview,probe_sources,nodes}"
  fi
  PANEL_THEME="${PANEL_THEME:-default}"
  PANEL_THEMES="${PANEL_THEMES:-${PANEL_CONTRACT_DEFAULT_THEMES:-default:Default}}"
  PANEL_MAX_BODY_BYTES="${PANEL_MAX_BODY_BYTES:-1048576}"
  ensure_panel_credentials
  export PANEL_WORKER_NAME PANEL_D1_NAME PANEL_COMPATIBILITY_DATE PANEL_PUBLIC_ENABLED PANEL_PUBLIC_PAGES PANEL_THEME PANEL_THEMES PANEL_ADMIN_PATH PANEL_MAX_BODY_BYTES

  validate_name "$PANEL_WORKER_NAME" "PANEL_WORKER_NAME"
  validate_name "$PANEL_D1_NAME" "PANEL_D1_NAME"

  if [ "${PANEL_DEPLOY_DRY_RUN}" != "1" ]; then
    [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ] || warn "CLOUDFLARE_ACCOUNT_ID is not set; wrangler must infer the account from login"
    if ! is_enabled "$PANEL_PUBLIC_ENABLED" && [ -z "$PANEL_PUBLIC_PAGES" ] && [ -z "${PANEL_TOKEN:-}" ]; then
      fail "set PANEL_TOKEN, set PANEL_PUBLIC_PAGES, or set PANEL_PUBLIC_ENABLED=true"
    fi
    log "checking Cloudflare authentication"
    run_wrangler whoami >/dev/null
    ensure_d1_database
  else
    PANEL_D1_ID="${PANEL_D1_ID:-00000000-0000-0000-0000-000000000000}"
    export PANEL_D1_ID
    warn "dry run enabled; Cloudflare resources will not be changed"
  fi

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
  TMP_CONFIG="${TMP_DIR}/wrangler.jsonc"
  export TMP_CONFIG
  cp "$WORKER_FILE" "${TMP_DIR}/worker.js"
  cp "$WORKER_CONTRACT_FILE" "${TMP_DIR}/panel-contract.generated.js"
  mkdir -p "${TMP_DIR}/web"
  cp -R "${WEB_DIR}/." "${TMP_DIR}/web/"
  write_config "$TMP_CONFIG"

  if [ "${PANEL_DEPLOY_DRY_RUN}" = "1" ]; then
    log "generated temporary Wrangler config:"
    sed 's/"database_id": "[^"]*"/"database_id": "<redacted>"/' "$TMP_CONFIG"
    exit 0
  fi

  log "validating Worker config"
  run_wrangler deploy --config "$TMP_CONFIG" --dry-run >/dev/null

  apply_d1_compat_migrations

  log "applying D1 schema to ${PANEL_D1_NAME}"
  run_wrangler d1 execute "$PANEL_D1_NAME" --remote --file "$SCHEMA_FILE"

  log "deploying Worker ${PANEL_WORKER_NAME}"
  set +e
  deploy_output="$(run_wrangler deploy --config "$TMP_CONFIG" --minify 2>&1)"
  deploy_status="$?"
  set -e
  printf '%s\n' "$deploy_output"
  [ "$deploy_status" -eq 0 ] || fail "wrangler deploy failed"

  put_secret "PANEL_SHARED_SECRET" "${PANEL_SHARED_SECRET:-}"
  put_secret "PANEL_NODE_SECRETS" "${PANEL_NODE_SECRETS:-}"
  put_secret "PANEL_TOKEN" "${PANEL_TOKEN:-}"
  delete_legacy_secret "PANEL_OPERATOR_TOKEN"
  delete_legacy_secret "PANEL_VIEW_TOKEN"
  delete_legacy_secret "PANEL_ADMIN_TOKEN"

  verify_deploy "$deploy_output"
  log "panel credentials saved to ${PANEL_CREDENTIAL_FILE}"
  log "read the file to configure agents and open the management path; keep it private"
}

main "$@"
