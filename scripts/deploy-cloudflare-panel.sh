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
  PANEL_SHARED_SECRET or PANEL_NODE_SECRETS
  PANEL_OPERATOR_TOKEN or PANEL_ADMIN_TOKEN, unless PANEL_PUBLIC_ENABLED=true or PANEL_PUBLIC_PAGES is not empty

Common configuration:
  PANEL_WORKER_NAME             default: vps-sentinel-panel
  PANEL_D1_NAME                 default: ${PANEL_WORKER_NAME}-db
  PANEL_D1_ID                   optional, reused when set
  PANEL_COMPATIBILITY_DATE      default: 2026-06-22
  PANEL_PUBLIC_ENABLED          default: false
  PANEL_PUBLIC_PAGES            default: overview,probe_sources,nodes
  PANEL_ADMIN_PATH              default: /admin
  PANEL_THEME                   default: default
  PANEL_THEMES                  default: default:Default
  PANEL_CORS_ORIGIN             optional exact origin for cross-origin agent/UI calls
  PANEL_MAX_BODY_BYTES          default: 1048576
  PANEL_VERIFY_URL              optional URL used for /api/v1/settings verification
  WRANGLER_BIN                  optional path to wrangler; otherwise wrangler or npx is used

Examples:
  CLOUDFLARE_ACCOUNT_ID=... \
  PANEL_SHARED_SECRET=... \
  PANEL_OPERATOR_TOKEN=... \
  PANEL_ADMIN_TOKEN=... \
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
const parsed = JSON.parse(input);
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
process.stdout.write(scan(parsed));
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
  create_output="$(run_wrangler d1 create "$PANEL_D1_NAME" --json)"
  PANEL_D1_ID="$(printf '%s' "$create_output" | parse_created_d1_id)"
  [ -n "$PANEL_D1_ID" ] || fail "could not parse D1 database id from wrangler output"
  export PANEL_D1_ID
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
    : "overview,probe_sources,nodes",
  PANEL_THEME: process.env.PANEL_THEME || "default",
  PANEL_THEMES: process.env.PANEL_THEMES || "default:Default",
  PANEL_ADMIN_PATH: process.env.PANEL_ADMIN_PATH || "/admin",
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
    run_worker_first: ["/api/*"],
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
  WORKER_FILE="${REPO_ROOT}/panel/cloudflare/worker.js"
  SCHEMA_FILE="${REPO_ROOT}/panel/cloudflare/schema.sql"
  WEB_DIR="${REPO_ROOT}/panel/web"

  [ -f "$WORKER_FILE" ] || fail "missing ${WORKER_FILE}"
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
    PANEL_PUBLIC_PAGES="overview,probe_sources,nodes"
  fi
  PANEL_THEME="${PANEL_THEME:-default}"
  PANEL_THEMES="${PANEL_THEMES:-default:Default}"
  PANEL_ADMIN_PATH="${PANEL_ADMIN_PATH:-/admin}"
  PANEL_MAX_BODY_BYTES="${PANEL_MAX_BODY_BYTES:-1048576}"
  export PANEL_WORKER_NAME PANEL_D1_NAME PANEL_COMPATIBILITY_DATE PANEL_PUBLIC_ENABLED PANEL_PUBLIC_PAGES PANEL_THEME PANEL_THEMES PANEL_ADMIN_PATH PANEL_MAX_BODY_BYTES

  validate_name "$PANEL_WORKER_NAME" "PANEL_WORKER_NAME"
  validate_name "$PANEL_D1_NAME" "PANEL_D1_NAME"

  if [ "${PANEL_DEPLOY_DRY_RUN}" != "1" ]; then
    [ -n "${CLOUDFLARE_ACCOUNT_ID:-}" ] || warn "CLOUDFLARE_ACCOUNT_ID is not set; wrangler must infer the account from login"
    if [ -z "${PANEL_SHARED_SECRET:-}" ] && [ -z "${PANEL_NODE_SECRETS:-}" ]; then
      fail "set PANEL_SHARED_SECRET or PANEL_NODE_SECRETS before deploying"
    fi
    if ! is_enabled "$PANEL_PUBLIC_ENABLED" && [ -z "$PANEL_PUBLIC_PAGES" ] && [ -z "${PANEL_OPERATOR_TOKEN:-}" ] && [ -z "${PANEL_ADMIN_TOKEN:-}" ]; then
      fail "set PANEL_OPERATOR_TOKEN or PANEL_ADMIN_TOKEN, set PANEL_PUBLIC_PAGES, or set PANEL_PUBLIC_ENABLED=true"
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
  put_secret "PANEL_OPERATOR_TOKEN" "${PANEL_OPERATOR_TOKEN:-}"
  put_secret "PANEL_VIEW_TOKEN" "${PANEL_VIEW_TOKEN:-}"
  put_secret "PANEL_ADMIN_TOKEN" "${PANEL_ADMIN_TOKEN:-}"

  verify_deploy "$deploy_output"
}

main "$@"
