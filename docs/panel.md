# Fleet Panel

The fleet panel is an optional push-mode dashboard for multiple VPS nodes. Agents keep their normal local-first behavior and only push a bounded, signed summary to the configured receiver. Local detection and active response can still use raw source IPs. Panel telemetry removes node IDs, hostnames, raw evidence details, and general network fields before remote storage, while admin-only response datasets intentionally keep external public source IPs for active-block review and probe-source blacklists.

## What Gets Pushed

Each panel payload contains:

- non-sensitive node name, agent version, privacy mode, enabled features, storage stats, and lightweight probe metrics such as CPU usage, load average, memory usage, uptime, aggregate network traffic, network rates, interface count, and agent RSS;
- scan summary counters;
- recent findings at or above `panel.min_severity`;
- recent incidents;
- baseline-drift review items;
- active-response block status such as source IP, rule, backend, reason, and expiry for admin users, with lower roles receiving redacted network fields;
- aggregated external probe-source records with source IP, IP version, network prefix, categories, rule IDs, latest reason, and block status for admin blacklist review.

Payload size is bounded by `panel.max_payload_bytes`. If the panel is unavailable, the agent stores a small local outbox in the existing SQLite rule-state store and retries later. The outbox is capped by `panel.outbox_max_items`.

The self-hosted and Worker panels store the signed payload after a second server-side redaction pass, and read APIs only expose fixed display columns. New uploads use `node_name` for signing and display, and do not serialize node IDs, host IDs, or hostnames. Raw evidence JSON, incident payload JSON, storage details, enabled feature lists, and database timestamps are not returned by browser-facing list endpoints. Public node APIs can return non-sensitive probe metrics so the UI can act as a lightweight node monitor without exposing IPs, paths, commands, or raw logs. External source IPs are only returned from admin-only `active_blocks` and `probe_sources` datasets; public and operator responses keep those fields redacted.

## Agent Configuration

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_id = ""       # deprecated compatibility field; new uploads do not send node IDs
node_name = "prod-web-1" # required for clear fleet display; never use public IPs or private hostnames
secret = "replace-with-a-long-random-secret"
min_severity = "Medium"
batch_size = 100
push_interval_seconds = 60
request_timeout_seconds = 60
outbox_max_items = 128
max_payload_bytes = 524288
privacy_mode = "strict" # strict removes node identity details and raw evidence; admin response datasets may still carry external public source IPs
ip_intel_paths = [] # optional CSV files: cidr,country,asn,organization
ip_intel_max_entries = 20000
```

Use HTTPS for remote panel URLs. Plain HTTP is accepted only for `localhost` or `127.0.0.1` because panel payloads can contain sensitive security context even though they are HMAC signed.

`panel.ip_intel_paths` is optional. When configured, the agent reads bounded local CSV files and enriches admin-only probe-source blacklist rows by longest CIDR prefix match. The panel does not call external ASN or GeoIP services by default, so enrichment does not leak attacker IPs to third parties. Empty, invalid, or missing files degrade to `unknown` country/ASN/organization fields.

Useful commands:

```bash
vs --config /etc/vps-sentinel/config.toml panel push
vs --config /etc/vps-sentinel/config.toml panel flush
vs --config /etc/vps-sentinel/config.toml panel outbox
```

For a step-by-step deployment guide covering Cloudflare Worker/D1 and a self-hosted VPS panel, see [面板部署教程](panel-deployment.zh-CN.md).

## Self-Hosted Rust Panel

The self-hosted service is Rust, not Python. Build it with:

```bash
cargo build --release -p sentinel-panel
```

SQLite example:

```bash
PANEL_SHARED_SECRET='replace-with-a-long-random-secret' \
PANEL_OPERATOR_TOKEN='replace-with-a-separate-operator-token' \
PANEL_ADMIN_TOKEN='replace-with-a-separate-admin-token' \
PANEL_DATABASE_URL='sqlite://panel.db' \
PANEL_DB_BACKEND='sqlite' \
PANEL_WEB_DIR='/usr/local/share/vps-sentinel/panel/web' \
target/release/vps-sentinel-panel --bind 0.0.0.0:8080
```

PostgreSQL example:

```bash
PANEL_SHARED_SECRET='replace-with-a-long-random-secret' \
PANEL_OPERATOR_TOKEN='replace-with-a-separate-operator-token' \
PANEL_ADMIN_TOKEN='replace-with-a-separate-admin-token' \
PANEL_DATABASE_URL='postgres://vps_sentinel:password@127.0.0.1:5432/vps_sentinel' \
PANEL_DB_BACKEND='postgres' \
PANEL_WEB_DIR='/usr/local/share/vps-sentinel/panel/web' \
target/release/vps-sentinel-panel --bind 0.0.0.0:8080
```

MySQL example:

```bash
PANEL_SHARED_SECRET='replace-with-a-long-random-secret' \
PANEL_OPERATOR_TOKEN='replace-with-a-separate-operator-token' \
PANEL_ADMIN_TOKEN='replace-with-a-separate-admin-token' \
PANEL_DATABASE_URL='mysql://vps_sentinel:password@127.0.0.1:3306/vps_sentinel' \
PANEL_DB_BACKEND='mysql' \
PANEL_WEB_DIR='/usr/local/share/vps-sentinel/panel/web' \
target/release/vps-sentinel-panel --bind 0.0.0.0:8080
```

The service initializes the selected database schema on startup. SQLite uses the existing `rusqlite` stack from the agent; PostgreSQL and MySQL use async pools. This avoids linking two different SQLite native libraries into the same workspace.

The installer and updater copy `panel/` to `/usr/local/share/vps-sentinel/panel` by default. Override `SHARE_DIR` if your package layout uses another directory.

For production, place the panel behind a reverse proxy with HTTPS and keep `PANEL_SHARED_SECRET`, `PANEL_NODE_SECRETS`, `PANEL_OPERATOR_TOKEN`, `PANEL_VIEW_TOKEN`, and `PANEL_ADMIN_TOKEN` out of shell history. `PANEL_SHARED_SECRET`/`PANEL_NODE_SECRETS` are only for agent ingest signatures. `PANEL_OPERATOR_TOKEN` is the browser token for normal operations. `PANEL_VIEW_TOKEN` remains supported as a legacy alias for the operator role. `PANEL_ADMIN_TOKEN` can read all panel detail and is required for review writes such as marking a finding as confirmed or false positive.

If `PANEL_PUBLIC_ENABLED=true`, browsers without a token can enter the public role. Public role APIs only expose aggregate trends, risk counts, severity distribution, node names, and node freshness. They do not expose finding lists, incident payloads, baseline subjects, active-block details, raw evidence, command lines, file paths, tokens, or raw logs.

If `PANEL_PUBLIC_ENABLED=false` and all browser tokens are missing, read APIs stay locked with `panel_view_token_not_configured`. The static UI can still load, but it will not show telemetry data.

## Browser Roles And Auto Refresh

The self-hosted Rust panel has three browser roles enforced by the backend:

- public: aggregate trend, risk count, severity distribution, node name, online status, and non-sensitive node resource metrics;
- operator: node name, rule, category, risk summary, action queue, redacted subject, impact, and recommendations;
- admin: full redacted evidence, active-block implementation detail, review state, false-positive marking, and audit logs.

The self-hosted UI uses WebSocket change events. It first exchanges the current browser role for a short-lived stream ticket through `GET /api/v1/stream-ticket`, then connects to `GET /api/v1/stream?ticket=<ticket>`. The ticket avoids putting browser tokens in the WebSocket URL. The stream sends a hello event, heartbeat pings, and refresh signals only after data changes; all data still comes from role-scoped JSON APIs. The Cloudflare Worker receiver currently returns `stream_unavailable`, so static deployments do not poll lists automatically.

The self-hosted Rust panel does not enable permissive CORS by default. The Worker receiver also requires an exact `PANEL_CORS_ORIGIN` when cross-origin static hosting is used; wildcard origins are intentionally ignored.

`PANEL_NODE_SECRETS` accepts JSON such as:

```json
{"prod-web-1":"node-specific-secret","prod-db-1":"another-node-secret"}
```

Node-specific secrets override the shared secret.

When using node-specific secrets with `privacy_mode = "strict"`, key `PANEL_NODE_SECRETS` by the non-sensitive `panel.node_name`. New agents sign uploads with `x-vps-sentinel-node-name` and do not serialize `node_id`, `host_id`, or `hostname` in the panel payload. The legacy `panel.node_id` field is accepted only for compatibility with older deployments.

## Cloudflare Worker/D1

The Worker receiver is in `panel/cloudflare/worker.js`; the D1 schema is in `panel/cloudflare/schema.sql`.

One-command deployment uses Wrangler and keeps Cloudflare secrets outside the repository:

```bash
CLOUDFLARE_ACCOUNT_ID='replace-with-account-id' \
PANEL_SHARED_SECRET='replace-with-a-long-random-agent-secret' \
PANEL_OPERATOR_TOKEN='replace-with-a-browser-operator-token' \
PANEL_ADMIN_TOKEN='replace-with-a-browser-admin-token' \
scripts/deploy-cloudflare-panel.sh
```

The script:

- reuses `PANEL_D1_NAME` when it already exists, or creates it when missing;
- applies `panel/cloudflare/schema.sql`;
- deploys `panel/cloudflare/worker.js` and `panel/web` as one Cloudflare Worker with static assets;
- stores `PANEL_SHARED_SECRET`, `PANEL_NODE_SECRETS`, `PANEL_OPERATOR_TOKEN`, `PANEL_VIEW_TOKEN`, and `PANEL_ADMIN_TOKEN` through Wrangler secrets;
- verifies `GET /api/v1/settings` when a Worker URL can be inferred, or when `PANEL_VERIFY_URL` is set.

No Cloudflare token, account ID, database ID, or panel secret is committed. Use `CLOUDFLARE_API_TOKEN` for non-interactive CI/server deploys, or run `wrangler login` once on an operator workstation. Optional variables include `PANEL_WORKER_NAME`, `PANEL_D1_NAME`, `PANEL_D1_ID`, `PANEL_PUBLIC_ENABLED`, `PANEL_THEME`, `PANEL_CORS_ORIGIN`, `PANEL_MAX_BODY_BYTES`, `WRANGLER_BIN`, and `PANEL_DEPLOY_VERIFY=0`.

Manual setup remains possible:

1. Create a D1 database.
2. Apply `panel/cloudflare/schema.sql`.
3. Deploy `panel/cloudflare/worker.js` with binding `DB` and bind `panel/web` as Worker static assets.
4. Set `PANEL_SHARED_SECRET` or `PANEL_NODE_SECRETS` as Worker secrets.
5. Set `PANEL_OPERATOR_TOKEN` and `PANEL_ADMIN_TOKEN`, or explicitly enable public mode.

The Worker exposes the same API shape as the Rust panel:

- `POST /api/v1/ingest`
- `GET /api/v1/summary`
- `GET /api/v1/nodes`
- `GET /api/v1/findings`
- `GET /api/v1/finding?id=<finding-id>`
- `POST /api/v1/finding-review`
- `GET /api/v1/incidents`
- `GET /api/v1/incident?id=<incident-id>`
- `GET /api/v1/baseline-drifts`
- `GET /api/v1/active-blocks`
- `GET /api/v1/probe-sources`
- `GET /api/v1/audit-logs`
- `GET /api/v1/stream-ticket` returns `stream_unavailable` for the Worker receiver

## Security Model

Panel ingest requests include:

- `x-vps-sentinel-node`
- `x-vps-sentinel-timestamp`
- `x-vps-sentinel-nonce`
- `x-vps-sentinel-body-sha256`
- `x-vps-sentinel-signature`

The signature is HMAC-SHA256 over:

```text
POST
/api/v1/ingest
<timestamp>
<nonce>
<body_sha256_hex>
```

Receivers reject stale timestamps, nonce replay, node mismatches, body-hash mismatches, and invalid signatures.

## Theme And Page Extensions

The panel UI is static and themeable. A theme lives under:

```text
panel/web/themes/<theme-name>/
```

Minimum theme:

```json
{
  "name": "my-theme",
  "styles": ["theme.css"],
  "pages": []
}
```

CSS files are loaded relative to the theme directory. Themes can override the CSS variables declared in `panel/web/styles.css`.
Remote theme assets are intentionally ignored; keep theme CSS and page modules under `panel/web/themes/<theme-name>/` so the panel remains static-hosting friendly and does not leak browser traffic to third-party CDNs. The app also sets `data-theme="<theme-name>"` on `<html>` and `<body>`, and `data-page="<page-id>"` on `<body>`, so a theme can safely scope page-specific overrides.

Useful theme variables include:

- layout: `--topbar-height`, `--sidebar-width`, `--radius`, `--radius-sm`, `--panel-body-min`, `--node-list-max-height`;
- surfaces: `--app-bg`, `--app-bg-strong`, `--app-bg-grid`, `--surface`, `--surface-muted`, `--surface-hover`, `--panel-title-bg`;
- text and borders: `--text`, `--muted`, `--muted-strong`, `--border`, `--border-strong`;
- security tones: `--critical`, `--high`, `--medium`, `--low`, `--success`, `--retired`;
- effects: `--shadow`, `--shadow-soft`, `--shadow-hover`, `--ring-shadow`, `--focus-ring`.

Custom pages can be added through the theme manifest:

```json
{
  "name": "ops-theme",
  "styles": ["theme.css"],
  "pages": [
    { "id": "ops", "label": "Ops", "module": "ops-page.js" }
  ]
}
```

The page module must export `render(context)`. The context includes:

- `context.api(path)` for `/api/v1` calls;
- `context.app`, the current page container;
- `context.datasets`, preloaded built-in datasets;
- `context.renderTable(rows, columns)`;
- `context.state` and the loaded theme manifest.

If a custom page module fails to load or does not export `render(context)`, the built-in pages still load. This keeps visual customization separate from the Rust API and avoids hardcoding dashboard pages in the backend.
