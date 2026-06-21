# Fleet Panel

The fleet panel is an optional push-mode dashboard for multiple VPS nodes. Agents keep their normal local-first behavior and only push a bounded, signed summary to the configured receiver. Local detection and active response can still use raw source IPs, but panel telemetry defaults to privacy-safe mode and removes raw IP addresses before it leaves the monitored host.

## What Gets Pushed

Each panel payload contains:

- node identity, display name, agent version, privacy mode, enabled features, and storage stats;
- scan summary counters;
- recent findings at or above `panel.min_severity`;
- recent incidents;
- baseline-drift review items;
- active-response block status such as rule, backend, reason, and expiry without raw blocked IPs.

Payload size is bounded by `panel.max_payload_bytes`. If the panel is unavailable, the agent stores a small local outbox in the existing SQLite rule-state store and retries later. The outbox is capped by `panel.outbox_max_items`.

The self-hosted and Worker panels store the signed payload after a second server-side redaction pass, and read APIs only expose fixed display columns. Raw IP addresses, raw evidence JSON, incident payload JSON, host IDs, storage details, enabled feature lists, and database timestamps are not returned by the browser-facing list endpoints.

## Agent Configuration

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_id = ""       # empty derives a stable privacy-safe node ID from the local host identity
node_name = ""     # empty uses agent.display_name; strict mode falls back to the privacy-safe node ID when needed
secret = "replace-with-a-long-random-secret"
min_severity = "Medium"
batch_size = 100
push_interval_seconds = 60
request_timeout_seconds = 10
outbox_max_items = 128
max_payload_bytes = 524288
privacy_mode = "strict" # strict avoids sending raw IPs or hostnames to the remote panel
```

Use HTTPS for remote panel URLs. Plain HTTP is accepted only for `localhost` or `127.0.0.1` because panel payloads can contain sensitive security context even though they are HMAC signed.

Useful commands:

```bash
vs panel push --config /etc/vps-sentinel/config.toml
vs panel flush --config /etc/vps-sentinel/config.toml
vs panel outbox --config /etc/vps-sentinel/config.toml
```

## Self-Hosted Rust Panel

The self-hosted service is Rust, not Python. Build it with:

```bash
cargo build --release -p sentinel-panel
```

SQLite example:

```bash
PANEL_SHARED_SECRET='replace-with-a-long-random-secret' \
PANEL_VIEW_TOKEN='replace-with-a-separate-browser-token' \
PANEL_ADMIN_TOKEN='replace-with-a-separate-admin-token' \
PANEL_DATABASE_URL='sqlite://panel.db' \
PANEL_DB_BACKEND='sqlite' \
PANEL_WEB_DIR='/usr/local/share/vps-sentinel/panel/web' \
target/release/vps-sentinel-panel --bind 0.0.0.0:8080
```

PostgreSQL example:

```bash
PANEL_SHARED_SECRET='replace-with-a-long-random-secret' \
PANEL_VIEW_TOKEN='replace-with-a-separate-browser-token' \
PANEL_ADMIN_TOKEN='replace-with-a-separate-admin-token' \
PANEL_DATABASE_URL='postgres://vps_sentinel:password@127.0.0.1:5432/vps_sentinel' \
PANEL_DB_BACKEND='postgres' \
PANEL_WEB_DIR='/usr/local/share/vps-sentinel/panel/web' \
target/release/vps-sentinel-panel --bind 0.0.0.0:8080
```

MySQL example:

```bash
PANEL_SHARED_SECRET='replace-with-a-long-random-secret' \
PANEL_VIEW_TOKEN='replace-with-a-separate-browser-token' \
PANEL_ADMIN_TOKEN='replace-with-a-separate-admin-token' \
PANEL_DATABASE_URL='mysql://vps_sentinel:password@127.0.0.1:3306/vps_sentinel' \
PANEL_DB_BACKEND='mysql' \
PANEL_WEB_DIR='/usr/local/share/vps-sentinel/panel/web' \
target/release/vps-sentinel-panel --bind 0.0.0.0:8080
```

The service initializes the selected database schema on startup. SQLite uses the existing `rusqlite` stack from the agent; PostgreSQL and MySQL use async pools. This avoids linking two different SQLite native libraries into the same workspace.

The installer and updater copy `panel/` to `/usr/local/share/vps-sentinel/panel` by default. Override `SHARE_DIR` if your package layout uses another directory.

For production, place the panel behind a reverse proxy with HTTPS and keep `PANEL_SHARED_SECRET`, `PANEL_NODE_SECRETS`, `PANEL_VIEW_TOKEN`, and `PANEL_ADMIN_TOKEN` out of shell history. `PANEL_SHARED_SECRET`/`PANEL_NODE_SECRETS` are only for agent ingest signatures. `PANEL_VIEW_TOKEN` is a browser read token. `PANEL_ADMIN_TOKEN` can also read and is required for review writes such as marking a finding as confirmed or false positive.

If both `PANEL_VIEW_TOKEN` and `PANEL_ADMIN_TOKEN` are missing, read APIs stay locked with `panel_view_token_not_configured`. The static UI can still load, but it will not show telemetry data.

The self-hosted Rust panel does not enable permissive CORS by default. The Worker receiver also requires an exact `PANEL_CORS_ORIGIN` when cross-origin static hosting is used; wildcard origins are intentionally ignored.

`PANEL_NODE_SECRETS` accepts JSON such as:

```json
{"prod-web-1":"node-specific-secret","prod-db-1":"another-node-secret"}
```

Node-specific secrets override the shared secret.

When using node-specific secrets with `privacy_mode = "strict"`, set `panel.node_id` to a stable privacy-safe value and use the same value in `PANEL_NODE_SECRETS`. If `panel.node_id` is empty, the agent derives an anonymous stable node ID locally instead of sending the raw host identity.

## Cloudflare Worker/D1

The Worker receiver is in `panel/cloudflare/worker.js`; the D1 schema is in `panel/cloudflare/schema.sql`.

High-level setup:

1. Create a D1 database.
2. Apply `panel/cloudflare/schema.sql`.
3. Deploy `panel/cloudflare/worker.js` with binding `DB`.
4. Set `PANEL_SHARED_SECRET` or `PANEL_NODE_SECRETS` as Worker secrets.
5. Serve `panel/web` as static assets through Cloudflare Pages or another static host.

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
- `GET /api/v1/audit-logs`

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

- layout: `--topbar-height`, `--sidebar-width`, `--radius`, `--radius-sm`;
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
