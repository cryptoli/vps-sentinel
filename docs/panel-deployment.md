# Panel Deployment

The fleet panel is optional. Agents continue to monitor locally and push signed, bounded telemetry to the panel when `[panel].enabled = true`.

## Modes

| Mode | Use when | Storage |
| --- | --- | --- |
| Cloudflare Worker/D1 | You want a low-maintenance public HTTPS panel without running another VPS service. | Cloudflare D1 |
| Self-hosted Rust panel | You want full Rust backend control, WebSocket refresh, and optional SQLite/PostgreSQL/MySQL. | SQLite, PostgreSQL, or MySQL |

## Token Model

| Secret | Purpose |
| --- | --- |
| `PANEL_SHARED_SECRET` | Shared HMAC ingest secret. Must match each agent's `[panel].secret`. |
| `PANEL_NODE_SECRETS` | Optional JSON map of node-specific secrets keyed by non-sensitive node name. |
| `PANEL_OPERATOR_TOKEN` | Browser token for redacted operator data. |
| `PANEL_ADMIN_TOKEN` | Browser token for admin pages, review writes, and sensitive operations. |
| `PANEL_VIEW_TOKEN` | Legacy operator-read alias. Prefer `PANEL_OPERATOR_TOKEN` for new installs. |

The default management entry path is `/cryptocaigou`. It only controls the UI entry route; API authorization still depends on bearer tokens.

## Cloudflare Worker/D1

1. Build the static UI:

```bash
cd panel/ui
npm install
npm run build:web
cd ../..
```

2. Deploy with Wrangler:

```bash
CLOUDFLARE_ACCOUNT_ID="<account-id>" \
PANEL_WORKER_NAME="vps-sentinel-panel" \
PANEL_D1_NAME="vps-sentinel-panel-db" \
PANEL_SHARED_SECRET="<long-agent-secret>" \
PANEL_OPERATOR_TOKEN="<operator-token>" \
PANEL_ADMIN_TOKEN="<admin-token>" \
PANEL_ADMIN_PATH="/cryptocaigou" \
PANEL_PUBLIC_PAGES="overview,probe_sources,nodes" \
scripts/deploy-cloudflare-panel.sh
```

The script:

- creates or reuses the D1 database;
- applies `panel/cloudflare/schema.sql`;
- deploys `panel/cloudflare/worker.js` plus `panel/web` static assets;
- stores secrets with Wrangler secret bindings;
- verifies `GET /api/v1/settings` when it can infer the Worker URL or when `PANEL_VERIFY_URL` is set.

No Cloudflare API token, account ID, D1 ID, or panel secret is committed. Use `wrangler login` locally or set `CLOUDFLARE_API_TOKEN` in a trusted CI/server environment.

3. Configure agents:

```toml
[panel]
enabled = true
url = "https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/ingest"
node_name = "prod-sg-1"
secret = "<same-long-agent-secret>"
privacy_mode = "strict"
```

4. Verify:

```bash
sudo vs panel push
curl -fsS https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/settings
```

Cloudflare Worker mode returns `stream_unavailable` for `/api/v1/stream-ticket`; it is meant for simple hosted display. The self-hosted Rust panel supports WebSocket refresh.

## Self-Hosted Rust Panel

1. Build and install:

```bash
cargo build --release --bin vps-sentinel-panel
sudo install -m 0755 target/release/vps-sentinel-panel /usr/local/bin/vps-sentinel-panel
sudo mkdir -p /usr/local/share/vps-sentinel/panel
sudo cp -a panel/web /usr/local/share/vps-sentinel/panel/web
```

2. Create environment file:

```bash
sudo install -d -m 0750 /etc/vps-sentinel-panel
sudo tee /etc/vps-sentinel-panel/panel.env >/dev/null <<'EOF'
PANEL_BIND=127.0.0.1:8858
PANEL_DB_BACKEND=sqlite
PANEL_DATABASE_URL=sqlite:///var/lib/vps-sentinel-panel/panel.db
PANEL_WEB_DIR=/usr/local/share/vps-sentinel/panel/web
PANEL_SHARED_SECRET=replace-with-a-long-agent-secret
PANEL_OPERATOR_TOKEN=replace-with-an-operator-token
PANEL_ADMIN_TOKEN=replace-with-an-admin-token
PANEL_ADMIN_PATH=/cryptocaigou
PANEL_PUBLIC_PAGES=overview,probe_sources,nodes
EOF
sudo chmod 0600 /etc/vps-sentinel-panel/panel.env
```

3. Create systemd service:

```bash
sudo useradd --system --home /var/lib/vps-sentinel-panel --shell /usr/sbin/nologin vps-sentinel-panel || true
sudo install -d -m 0750 -o vps-sentinel-panel -g vps-sentinel-panel /var/lib/vps-sentinel-panel
sudo tee /etc/systemd/system/vps-sentinel-panel.service >/dev/null <<'EOF'
[Unit]
Description=vps-sentinel fleet panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vps-sentinel-panel
Group=vps-sentinel-panel
EnvironmentFile=/etc/vps-sentinel-panel/panel.env
ExecStart=/usr/local/bin/vps-sentinel-panel
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/vps-sentinel-panel

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now vps-sentinel-panel
```

4. Put the service behind HTTPS using Nginx, Caddy, or another reverse proxy, then set agent `[panel].url` to `https://your-panel-domain/api/v1/ingest`.

## PostgreSQL or MySQL

Set the backend and URL instead of SQLite:

```bash
PANEL_DB_BACKEND=postgres
PANEL_DATABASE_URL=postgres://vps_sentinel:password@127.0.0.1:5432/vps_sentinel
```

```bash
PANEL_DB_BACKEND=mysql
PANEL_DATABASE_URL=mysql://vps_sentinel:password@127.0.0.1:3306/vps_sentinel
```

The Rust panel initializes compatible schema on startup.

## Public Pages and Themes

`PANEL_PUBLIC_PAGES` controls pages visible without a browser token. The recommended default is:

```text
overview,probe_sources,nodes
```

Set it to an empty value if every page must require a token.

Themes are registered with `PANEL_THEMES`, for example:

```bash
PANEL_THEMES='default:Default,ocean:Ocean'
PANEL_THEME='default'
```

Theme files live under `panel/web/themes/<theme-id>/` and should only contain static CSS/JSON assets.
