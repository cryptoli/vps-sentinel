# 面板部署教程

多 VPS 面板是可选组件。Agent 仍然本地检测，只在 `[panel].enabled = true` 时向面板推送有签名、有大小上限的遥测数据。

## 部署模式

| 模式 | 适合场景 | 存储 | 实时能力 |
| --- | --- | --- | --- |
| Cloudflare Worker/D1 | 不想维护面板服务器，希望直接获得 HTTPS 和边缘托管。 | Cloudflare D1 | REST 增量加载。真正跨请求 WebSocket 广播需要 Durable Objects。 |
| 自建 Rust 面板 | 需要完整后端控制、私有部署、WebSocket 刷新。 | SQLite、PostgreSQL 或 MySQL | 带数据集范围的 WebSocket 刷新事件。 |

## Token 和管理路径

| 配置项 | 含义 | 是否必须 |
| --- | --- | --- |
| `PANEL_SHARED_SECRET` | HMAC 上报密钥，agent 的 `[panel].secret` 必须使用同一个值。 | 使用共享密钥时必须。 |
| `PANEL_NODE_SECRETS` | 可选，按非敏感 `panel.node_name` 配置单节点上报密钥的 JSON map。 | 可选。 |
| `PANEL_TOKEN` | 浏览器私有访问 token，用于私有页面和复核操作。 | 脚本未传入时自动生成。 |
| `PANEL_ADMIN_PATH` | 浏览器管理入口路径。它不是 API 安全边界，API 仍由 token 授权。 | 脚本未传入时自动生成。 |
| `PANEL_PUBLIC_PAGES` | 不输入 token 也能访问的页面，例如 `overview,probe_sources,nodes`。 | 可选。 |

新部署不应该使用固定 `/admin`。部署脚本会自动生成类似 `/4f9a12d0c8ab` 的随机管理路径，并和 token 一起保存。旧凭据文件中的 `PANEL_ADMIN_TOKEN`、`PANEL_OPERATOR_TOKEN` 或 `PANEL_VIEW_TOKEN` 会迁移为新的 `PANEL_TOKEN`。

## Cloudflare Worker/D1

1. 构建静态 UI：

```bash
cd panel/ui
npm install
npm run build:web
cd ../..
```

2. 使用 Wrangler 部署：

```bash
CLOUDFLARE_ACCOUNT_ID="<account-id>" \
scripts/deploy-cloudflare-panel.sh
```

如果在 CI 或非交互 VPS 上部署，需要在 shell 中设置 `CLOUDFLARE_API_TOKEN`。不要把 Cloudflare 凭据提交到仓库。

脚本会创建或复用 D1，执行兼容 schema 迁移，部署 Worker 和 `panel/web`，写入 Worker secrets，并验证 `GET /api/v1/settings`。

生成的面板凭据保存在：

```bash
cat ~/.config/vps-sentinel/cloudflare-panel.env
```

这个文件里包含：

- `PANEL_SHARED_SECRET`：写入每台 agent 的 `[panel].secret`；
- `PANEL_TOKEN`：管理入口和私有页面使用的访问 token；
- `PANEL_ADMIN_PATH`：浏览器管理入口路径，例如 `https://worker.example.workers.dev/<随机路径>`。

可以自定义凭据保存位置：

```bash
PANEL_CREDENTIAL_FILE=/secure/path/panel.env scripts/deploy-cloudflare-panel.sh
```

重新部署时，如果要保持旧 agent 继续可用，请复用保存的凭据文件，或显式传入同一个 `PANEL_SHARED_SECRET`。

3. 配置 agent：

```toml
[panel]
enabled = true
url = "https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/ingest"
node_name = "prod-sg-1"
secret = "<cloudflare-panel.env 里的 PANEL_SHARED_SECRET>"
privacy_mode = "strict"
```

4. 验证：

```bash
sudo vs panel push
curl -fsS https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/settings
```

Cloudflare Worker 模式目前对 `/api/v1/stream-ticket` 返回 `stream_unavailable`。普通 Worker 可以处理 API 和 D1 存储，但 agent 写入后可靠广播给所有浏览器需要 Durable Objects 或其他有状态扇出服务。当前 UI 仍然通过 REST 增量加载数据，不会整页刷新。

## 自建 Rust 面板

1. 构建并安装：

```bash
cargo build --release --bin vps-sentinel-panel
sudo install -m 0755 target/release/vps-sentinel-panel /usr/local/bin/vps-sentinel-panel
sudo mkdir -p /usr/local/share/vps-sentinel/panel
sudo cp -a panel/web /usr/local/share/vps-sentinel/panel/web
```

2. 生成安全环境文件：

```bash
sudo PANEL_ENV_FILE=/etc/vps-sentinel-panel/panel.env scripts/create-panel-env.sh
sudo cat /etc/vps-sentinel-panel/panel.env
```

如果环境文件已经存在，生成脚本会复用已有值；缺少的 `PANEL_SHARED_SECRET`、`PANEL_TOKEN`、`PANEL_ADMIN_PATH` 会自动随机生成。旧的 `PANEL_ADMIN_TOKEN`、`PANEL_OPERATOR_TOKEN` 或 `PANEL_VIEW_TOKEN` 会作为 `PANEL_TOKEN` 迁移复用。

随机值优先使用 `openssl`，其次使用 `/dev/urandom` + `od`，最后才回退到 Node.js。极简系统需要安装 `openssl`，或者在执行脚本前手动设置这四个 `PANEL_*` 值。

可选覆盖项：

```bash
sudo PANEL_DB_BACKEND=postgres \
PANEL_DATABASE_URL='postgres://vps_sentinel:password@127.0.0.1:5432/vps_sentinel' \
scripts/create-panel-env.sh
```

3. 创建 systemd 服务：

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

4. 使用 Nginx、Caddy 或其他反向代理提供 HTTPS，然后把 agent 的 `[panel].url` 设置为 `https://your-panel-domain/api/v1/ingest`。

## 存储后端

SQLite 默认配置：

```bash
PANEL_DB_BACKEND=sqlite
PANEL_DATABASE_URL=sqlite:///var/lib/vps-sentinel-panel/panel.db
```

PostgreSQL：

```bash
PANEL_DB_BACKEND=postgres
PANEL_DATABASE_URL=postgres://vps_sentinel:password@127.0.0.1:5432/vps_sentinel
```

MySQL：

```bash
PANEL_DB_BACKEND=mysql
PANEL_DATABASE_URL=mysql://vps_sentinel:password@127.0.0.1:3306/vps_sentinel
```

Rust 面板启动时会初始化兼容 schema。

## 主题

主题通过 `PANEL_THEMES` 注册，例如：

```bash
PANEL_THEMES='default:Default,ocean:Ocean'
PANEL_THEME='default'
```

主题文件放在 `panel/web/themes/<theme-id>/`，只应包含静态 CSS/JSON 资源。
