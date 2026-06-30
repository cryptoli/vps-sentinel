# 面板部署教程

多服务器面板是可选组件。Agent 默认继续本地监控，只有 `[panel].enabled = true` 时才会推送带签名、有大小限制的遥测数据。

## 部署模式

| 模式 | 适合场景 | 存储 | 刷新能力 |
| --- | --- | --- | --- |
| Cloudflare Worker/D1 | 不想维护面板服务器，希望直接获得 HTTPS 和边缘托管。 | Cloudflare D1 | REST 范围刷新。普通 Worker 没有可靠的跨请求 WebSocket 广播，除非增加 Durable Objects 等有状态层。 |
| 自建 Rust 面板 | 需要完整后端控制、私有部署和自选数据库。 | SQLite、PostgreSQL 或 MySQL | WebSocket 范围刷新，同时保留同一套 REST API。 |

自建面板和 Cloudflare 面板应在鉴权、公开/私有页面权限、隐私脱敏、节点展示、黑名单展示、复核接口和主题加载上保持一致。当前有意保留的差异只有刷新传输方式：自建 Rust 面板支持 WebSocket 事件，Cloudflare Worker 部署在未引入有状态广播层时使用 REST fallback。

## Token 和管理路径

| 配置 | 含义 | 是否必须 |
| --- | --- | --- |
| `PANEL_SHARED_SECRET` | HMAC 上报密钥，agent 的 `[panel].secret` 必须使用同一个值。 | 使用共享密钥时必须 |
| `PANEL_NODE_SECRETS` | 可选，按非敏感 `panel.node_name` 配置单节点上报密钥的 JSON map。 | 可选 |
| `PANEL_TOKEN` | 唯一浏览器私有访问 token，用于详情、复核、审计日志和管理入口。 | 未传入时脚本自动生成 |
| `PANEL_ADMIN_PATH` | 浏览器管理入口路径。它只是入口保护，不是 API 安全边界，私有 API 仍必须带 `PANEL_TOKEN`。 | 未传入时脚本自动生成 |
| `PANEL_PUBLIC_PAGES` | 不输入 token 也能访问的页面，例如 `overview,probe_sources,nodes`。 | 可选 |

新部署不要使用固定 `/admin`。脚本会自动生成类似 `/4f9a12d0c8ab` 的随机路径，并与 token 一起保存。旧凭据文件里的 `PANEL_ADMIN_TOKEN`、`PANEL_OPERATOR_TOKEN`、`PANEL_VIEW_TOKEN` 会迁移为 `PANEL_TOKEN`。

## Cloudflare Worker/D1 部署

### 1. 构建前端

`panel/web` 是 Cloudflare 和自建面板共用的已提交静态部署产物。前端源码以 `panel/ui` 为准；修改 UI 源码后，应在 `panel/ui` 下运行 `npm run build:web` 重新生成 `panel/web`。不要手工修改 `panel/web/_next` 下的打包文件，这些文件只能由前端构建产生。

```bash
cd panel/ui
npm install
npm run build:web
cd ../..
```

### 2. 使用脚本部署

```bash
CLOUDFLARE_ACCOUNT_ID="<account-id>" \
CLOUDFLARE_API_TOKEN="<api-token>" \
scripts/deploy-cloudflare-panel.sh
```

脚本会：

- 创建或复用 D1 数据库；
- 执行兼容 schema 迁移；
- 打包 `panel/cloudflare/worker.js` 和 `panel/web`；
- 将 `PANEL_SHARED_SECRET`、`PANEL_TOKEN` 写入 Worker secrets；
- 设置 `PANEL_ADMIN_PATH`、`PANEL_PUBLIC_PAGES`、主题等非 secret 变量；
- 部署后验证 `GET /api/v1/settings`。

Cloudflare 部署会使用 Cloudflare 请求地域以及 agent 上传的安全节点地域字段来显示国家图标。agent 不会上报自己的公网 IP，只会在启用节点地域探测时上传已脱敏的国家、地区和城市。

如果确实要固定管理路径，可以显式指定：

```bash
CLOUDFLARE_ACCOUNT_ID="<account-id>" \
CLOUDFLARE_API_TOKEN="<api-token>" \
PANEL_ADMIN_PATH="/cryptocaigou" \
scripts/deploy-cloudflare-panel.sh
```

默认推荐不传 `PANEL_ADMIN_PATH`，让脚本自动生成随机路径。

### 3. 查看自动生成的凭据

```bash
cat ~/.config/vps-sentinel/cloudflare-panel.env
```

文件中包含：

- `PANEL_SHARED_SECRET`：写入每台 agent 的 `[panel].secret`；
- `PANEL_TOKEN`：浏览器管理入口输入的 token；
- `PANEL_ADMIN_PATH`：浏览器访问路径，例如 `https://worker.example.workers.dev/<随机路径>`；
- `PANEL_PUBLIC_PAGES`：无需 token 可访问的页面。

如果要自定义凭据文件位置：

```bash
PANEL_CREDENTIAL_FILE=/secure/path/cloudflare-panel.env scripts/deploy-cloudflare-panel.sh
```

重新部署时，如果希望旧 agent 继续可用，请复用保存的凭据文件，或者显式传入同一个 `PANEL_SHARED_SECRET`。

### 4. 配置 agent

```toml
[panel]
enabled = true
url = "https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/ingest"
node_name = "prod-sg-1"
secret = "<cloudflare-panel.env 里的 PANEL_SHARED_SECRET>"
privacy_mode = "strict"
```

重载并测试：

```bash
sudo vs config validate
sudo vs panel push
sudo vs reload
```

### 5. 验证 Cloudflare 面板

```bash
curl -fsS https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/settings
curl -fsS https://vps-sentinel-panel.<your-workers-subdomain>.workers.dev/api/v1/probe-sources
```

公开黑名单会展示已确认封禁的来源 IP 和归属字段，但不会暴露节点名称、主机名、文件路径、命令行、原始证据或敏感配置。

## 自建 Rust 面板

### 1. 构建并安装

```bash
cd panel/ui
npm install
npm run build:web
cd ../..
cargo build --release --bin vps-sentinel-panel
sudo install -m 0755 target/release/vps-sentinel-panel /usr/local/bin/vps-sentinel-panel
sudo mkdir -p /usr/local/share/vps-sentinel/panel
sudo rm -rf /usr/local/share/vps-sentinel/panel/web
sudo cp -a panel/web /usr/local/share/vps-sentinel/panel/web
```

### 2. 生成环境文件

```bash
sudo PANEL_ENV_FILE=/etc/vps-sentinel-panel/panel.env scripts/create-panel-env.sh
sudo cat /etc/vps-sentinel-panel/panel.env
```

如果环境文件已经存在，生成脚本会复用已有值；缺少的 `PANEL_SHARED_SECRET`、`PANEL_TOKEN`、`PANEL_ADMIN_PATH` 会随机生成。

可选本地 GeoIP 数据库：

```bash
sudo PANEL_ENV_FILE=/etc/vps-sentinel-panel/panel.env \
PANEL_GEOIP_CITY_DB="/opt/geoip/GeoLite2-City.mmdb" \
PANEL_GEOIP_ASN_DB="/opt/geoip/GeoLite2-ASN.mmdb" \
scripts/create-panel-env.sh
```

`PANEL_GEOIP_CITY_DB` 和 `PANEL_GEOIP_ASN_DB` 支持 MaxMind 兼容的 MMDB 文件，包括 MaxMind GeoLite2/GeoIP2 和 DB-IP Lite/Commercial 数据库。它们是可选项，只用于自建面板看到的真实远端请求 IP；如果 agent 上报到 `localhost` 或经过内网代理，面板会使用 agent 自己上传的脱敏国家/地区/城市，而不是把 `127.0.0.1` 当成节点地域。

数据库示例：

```bash
sudo PANEL_ENV_FILE=/etc/vps-sentinel-panel/panel.env \
PANEL_DB_BACKEND=sqlite \
PANEL_DATABASE_URL='sqlite:///var/lib/vps-sentinel-panel/panel.db' \
scripts/create-panel-env.sh
```

```bash
sudo PANEL_ENV_FILE=/etc/vps-sentinel-panel/panel.env \
PANEL_DB_BACKEND=postgres \
PANEL_DATABASE_URL='postgres://vps_sentinel:password@127.0.0.1:5432/vps_sentinel' \
scripts/create-panel-env.sh
```

```bash
sudo PANEL_ENV_FILE=/etc/vps-sentinel-panel/panel.env \
PANEL_DB_BACKEND=mysql \
PANEL_DATABASE_URL='mysql://vps_sentinel:password@127.0.0.1:3306/vps_sentinel' \
scripts/create-panel-env.sh
```

### 3. 创建 systemd 服务

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
WorkingDirectory=/var/lib/vps-sentinel-panel
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

### 4. 放到 HTTPS 后面

可以使用 Nginx、Caddy 或其他反向代理。Agent 上报地址应为：

```text
https://your-panel-domain/api/v1/ingest
```

浏览器访问地址为：

```text
https://your-panel-domain/<PANEL_ADMIN_PATH>
```

## 主题扩展

主题通过 `PANEL_THEMES` 注册：

```bash
PANEL_THEMES='default:Default,ocean:Ocean'
PANEL_THEME='default'
```

主题文件放在 `panel/web/themes/<theme-id>/`，只应包含静态 CSS/JSON 资源。详见 [panel-themes.zh-CN.md](panel-themes.zh-CN.md)。

## 安全注意事项

- `PANEL_SHARED_SECRET`、`PANEL_TOKEN`、Cloudflare API token、数据库密码、SMTP 凭据和 webhook secret 保存在本地配置、Worker secrets 或 systemd 环境文件中。
- `node_name` 只能使用非敏感展示名称。
- 公开页面不应暴露原始证据、主机名、文件路径、命令行、后端细节、私网 IP，公开黑名单也不应暴露节点名称。
- 公开 `GET /api/v1/settings` 不应泄露 `PANEL_ADMIN_PATH`，只返回当前浏览器路径是否为管理入口。
- 即使管理路径被隐藏，私有 API 仍必须使用 `Authorization: Bearer <PANEL_TOKEN>`。
