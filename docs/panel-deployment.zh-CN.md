# 面板部署教程

本文说明如何部署 vps-sentinel 多 VPS 面板，并把各个 agent 的安全遥测推送到面板中。面板是可选组件：agent 本地检测、通知和主动封禁不依赖面板；面板只负责集中展示多台服务器的安全状态。

## 选择部署方式

| 方式 | 适合场景 | 存储 | 特点 |
| --- | --- | --- | --- |
| Cloudflare Worker/D1 | 不想维护面板服务器，希望边缘托管、HTTPS 和静态资源一起部署 | Cloudflare D1 | 推荐给多数用户；被监控 VPS 不需要开放入站端口 |
| VPS 自建 Rust 面板 | 希望数据完全落在自己的服务器，或需要 WebSocket 实时刷新 | SQLite、PostgreSQL、MySQL | 需要自己维护进程、反代和 HTTPS |

两种方式的 agent 配置基本一致：`[panel].url` 指向面板的 `/api/v1/ingest`，`[panel].secret` 与面板的 `PANEL_SHARED_SECRET` 或节点专用 secret 保持一致。

## 密钥和角色

面板有两类密钥，不要混用：

| 名称 | 用途 | 谁使用 |
| --- | --- | --- |
| `PANEL_SHARED_SECRET` | agent 上报签名密钥 | 面板和每台 agent |
| `PANEL_NODE_SECRETS` | 按节点名配置不同上报签名密钥 | 面板和对应 agent |
| `PANEL_OPERATOR_TOKEN` | 浏览器运维层访问 token | 运维人员 |
| `PANEL_ADMIN_TOKEN` | 浏览器管理层访问 token | 管理员 |

生成密钥示例：

```bash
openssl rand -hex 32  # PANEL_SHARED_SECRET
openssl rand -hex 24  # PANEL_OPERATOR_TOKEN
openssl rand -hex 24  # PANEL_ADMIN_TOKEN
```

生产环境建议把这些值保存到密码管理器或服务器本地的 `0600` 环境文件里，不要写进 Git 仓库、README、shell history 或截图。

## 方式一：部署到 Cloudflare Worker/D1

Cloudflare 方式使用：

- Worker：承载 API 和静态面板 UI；
- D1：保存节点、告警、事件、主动封禁和外部探查来源记录；
- Worker secrets：保存上报密钥和浏览器访问 token。

### 1. 准备环境

在本地电脑、CI 机器或任意能运行 Node.js 的 Linux 服务器上执行：

```bash
git clone https://github.com/cryptoli/vps-sentinel.git
cd vps-sentinel
node --version
npx wrangler --version
```

首次交互式部署可以登录 Wrangler：

```bash
npx wrangler login
npx wrangler whoami
```

非交互式服务器或 CI 部署使用 Cloudflare API Token：

```bash
export CLOUDFLARE_API_TOKEN='replace-with-cloudflare-api-token'
export CLOUDFLARE_ACCOUNT_ID='replace-with-cloudflare-account-id'
npx wrangler whoami
```

API Token 至少需要能管理 Workers、D1 和 Worker secrets。不要把 token 写入脚本或仓库。

### 2. 配置部署变量

建议创建一个不提交到 Git 的本地环境文件：

```bash
umask 077
cat > .panel.cloudflare.env <<'EOF'
CLOUDFLARE_ACCOUNT_ID=replace-with-cloudflare-account-id
PANEL_WORKER_NAME=vps-sentinel-panel
PANEL_D1_NAME=vps-sentinel-panel-db
PANEL_SHARED_SECRET=replace-with-a-long-random-agent-secret
PANEL_OPERATOR_TOKEN=replace-with-a-browser-operator-token
PANEL_ADMIN_TOKEN=replace-with-a-browser-admin-token
PANEL_PUBLIC_ENABLED=false
PANEL_THEME=default
EOF
```

加载环境变量：

```bash
set -a
. ./.panel.cloudflare.env
set +a
```

重要：后续升级时继续使用同一个 `PANEL_SHARED_SECRET`。如果换了这个值，已经部署的 agent 会因为签名不匹配而无法上报。

### 3. 一键部署

```bash
scripts/deploy-cloudflare-panel.sh
```

脚本会自动完成：

1. 复用同名 D1，找不到时创建 D1；
2. 执行 `panel/cloudflare/schema.sql`；
3. 生成临时 Wrangler 配置；
4. 部署 `panel/cloudflare/worker.js`；
5. 把 `panel/web` 作为 Worker static assets 一起部署；
6. 用 Wrangler secrets 写入 `PANEL_SHARED_SECRET`、`PANEL_NODE_SECRETS`、`PANEL_OPERATOR_TOKEN`、`PANEL_VIEW_TOKEN` 和 `PANEL_ADMIN_TOKEN`；
7. 尝试访问 `/api/v1/settings` 验证部署。

部署前只验证配置、不改 Cloudflare 资源：

```bash
scripts/deploy-cloudflare-panel.sh --dry-run
```

如果脚本无法从 Wrangler 输出中推断 Worker URL，可以显式指定：

```bash
PANEL_VERIFY_URL='https://vps-sentinel-panel.example.workers.dev' \
scripts/deploy-cloudflare-panel.sh
```

### 4. 找到面板访问地址

默认地址格式：

```text
https://<PANEL_WORKER_NAME>.<你的-workers-subdomain>.workers.dev/
```

如果使用自定义域名，可以在 Cloudflare Dashboard 中给该 Worker 绑定 route 或 custom domain。绑定自定义域名后，agent 的上报 URL 也可以改成自定义域名的 `/api/v1/ingest`。

### 5. 验证 Cloudflare 面板

先设置面板 URL：

```bash
export PANEL_URL='https://<PANEL_WORKER_NAME>.<你的-workers-subdomain>.workers.dev'
```

无 token 的设置接口应该能返回面板配置：

```bash
curl -fsS "$PANEL_URL/api/v1/settings"
```

用 admin token 验证摘要接口：

```bash
curl -fsS \
  -H "Authorization: Bearer $PANEL_ADMIN_TOKEN" \
  "$PANEL_URL/api/v1/summary"
```

浏览器打开：

```text
https://<PANEL_WORKER_NAME>.<你的-workers-subdomain>.workers.dev/
```

输入 `PANEL_OPERATOR_TOKEN` 或 `PANEL_ADMIN_TOKEN` 后保存。`PANEL_ADMIN_TOKEN` 可查看管理层数据，`PANEL_OPERATOR_TOKEN` 只查看运维层数据。

### 6. 配置 agent 上报到 Cloudflare

在每台被监控 VPS 的 `/etc/vps-sentinel/config.toml` 中配置：

```toml
[panel]
enabled = true
url = "https://<PANEL_WORKER_NAME>.<你的-workers-subdomain>.workers.dev/api/v1/ingest"
node_name = "prod-web-1"
secret = "replace-with-the-same-PANEL_SHARED_SECRET"
min_severity = "Medium"
batch_size = 100
push_interval_seconds = 60
request_timeout_seconds = 60
outbox_max_items = 128
max_payload_bytes = 524288
privacy_mode = "strict"
```

节点名必须是非敏感名称，不要用公网 IP、内网 IP 或完整主机名。建议使用 `prod-web-1`、`sg-edge-1`、`db-primary` 这类名称。

校验并重载 agent：

```bash
sudo vs --config /etc/vps-sentinel/config.toml config validate
sudo vs --config /etc/vps-sentinel/config.toml reload
```

手动推送一次当前快照：

```bash
sudo vs --config /etc/vps-sentinel/config.toml panel push
sudo vs --config /etc/vps-sentinel/config.toml panel outbox
```

如果面板临时不可用，agent 会把有界 outbox 保存在本地 SQLite 中。恢复后可执行：

```bash
sudo vs --config /etc/vps-sentinel/config.toml panel flush
```

### 7. Cloudflare 面板升级

升级时保留同一个 `.panel.cloudflare.env`：

```bash
git pull
set -a
. ./.panel.cloudflare.env
set +a
scripts/deploy-cloudflare-panel.sh
```

脚本会复用同名 D1，并重新执行兼容 schema。不要在升级时重新生成 `PANEL_SHARED_SECRET`，除非你准备同步更新所有 agent。

## 方式二：自建到 VPS

自建方式使用 Rust 二进制 `vps-sentinel-panel`。它可以直接服务静态 UI 和 API，并支持 WebSocket 变更事件。生产环境建议让面板只监听 `127.0.0.1`，再由 Nginx、Caddy 或其他反向代理提供 HTTPS。

### 1. 准备服务器

建议系统：

- Debian 12 / Ubuntu 22.04+ / RHEL 系 / Fedora；
- systemd；
- 至少 256 MiB 内存；
- 预留磁盘空间给面板数据库；
- 一个域名，例如 `panel.example.com`。

安装基础依赖示例：

```bash
sudo apt-get update
sudo apt-get install -y curl git build-essential pkg-config openssl ca-certificates
```

安装 Rust：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup default stable
```

### 2. 构建和安装面板

```bash
git clone https://github.com/cryptoli/vps-sentinel.git
cd vps-sentinel
cargo build --release -p sentinel-panel

sudo install -m 0755 target/release/vps-sentinel-panel /usr/local/bin/vps-sentinel-panel
sudo install -d /usr/local/share/vps-sentinel
sudo rm -rf /usr/local/share/vps-sentinel/panel
sudo install -d /usr/local/share/vps-sentinel/panel
sudo cp -a panel/web /usr/local/share/vps-sentinel/panel/web
```

如果你已经通过项目安装脚本安装过程序，`vps-sentinel-panel` 和 `panel/web` 可能已经被复制到系统路径；仍建议用上面的命令确认面板二进制和静态资源是当前版本。

### 3. 创建运行用户和目录

```bash
sudo useradd --system --home /var/lib/vps-sentinel-panel --shell /usr/sbin/nologin vps-sentinel-panel || true
sudo install -d -m 0750 -o vps-sentinel-panel -g vps-sentinel-panel /var/lib/vps-sentinel-panel
sudo install -d -m 0750 /etc/vps-sentinel
```

### 4. 选择数据库

#### SQLite

适合个人或小规模面板，部署最简单：

```bash
sudo tee /etc/vps-sentinel/panel.env >/dev/null <<'EOF'
PANEL_BIND=127.0.0.1:8080
PANEL_DB_BACKEND=sqlite
PANEL_DATABASE_URL=sqlite:///var/lib/vps-sentinel-panel/panel.db
PANEL_WEB_DIR=/usr/local/share/vps-sentinel/panel/web
PANEL_SHARED_SECRET=replace-with-a-long-random-agent-secret
PANEL_OPERATOR_TOKEN=replace-with-a-browser-operator-token
PANEL_ADMIN_TOKEN=replace-with-a-browser-admin-token
PANEL_PUBLIC_ENABLED=false
PANEL_THEME=default
PANEL_MAX_BODY_BYTES=1048576
EOF
sudo chmod 0600 /etc/vps-sentinel/panel.env
```

#### PostgreSQL

适合更长期、更规范的自建部署：

```bash
sudo -u postgres createuser vps_sentinel
sudo -u postgres createdb -O vps_sentinel vps_sentinel
sudo -u postgres psql -c "ALTER USER vps_sentinel WITH PASSWORD 'replace-with-strong-db-password';"
```

`/etc/vps-sentinel/panel.env`：

```bash
PANEL_BIND=127.0.0.1:8080
PANEL_DB_BACKEND=postgres
PANEL_DATABASE_URL=postgres://vps_sentinel:replace-with-strong-db-password@127.0.0.1:5432/vps_sentinel
PANEL_WEB_DIR=/usr/local/share/vps-sentinel/panel/web
PANEL_SHARED_SECRET=replace-with-a-long-random-agent-secret
PANEL_OPERATOR_TOKEN=replace-with-a-browser-operator-token
PANEL_ADMIN_TOKEN=replace-with-a-browser-admin-token
PANEL_PUBLIC_ENABLED=false
PANEL_THEME=default
PANEL_MAX_BODY_BYTES=1048576
```

#### MySQL / MariaDB

```sql
CREATE DATABASE vps_sentinel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vps_sentinel'@'127.0.0.1' IDENTIFIED BY 'replace-with-strong-db-password';
GRANT ALL PRIVILEGES ON vps_sentinel.* TO 'vps_sentinel'@'127.0.0.1';
FLUSH PRIVILEGES;
```

`/etc/vps-sentinel/panel.env`：

```bash
PANEL_BIND=127.0.0.1:8080
PANEL_DB_BACKEND=mysql
PANEL_DATABASE_URL=mysql://vps_sentinel:replace-with-strong-db-password@127.0.0.1:3306/vps_sentinel
PANEL_WEB_DIR=/usr/local/share/vps-sentinel/panel/web
PANEL_SHARED_SECRET=replace-with-a-long-random-agent-secret
PANEL_OPERATOR_TOKEN=replace-with-a-browser-operator-token
PANEL_ADMIN_TOKEN=replace-with-a-browser-admin-token
PANEL_PUBLIC_ENABLED=false
PANEL_THEME=default
PANEL_MAX_BODY_BYTES=1048576
```

### 5. 创建 systemd 服务

```bash
sudo tee /etc/systemd/system/vps-sentinel-panel.service >/dev/null <<'EOF'
[Unit]
Description=vps-sentinel fleet panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vps-sentinel-panel
Group=vps-sentinel-panel
EnvironmentFile=/etc/vps-sentinel/panel.env
ExecStart=/usr/local/bin/vps-sentinel-panel
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/vps-sentinel-panel

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vps-sentinel-panel
sudo systemctl status vps-sentinel-panel --no-pager
```

如果使用 PostgreSQL/MySQL 且面板不需要写本地 SQLite 文件，仍然可以保留 `/var/lib/vps-sentinel-panel` 作为运行目录和后续缓存目录。

### 6. 配置 HTTPS 反向代理

Nginx 示例：

```nginx
server {
    listen 80;
    server_name panel.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name panel.example.com;

    ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Caddy 示例：

```caddyfile
panel.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

不要直接把面板以明文 HTTP 暴露在公网。agent 上报内容经过 HMAC 签名，但浏览器 token 和安全上下文仍应走 HTTPS。

### 7. 验证自建面板

本机 API：

```bash
curl -fsS http://127.0.0.1:8080/api/v1/settings
```

带 admin token 的摘要：

```bash
curl -fsS \
  -H "Authorization: Bearer <PANEL_ADMIN_TOKEN>" \
  http://127.0.0.1:8080/api/v1/summary
```

日志：

```bash
journalctl -u vps-sentinel-panel -n 100 --no-pager
```

浏览器访问：

```text
https://panel.example.com/
```

### 8. 配置 agent 上报到自建面板

在每台被监控 VPS 上配置：

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_name = "prod-web-1"
secret = "replace-with-the-same-PANEL_SHARED_SECRET"
min_severity = "Medium"
batch_size = 100
push_interval_seconds = 60
request_timeout_seconds = 60
outbox_max_items = 128
max_payload_bytes = 524288
privacy_mode = "strict"
```

重载并测试：

```bash
sudo vs --config /etc/vps-sentinel/config.toml config validate
sudo vs --config /etc/vps-sentinel/config.toml reload
sudo vs --config /etc/vps-sentinel/config.toml panel push
sudo vs --config /etc/vps-sentinel/config.toml panel outbox
```

### 9. 自建面板升级

```bash
cd vps-sentinel
git pull
cargo build --release -p sentinel-panel

sudo systemctl stop vps-sentinel-panel
sudo install -m 0755 target/release/vps-sentinel-panel /usr/local/bin/vps-sentinel-panel
sudo rm -rf /usr/local/share/vps-sentinel/panel
sudo install -d /usr/local/share/vps-sentinel/panel
sudo cp -a panel/web /usr/local/share/vps-sentinel/panel/web
sudo systemctl start vps-sentinel-panel
sudo systemctl status vps-sentinel-panel --no-pager
```

数据库 schema 会在面板启动时按当前后端自动初始化或补齐。升级时不要覆盖 `/etc/vps-sentinel/panel.env`。

## 常见问题

### 浏览器能打开页面，但没有数据

检查：

```bash
sudo vs --config /etc/vps-sentinel/config.toml panel push
sudo vs --config /etc/vps-sentinel/config.toml panel outbox
```

如果 outbox 有积压，说明 agent 无法成功上报。继续检查面板 URL、HTTPS、`PANEL_SHARED_SECRET` 是否一致。

### 返回 `signature_mismatch`

agent 的 `[panel].secret` 与面板的 `PANEL_SHARED_SECRET` 不一致，或使用了 `PANEL_NODE_SECRETS` 但 key 没有匹配 `panel.node_name`。

### 返回 `nonce_node_mismatch`

agent 发送的节点名与签名 nonce 前缀不一致。升级到新版本后，优先使用 `panel.node_name`，不要继续依赖旧的 `panel.node_id`。

### 返回 `missing_or_invalid_panel_token`

浏览器 API 需要 token。输入 `PANEL_OPERATOR_TOKEN` 或 `PANEL_ADMIN_TOKEN`。如果希望无需 token 查看公开聚合数据，可以显式设置：

```bash
PANEL_PUBLIC_ENABLED=true
```

公开层只返回聚合趋势、风险数量、等级分布、节点名称和在线状态，不返回原始证据、命令行、文件路径、密钥、日志或敏感配置。

### Cloudflare Worker 没有 WebSocket 自动刷新

Cloudflare Worker 接收端的 `/api/v1/stream-ticket` 会返回 `stream_unavailable`。自建 Rust 面板支持 WebSocket 变更事件；Cloudflare 版本更适合低维护的集中展示。

### Cloudflare 脚本重复运行会不会覆盖数据

不会删除 D1 数据。脚本会复用同名 D1，并执行兼容 schema。它会重新设置 Worker secrets；如果你传入新的 `PANEL_SHARED_SECRET`，agent 必须同步更新。因此建议把 `.panel.cloudflare.env` 保留在本地安全位置，升级时复用。

### 自建面板是否能直接暴露公网端口

技术上可以把 `PANEL_BIND=0.0.0.0:8080`，但不推荐。生产环境应绑定 `127.0.0.1:8080`，通过 Nginx/Caddy 提供 HTTPS。

### 如何确认数据库正常

SQLite：

```bash
sqlite3 /var/lib/vps-sentinel-panel/panel.db '.tables'
sqlite3 /var/lib/vps-sentinel-panel/panel.db 'select count(*) from nodes;'
```

PostgreSQL：

```bash
psql "$PANEL_DATABASE_URL" -c '\dt'
psql "$PANEL_DATABASE_URL" -c 'select count(*) from nodes;'
```

MySQL：

```bash
mysql -h 127.0.0.1 -u vps_sentinel -p vps_sentinel -e 'show tables;'
mysql -h 127.0.0.1 -u vps_sentinel -p vps_sentinel -e 'select count(*) from nodes;'
```

## 上线检查清单

- 面板 URL 使用 HTTPS；
- `PANEL_SHARED_SECRET` 足够长且没有提交到 Git；
- `PANEL_OPERATOR_TOKEN` 和 `PANEL_ADMIN_TOKEN` 已保存；
- 每台 agent 的 `panel.node_name` 不含公网 IP、内网 IP 或敏感主机名；
- `vs panel push` 返回成功；
- 面板 `summary` 能看到节点数量；
- 自建面板的 systemd 服务已启用；
- 自建面板反向代理支持 WebSocket upgrade；
- Cloudflare 部署保留了 `.panel.cloudflare.env`，后续升级不会换 secret。
