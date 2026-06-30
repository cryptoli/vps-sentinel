# Agent 部署教程

本文说明如何在 Linux VPS 上安装和运维 `vps-sentinel` agent。多服务器面板部署见 [panel-deployment.zh-CN.md](panel-deployment.zh-CN.md)。

## 环境要求

- 需要 root 或 sudo 权限。
- 推荐 systemd。非 systemd 主机也可以手动运行 `vps-sentinel scan`。
- 一键安装至少需要 `curl` 和 CA 证书。
- 只有安装器无法使用兼容 release 二进制、需要回退源码编译时才需要 Rust。
- 可选工具会增强可见性：`journalctl`、`ss`、`nft`、`iptables`、`dpkg`/`rpm`/`apk`/`pacman`、`nvidia-smi`、`rocm-smi`、`auditd`、`bpftrace`。

## 推荐完整一键安装

真实节点建议第一次安装就把通知、面板上报、主动响应、存储限制和节点地域探测配置好：

```bash
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<your-bot-token>" \
  TELEGRAM_CHAT_ID="<your-chat-id>" \
  TELEGRAM_MIN_SEVERITY="Medium" \
  PANEL_URL="https://your-panel.example.com/api/v1/ingest" \
  PANEL_SHARED_SECRET="<same-secret-as-panel>" \
  PANEL_NODE_NAME="prod-web-1" \
  PANEL_MIN_SEVERITY="Low" \
  PANEL_PRIVACY_MODE="strict" \
  PANEL_UPLOAD_HOSTNAME="yes" \
  PANEL_NODE_LOCATION_ENABLED="yes" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="yes" \
  STORAGE_MAX_DATABASE_SIZE_MB="256" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

这条命令会启用主要本地防护能力、Telegram 告警，以及向面板推送隐私脱敏后的遥测。如果不填写 `TELEGRAM_*`，就不会发送 Telegram；如果同时不填写 `PANEL_URL` 和 `PANEL_SHARED_SECRET`，就不会配置面板上报。

## 本地试用安装

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sudo sh
```

这条最短命令只适合快速本地试用。它会安装守护进程和本地检测，但不会配置 Telegram、邮件/webhook 通知或面板上报。

安装脚本会：

- 安装 `vps-sentinel` 和简写命令 `vs`；
- 在 Debian/Ubuntu、RHEL 系、Fedora、Alpine、Arch 系主机上安装兼容依赖；
- 优先使用能在当前机器执行的 release 二进制，不兼容时自动回退到源码编译；
- 仅在 `/etc/vps-sentinel/config.toml` 不存在时创建默认配置；
- 校验配置、迁移兼容旧字段、同步新增默认字段、创建初始基线、执行一次不通知的预热扫描；
- systemd 可用时安装并启动服务；
- 重装时保留已有配置、SQLite 状态、基线、通知凭据、面板密钥和封禁历史。

## 只启用 Telegram 的安装方式

推荐使用下面这种形式，便于查看脚本内容和错误输出：

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o /tmp/vps-sentinel-install.sh
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<your-bot-token>" \
  TELEGRAM_CHAT_ID="<your-chat-id>" \
  TELEGRAM_MIN_SEVERITY="Medium" \
  sh /tmp/vps-sentinel-install.sh
```

也可以写成一行：

```bash
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<your-bot-token>" \
  TELEGRAM_CHAT_ID="<your-chat-id>" \
  TELEGRAM_MIN_SEVERITY="Medium" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

参数含义：

| 变量 | 含义 | 是否必须 |
| --- | --- | --- |
| `VPS_NAME` | 告警、报告和面板节点中显示的名称。不要填公网 IP、敏感主机名或云厂商实例 ID。 | 建议填写 |
| `TELEGRAM_BOT_TOKEN` | BotFather 创建的 Telegram bot token。 | 启用 Telegram 时必须 |
| `TELEGRAM_CHAT_ID` | Telegram 目标 chat ID。 | 启用 Telegram 时必须 |
| `TELEGRAM_MIN_SEVERITY` | 最低通知等级：`Low`、`Medium`、`High`、`Critical`。 | 可选，默认 `Medium` |

如果只填了 `TELEGRAM_BOT_TOKEN` 或只填了 `TELEGRAM_CHAT_ID`，安装器会直接停止，避免写入不可用的通知配置。

面板相关参数：

| 变量 | 含义 | 是否必须 |
| --- | --- | --- |
| `PANEL_URL` | 面板上报地址，通常是 `https://<panel-domain>/api/v1/ingest`。 | 启用面板上报时必须 |
| `PANEL_SHARED_SECRET` | 面板部署脚本生成的 HMAC 共享密钥。 | 启用面板上报时必须 |
| `PANEL_NODE_NAME` | 面板展示的节点名称；不填时使用 `VPS_NAME`。不要使用公网 IP。 | 建议填写 |
| `PANEL_MIN_SEVERITY` | 上报到面板的最低风险等级，默认 `Low`。 | 可选 |
| `PANEL_PRIVACY_MODE` | 正常使用保持 `strict`。它会在上报前移除服务器公网 IP、节点 ID、路径、命令行和原始证据。 | 可选 |
| `PANEL_UPLOAD_HOSTNAME` | `yes` 表示允许上传不含 IP、不像云实例 ID、且通过脱敏校验的主机名。 | 可选 |
| `PANEL_NODE_LOCATION_ENABLED` | `yes` 表示 agent 自动探测国家/地区/城市，并只上传这些非敏感展示字段，不上传公网 IP。 | 可选 |
| `PANEL_NODE_LOCATION_URL` | 可选 HTTPS JSON 或 Cloudflare trace 地域接口，默认 `https://ipapi.co/json/`。 | 可选 |

## 常用安装参数

```bash
sudo BRANCH="main" \
  INSTALL_METHOD="auto" \
  INSTALL_DEPS="yes" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD="4" \
  ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD="25" \
  ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="yes" \
  STORAGE_MAX_DATABASE_SIZE_MB="256" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

常用变量说明：

| 变量 | 含义 |
| --- | --- |
| `BRANCH` | 源码检出分支，默认 `main`。 |
| `REPO_URL` | Git 仓库地址，默认官方 GitHub 仓库。 |
| `INSTALL_METHOD` | `auto`、`release` 或 `source`。`auto` 会先验证 release 二进制，不兼容再源码编译。 |
| `INSTALL_DEPS` | `yes` 或 `no`，是否通过系统包管理器安装依赖。 |
| `INSTALL_SYSTEMD` | `auto`、`yes` 或 `no`，是否安装 systemd 服务。 |
| `CLEAN_SOURCE_TARGET` | `yes` 或 `no`，默认 `yes`。源码安装/升级成功后删除 `$WORK_DIR/target`，避免 Rust 构建产物长期占用数 GB 磁盘。 |
| `ENABLE_SERVICE` | `yes` 或 `no`，安装后是否启用并启动服务。 |
| `RUN_DOCTOR` | `yes` 或 `no`，安装后是否执行 `vs doctor`。 |
| `RUN_FIRST_SCAN` | `yes` 或 `no`，是否执行一次不通知的预热扫描。 |
| `RUN_NOTIFY_TEST` | `auto`、`yes` 或 `no`，是否发送 Telegram 测试消息。 |
| `MIGRATE_CONFIG` | `yes` 或 `no`，是否执行兼容配置迁移。 |
| `SYNC_CONFIG_DEFAULTS` | `yes` 或 `no`，是否补齐新增默认配置项。 |
| `CONFIG_DIR` | 配置目录，默认 `/etc/vps-sentinel`。 |
| `DATA_DIR` | 本地状态目录，默认 `/var/lib/vps-sentinel`。 |
| `LOG_DIR` | 日志目录，默认 `/var/log/vps-sentinel`。 |

主动封禁相关变量会写入 `/etc/vps-sentinel/config.toml` 的 `[active_response]`。生产环境启用封禁前，请先把跳板机、监控系统、VPN 出口、办公固定 IP 加入 allowlist。

## 升级

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sudo sh
```

升级脚本会保留已有配置和状态。它会先验证目标二进制能否运行，再替换当前版本；如果二进制不兼容，会使用源码编译，并确保 Rust 有默认 stable toolchain。源码升级成功后默认清理 `$WORK_DIR/target`；只有明确需要保留 Rust 构建缓存时才设置 `CLEAN_SOURCE_TARGET=no`。

常用升级参数：

```bash
sudo BRANCH="main" \
  INSTALL_METHOD="auto" \
  VALIDATE_CONFIG="yes" \
  MIGRATE_CONFIG="yes" \
  SYNC_CONFIG_DEFAULTS="yes" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sh'
```

## 服务操作

```bash
sudo vs doctor
sudo vs scan
sudo vs reload
sudo systemctl status vps-sentinel --no-pager
sudo systemctl stop vps-sentinel
sudo systemctl start vps-sentinel
```

`vs reload` 会先校验配置，再重载 daemon。

## 通知配置

编辑 `/etc/vps-sentinel/config.toml`：

```toml
[notifications]
language = "zh_cn" # zh_cn 或 en
time_zone = "local"

[notifications.telegram]
enabled = true
bot_token = "<bot-token>"
chat_id = "<chat-id>"
min_severity = "Medium"
```

支持 Telegram、Email SMTP、webhook、ntfy、Gotify、Bark、ServerChan。

## 配置面板上报

部署面板后，在每台 agent 上配置：

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_name = "prod-sg-1"
secret = "same-long-secret-as-panel"
privacy_mode = "strict"
upload_hostname = true
node_location_enabled = true
node_location_url = "https://ipapi.co/json/"
```

验证：

```bash
sudo vs config validate
sudo vs panel push
sudo vs panel outbox
sudo vs reload
```

`node_name` 只应使用非敏感展示名称，不要填公网 IP、云厂商实例 ID 或密钥。agent 只会在主机名不含 IP、不含危险字符时上传脱敏后的主机名。国家、地区、城市属于展示字段；用于推导地域的服务器公网 IP 不会上报。自建面板还可以通过本地 MaxMind/DB-IP MMDB 文件补充请求来源地域；Cloudflare 面板会优先使用 Cloudflare 请求地域。

## 主动封禁

```toml
[active_response]
enabled = true
strategy = "balanced" # observe, balanced, strict
firewall_backend = "auto"
ssh_failed_login_block_threshold = 4
web_probe_block_threshold = 25
permanent_block_enabled = true
permanent_block_threshold = 3
```

常用命令：

```bash
sudo vs blocks list
sudo vs blocks unblock <ip>
sudo vs blocks unblock-all --yes
sudo vs blocks cleanup
```

## 基线复核

```bash
sudo vs baseline create
sudo vs baseline diff
sudo vs baseline approve <approval-key>
```

软件包升级和计划维护可能产生合法漂移。刷新基线前请先看证据。

## 结构化配置与本地菜单

重复性配置修改建议使用结构化 `vs config` 命令，不要用 `sed` 直接改 TOML：

```bash
sudo vs config allowlist add file-path '/etc/systemd/system/snap-*.mount'
sudo vs config allowlist add file-path '/etc/systemd/system/snap-*.scope'
sudo vs config trusted-admin add 203.0.113.10
sudo vs config suppress-rule add CONFIG-004 --global
sudo vs config normalize
sudo vs config validate
sudo vs reload
```

`config migrate` 和 `config sync-defaults` 会把 `[allowlist]` 规范化为稳定数组格式，避免自动化脚本写出重复 key 或格式不一致的配置。

需要引导式本地操作时可以使用：

```bash
sudo vs menu
```

菜单覆盖可信管理员 IP 编辑、allowlist 路径编辑、刷新基线、查看和解除主动封禁、配置校验和服务重载。它是本地 CLI 流程，不需要暴露 fleet panel。

不要在面板服务器上放 SSH 私钥，也不要把大范围 SSH agent forwarding 放到面板服务器。面板是推模式仪表盘：agent 向面板上报签名遥测，常规特权操作应在各节点本地执行，或从独立管理员工作站执行。这样可以避免面板被攻破后直接成为横向进入所有节点的 SSH 跳板。

## 排障

```bash
sudo vs doctor
sudo journalctl -u vps-sentinel -n 100 --no-pager
sudo vs config validate
sudo vs storage stats
```

如果 daemon 权限不足，部分采集器会降级。`vs doctor` 会说明哪些模块可见性不足。
