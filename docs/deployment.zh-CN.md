# Agent 部署教程

本文说明如何在 Linux VPS 上安装和运维 `vps-sentinel` agent。面板部署见 [panel-deployment.zh-CN.md](panel-deployment.zh-CN.md)。

## 环境要求

- 需要 root 或 sudo 权限。
- 推荐 systemd；非 systemd 主机也可以手动运行 `vps-sentinel scan`。
- 只有安装脚本回退到源码编译时才需要 Rust。
- 可选工具能增强可见性：`journalctl`、`ss`、`nft`、`iptables`、`dpkg`/`rpm`/`apk`/`pacman`、`nvidia-smi`、`rocm-smi`、`auditd`、`bpftrace`。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sudo sh
```

常用安装变量：

```bash
sudo VPS_NAME="prod-sg-1" \
  TELEGRAM_BOT_TOKEN="<bot-token>" \
  TELEGRAM_CHAT_ID="<chat-id>" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

安装脚本会：

- 安装 `vps-sentinel` 和简写命令 `vs`；
- 只在配置不存在时创建 `/etc/vps-sentinel/config.toml`；
- 校验配置、创建初始基线、执行一次不通知的预热扫描；
- systemd 可用时安装并启动服务；
- 重装时保留已有配置。

## 升级

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sudo sh
```

升级脚本会先验证 release 二进制能否在当前机器执行；不兼容时回退到本机源码编译。已有配置、SQLite 状态、基线、通知凭据和面板密钥不会被覆盖。

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

## 配置通知

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

支持 Telegram、邮件 SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。

## 配置面板上报

部署面板后，在每台 agent 上配置：

```toml
[panel]
enabled = true
url = "https://panel.example.com/api/v1/ingest"
node_name = "prod-sg-1"
secret = "same-long-secret-as-panel"
privacy_mode = "strict"

[panel.location]
country_code = "SG"
country = "Singapore"
city = "Singapore"
```

验证：

```bash
sudo vs config validate
sudo vs panel push
sudo vs panel outbox
sudo vs reload
```

`node_name` 只应该使用非敏感展示名，不要填公网 IP、私有主机名、云厂商实例 ID 或密钥。

## 主动响应

主动响应只会在 SSH/Web 证据足够明确且通过安全检查后写入来源 IP 封禁：

```toml
[active_response]
enabled = true
strategy = "balanced" # observe, balanced, strict
firewall_backend = "auto"
ssh_failed_login_block_threshold = 6
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

请把自己的跳板机、监控机、VPN 出口、办公室固定 IP 加入 `[allowlist].ips`。

## 基线复核

```bash
sudo vs baseline create
sudo vs baseline diff
sudo vs baseline approve <approval-key>
```

软件包升级和计划维护可能产生合法漂移。刷新基线前先看证据。

## 排障

```bash
sudo vs doctor
sudo journalctl -u vps-sentinel -n 100 --no-pager
sudo vs config validate
sudo vs storage stats
```

如果 daemon 权限不足，部分采集器会降级。`vs doctor` 会说明哪些模块受影响。
