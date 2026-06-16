# vps-sentinel

面向 Linux VPS 的轻量级 Rust 入侵迹象监控工具。

`vps-sentinel` 用于发现异常 SSH 登录、`authorized_keys` 变化、异常用户和提权、持久化启动项、可疑进程、新增公网监听端口、WebShell 风格文件、Web 扫描请求和常见危险配置。它优先本地运行、本地存储，适合个人 VPS、独立站长和小型服务维护者。

主 README 使用英文：[README.md](README.md)

![CI](https://github.com/cryptoli/vps-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 项目定位

这是防御型监控工具，目标是“早发现、给证据、给建议”。

它不是：

- 杀毒软件；
- 漏洞利用框架；
- 密码爆破工具；
- 第三方主机扫描器；
- C2、后门或隐藏工具；
- 主机绝对安全保证。

## 功能

- 单 Rust CLI 二进制：`vps-sentinel`。
- 本地 SQLite 存储。
- TOML 配置。
- JSON 结构化日志。
- 基线 create/show/diff/reset。
- Debian/Ubuntu 与 RHEL 系日志解析。
- `authorized_keys`、用户、cron、systemd、shell profile、关键文件变化检测。
- 可疑进程检测：临时目录执行、已删除可执行文件仍运行、反弹 shell、挖矿、扫描器。
- 新增公网监听端口和高危端口暴露检测。
- Web 访问日志中的常见漏洞探测检测。
- WebShell 风格文件特征检测，内容扫描有大小限制。
- 统一 `Finding` 模型：风险等级、规则 ID、证据、影响、建议、去重 key。
- 统一通知 trait：Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。
- systemd unit、一键安装脚本、更新脚本。

## 一键安装

建议先下载审阅脚本，再执行：

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o install.sh
sudo sh install.sh
```

脚本会：

- 自动识别 apt、dnf、yum、apk、pacman；
- 安装构建依赖；
- 缺少 `cargo` 时通过 rustup 安装 Rust；
- 默认克隆到 `/opt/vps-sentinel-src`；
- release 构建；
- 安装二进制到 `/usr/local/bin/vps-sentinel`；
- 仅在配置不存在时创建 `/etc/vps-sentinel/config.toml`；
- systemd 可用时安装并启用服务。

可通过环境变量自定义：

```bash
sudo REPO_URL=https://github.com/cryptoli/vps-sentinel.git \
  BRANCH=main \
  WORK_DIR=/opt/vps-sentinel-src \
  PREFIX=/usr/local \
  sh install.sh
```

## 更新

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

更新脚本会拉取 GitHub 最新代码、重新构建、保留已有配置，并在服务已启用时重启服务。

## 手动构建

```bash
git clone https://github.com/cryptoli/vps-sentinel.git
cd vps-sentinel
cargo build --release --locked
sudo install -m 0755 target/release/vps-sentinel /usr/local/bin/vps-sentinel
```

## 首次运行

```bash
sudo vps-sentinel init --path /etc/vps-sentinel/config.toml
sudo vps-sentinel config validate --config /etc/vps-sentinel/config.toml
sudo vps-sentinel doctor --config /etc/vps-sentinel/config.toml
sudo vps-sentinel baseline create --config /etc/vps-sentinel/config.toml
sudo vps-sentinel scan --config /etc/vps-sentinel/config.toml
```

启动守护进程：

```bash
sudo systemctl enable --now vps-sentinel
sudo journalctl -u vps-sentinel -f
```

## 命令

```bash
vps-sentinel init
vps-sentinel check
vps-sentinel scan
vps-sentinel daemon
vps-sentinel baseline create
vps-sentinel baseline show
vps-sentinel baseline diff
vps-sentinel baseline reset
vps-sentinel events list
vps-sentinel events show <event_id>
vps-sentinel rules list
vps-sentinel rules test <rule_id>
vps-sentinel notify test
vps-sentinel config validate
vps-sentinel doctor
```

## 配置

完整示例见 [config/config.example.toml](config/config.example.toml)。

默认系统配置：

```text
/etc/vps-sentinel/config.toml
```

用户级配置：

```text
~/.config/vps-sentinel/config.toml
```

Webhook 示例：

```toml
[notifications.webhook]
enabled = true
url = "https://example.com/security-webhook"
secret = ""
min_severity = "Medium"
```

白名单示例：

```toml
[allowlist]
users = ["deploy"]
ips = ["203.0.113.10"]
listening_ports = [22, 80, 443, 8080]
process_paths = ["/usr/local/bin/my-service"]
file_paths = ["/etc/systemd/system/my-service.service"]
```

## 常见告警

- `SSH-001`: root SSH 登录。
- `SSH-003`: SSH 爆破模式。
- `SSH-005`: `authorized_keys` 相对基线变化。
- `USER-002`: UID 0 用户新增或变化。
- `PERSIST-002`: 可疑启动命令。
- `PROC-003`: 反弹 shell 命令模式。
- `NET-001`: 公网监听端口。
- `FILE-002`: WebShell 风格文件内容。
- `CONFIG-003`: 高危服务端口公网暴露。

## 隐私与安全边界

- 默认不上传日志。
- 默认不启用通知渠道。
- 默认不杀进程、不封 IP、不删除文件。
- SQLite 本地存储。
- 文件内容扫描有大小限制，只提取特征。
- token、密码、密钥不写入日志。

详情见 [docs/privacy.md](docs/privacy.md) 和 [docs/threat-model.md](docs/threat-model.md)。

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=cryptoli/vps-sentinel&type=Date)](https://www.star-history.com/#cryptoli/vps-sentinel&Date)

## 开源许可证

本项目使用 MIT License。见 [LICENSE](LICENSE) 和 [docs/open-source-license.md](docs/open-source-license.md)。

## 路线图

- v0.1：CLI、配置、SQLite、基线、SSH/文件/用户/持久化/进程/网络/Web 日志检测、通知、systemd。
- v0.2：Docker 深度检测、告警聚合、Prometheus metrics、规则系统增强。
- v0.3：本地 HTTP API、简单 dashboard、可选 dry-run 主动响应、隔离区。
