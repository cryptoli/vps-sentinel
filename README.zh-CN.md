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

## 支持功能

| 模块 | 支持能力 |
| --- | --- |
| SSH 监控 | 解析 Debian/Ubuntu 与 RHEL 系认证日志；检测 root 登录、密码登录、爆破模式、新登录来源 IP、`authorized_keys` 基线漂移。 |
| 基线漂移 | 为用户、SSH key、关键文件、持久化项和监听端口创建本地基线，并在后续扫描中对比变化。 |
| 用户与权限 | 检测新增用户、UID 0 用户、与权限相关的用户变化。 |
| 文件完整性 | 监控关键路径和 Web 根目录；进行有大小限制的哈希与内容扫描；检测关键文件变化、Web 目录可执行脚本、WebShell 风格特征。 |
| 持久化检查 | 监控 cron、systemd、shell profile、`ld.so.preload` 等启动相关位置。 |
| 进程检查 | 读取 procfs，识别临时目录执行、已删除可执行文件仍运行、反弹 shell 片段、挖矿和扫描器命令。 |
| 网络检查 | 读取监听 socket 与所属进程；检测新增公网监听、非白名单端口和高危服务端口暴露。 |
| Web 日志 | 解析常见 access log 行，检测自动化漏洞探测路径。 |
| Rootkit 信号 | 采集轻量级本地信号，用于发现隐藏进程和可疑 procfs 行为。 |
| Docker 上下文 | 检测 Docker 是否存在并给出初始容器攻击面提示；深度容器检查计划在后续版本增强。 |
| 本地存储 | 使用 SQLite 存储 raw events、findings、baseline 和通知记录。 |
| 噪声控制 | 支持白名单、最低等级、finding 去重和保留周期。 |
| 通知告警 | 支持 Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| 运维部署 | 单 CLI 二进制、JSON 日志、systemd unit、一键安装脚本、更新脚本。 |

## 支持的通知渠道

所有通知渠道默认关闭，需要在 `config.toml` 中按需启用。

| 渠道 | 配置段 | 必填字段 | 常见用途 |
| --- | --- | --- | --- |
| Telegram | `[notifications.telegram]` | `enabled`, `bot_token`, `chat_id` | 通过 Telegram bot 给个人或团队发告警。 |
| Email SMTP | `[notifications.email]` | `enabled`, `smtp_host`, `smtp_port`, `username`, `password`, `from`, `to` | 传统邮件告警。 |
| Webhook | `[notifications.webhook]` | `enabled`, `url` | 自定义 HTTP 接收端、自动化平台、自建告警路由。 |
| ntfy | `[notifications.ntfy]` | `enabled`, `server`, `topic` | ntfy.sh 或自建 ntfy 推送。 |
| Gotify | `[notifications.gotify]` | `enabled`, `server`, `token` | 自建 Gotify 推送。 |
| Bark | `[notifications.bark]` | `enabled`, `server`, `device_key` | Bark iOS 推送。 |
| ServerChan | `[notifications.serverchan]` | `enabled`, `send_key` | ServerChan 通知。 |

每个渠道都支持 `min_severity`，可以让低风险 finding 只保存在本地，高风险 finding 才发送出去。HTTP 类型通知渠道统一使用 `notifications.request_timeout_seconds` 控制请求超时，默认 15 秒。

Telegram 示例：

```toml
[notifications.telegram]
enabled = true
bot_token = "<telegram-bot-token>"
chat_id = "<telegram-chat-id>"
min_severity = "Medium"
```

Webhook 示例：

```toml
[notifications.webhook]
enabled = true
url = "https://example.com/security-webhook"
secret = ""
min_severity = "Medium"
```

## 架构

```text
vps-sentinel/
  crates/
    sentinel-core/   # config, errors, severity, RawEvent, Finding
    sentinel-agent/  # collectors, detectors, baseline, SQLite, notifiers, daemon
    sentinel-cli/    # vps-sentinel command line
  config/            # 示例配置
  packaging/         # systemd 模板和打包安装辅助脚本
  docs/              # 部署、隐私、规则和通知扩展文档
```

Collectors 负责采集事实，Detectors 把事实转换成 findings。存储与通知只消费统一的 `Finding` 模型，因此后续扩展规则和通知渠道时不需要让模块互相耦合。

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

常用安装变量：

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `REPO_URL` | `https://github.com/cryptoli/vps-sentinel.git` | 要克隆的 Git 仓库。 |
| `BRANCH` | `main` | 要安装的分支。 |
| `WORK_DIR` | `/opt/vps-sentinel-src` | 源码目录。 |
| `PREFIX` | `/usr/local` | 二进制安装前缀。 |
| `CONFIG_DIR` | `/etc/vps-sentinel` | `config.toml` 所在目录。 |
| `DATA_DIR` | `/var/lib/vps-sentinel` | SQLite 数据目录。 |
| `LOG_DIR` | `/var/log/vps-sentinel` | 运行日志目录。 |
| `INSTALL_DEPS` | `yes` | 设置为 `no` 可跳过包管理器依赖安装。 |
| `INSTALL_SYSTEMD` | `auto` | `auto`、`yes` 或 `no`，控制是否安装 systemd unit。 |
| `ENABLE_SERVICE` | `yes` | 设置为 `no` 时只安装 unit，不启动服务。 |
| `SERVICE_NAME` | `vps-sentinel` | systemd 服务名。 |
| `SERVICE_PATH` | `/etc/systemd/system/<SERVICE_NAME>.service` | systemd unit 路径。 |

## 更新

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

更新脚本会拉取 GitHub 最新代码、重新构建、保留已有配置、刷新 systemd unit，并在服务已启用时重启服务。

常用更新变量：

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `REPO_URL` | `https://github.com/cryptoli/vps-sentinel.git` | 更新来源仓库。 |
| `BRANCH` | `main` | 更新分支。 |
| `WORK_DIR` | `/opt/vps-sentinel-src` | 已存在或新建的源码目录。 |
| `PREFIX` | `/usr/local` | 二进制安装前缀。 |
| `CONFIG_DIR` | `/etc/vps-sentinel` | 已有配置目录。 |
| `DATA_DIR` | `/var/lib/vps-sentinel` | 生成 systemd unit 时使用的数据目录。 |
| `LOG_DIR` | `/var/log/vps-sentinel` | 生成 systemd unit 时使用的日志目录。 |
| `INSTALL_SYSTEMD` | `auto` | 设置为 `no` 可跳过 unit 刷新。 |
| `RESTART_SERVICE` | `auto` | `auto`、`yes` 或 `no`，控制是否重启服务。 |

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

## 命令说明

全局选项：

| 选项 | 含义 |
| --- | --- |
| `--config <path>` | 指定 TOML 配置文件。未指定时依次查找 `config.toml`、`~/.config/vps-sentinel/config.toml`、`/etc/vps-sentinel/config.toml`。 |
| `--log-level <level>` | 当未设置 `RUST_LOG` 时使用的日志等级，默认 `info`。 |
| `--version` | 输出版本号。 |
| `--help` | 查看命令帮助。 |

命令：

| 命令 | 含义 |
| --- | --- |
| `vps-sentinel init --path <path>` | 写入默认配置文件；目标文件已存在时会失败。 |
| `vps-sentinel init --path <path> --force` | 强制重写配置文件；生产环境已有调优配置时应谨慎使用。 |
| `vps-sentinel config validate --config <path>` | 只解析并校验配置，不运行采集器。编辑配置后建议先执行。 |
| `vps-sentinel doctor --config <path>` | 检查运行环境：root 可见性、Unix 目标支持、存储目录可写性、认证日志可见性。 |
| `vps-sentinel check --config <path>` | 执行一次采集和检测，但不持久化结果、不发送通知。适合快速检查和冒烟测试。 |
| `vps-sentinel scan --config <path>` | 执行一次完整扫描，持久化 raw events/findings，记录通知日志，应用去重，并发送已启用通知。 |
| `vps-sentinel scan --no-notify --config <path>` | 持久化扫描结果但不发送通知。适合启用通知前试运行。 |
| `vps-sentinel daemon --config <path>` | 按 `agent.scan_interval_seconds` 持续扫描，适合交给 systemd 运行。 |
| `vps-sentinel baseline create --config <path>` | 将当前可信状态写入 SQLite 基线。建议安装后和确认合法变更后执行。 |
| `vps-sentinel baseline show --config <path>` | 输出已保存的最新基线。 |
| `vps-sentinel baseline diff --config <path>` | 将当前状态与已保存基线对比并输出漂移。 |
| `vps-sentinel baseline reset --config <path>` | 清空已保存基线。清空后需要重新执行 `baseline create`。 |
| `vps-sentinel events list --config <path>` | 列出最近保存的 findings；可通过 `--limit <n>` 控制数量。 |
| `vps-sentinel events show <event_id> --config <path>` | 按 finding ID 输出单条已保存 finding 的 JSON。 |
| `vps-sentinel rules list` | 列出内置检测规则、默认等级和描述。 |
| `vps-sentinel rules test <rule_id>` | 检查指定内置规则 ID 是否存在并可加载。 |
| `vps-sentinel notify test --config <path>` | 构造一条 Info 级别测试 finding 并发送到已启用通知渠道，用于验证凭据和路由。 |

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

默认使用 SQLite：

```toml
[storage]
type = "sqlite"
path = "/var/lib/vps-sentinel/sentinel.db"
retention_days = 30
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

## 告警内容

每条告警包含：

- event ID；
- host ID；
- 时间戳；
- 模块/分类；
- 规则 ID；
- 风险等级；
- 目标对象；
- 证据；
- 影响；
- 建议；
- 去重 key。

常见规则：

- `SSH-001`：root SSH 登录。
- `SSH-003`：SSH 爆破模式。
- `SSH-005`：`authorized_keys` 相对基线变化。
- `USER-002`：UID 0 用户新增或变化。
- `PERSIST-002`：可疑启动命令。
- `PROC-003`：反弹 shell 命令模式。
- `NET-001`：公网监听端口。
- `FILE-002`：WebShell 风格文件内容。
- `CONFIG-003`：高危服务端口公网暴露。

## 部署说明

部分采集器需要 root 级别可见性。如果不是 root 运行，`doctor` 会报告可见性降低，相关模块会降级而不是崩溃。

systemd unit 使用：

- `NoNewPrivileges=true`
- `ProtectSystem=full`
- `ProtectHome=read-only`
- 仅允许配置的数据目录和日志目录写入

更多内容见 [docs/deployment.md](docs/deployment.md)。

## 隐私与安全边界

- 默认不上传日志。
- 默认不启用通知渠道。
- 默认不杀进程、不封 IP、不删除文件。
- SQLite 本地存储。
- 文件内容扫描有大小限制，只提取特征。
- token、密码、密钥应只放在本地配置文件中，不应提交到仓库。

详情见 [docs/privacy.md](docs/privacy.md) 和 [docs/threat-model.md](docs/threat-model.md)。

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=cryptoli/vps-sentinel&type=Date)](https://www.star-history.com/#cryptoli/vps-sentinel&Date)

## 开源许可证

本项目使用 MIT License。见 [LICENSE](LICENSE) 和 [docs/open-source-license.md](docs/open-source-license.md)。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。新增规则必须是防御型、可解释、有证据、默认安全的。

## 安全问题反馈

请按照 [SECURITY.md](SECURITY.md) 私下报告安全漏洞。

## 路线图

- v0.1：CLI、配置、SQLite、基线、SSH/文件/用户/持久化/进程/网络/Web 日志检测、通知、systemd。
- v0.2：Docker 深度检测、告警聚合、Prometheus metrics、规则系统增强。
- v0.3：本地 HTTP API、简单 dashboard、可选 dry-run 主动响应、隔离区。
