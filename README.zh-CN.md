# vps-sentinel

面向 Linux VPS 的轻量级 Rust 入侵信号监控工具。

`vps-sentinel` 用于发现可疑 SSH 登录、`authorized_keys` 变化、异常用户与提权、持久化启动项、可疑进程、新增公网监听端口、WebShell 风格文件、Web 探测请求和常见高风险配置。它优先本地运行、本地存储，适合个人 VPS、独立站长和小型服务维护者。

主 README 使用英文：[README.md](README.md)

![CI](https://github.com/cryptoli/vps-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 项目定位

这是防御型监控工具，目标是尽早发现异常、给出证据、给出处理建议。

它不是：

- 杀毒软件；
- 漏洞利用框架；
- 密码爆破工具；
- 第三方主机扫描器；
- C2、后门或隐蔽工具；
- 主机绝对安全保证。

## 支持功能

| 模块 | 支持能力 |
| --- | --- |
| SSH 监控 | 解析 Debian/Ubuntu 与 RHEL 系认证日志；检测 root 登录、密码登录、爆破模式、新登录来源 IP、`authorized_keys` 基线漂移。 |
| 基线漂移 | 为用户、SSH key、关键文件、持久化项和监听端口创建本地基线，并在后续扫描中对比变化。 |
| 用户与权限 | 检测新增用户、UID 0 用户、权限相关用户变化。 |
| 文件完整性 | 监控关键路径和 Web 根目录；对限定大小内文件做哈希和内容扫描；检测关键文件变化、Web 目录可执行脚本、WebShell 风格特征。 |
| 持久化检查 | 监控 cron、systemd、shell profile、`ld.so.preload` 等启动相关位置。 |
| 进程检查 | 读取 procfs，识别临时目录执行、已删除可执行文件仍在运行、反向 shell 片段、挖矿和扫描器命令。 |
| 网络检查 | 读取监听 socket 与所属进程；检测新增公网监听、非白名单端口和高风险服务端口暴露。 |
| Web 日志 | 解析常见 access log 行，检测自动化漏洞探测路径。 |
| Rootkit 信号 | 采集轻量级本地指标，用于发现隐藏进程和可疑 procfs 行为。 |
| Docker 上下文 | 检测 Docker 可用性并给出初始容器攻击面提示；深度容器检查计划在后续版本增强。 |
| 本地存储 | 使用 SQLite 存储 raw events、findings、baseline、扫描记录和通知日志。 |
| 噪声控制 | 支持白名单、最低告警级别、finding 去重和保留周期。 |
| 通知告警 | 支持 Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| 运维部署 | 单 CLI 二进制、JSON 日志、systemd unit、一键安装脚本、更新脚本。 |

## 支持的通知渠道

所有通知渠道默认关闭，需要在 `config.toml` 中按需启用。

| 渠道 | 配置段 | 必填字段 | 常见用途 |
| --- | --- | --- | --- |
| Telegram | `[notifications.telegram]` | `enabled`, `bot_token`, `chat_id` | 通过 Telegram bot 给个人或团队发送告警。 |
| Email SMTP | `[notifications.email]` | `enabled`, `smtp_host`, `smtp_port`, `from`, `to` | 邮件告警，支持 STARTTLS、隐式 TLS 和无认证本地 SMTP 中继。 |
| Webhook | `[notifications.webhook]` | `enabled`, `url` | 自定义 HTTP 接收端、自动化平台、自建告警路由；发送原始 `Finding` JSON，并附带 `X-Vps-Sentinel-Vps-Name`。 |
| ntfy | `[notifications.ntfy]` | `enabled`, `server`, `topic` | ntfy.sh 或自建 ntfy 推送。 |
| Gotify | `[notifications.gotify]` | `enabled`, `server`, `token` | 自建 Gotify 推送。 |
| Bark | `[notifications.bark]` | `enabled`, `server`, `device_key` | Bark iOS 推送。 |
| ServerChan | `[notifications.serverchan]` | `enabled`, `send_key` | ServerChan 通知。 |

每个渠道都支持 `min_severity`，可以让低风险 finding 只保存在本地，高风险 finding 才发送出去。HTTP 类通知渠道统一使用 `notifications.request_timeout_seconds` 控制请求超时，默认 15 秒。面向人的通知渠道使用模板策略：Telegram 使用兼容 Telegram 的 HTML，Email 同时发送纯文本和完整 HTML，ServerChan 与 Gotify 使用 Markdown，ntfy/Bark 使用兼容性最好的纯文本。

通知文本支持英文和简体中文：

```toml
[notifications]
request_timeout_seconds = 15
language = "zh_cn" # en 或 zh_cn
```

告警标题会包含配置的 VPS 名称，方便多台服务器同时部署时快速区分来源：

```toml
[agent]
display_name = "prod-web-1"
hostname = "prod-web-1.example.com"
host_id = "prod-web-1"
```

`display_name` 是通知标题里展示的人类可读 VPS 名称。`host_id` 是用于 finding、存储和去重的稳定技术标识。`display_name` 为空时会依次回退到 `hostname`、`host_id`、`local-host`。

Telegram 示例：

```toml
[notifications.telegram]
enabled = true
bot_token = "<telegram-bot-token>"
chat_id = "<telegram-chat-id>"
min_severity = "Medium"
```

邮件示例：

```toml
[notifications.email]
enabled = true
smtp_host = "smtp.example.com"
smtp_port = 587
tls_mode = "start_tls" # start_tls、tls 或 none
username = "smtp-user"
password = "smtp-password"
from = "vps-sentinel@example.com"
to = ["ops@example.com"]
subject_prefix = "[vps-sentinel]"
min_severity = "High"
```

如果使用无认证的本地 SMTP 中继，可以设置 `tls_mode = "none"`，并保持 `username`、`password` 为空。程序会拒绝在明文 SMTP 下使用账号密码。

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
  packaging/         # systemd 模板和安装辅助脚本
  docs/              # 部署、隐私、规则和通知扩展文档
```

Collectors 负责采集事实，Detectors 把事实转换成 findings。存储与通知只消费统一的 `Finding` 模型，因此后续扩展规则和通知渠道时不需要让模块互相耦合。

## 一键安装

建议先下载审阅脚本，再执行：

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o install.sh
sudo sh install.sh
```

安装脚本会：

- 自动识别 apt、dnf、yum、apk、pacman；
- 安装构建依赖；
- 缺少 `cargo` 时通过 rustup 安装 Rust；
- 默认克隆源码到 `/opt/vps-sentinel-src`；
- 执行 release 构建；
- 安装二进制到 `/usr/local/bin/vps-sentinel`；
- 安装 `vps-sentinel-reload`，用于安全重载配置；
- 仅在配置不存在时创建 `/etc/vps-sentinel/config.toml`；
- 可通过环境变量直接写入 Telegram 配置；
- 自动校验配置、运行 `doctor`、在缺少基线时创建初始基线，并执行一次不发送通知的预热扫描；
- systemd 可用时安装并启用服务。

可通过环境变量自定义：

```bash
sudo REPO_URL=https://github.com/cryptoli/vps-sentinel.git \
  BRANCH=main \
  WORK_DIR=/opt/vps-sentinel-src \
  PREFIX=/usr/local \
  sh install.sh
```

安装时直接启用 Telegram：

```bash
sudo TELEGRAM_BOT_TOKEN="<telegram-bot-token>" \
  TELEGRAM_CHAT_ID="<telegram-chat-id>" \
  TELEGRAM_MIN_SEVERITY=Medium \
  VPS_NAME=prod-web-1 \
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
| `INSTALL_DEPS` | `yes` | 设为 `no` 可跳过系统依赖安装。 |
| `INSTALL_SYSTEMD` | `auto` | `auto`、`yes` 或 `no`，控制是否安装 systemd unit。 |
| `ENABLE_SERVICE` | `yes` | 设为 `no` 时只安装 unit，不启动服务。 |
| `RUN_DOCTOR` | `yes` | 安装过程中运行环境检查。 |
| `BOOTSTRAP_BASELINE` | `yes` | 没有基线时自动创建初始基线。 |
| `RUN_FIRST_SCAN` | `yes` | 执行一次 `scan --no-notify`，完整输出写入 `<LOG_DIR>/first-scan.log`。 |
| `VPS_NAME` | 空 | 可选的人类可读 VPS 名称，会写入 `agent.display_name` 并展示在通知标题中。 |
| `TELEGRAM_BOT_TOKEN` | 空 | 写入本地配置的 Telegram bot token。 |
| `TELEGRAM_CHAT_ID` | 空 | 写入本地配置的 Telegram chat ID。 |
| `TELEGRAM_MIN_SEVERITY` | `Medium` | Telegram 通知的最低等级。 |
| `RUN_NOTIFY_TEST` | `auto` | `auto`、`yes` 或 `no`；`auto` 会在提供 Telegram 环境变量时发送测试通知。 |
| `SERVICE_NAME` | `vps-sentinel` | systemd 服务名。 |
| `SERVICE_PATH` | `/etc/systemd/system/<SERVICE_NAME>.service` | systemd unit 路径。 |

## 更新

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

更新脚本会拉取 GitHub 最新代码、重新构建、保留已有配置、校验配置、刷新 systemd unit，并在服务已启用时 reload 或 restart 服务。

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
| `INSTALL_SYSTEMD` | `auto` | 设为 `no` 可跳过 unit 刷新。 |
| `RESTART_SERVICE` | `auto` | `auto`、`yes` 或 `no`，控制是否 reload/restart 服务。 |
| `VALIDATE_CONFIG` | `yes` | 服务 reload/restart 前校验已有配置。 |

## 重载配置

修改 `/etc/vps-sentinel/config.toml` 后执行：

```bash
sudo vps-sentinel-reload
```

等价的 systemd 命令：

```bash
sudo systemctl reload vps-sentinel
```

重载前会先校验 TOML。校验失败时，daemon 会继续使用旧的内存配置。

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
| `--log-level <level>` | 未设置 `RUST_LOG` 时使用的日志级别，默认 `info`。 |
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
| `vps-sentinel-reload` | 校验 `/etc/vps-sentinel/config.toml` 并重载运行中的 systemd 服务。 |

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

告警中的 VPS 身份：

```toml
[agent]
display_name = "prod-web-1"
hostname = "prod-web-1.example.com"
host_id = "prod-web-1"
```

网络告警策略：

```toml
[network]
alert_on_new_listening_port = true
expected_public_ports = [22, 80, 443]
high_risk_public_ports = [2375, 2376, 3306, 5432, 6379, 9200, 27017]
public_listen_allowlist = [22, 80, 443]
```

- `expected_public_ports` 用于压制 SSH、HTTP、HTTPS 等正常公网服务的通用监听噪音。
- `high_risk_public_ports` 是可配置的高风险服务端口列表；除非显式加入白名单，否则会从当前 socket 状态直接告警。
- `public_listen_allowlist` 和 `[allowlist].listening_ports` 会压制已确认合法的端口，包括有意公网暴露的高风险端口。
- `NET-001` 只会在普通公网端口相对已保存基线新增时触发，不会对每次扫描都存在的稳定监听端口重复告警。

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

- `SSH-001`：Root SSH 登录。
- `SSH-003`：SSH 爆破模式。
- `SSH-005`：`authorized_keys` 相对基线发生变化。
- `USER-002`：UID 0 用户新增或变更。
- `PERSIST-002`：可疑启动命令。
- `PROC-003`：反向 shell 命令模式。
- `NET-001`：公网监听端口。
- `FILE-002`：WebShell 风格文件内容。
- `CONFIG-003`：高危服务端口公网暴露。

## 部署说明

部分采集器需要 root 级别可见性。如果不是 root 运行，`doctor` 会报告可见性降低，相关模块会降级而不是崩溃。

运行时资源占用较小。在本项目验证使用的参考 VPS 上，systemd 服务在默认 60 秒扫描循环下的 `MemoryCurrent` 约为 2.7-3.3 MiB。实际内存会受日志尾部大小、文件完整性路径范围和已启用通知渠道影响。

systemd unit 使用：

- `NoNewPrivileges=true`
- `ProtectSystem=full`
- `ProtectHome=read-only`
- 仅允许配置的数据目录和日志目录写入

更多内容见 [docs/deployment.md](docs/deployment.md)。

## 隐私与安全边界

- 默认不上报日志；
- 默认不启用通知渠道；
- 默认不杀进程、不封 IP、不删除文件；
- SQLite 本地存储；
- 文件内容扫描有大小限制，只提取特征；
- token、密码、密钥应只放在本地配置文件中，不应提交到仓库。

启用 `privacy.mask_ip` 或 `privacy.mask_command_args` 后，事件、finding 和通知证据会在持久化与发送前脱敏。

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
