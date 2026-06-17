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
| SSH 监控 | 解析 Debian/Ubuntu 与 RHEL 系认证日志；检测 root 登录、密码登录、普通成功登录、爆破模式和 `authorized_keys`/`authorized_keys2` 基线漂移。 |
| 基线漂移 | 为用户、SSH key、关键文件、持久化项和监听端口创建本地基线，并在后续扫描中对比变化；近期软件包活动会作为上下文附加到漂移告警中。 |
| 用户与权限 | 检测新增用户、UID 0 用户、权限相关用户变化。 |
| 文件完整性 | 监控关键路径和 Web 根目录；对限定大小内文件做哈希和内容扫描；检测关键文件变化、Web 目录可执行脚本、达到风险评分阈值的 WebShell 风格特征组合。 |
| 持久化检查 | 监控 cron、systemd、shell profile、`ld.so.preload` 等启动相关位置，并对可疑启动命令进行风险评分。 |
| 进程检查 | 读取 procfs argv、可执行路径、工作目录、socket FD 数和 UID 上下文，识别临时目录执行、达到风险评分阈值的 deleted executable、网络命令执行桥接、可疑行为聚类和已知挖矿/扫描器身份。 |
| 网络检查 | 读取监听 socket 与所属进程；检测高风险公网服务、可疑监听进程、监听 owner 基线漂移和新增公网监听。22/80/443 等预期端口会降低噪音，但不会被无脑信任。 |
| Web 日志 | 解析常见 access log 行，检测自动化漏洞探测路径。 |
| Rootkit 信号 | 采集轻量级本地指标，用于发现隐藏进程和可疑 procfs 行为。 |
| Docker 上下文 | 检测 Docker 可用性并给出初始容器攻击面提示；深度容器检查计划在后续版本增强。 |
| 本地存储 | 使用 SQLite 存储 raw events、findings、baseline、扫描记录和通知日志。 |
| 噪声控制 | 支持白名单、最低告警级别、finding 去重和保留周期。 |
| 通知告警 | 支持 Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| 运维部署 | 单 CLI 二进制、JSON 日志、systemd unit、一键安装脚本、更新脚本、重载脚本和停止脚本。 |

## 检测模型

命令执行相关规则是行为画像规则，不是简单的工具名或端口名匹配。vps-sentinel 会从 `/proc/<pid>/cmdline` 保留结构化 argv，构建命令画像，并且只有在网络通道、shell 目标、`SYSTEM:` 命令执行器、fd 复制、内联 socket 代码、TTY 分配等高风险特征组合出现时，才触发 `PROC-003` 或 `NET-003`。

已知挖矿/扫描器检测会更克制：`PROC-004` 只会用可执行文件路径、进程名、结构化 `argv[0]` 等进程身份字段匹配 `xmrig`、`masscan`、`zmap` 等已知工具名，并兼容 `.exe` 后缀。结构化进程身份可用时，普通命令参数里出现这些词不会直接告警。

deleted executable 和启动项告警也采用评分模型。`PROC-002` 需要同时具备临时目录执行、memfd 或匿名文件、隐藏的非标准可执行文件、网络执行桥、已知挖矿/扫描器身份等风险特征；系统升级后遗留的 `systemd`、`dockerd`、`python3` 等标准路径 deleted 进程，如果没有其它风险特征，会被视为维护上下文。`PERSIST-002` 会对启动命令中的下载后管道执行、临时路径自启动、base64 解码后 shell 执行、网络到 shell 执行桥等组合进行评分；单独的 `bash -c` 服务包装不会触发默认阈值。

文件和持久化基线漂移不会因为存在软件包活动就被自动压制。agent 会采集近期 apt/dpkg/yum/dnf/pacman/apk 日志活动，并把该上下文附加到 `FILE-001`、`PERSIST-001` 和 `PERSIST-003` 的证据与建议中。这样既不会隐藏真实漂移，也方便先对照软件包日志确认，再决定是否刷新基线。

WebShell 内容检测也采用评分模型，不再因为单个 marker 直接告警。合法管理脚本中单独出现 `eval` 默认达不到阈值；Web 脚本中的命令执行、动态执行叠加编码 payload、命令执行叠加编码、Web 脚本中出现大块编码内容等组合才会触发 `FILE-002`。

`PROC-005` 用于补充识别已改名、轻度伪装、没有明显临时路径或网络 shell 桥接的可疑进程。它组合内核线程伪装、Web 根目录执行、隐藏可执行文件名、可疑工作目录、socket FD 活动、有效 root 权限等弱信号。默认阈值下单个弱信号不会独立告警。

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
time_zone = "local" # local 或 utc
include_technical_fields = false
```

所选语言会影响字段名以及内置规则内容，包括告警标题、说明、影响和建议。时间会统一显示为 `YYYY-MM-DD HH:MM:SS +08:00` 本地时间格式，或 `YYYY-MM-DD HH:MM:SS UTC`。规则 ID、事件 ID、去重 Key 等技术字段默认隐藏；需要排障或自动化关联时可设置 `include_technical_fields = true`。

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

## Linux 兼容性

vps-sentinel 面向带 `/proc`、POSIX shell 和 root 级可见性的 Linux VPS。项目使用 Rust 1.76+ 从源码构建，HTTP/TLS 使用 rustls，SQLite 使用 bundled SQLite，因此不依赖系统 OpenSSL 开发包或系统 SQLite 开发包。

| 环境 | 兼容性 |
| --- | --- |
| Debian / Ubuntu | 一等支持。安装脚本使用 `apt-get`；SSH 认证日志通常来自 `/var/log/auth.log`，systemd 主机可回退到 `journalctl`。 |
| RHEL 系、Rocky、AlmaLinux、CentOS、Amazon Linux | 一等支持。安装脚本使用 `dnf` 或 `yum`；SSH 认证日志通常来自 `/var/log/secure`。 |
| Fedora | 通过 `dnf` 和 systemd 一等支持。 |
| Arch / Manjaro | 通过 `pacman` 支持；软件包活动上下文读取 `/var/log/pacman.log`。 |
| Alpine | 尽力支持。安装脚本使用 `apk`，程序可在 musl 目标运行；如果系统没有 systemd，会跳过 systemd service，需要用其它 supervisor 或手动运行 `vps-sentinel daemon --config ...`。 |
| 通用 Linux | 当系统具备 `curl`、`git`、C 工具链、`pkg-config`、Rust 和 procfs 时可用；如果包管理器不受安装脚本支持，可设置 `INSTALL_DEPS=no` 后自行安装依赖。 |
| 非 Linux Unix / Windows | 不是运行时目标。代码可用于开发编译，但主机监控依赖 Linux procfs、认证日志和 Linux 文件系统布局。 |

systemd 对安装不是强制要求，但 `vps-sentinel-reload`、`vps-sentinel-stop` 和自动守护进程管理需要 systemd。没有 systemd 时，安装脚本仍会构建二进制并写入配置，daemon 需要交给用户自己的 init/supervisor 管理。非 root 运行时程序会降级而不是崩溃，但 SSH 日志、`/proc/<pid>/fd`、受保护文件和持久化路径可能不可见。

## 功能实现方式与效果

| 功能 | 实现方式 | 实际效果 |
| --- | --- | --- |
| SSH 登录监控 | 读取配置的 auth log；日志文件不存在时回退读取 `ssh.service`/`sshd.service` 的 `journalctl`。 | 识别 root 登录、密码登录、普通成功登录，以及按来源 IP 聚合的爆破行为。 |
| SSH key 完整性 | 独立哈希监控 `authorized_keys` 和 `authorized_keys2`，不依赖总的文件完整性开关。 | 即使关闭通用文件完整性，也能发现 SSH 持久化 key 变化。 |
| 文件和持久化漂移 | 使用 SQLite 保存本地基线，后续扫描做快照 diff；同一路径的文件/持久化 finding 会合并，并附带软件包活动上下文。 | 能发现真实漂移，同时减少合法软件更新时的判断成本；基线只会在用户明确执行命令时刷新。 |
| WebShell 内容 | 对限定大小内的文件内容提取风险 marker，并结合 Web 路径、脚本类型和 marker 组合评分。 | 单个弱 marker 默认不告警，但能识别经典 Web 命令执行和编码 payload 组合。 |
| 进程风险 | 读取 procfs argv、可执行路径、cwd、UID/EUID、deleted 状态和 socket FD 数，并按规则评分、白名单和同 PID 信号聚合处理。 | 识别临时路径执行、可疑 deleted executable、网络 shell 桥接、已知挖矿/扫描器身份和改名行为聚类，同时避免同一进程发送多条告警。 |
| 网络监听 | 解析 `/proc/net/tcp*` 和 `/proc/net/udp*`，通过 `/proc/<pid>/fd` 反查进程，与监听 owner 基线对比，并优先报告可疑 owner 行为而不是普通端口暴露。 | 22/80/443 等预期端口只降低通用噪音；进程变化或可疑进程仍会告警，高风险端口画像会作为证据保留。 |
| 通知 | 将统一 `Finding` 模型按渠道模板渲染：Telegram HTML、Email HTML+纯文本、Markdown 或纯文本。 | 消息包含 VPS 名称、规范化时间、本地化字段、证据、影响和建议。 |
| 噪声控制 | 使用扫描内去重、跨扫描去重、状态提醒间隔、安静时段和小时级通知预算。 | 减少重复消息，同时保留高价值告警的可见性。 |

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
- 安装 `vps-sentinel-stop`，用于停止服务且不删除配置或数据；
- 仅在配置不存在时创建 `/etc/vps-sentinel/config.toml`；
- 可通过环境变量直接写入 Telegram 配置；
- systemd 可用时先写入 unit，使初始基线包含本程序自己的服务文件；
- 自动校验配置、运行 `doctor`、在缺少基线时创建初始基线，并执行一次不发送通知的预热扫描；
- 初始基线完成后再启用 systemd 服务。

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

更新脚本会拉取 GitHub 最新代码、重新构建、保留已有配置、校验配置、刷新 systemd unit，并在服务正在运行或已启用时 restart 服务，确保新二进制真正生效。它默认不会刷新已有基线，避免 `authorized_keys` 等未确认漂移在更新时被静默吸收为可信状态。systemd unit 内容未变化时不会重写文件，避免例行更新造成 unit mtime 变化。只修改配置、不替换二进制时使用 `vps-sentinel-reload`。

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
| `REFRESH_BASELINE` | `no` | 只有在已经人工确认当前漂移可信时，才设置为 `yes` 让更新脚本刷新已有基线。 |

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

## 停止服务

停止 daemon，但不删除配置、基线、日志或二进制文件：

```bash
sudo vps-sentinel-stop
```

等价的 systemd 命令：

```bash
sudo systemctl stop vps-sentinel
```

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
| `vps-sentinel-stop` | 停止运行中的 systemd 服务，但保留配置、数据、日志和二进制文件。 |

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

SSH 告警策略：

```toml
[ssh]
alert_on_root_login = true
alert_on_password_login = true
alert_on_successful_login = true
auth_log_lookback_seconds = 300
```

`alert_on_successful_login` 覆盖未被 root 登录或密码登录规则覆盖的普通成功 SSH 登录，并不只针对陌生 IP。普通成功登录为 `Info`，root 登录仍为 `High`，密码登录仍为 `Medium`。SSH 登录按“用户 + 来源 IP”去重，端口只作为证据展示；SSH 暴力破解按来源 IP 去重，失败次数上涨不会在每次扫描时生成新的去重 Key。`auth_log_lookback_seconds` 限制每次扫描读取认证日志时向前回看的时间窗口，避免旧登录日志反复产生通知。当 `/var/log/auth.log` 和 `/var/log/secure` 等配置的认证日志文件不存在时，vps-sentinel 会回退读取 `ssh.service` 和 `sshd.service` 的 `journalctl` 日志。

文件完整性评分：

```toml
[file_integrity]
webshell_min_score = 70
```

`webshell_min_score` 控制何时产生 `FILE-002`。检测器会对 marker 组合和 Web 脚本上下文评分，而不是单独命中一个 marker 就告警，从而减少合法管理脚本误报，同时保留对经典 Web 命令执行和编码命令执行组合的识别能力。

软件包活动上下文：

```toml
[package_manager]
enabled = true
recent_activity_window_seconds = 3600
max_log_tail_bytes = 8192
log_paths = [
  "/var/log/dpkg.log",
  "/var/log/apt/history.log",
  "/var/log/yum.log",
  "/var/log/dnf.log",
  "/var/log/pacman.log",
  "/var/log/apk.log",
]
```

近期软件包活动会作为证据附加到文件和持久化漂移 finding 中。它不是白名单，也不会自动刷新基线；应先对照软件包日志确认漂移可信，再执行 `baseline create` 重新捕获可信状态。

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
- 预期端口不会被无脑信任。程序仍会检查持有端口的进程、可执行文件路径、命令行和基线 owner 漂移，因此伪装在 80/443 后面的可疑进程仍会触发 `NET-002` 或 `NET-003`。
- `high_risk_public_ports` 是可配置的高风险服务端口列表；除非显式加入 `[allowlist].listening_ports`，否则会从当前 socket 状态直接告警。如果端口 owner 同时具备可疑进程特征，`NET-003` 会优先发送并附带服务画像，而不是再额外发送一条普通 `CONFIG-003` 告警。
- `public_listen_allowlist` 作为旧配置兼容项处理，语义等同预期公网端口。只有 `[allowlist].listening_ports` 表示你明确希望压制该端口的所有网络告警。
- `NET-001` 只会在普通 TCP/TCP6 公网端口相对已保存基线新增时触发，不会对每次扫描都存在的稳定监听端口重复告警。普通 UDP 高端口默认视为动态流量，除非命中高风险服务端口或可疑监听进程规则。

进程指标策略：

```toml
[process]
deleted_executable_min_score = 70
behavior_min_score = 70
suspicious_socket_fd_threshold = 20
known_bad_tool_names = ["xmrig", "kinsing", "masscan", "zmap"]
```

`deleted_executable_min_score` 控制何时产生 `PROC-002`。deleted executable 状态会结合路径、进程身份和命令行为评分；标准系统二进制在软件包升级后仍短暂运行，不会单独触发高危告警。`behavior_min_score` 控制 `PROC-005`，它会组合内核线程伪装、Web 根目录执行、隐藏可执行文件名、可疑工作目录、socket FD 活动和有效 root 权限等弱信号。`suspicious_socket_fd_threshold` 控制 socket 持有数量达到多少时成为更强的行为信号。`known_bad_tool_names` 控制 `PROC-004` 的已知挖矿/扫描器指标词表。它会匹配 `exe_path`、`executable`、进程名和结构化 `argv[0]` 等进程身份字段，并兼容 `.exe` 后缀；缺少结构化身份的旧事件才回退到命令 token basename 匹配。同一个 PID 同时命中多个进程规则时，扫描器会保留一条最高价值 finding，并合并进程信号、风险原因、影响和处置建议。

持久化命令评分：

```toml
[persistence]
suspicious_command_min_score = 70
```

`suspicious_command_min_score` 控制何时产生 `PERSIST-002`。启动命令会按下载后管道执行、临时路径自启动、编码 shell payload、网络执行桥等组合特征评分。合法 systemd 单元中常见的普通 shell 包装命令不会单独超过默认阈值。

Web 日志策略：

```toml
[web]
error_burst_threshold = 20
```

`error_burst_threshold` 控制同一来源 IP 在扫描窗口内产生多少次 403/404 后触发 `WEB-002`。小型私有服务可以调低，让探测更敏感；公开高流量站点如果自然存在大量缺失资源请求，可以适当调高，减少噪音。

噪声控制：

```toml
[noise_control]
dedup_window_seconds = 3600
state_reminder_interval_seconds = 86400
max_alerts_per_hour = 30
rate_limit_bypass_min_severity = "High"
quiet_hours_bypass_min_severity = "High"
```

`dedup_window_seconds` 会抑制相同稳定去重 Key 的重复事件型 finding。`state_reminder_interval_seconds` 用于持续存在的状态型 finding，例如高风险 SSH 配置、Docker socket 存在、基线漂移、长驻可疑进程和 WebShell 风格文件；默认 24 小时间隔可以避免不变的主机状态在每次重启或每小时扫描后重复发相同消息。新的目标、来源或规则证据仍会生成独立 finding。`max_alerts_per_hour` 只限制较低等级通知的发送量；达到或高于 `rate_limit_bypass_min_severity` 的 finding 会绕过小时预算，因此 `SSH-005` 这类高价值信号在噪声较多时仍会发送。启用 `quiet_hours` 后，低于 `quiet_hours_bypass_min_severity` 的 finding 会被安静时段抑制；默认仍保留 High 和 Critical 通知。

白名单示例：

```toml
[allowlist]
users = ["deploy"]
ips = ["203.0.113.10"]
listening_ports = [22, 80, 443, 8080]
process_paths = ["/usr/local/bin/my-service"]
process_command_contains = ["trusted-forwarder tcp-listen:8443"]
file_paths = ["/etc/systemd/system/my-service.service"]
```

`process_command_contains` 用于已知合法的长驻命令片段。建议填写足够精确、能识别目标命令的片段，不要填写过宽泛的进程名。

`PROC-003` 不会因为转发工具名、IP 地址、监听参数或单独的 `/bin/sh -c` 触发。检测器会基于 `/proc/<pid>/cmdline` 的 argv 构建命令画像，并要求出现高置信行为组合，例如：

- `/dev/tcp` 叠加交互式 shell 和文件描述符重定向；
- 网络通道通过 `-e`、`--exec`、`EXEC:` 或 `SHELL:` 直接桥接到 shell 目标；
- 网络通道桥接到 `SYSTEM:` 命令执行器；
- 内联解释器同时使用 socket API、fd duplication 和 shell 目标；
- 网络命令为 shell 分配 TTY。

正常服务包装命令，例如 `/bin/sh -c '/usr/local/bin/app --listen 0.0.0.0:443'`，以及普通 TCP/UDP 转发命令不应触发 `PROC-003`。

## 告警内容

面向用户的告警默认包含：

- VPS 名称；
- 主机 ID；
- 规范化时间；
- 模块/分类；
- 风险等级；
- 目标对象；
- 证据；
- 影响；
- 建议。

当 `notifications.include_technical_fields = true` 时，告警会额外包含规则 ID、事件 ID 和去重 Key。

常见规则：

- `SSH-001`：Root SSH 登录。
- `SSH-002`：SSH 密码登录。
- `SSH-003`：SSH 爆破模式。
- `SSH-004`：SSH 成功登录。
- `SSH-005`：`authorized_keys` 或 `authorized_keys2` 相对基线发生变化。
- `USER-002`：UID 0 用户新增或变更。
- `PERSIST-002`：可疑启动命令。
- `PROC-002`：达到风险评分阈值的 deleted executable 进程。
- `PROC-003`：网络命令执行桥接。
- `PROC-005`：可疑进程行为聚类。
- `NET-001`：相对基线新增的公网监听端口。
- `NET-002`：公网监听端口背后的进程相对基线发生变化。
- `NET-003`：公网监听端口背后存在可疑进程。
- `FILE-002`：WebShell 风格文件内容。
- `CONFIG-003`：高危服务端口公网暴露。

## 部署说明

部分采集器需要 root 级别可见性。如果不是 root 运行，`doctor` 会报告可见性降低，相关模块会降级而不是崩溃。

作为常驻 agent，运行时资源占用较小。在当前验证 VPS 上，默认 60 秒扫描循环下 daemon 进程 RSS 约为 10-13 MiB。systemd cgroup 的 `MemoryCurrent` 可能明显更高，从几十 MiB 到几百 MiB 都可能出现，因为 Linux 可能把近期触达的文件缓存和 cgroup 内存统计计入服务。实际内存压力会受日志尾部大小、文件完整性路径范围、内核统计方式和已启用通知渠道影响；判断 daemon 自身稳定占用时应优先看进程 RSS。

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
