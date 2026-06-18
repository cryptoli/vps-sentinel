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
| SSH 监控 | 解析 Debian/Ubuntu 与 RHEL 系认证日志；检测 root 登录、密码登录、普通成功登录、爆破模式、`authorized_keys`/`authorized_keys2` 基线漂移、SSH key 文件权限异常和高风险软链。 |
| 基线漂移 | 为用户、SSH key、关键文件、持久化项和监听端口创建本地基线，并在后续扫描中对比变化；近期软件包活动会作为上下文附加到漂移告警中。 |
| 用户与权限 | 检测新增用户、UID 0 用户、权限相关用户变化。 |
| 文件完整性 | 监控关键路径和 Web 根目录；对限定大小内文件做哈希和内容扫描；检测关键文件变化、Web 目录可执行脚本、达到风险评分阈值的 WebShell 风格特征组合。 |
| 日志完整性 | 监控敏感认证/登录日志文件，识别高风险软链和没有近期轮转上下文的大幅截断。 |
| 持久化检查 | 监控 cron、systemd、shell profile、`ld.so.preload` 等启动相关位置，并对可疑启动命令进行风险评分。 |
| 进程和 GPU 检查 | 读取 procfs argv、父进程、可执行路径、工作目录、UID 上下文、socket FD 数、CPU 生命周期指标、procfs 启动时间漂移、cgroup/container 上下文、systemd unit/ExecStart、可执行文件 owner/size/hash、软件包归属、出站连接画像，并在 `nvidia-smi` 可用时读取 NVIDIA GPU 计算进程事实，识别临时目录执行、达到风险评分阈值的 deleted executable、网络命令执行桥接、可疑行为聚类、已知挖矿/扫描器身份和可疑 GPU 计算负载。 |
| 网络检查 | 读取监听 socket 与所属进程；附加进程上下文和防火墙状态；检测高风险公网服务、可疑监听进程、监听 owner 基线漂移和新增公网监听。22/80/443 等预期端口会降低噪音，但不会被无脑信任。 |
| Web 日志 | 解析常见 access log 行，将自动化探测归类为攻击家族，并按来源聚合同类路径，避免按路径刷屏。 |
| Rootkit 信号 | 采集轻量级本地指标，用于发现隐藏进程和可疑 procfs 行为。 |
| Docker 上下文 | 检测 Docker 可用性并给出初始容器攻击面提示，不要求 Docker 写权限。 |
| 本地存储 | 使用 SQLite 存储 raw events、findings、baseline、扫描记录和通知日志；重复 raw fact 使用稳定存储键，并提供可配置数据库容量上限，避免无限增长。 |
| 噪声控制 | 支持白名单、最低告警级别、finding 去重和保留周期。 |
| 主动响应 | 可选通过 nftables 或 iptables 临时封禁高置信公网来源 IP，例如明显 Web 探测和 SSH 爆破；默认关闭。 |
| 通知告警 | 支持 Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| 运维部署 | 单 CLI 二进制、`vs` 简写、JSON 日志、systemd unit、一键安装脚本、更新脚本、内置重载命令和停止脚本。 |

## 检测模型

命令执行相关规则是行为画像规则，不是简单的工具名或端口名匹配。vps-sentinel 会从 `/proc/<pid>/cmdline` 保留结构化 argv，构建命令画像，并且只有在网络通道、shell 目标、`SYSTEM:` 命令执行器、fd 复制、内联 socket 代码、TTY 分配等高风险特征组合出现时，才触发 `PROC-003` 或 `NET-003`。

已知挖矿/扫描器检测会更克制：`PROC-004` 只会用可执行文件路径、进程名、结构化 `argv[0]` 等进程身份字段匹配 `xmrig`、`masscan`、`zmap` 等已知工具名，并兼容 `.exe` 后缀。结构化进程身份可用时，普通命令参数里出现这些词不会直接告警。当 procfs CPU 数据可用时，告警会附带生命周期平均 CPU、进程年龄和累计 CPU 秒数；持续高 CPU 会增强判断，但单独高 CPU 不会触发告警。

deleted executable 和启动项告警也采用评分模型。`PROC-002` 需要同时具备临时目录执行、memfd 或匿名文件、隐藏的非标准可执行文件、网络执行桥、已知挖矿/扫描器身份等风险特征；系统升级后遗留的 `systemd`、`dockerd`、`python3` 等标准路径 deleted 进程，如果没有其它风险特征，会被视为维护上下文。`PERSIST-002` 会对启动命令中的下载后管道执行、临时路径自启动、base64 解码后 shell 执行、网络到 shell 执行桥等组合进行评分；单独的 `bash -c` 服务包装不会触发默认阈值。

文件和持久化基线漂移不会因为存在软件包活动就被自动压制。agent 会采集近期 apt/dpkg/yum/dnf/pacman/apk 日志活动，并把该上下文附加到 `FILE-001`、`PERSIST-001` 和 `PERSIST-003` 的证据与建议中。这样既不会隐藏真实漂移，也方便先对照软件包日志确认，再决定是否刷新基线。

SSH key 文件状态检测独立于基线漂移。`authorized_keys` 内容变化仍按持久化漂移告警；当前状态只有在存在明确文件系统证据时才单独告警，例如 group/other 可写权限，或软链指向 `/dev/null`、临时目录、共享内存目录、运行时目录等高风险位置。这能识别常见本地持久化弱点，同时不会把所有软链都当成恶意。

敏感认证/登录日志完整性是有状态检测。vps-sentinel 会记录上一次扫描时的文件类型和大小；如果发现 `/var/log/auth.log -> /dev/null` 这类高风险重定向会立即告警；如果日志文件大幅变小，只有同时超过配置的大小和比例阈值，并且没有 `auth.log.1` 这类近期轮转文件时才告警；如果某个配置中的敏感日志上一轮存在、这一轮消失，也会告警。因此正常 logrotate 不会刷屏，而入侵后的清理或删除日志行为可以被看到。

WebShell 内容检测也采用评分模型，不再因为单个 marker 直接告警。合法管理脚本中单独出现 `eval` 默认达不到阈值；Web 脚本中的命令执行、动态执行叠加编码 payload、命令执行叠加编码、Web 脚本中出现大块编码内容等组合才会触发 `FILE-002`。

`PROC-005` 用于补充识别已改名、轻度伪装、没有明显临时路径或网络 shell 桥接的可疑进程。它组合内核线程伪装、Web 根目录执行、隐藏可执行文件名、可疑工作目录、socket FD 活动、持续高 CPU、同一进程身份的 procfs 启动时间漂移、有效 root 权限等弱信号。默认阈值下单个弱信号不会独立告警，启动时间漂移也只会在已经存在其它可疑上下文时加权。

`PROC-006` 在宿主机服务能看到 `nvidia-smi` 时提供 NVIDIA GPU 挖矿检测。采集器读取当前 GPU compute apps，并按 PID 与 procfs、出站连接事实关联。GPU 显存占用本身不会告警，因为正常 CUDA、AI 训练、渲染、转码任务也可能大量占用显存；该规则需要叠加更强证据，例如已知 GPU 挖矿器身份、配置中的矿池远端端口、临时或 deleted executable、匿名/memfd 可执行文件、网络命令执行桥接，或隐藏 GPU 可执行文件伴随公网出站连接。非 NVIDIA GPU 技术栈，以及看不到宿主机 GPU/进程命名空间的容器化部署，不在该信号覆盖范围内。

进程和监听端口告警会尽可能带出完整证据链：父进程、systemd unit、systemd `ExecStart`、可执行文件 UID/GID、文件大小、有限 BLAKE3 hash、dpkg/rpm/pacman/apk 软件包归属、cgroup/container 上下文、procfs 启动时间漂移、出站连接数量、公网出站连接数量和远端端口画像。软件包归属查询与防火墙探测都设置了短超时和单次扫描缓存，因此平台工具缺失或响应慢时只会缺少该证据，不会阻塞扫描。这些字段是辅助证据或弱信号。例如 systemd `ExecStart` 不匹配不会单独告警，但如果监听端口 owner 已经相对基线变化，它可以把普通 owner 变化升级为可疑监听进程。

防火墙状态是辅助判断，不是唯一依据。端口暴露仍以 `/proc/net/*` 的内核 socket 状态为准；`ufw`、`firewalld`、`nftables` 和 `iptables` 状态会作为证据附加，帮助判断公网监听是否真的可能被外部访问。

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

CI 会在 Ubuntu 上运行完整 Rust 测试、校验 shell 脚本、执行临时目录安装冒烟测试，并在 Debian Bookworm 与 Alpine musl 容器中做兼容性 smoke test。Release workflow 已准备 `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、`x86_64-unknown-linux-musl` 和 `aarch64-unknown-linux-musl` 目标。

systemd 对安装不是强制要求，但服务 reload/start/stop 管理需要 systemd。没有 systemd 时，安装脚本仍会构建二进制并写入配置，daemon 需要交给用户自己的 init/supervisor 管理。非 root 运行时程序会降级而不是崩溃，但 SSH 日志、`/proc/<pid>/fd`、受保护文件和持久化路径可能不可见。

主动响应需要 root 权限，以及可用的 nftables 或 iptables/ip6tables 用户态命令。在使用 firewalld、ufw 或人工重载防火墙的主机上，vps-sentinel 会在每次扫描时把已保存封禁状态和真实防火墙规则重新对照，发现规则消失时会移除失效的本地状态。

CI 中使用的 Docker 容器只用于构建和兼容性测试，不代表推荐运行方式。普通容器运行时通常只能看到容器自己的进程表、文件系统和日志，无法可靠监控宿主机入侵。生产环境应把 daemon 直接安装在 VPS 宿主机上，并以 root 可见性运行，推荐使用项目提供的 systemd unit。

## 功能实现方式与效果

| 功能 | 实现方式 | 实际效果 |
| --- | --- | --- |
| SSH 登录监控 | 读取配置的 auth log；日志文件不存在时回退读取 `ssh.service`/`sshd.service` 的 `journalctl`。 | 识别 root 登录、密码登录、普通成功登录，以及按来源 IP 聚合的爆破行为。 |
| SSH key 完整性 | 独立哈希监控 `authorized_keys` 和 `authorized_keys2`，不依赖总的文件完整性开关；同时记录文件类型、可用时的 Unix 权限和软链目标。 | 即使关闭通用文件完整性，也能发现 SSH 持久化 key 变化；无需历史基线也能识别可写权限或高风险软链状态。 |
| 文件和持久化漂移 | 使用 SQLite 保存本地基线，后续扫描做快照 diff；同一路径的文件/持久化 finding 会合并，并附带软件包活动上下文。 | 能发现真实漂移，同时减少合法软件更新时的判断成本；基线只会在用户明确执行命令时刷新。 |
| 日志篡改信号 | 采集敏感日志文件快照并与本地规则状态对比；高风险软链立即告警，日志截断需要满足配置的比例和字节阈值且没有近期轮转文件；曾经出现过的配置日志消失也会报告。 | 识别把认证日志重定向到 `/dev/null`、清空日志或删除日志等反取证行为，同时避免正常 logrotate 误报。 |
| WebShell 内容 | 对限定大小内的文件内容提取风险 marker，并结合 Web 路径、脚本类型和 marker 组合评分。 | 单个弱 marker 默认不告警，但能识别经典 Web 命令执行和编码 payload 组合。 |
| Web 探测 | `WEB-001` 按来源 IP、探测家族和响应画像聚合。404 PHPUnit 目录爆破等未命中探测默认为 Low；敏感路径成功响应或受保护的 exploit 路径会提升等级。 | 扫描器命中大量路径变体时只生成一条可读 finding，而不是几十条 Telegram 消息。 |
| 进程和 GPU 风险 | 读取 procfs argv、父进程、可执行路径、cwd、UID/EUID、deleted 状态、socket FD 数、生命周期 CPU 指标、启动时间漂移、cgroup/container 上下文、systemd unit/ExecStart、可执行文件元数据/hash、软件包归属、出站连接画像和 NVIDIA GPU 计算进程状态，并按规则评分、白名单、规则状态和同 PID 信号聚合处理。`PROC-005` 必须先出现伪装、隐藏、可疑目录或 Web 路径等主风险信号，socket、出站连接、重启漂移和 root 上下文只能辅助加权；`PROC-006` 需要 GPU 计算活动叠加挖矿或高风险运行证据。 | 识别临时路径执行、可疑 deleted executable、网络 shell 桥接、已知挖矿/扫描器身份、改名行为聚类和可疑 GPU 挖矿负载，同时避免 PID、CPU、GPU、连接计数等波动字段或正常高连接业务服务导致重复/误报消息。 |
| 网络监听 | 解析 `/proc/net/tcp*` 和 `/proc/net/udp*`，通过 `/proc/<pid>/fd` 反查进程，与监听 owner 基线对比，附加进程/防火墙上下文，并优先报告可疑 owner 行为而不是普通端口暴露。 | 22/80/443 等预期端口只降低通用噪音；进程变化或可疑进程仍会告警，高风险端口画像和防火墙状态会作为证据保留。 |
| 通知 | 将统一 `Finding` 模型按渠道模板渲染：Telegram HTML、Email HTML+纯文本、Markdown 或纯文本。 | 消息包含 VPS 名称、规范化时间、本地化字段、证据、影响和建议。 |
| 噪声控制 | 使用扫描内去重、跨扫描去重、状态提醒间隔、安静时段和小时级通知预算。 | 减少重复消息，同时保留高价值告警的可见性。 |
| 主动响应 | 在扫描内 finding 合并/去重后、跨扫描通知去重前评估封禁候选；只有不在 `[allowlist].ips` 中的公网 IP 才可能被封。Web 需要敏感路径成功响应、单次高置信 RCE 风格 exploit 探测、重复低置信 exploit 探测，或高频探测/错误突发；SSH 需要达到比告警更严格的失败次数阈值。 | 可把明显扫描源临时丢进防火墙，同时避免每条告警都变成破坏性动作。 |

## 一键安装

建议先下载审阅脚本，再执行：

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh -o install.sh
sudo sh install.sh
```

安装脚本会：

- 自动识别 apt、dnf、yum、apk、pacman；
- 安装构建依赖；
- 默认优先尝试下载 release artifact，artifact 不存在或不能在当前机器执行时回退到源码构建；
- 只有在需要源码构建且 `cargo` 缺失或配置异常时，才通过 rustup 安装或修复 Rust toolchain；
- 仅在源码构建时克隆源码到 `/opt/vps-sentinel-src`；
- 回退源码构建时执行 release 构建；
- 安装二进制到 `/usr/local/bin/vps-sentinel`，并创建简写 `/usr/local/bin/vs`；
- 当发布包或源码树包含 helper 时，安装 `vps-sentinel-install`、`vps-sentinel-update` 和 `vps-sentinel-stop`；
- 仅在配置不存在时创建 `/etc/vps-sentinel/config.toml`；
- 可通过环境变量直接写入 Telegram 配置；
- systemd 可用时先写入 unit，使初始基线包含本程序自己的服务文件；
- 写入 `.bak` 备份后删除废弃配置字段；如需跳过可设置 `MIGRATE_CONFIG=no`；
- 追加当前版本新增的默认配置项，但不覆盖已有值；如需跳过可设置 `SYNC_CONFIG_DEFAULTS=no`；
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
| `INSTALL_METHOD` | `auto` | `auto` 和 `release` 都会优先下载 release artifact，如果 artifact 不存在或不能在当前机器执行，会回退源码构建；`source` 强制本地构建。 |
| `RELEASE_VERSION` | `latest` | `INSTALL_METHOD=auto` 或 `release` 时下载的 release tag。 |
| `RELEASE_ARTIFACT_URL` | 空 | 覆盖 release artifact 下载地址，适合镜像、本地 artifact 测试和 CI 冒烟测试。 |
| `TARGET_TRIPLE` | 自动识别 | 覆盖 release artifact 目标，例如 `x86_64-unknown-linux-gnu` 或 `aarch64-unknown-linux-musl`。 |
| `INSTALL_SYSTEMD` | `auto` | `auto`、`yes` 或 `no`，控制是否安装 systemd unit。 |
| `ENABLE_SERVICE` | `yes` | 设为 `no` 时只安装 unit，不启动服务。 |
| `RUN_DOCTOR` | `yes` | 安装过程中运行环境检查。 |
| `MIGRATE_CONFIG` | `yes` | 写入 `.bak` 备份后删除废弃配置字段；设置为 `no` 可跳过。 |
| `SYNC_CONFIG_DEFAULTS` | `yes` | 追加当前版本缺失的默认配置项，不覆盖用户已有值；设置为 `no` 可跳过。 |
| `BOOTSTRAP_BASELINE` | `yes` | 没有基线时自动创建初始基线。 |
| `RUN_FIRST_SCAN` | `yes` | 执行一次 `scan --no-notify`，完整输出写入 `<LOG_DIR>/first-scan.log`。 |
| `VPS_NAME` | 空 | 可选的人类可读 VPS 名称，会写入 `agent.display_name` 并展示在通知标题中。 |
| `TELEGRAM_BOT_TOKEN` | 空 | 写入本地配置的 Telegram bot token。 |
| `TELEGRAM_CHAT_ID` | 空 | 写入本地配置的 Telegram chat ID。 |
| `TELEGRAM_MIN_SEVERITY` | `Medium` | Telegram 通知的最低等级。 |
| `RUN_NOTIFY_TEST` | `auto` | `auto`、`yes` 或 `no`；`auto` 会在提供 Telegram 环境变量时发送测试通知。 |
| `STORAGE_MAX_DATABASE_SIZE_MB` | 空 | 可选覆盖 `[storage].max_database_size_mb`；已有配置只会在传入该变量时被修改。 |
| `ACTIVE_RESPONSE_ENABLED` | 空 | 设置为 `yes` 会写入 `active_response.enabled = true`；主动响应默认关闭。 |
| `ACTIVE_RESPONSE_FIREWALL_BACKEND` | 空 | 可选 `auto`、`nftables` 或 `iptables`。 |
| `ACTIVE_RESPONSE_BLOCK_TTL_SECONDS` | 空 | 可选临时封禁 TTL。 |
| `ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN` | 空 | 可选单轮扫描新增封禁数量上限。 |
| `ACTIVE_RESPONSE_WEB_PROBE_BLOCK_THRESHOLD` | 空 | 可选高频 Web 探测封禁阈值。 |
| `ACTIVE_RESPONSE_WEB_EXPLOIT_BLOCK_THRESHOLD` | 空 | 可选重复 exploit 家族 Web 探测封禁阈值。 |
| `ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD` | 空 | 可选 SSH 爆破封禁阈值。 |
| `SERVICE_NAME` | `vps-sentinel` | systemd 服务名。 |
| `SERVICE_PATH` | `/etc/systemd/system/<SERVICE_NAME>.service` | systemd unit 路径。 |

## 更新

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh -o update.sh
sudo sh update.sh
```

更新脚本默认优先下载 release artifact，并先用 `--version` 验证二进制能否在当前机器执行；只有 artifact 不存在或不兼容时，才回退到源码构建。源码回退路径会拉取指定分支，并在 `cargo` 缺失或配置异常时通过 rustup 修复 Rust toolchain。两条路径都会保留已有配置、写入 `.bak` 备份后删除废弃配置字段、追加当前版本缺失的默认配置项但不覆盖已有值、校验最终配置、刷新 systemd unit、更新 `vs` 简写，并在服务正在运行或已启用时 restart 服务，确保新二进制真正生效。它默认不会刷新已有基线，避免 `authorized_keys` 等未确认漂移在更新时被静默吸收为可信状态。systemd unit 内容未变化时不会重写文件，避免例行更新造成 unit mtime 变化。只修改配置、不替换二进制时使用 `vps-sentinel reload` 或 `vs reload`。

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
| `INSTALL_DEPS` | `yes` | 设为 `no` 可跳过系统依赖安装。 |
| `INSTALL_METHOD` | `auto` | `auto` 和 `release` 都会优先下载 release artifact，如果 artifact 不存在或不能在当前机器执行，会回退源码构建；`source` 强制本地构建。 |
| `RELEASE_VERSION` | `latest` | `INSTALL_METHOD=auto` 或 `release` 时下载的 release tag。 |
| `RELEASE_ARTIFACT_URL` | 空 | 覆盖 release artifact 下载地址，适合镜像和本地 artifact 验证。 |
| `TARGET_TRIPLE` | 自动识别 | 覆盖 release artifact 目标，例如 `x86_64-unknown-linux-gnu` 或 `aarch64-unknown-linux-musl`。 |
| `INSTALL_SYSTEMD` | `auto` | 设为 `no` 可跳过 unit 刷新。 |
| `RESTART_SERVICE` | `auto` | `auto`、`yes` 或 `no`，控制是否 reload/restart 服务。 |
| `VALIDATE_CONFIG` | `yes` | 服务 reload/restart 前校验已有配置。 |
| `MIGRATE_CONFIG` | `yes` | 写入 `.bak` 备份后删除废弃配置字段；设置为 `no` 可跳过。 |
| `SYNC_CONFIG_DEFAULTS` | `yes` | 追加当前版本缺失的默认配置项，不覆盖用户已有值；设置为 `no` 可跳过。 |
| `REFRESH_BASELINE` | `no` | 只有在已经人工确认当前漂移可信时，才设置为 `yes` 让更新脚本刷新已有基线。 |

## 重载配置

修改 `/etc/vps-sentinel/config.toml` 后执行：

```bash
sudo vps-sentinel reload
sudo vs reload
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

已安装的简写：

| 命令 | 等价命令 |
| --- | --- |
| `vs ...` | `vps-sentinel ...` |

命令：

| 命令 | 含义 |
| --- | --- |
| `vps-sentinel init --path <path>` | 写入默认配置文件；目标文件已存在时会失败。 |
| `vps-sentinel init --path <path> --force` | 强制重写配置文件；生产环境已有调优配置时应谨慎使用。 |
| `vps-sentinel config validate --config <path>` | 只解析并校验配置，不运行采集器。编辑配置后建议先执行。 |
| `vps-sentinel config print-default` | 输出内置默认 TOML 配置。 |
| `vps-sentinel config diff-default --config <path>` | 对比当前配置和默认配置，列出缺失、未知和废弃字段。 |
| `vps-sentinel config migrate --config <path>` | 删除废弃字段，写入 `.bak` 备份，并验证迁移后的配置。 |
| `vps-sentinel config migrate --dry-run --config <path>` | 只显示将被删除的废弃字段，不修改文件。 |
| `vps-sentinel config sync-defaults --config <path>` | 追加当前版本缺失的默认配置项，保留已有值，写入 `.bak` 备份，并验证结果。 |
| `vps-sentinel config sync-defaults --dry-run --config <path>` | 只显示将被追加的默认配置项，不修改文件。 |
| `vps-sentinel doctor --config <path>` | 检查运行环境：root 可见性、Unix 目标支持、存储目录可写性、认证日志可见性。 |
| `vps-sentinel check --config <path>` | 执行一次采集和检测，但不持久化结果、不发送通知。适合快速检查和冒烟测试。 |
| `vps-sentinel scan --config <path>` | 执行一次完整扫描，持久化 raw events/findings，记录通知日志，应用去重，并发送已启用通知。 |
| `vps-sentinel scan --no-notify --config <path>` | 持久化扫描结果但不发送通知。适合启用通知前试运行。 |
| `vps-sentinel daemon --config <path>` | 按 `agent.scan_interval_seconds` 持续扫描，适合交给 systemd 运行。 |
| `vps-sentinel baseline create --config <path>` | 将当前可信状态写入 SQLite 基线。建议安装后和确认合法变更后执行。 |
| `vps-sentinel baseline show --config <path>` | 输出已保存的最新基线。 |
| `vps-sentinel baseline diff --config <path>` | 将当前状态与已保存基线对比并输出漂移。 |
| `vps-sentinel baseline reset --config <path>` | 清空已保存基线。清空后需要重新执行 `baseline create`。 |
| `vps-sentinel blocks list --config <path>` | 列出当前记录的主动响应封禁 IP；默认会校验防火墙规则是否仍然存在。 |
| `vps-sentinel blocks cleanup --config <path>` | 清理已过期封禁记录，以及 firewalld/ufw reload 或人工改动后防火墙规则已消失的失效记录。 |
| `vps-sentinel blocks unblock <ip> --config <path>` | 从可用防火墙后端和本地主动响应状态中解除单个 IP。 |
| `vps-sentinel blocks unblock-all --yes --config <path>` | 解除所有已记录的主动响应封禁；必须显式加 `--yes`，避免误操作。 |
| `vps-sentinel events list --config <path>` | 列出最近保存的 findings；可通过 `--limit <n>` 控制数量。 |
| `vps-sentinel events show <event_id> --config <path>` | 按 finding ID 输出单条已保存 finding 的 JSON。 |
| `vps-sentinel storage stats --config <path>` | 输出 SQLite 行数和数据库占用。 |
| `vps-sentinel storage prune --config <path>` | 手动执行普通扫描结束后同样会执行的保留期清理和数据库容量上限清理。 |
| `vps-sentinel storage clear <target> --yes --config <path>` | 手动清理指定历史数据，例如 `raw-events`、`findings`、`notifications`、`scan-runs`、`baselines` 或 `all-history`。 |
| `vps-sentinel storage vacuum --config <path>` | 不删除行，只执行 SQLite checkpoint/VACUUM/optimize。 |
| `vps-sentinel rules list` | 列出内置检测规则、默认等级和描述。 |
| `vps-sentinel rules test <rule_id>` | 检查指定内置规则 ID 是否存在并可加载。 |
| `vps-sentinel notify test --config <path>` | 构造一条 Info 级别测试 finding 并发送到已启用通知渠道，用于验证凭据和路由。 |
| `vps-sentinel reload --config <path>` | 校验配置并重载运行中的 systemd 服务。安装后可用 `vs reload` 简写。 |
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
max_database_size_mb = 256
```

`retention_days` 会按时间删除旧 raw events、findings、通知日志和扫描记录。`max_database_size_mb` 是额外的磁盘安全上限；当 SQLite 主库加 WAL/SHM 旁路文件超过上限时，程序会优先裁剪最旧的高容量数据，执行 WAL checkpoint 和 `VACUUM` 回收磁盘空间，并保留 baseline 与 rule_state。小磁盘 VPS 可以降低该值；如果需要更长本地取证历史，可以适当调大。

自动清理会在每次持久化扫描结束后执行。手动清理复用同一套存储逻辑：`vs storage prune` 会执行保留期清理和容量上限清理，`vs storage stats` 会显示行数和数据库占用，`vs storage clear notifications --yes` 可以清理通知发送历史，`vs storage clear all-history --yes` 会清理 raw events、findings、通知日志和扫描记录，但不会删除基线或规则状态。`baselines` 必须单独清理，因为这会影响后续漂移检测。

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

敏感日志完整性：

```toml
[log_integrity]
enabled = true
paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"]
truncate_drop_percent = 90
truncate_min_drop_bytes = 262144
rotation_grace_seconds = 900
```

`TAMPER-001` 检测敏感日志路径是否被软链到 `/dev/null`、`/tmp`、`/var/tmp`、`/dev/shm`、`/run` 等高风险目标。`TAMPER-002` 会把当前大小与本地规则状态中的上一次大小对比，并要求同时超过 `truncate_drop_percent` 和 `truncate_min_drop_bytes`。如果 `rotation_grace_seconds` 时间窗口内存在近期更新的轮转文件，会视为正常轮转上下文，不产生告警。`TAMPER-003` 只会在配置中的敏感日志曾经被扫描到、随后消失时报告，因此某个发行版原本就没有 `/var/log/auth.log` 不会仅因路径不存在而误报。

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
- 公网暴露判断会识别监听地址：`0.0.0.0`、`::` 和明确的公网可路由地址会按公网处理；loopback、RFC1918 IPv4、IPv6 ULA 和 link-local 地址不会按公网监听规则处理。
- `public_listen_allowlist` 作为旧配置兼容项处理，语义等同预期公网端口。只有 `[allowlist].listening_ports` 表示你明确希望压制该端口的所有网络告警。
- `NET-001` 只会在普通 TCP/TCP6 公网端口相对已保存基线新增时触发，不会对每次扫描都存在的稳定监听端口重复告警。普通 UDP 高端口默认视为动态流量，除非命中高风险服务端口或可疑监听进程规则。

进程指标策略：

```toml
[process]
deleted_executable_min_score = 70
behavior_min_score = 70
high_cpu_threshold_percent = 80.0
high_cpu_duration_seconds = 120
suspicious_socket_fd_threshold = 20
known_bad_tool_names = ["xmrig", "xmr-stak", "kinsing", "masscan", "zmap", "lolminer", "nbminer", "gminer", "t-rex", "trex", "teamredminer", "phoenixminer", "ethminer", "ccminer", "cpuminer", "bminer", "nanominer", "wildrig", "rigel", "bzminer"]
```

`deleted_executable_min_score` 控制何时产生 `PROC-002`。deleted executable 状态会结合路径、进程身份和命令行为评分；标准系统二进制在软件包升级后仍短暂运行，不会单独触发高危告警。`behavior_min_score` 控制 `PROC-005`，它会组合内核线程伪装、Web 根目录执行、隐藏可执行文件名、可疑工作目录、socket FD 活动、持续高 CPU、同一进程身份的 procfs 启动时间漂移和有效 root 权限等弱信号。启动时间漂移保存在本地规则状态中，只会增强已经可疑的进程；正常服务重启不会单独告警。`high_cpu_threshold_percent` 和 `high_cpu_duration_seconds` 基于 procfs 的生命周期 CPU 时间与进程年龄定义持续高 CPU；高 CPU 是辅助信号，不是单独告警条件。`suspicious_socket_fd_threshold` 控制 socket 持有数量达到多少时成为更强的行为信号。`known_bad_tool_names` 控制 `PROC-004` 的已知挖矿/扫描器指标词表。它会匹配 `exe_path`、`executable`、进程名和结构化 `argv[0]` 等进程身份字段，并兼容 `.exe` 后缀；缺少结构化身份的旧事件才回退到命令 token basename 匹配。同一个 PID 同时命中多个进程规则时，扫描器会保留一条最高价值 finding，并合并进程信号、风险原因、影响和处置建议。

GPU 指标策略：

```toml
[gpu]
enabled = true
nvidia_smi_path = "nvidia-smi"
command_timeout_seconds = 2
min_memory_mb = 256
mining_min_score = 80
mining_pool_ports = [3333, 3334, 3335, 4444, 5555, 7777, 8888, 9999, 14444, 16000, 18081, 18082]
```

`PROC-006` 只有在服务能运行 `nvidia-smi` 且能看到宿主机 GPU compute process 表时可用。单独 GPU 显存占用只作为正常工作负载上下文，不会告警。触发告警需要叠加配置中的 GPU 挖矿器身份、临时/deleted/匿名可执行文件、配置中的矿池端口、网络命令执行桥接，或隐藏 GPU 可执行文件伴随公网出站连接等证据。如果把 vps-sentinel 放在容器里运行，需要具备宿主机 PID/procfs 和 GPU runtime 可见性，否则无法准确检查宿主机 GPU 挖矿进程。

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

`WEB-001` 会识别 `.env`、`.git`、PHPUnit `eval-stdin.php`、CGI shell traversal、命令注入、PHP 配置写入 payload、SQL 注入、phpMyAdmin、WordPress admin、actuator、server-status 等探测家族。同一来源 IP 的相似路径会按探测家族和响应画像聚合。纯 404/400/301 目录爆破默认是 Low；敏感路径成功响应会升为 High；被拒绝的主动 exploit payload 保持 Medium 上下文。`error_burst_threshold` 控制未命中探测家族规则的同一来源 IP 在扫描窗口内产生多少次 403/404 后触发 `WEB-002`。小型私有服务可以调低，让探测更敏感；公开高流量站点如果自然存在大量缺失资源请求，可以适当调高，减少噪音。

主动响应策略：

```toml
[active_response]
enabled = false
firewall_backend = "auto"
block_ttl_seconds = 3600
max_blocks_per_scan = 20
web_probe_block_threshold = 25
web_exploit_block_threshold = 5
ssh_failed_login_block_threshold = 15
```

主动响应默认关闭，因为它会修改本机防火墙策略；需要设置 `active_response.enabled = true`，或安装时传入 `ACTIVE_RESPONSE_ENABLED=yes`，才会写入防火墙。启用后，扫描器会在扫描内合并/去重之后、跨扫描通知去重之前执行封禁，因此同一来源计数升高时，即使重复通知会被压制，也仍能触发封禁。SSH 封禁需要先形成 `SSH-003` finding，默认扫描窗口内 15 次失败触发封禁，而 SSH 告警阈值默认是 10。Web 封禁覆盖敏感路径成功响应、单次高置信 RCE 风格探测（例如命令注入、PHP 配置写入、CGI shell traversal、PHPUnit `eval-stdin.php`）、重复低置信 exploit 探测和高频错误爆发。安静时段和通知限流不会阻止封禁。后端优先使用 nftables，不可用时回退到 iptables/ip6tables。封禁是临时的：nftables 使用 set timeout，程序也会把封禁状态写入 SQLite，后续扫描会清理过期记录。只有公网可路由来源 IP 才会被考虑，`[allowlist].ips` 始终优先。如果某条 finding 触发了主动响应决策，同一条告警会展示动作状态、IP、后端、原因、到期时间，以及失败或跳过详情。

每次扫描都会先把主动响应状态和真实防火墙规则同步，再判断某个来源是否已经封禁。如果规则已过期、被 firewalld/ufw reload 清掉，或者被人工修改，程序会移除失效状态；如果该来源仍然满足高置信封禁条件，后续可以再次封禁。iptables 后端在插入前会用 `-C` 检查规则是否已存在，避免重复 DROP 规则；手动解除封禁会删除重复匹配规则。日常运维可以使用 `vs blocks list`、`vs blocks cleanup`、`vs blocks unblock <ip>` 和 `vs blocks unblock-all --yes`。

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

## 发布工程

仓库已经包含 release workflow，但发布由 tag 触发。推送 `v*` tag 时会构建 x86_64/aarch64 的 GNU 与 musl Linux tarball，校验包内容，生成 SHA-256 checksum，并基于 x86_64 GNU artifact 生成 `.deb` 与 `.rpm` 包后上传到 GitHub Release。安装脚本和更新脚本都支持通过 `INSTALL_METHOD=auto` 或 `INSTALL_METHOD=release` 消费这些 artifact；安装前会用 `--version` 验证二进制能否在当前机器执行，不能执行时回退源码构建。`RELEASE_ARTIFACT_URL` 可用于镜像或本地安装包验证。

在正式 release 存在前，`INSTALL_METHOD=auto` 和 `INSTALL_METHOD=release` 会自动回退到源码构建路径。包安装仍会创建 `/etc/vps-sentinel/config.toml`、安装 `vs` 简写和辅助脚本、校验配置、初始化基线，并在 systemd 可用时安装服务。

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
- `SSH-006`：`authorized_keys` 或 `authorized_keys2` 权限不安全，或软链指向高风险目标。
- `USER-002`：UID 0 用户新增或变更。
- `TAMPER-001`：敏感认证/登录日志路径被重定向到高风险目标。
- `TAMPER-002`：敏感认证/登录日志在没有轮转上下文的情况下被大幅截断。
- `TAMPER-003`：曾经出现过的敏感认证/登录日志文件消失。
- `PERSIST-002`：可疑启动命令。
- `PROC-002`：达到风险评分阈值的 deleted executable 进程。
- `PROC-003`：网络命令执行桥接。
- `PROC-005`：可疑进程行为聚类。
- `PROC-006`：可疑 GPU 计算或挖矿进程。
- `NET-001`：相对基线新增的公网监听端口。
- `NET-002`：公网监听端口背后的进程相对基线发生变化。
- `NET-003`：公网监听端口背后存在可疑进程。
- `FILE-002`：WebShell 风格文件内容。
- `CONFIG-003`：高危服务端口公网暴露。

## 部署说明

部分采集器需要 root 级别可见性。如果不是 root 运行，`doctor` 会报告可见性降低，相关模块会降级而不是崩溃。

作为常驻 agent，运行时资源占用较小。在当前验证 VPS 上，默认 60 秒扫描循环下 daemon 进程 RSS 约为 10-13 MiB。systemd cgroup 的 `MemoryCurrent` 可能明显更高，从几十 MiB 到几百 MiB 都可能出现，因为 Linux 可能把近期触达的文件缓存和 cgroup 内存统计计入服务。实际内存压力会受日志尾部大小、文件完整性路径范围、内核统计方式和已启用通知渠道影响；判断 daemon 自身稳定占用时应优先看进程 RSS。raw event 存储会对重复事实使用稳定键，因此重复扫描同一段日志尾部或未变化主机状态时会覆盖旧行，而不是每分钟追加相同数据。SQLite 存储还会受 `storage.max_database_size_mb` 约束；超过上限时会裁剪旧的高容量数据并执行 `VACUUM` 回收磁盘空间。

systemd unit 使用：

- `NoNewPrivileges=true`
- `ProtectSystem=full`
- `ProtectHome=read-only`
- 仅允许配置的数据目录和日志目录写入

更多内容见 [docs/deployment.md](docs/deployment.md)。

## 隐私与安全边界

- 默认不上报日志；
- 默认不启用通知渠道；
- 默认不杀进程、不封 IP、不删除文件；只有显式设置 `[active_response].enabled = true` 时才会写入防火墙封禁规则；
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
