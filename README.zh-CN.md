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
| SSH 监控 | 解析 Debian/Ubuntu 与 RHEL 系认证日志；检测 root 登录、密码登录、普通成功登录、爆破模式、爆破后同源成功登录、`authorized_keys`/`authorized_keys2` 基线漂移、SSH key 文件权限异常和高风险软链。 |
| 基线漂移 | 为用户、SSH key、关键文件、持久化项和监听端口创建本地基线，并在后续扫描中对比变化；支持按审批 key 确认已审核漂移后刷新基线；近期软件包活动会作为上下文附加到漂移告警中。 |
| 用户与权限 | 检测新增用户、UID 0 用户、权限相关用户变化。 |
| 文件完整性 | 监控关键路径和 Web 根目录；对限定大小内文件做哈希和内容扫描；检测关键文件变化、Web 目录可执行脚本、达到风险评分阈值的 WebShell 风格特征组合。 |
| 日志完整性 | 监控敏感认证/登录日志文件，识别高风险软链和没有近期轮转上下文的大幅截断。 |
| 持久化检查 | 监控 cron、systemd、shell profile、`ld.so.preload` 等启动相关位置，并对可疑启动命令进行风险评分。 |
| 进程和 GPU 检查 | 读取 procfs argv、父进程、可执行路径、工作目录、UID 上下文、socket FD 数、CPU 生命周期指标、procfs 启动时间漂移、结构化 cgroup/container 上下文、systemd unit/ExecStart、可执行文件 owner/size/hash、软件包归属、出站连接画像，并通过 `nvidia-smi` 读取 NVIDIA GPU 计算进程、通过 `rocm-smi` 读取 AMD/ROCm GPU 进程事实，识别达到风险评分阈值的可疑可执行路径、deleted executable、网络命令执行桥接、可疑行为聚类、已知挖矿/扫描器身份和可疑 GPU 计算负载。 |
| 网络检查 | 读取监听 socket 与所属进程；附加进程上下文和防火墙状态；检测高风险公网服务、可疑监听进程、监听 owner 基线漂移和新增公网监听。22/80/443 等预期端口会降低噪音，但不会被无脑信任。 |
| Web 日志 | 解析常见 access log、JSON access log、Nginx 风格 error log 请求上下文和近期 `.1` 轮转日志；可从可信代理/CDN 的 JSON 字段还原真实客户端 IP，无法还原时不会把代理边缘当攻击者封禁；将自动化探测归类为攻击家族，并按来源聚合同类路径，避免按路径刷屏。 |
| Rootkit 信号 | 采集轻量级本地指标，用于发现隐藏进程和可疑 procfs 行为。 |
| Docker 上下文 | 检测 Docker 可用性并给出初始容器攻击面提示，不要求 Docker 写权限。 |
| 事件关联 | 按来源 IP、路径、进程、分类和时间窗口把相关 finding 聚合为 incident，并生成扫描窗口内的攻击时间线。 |
| 攻击指纹 | 从 Web、SSH、进程和持久化 finding 中提取归一化攻击指纹；保存精确 hash 和 SimHash 近似键；即使攻击源 IP 变化，也能按攻击手法聚合，并提供指纹时间线、解释和人工判定。 |
| 证据和规则治理 | 统一归一化来源 IP、用户、路径、计数和探测家族等常见 evidence 字段，并维护内置规则 owner、分类、响应范围和证据契约矩阵。 |
| 服务画像 | 维护监听服务 owner 画像，发现新增服务或已知监听端口背后的可执行文件漂移；支持按进程身份建模动态 UDP/UDP6 高位端口，并忽略可配置的客户端临时 UDP 与本地 SSH 转发监听。 |
| 高级采集 | 默认启用 auditd 日志采集和 eBPF JSONL/命令桥接入口；auditd 事件可识别 procfs 快照可能错过的短生命周期网络命令执行和非交互式提权 shell 执行。 |
| 外部规则 | 支持 Sigma-like TOML 事件规则、外部规则校验和可选 YARA CLI 扫描；规则引擎默认启用，但只有配置了规则路径或扫描根目录后才会实际运行。 |
| 威胁情报 | 可选用本地或远程 indicator 对 IP、路径、域名、哈希做证据增强；命中只是辅助证据，不会单独触发封禁。 |
| 多 VPS 视图 | 导出和导入轻量级节点快照，方便在一个本地 SQLite 中查看多台 VPS 摘要。 |
| 维护模式 | 支持有时限的维护窗口，在计划升级期间压制低/中危基线漂移和交互式 SSH 登录噪声，但不隐藏爆破或其它攻击信号。 |
| 本地存储与资源控制 | 使用 SQLite 存储 raw events、findings、baseline、扫描记录和自包含通知日志；重复 raw fact 使用稳定存储键，默认不持久化完整原始日志行，普通 Web 访问事件默认不入库，并提供保留期、数据库容量和运行时预算上限，避免无限增长。 |
| 噪声控制 | 支持白名单、最低告警级别、finding 去重和保留周期。 |
| 主动响应 | 默认启用，以 `observe`、`balanced` 或 `strict` 策略处理高置信公网来源 IP；不同证据层会调整临时 TTL 和永久升级阈值，最终写防火墙仍通过 nftables 或 iptables，并带公网 IP、白名单和可信代理归因保护。 |
| 通知告警 | 支持 Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| 运维部署 | 单 CLI 二进制、`vs` 简写、JSON 日志、systemd unit、一键安装脚本、更新脚本、内置重载命令、停止脚本、配置迁移、报告和处置建议命令。 |

## 检测模型

命令执行相关规则是行为画像规则，不是简单的工具名或端口名匹配。vps-sentinel 会从 `/proc/<pid>/cmdline` 保留结构化 argv，构建命令画像，并且只有在网络通道、shell 目标、`SYSTEM:` 命令执行器、fd 复制、内联 socket 代码、TTY 分配等高风险特征组合出现时，才触发 `PROC-003` 或 `NET-003`。

已知挖矿/扫描器检测会更克制：`PROC-004` 只会用可执行文件路径、进程名、结构化 `argv[0]` 等进程身份字段匹配 `xmrig`、`masscan`、`zmap` 等已知工具名，并兼容 `.exe` 后缀。结构化进程身份可用时，普通命令参数里出现这些词不会直接告警。当 procfs CPU 数据可用时，告警会附带生命周期平均 CPU、进程年龄和累计 CPU 秒数；持续高 CPU 会增强判断，但单独高 CPU 不会触发告警。

可执行路径、deleted executable 和启动项告警也采用评分模型。`PROC-001` 会把常见落地目录作为强证据，但会把 `/run` 这类运行时状态路径作为弱上下文，必须叠加隐藏文件名、root 上下文、socket、公网出站、网络执行桥、持续高 CPU、已知挖矿/扫描器身份等信号才会告警。`PROC-002` 需要同时具备可疑可执行路径、memfd 或匿名文件、隐藏的非标准可执行文件、网络执行桥、已知挖矿/扫描器身份等风险特征；系统升级后遗留的 `systemd`、`dockerd`、`python3` 等标准路径 deleted 进程，如果没有其它风险特征，会被视为维护上下文。`PERSIST-002` 会对启动命令中的下载后管道执行、临时路径自启动、base64 解码后 shell 执行、网络到 shell 执行桥等组合进行评分；单独的 `bash -c` 服务包装不会触发默认阈值。

文件和持久化基线漂移不会因为存在软件包活动就被自动压制。agent 会采集近期 apt/dpkg/yum/dnf/pacman/apk 日志活动，并把该上下文附加到 `FILE-001`、`PERSIST-001` 和 `PERSIST-003` 的证据与建议中。这样既不会隐藏真实漂移，也方便先对照软件包日志确认，再决定是否刷新基线。

SSH key 文件状态检测独立于基线漂移。采集器会读取 OpenSSH 默认 key 路径，并解析 `sshd_config` 及 `sshd_config.d/*.conf` 中的 `AuthorizedKeysFile`，因此自定义 key 文件位置也会被监控。`authorized_keys` 内容变化仍按持久化漂移告警；当前状态只有在存在明确文件系统证据时才单独告警，例如 group/other 可写权限，或软链指向 `/dev/null`、临时目录、共享内存目录、运行时目录等高风险位置。

敏感认证/登录日志完整性是有状态检测。vps-sentinel 会记录上一次扫描时的文件类型和大小；如果发现 `/var/log/auth.log -> /dev/null` 这类高风险重定向会立即告警；如果日志文件大幅变小，只有同时超过配置的大小和比例阈值，并且没有 `auth.log.1` 这类近期轮转文件时才告警；如果某个配置中的敏感日志上一轮存在、这一轮消失，也会告警。因此正常 logrotate 不会刷屏，而入侵后的清理或删除日志行为可以被看到。

WebShell 内容检测也采用评分模型，不再因为单个 marker 直接告警。合法管理脚本中单独出现 `eval` 默认达不到阈值；Web 脚本中的命令执行、动态执行叠加编码 payload、命令执行叠加编码、Web 脚本中出现大块编码内容等组合才会触发 `FILE-002`。

`PROC-005` 用于补充识别已改名、轻度伪装、没有明显临时路径或网络 shell 桥接的可疑进程。它组合内核线程伪装、Web 根目录执行、隐藏可执行文件名、可疑工作目录、socket FD 活动、持续高 CPU、同一进程身份的 procfs 启动时间漂移、有效 root 权限等弱信号。默认阈值下单个弱信号不会独立告警，启动时间漂移也只会在已经存在其它可疑上下文时加权。

`PROC-006` 在宿主机服务能看到 `nvidia-smi` 或 `rocm-smi` 时提供 GPU 挖矿检测。采集器读取当前 GPU compute apps，并按 PID 与 procfs、出站连接事实关联。GPU 显存占用本身不会告警，因为正常 CUDA、ROCm、AI 训练、渲染、转码任务也可能大量占用显存；该规则需要叠加更强证据，例如已知 GPU 挖矿器身份、配置中的矿池远端端口、临时或 deleted executable、匿名/memfd 可执行文件、网络命令执行桥接，或隐藏 GPU 可执行文件伴随公网出站连接。看不到宿主机 GPU/进程命名空间的容器化部署，不在该信号覆盖范围内。

进程和监听端口告警会尽可能带出完整证据链：父进程、systemd unit、systemd `ExecStart`、可执行文件 UID/GID、文件大小、有限 BLAKE3 hash、dpkg/rpm/pacman/apk 软件包归属、cgroup/container 上下文、procfs 启动时间漂移、出站连接数量、公网出站连接数量和远端端口画像。软件包归属查询与防火墙探测都设置了短超时和单次扫描缓存，因此平台工具缺失或响应慢时只会缺少该证据，不会阻塞扫描。这些字段是辅助证据或弱信号。例如 systemd `ExecStart` 不匹配不会单独告警，但如果监听端口 owner 已经相对基线变化，它可以把普通 owner 变化升级为可疑监听进程。

防火墙状态是辅助判断，不是唯一依据。端口暴露仍以 `/proc/net/*` 的内核 socket 状态为准；`ufw`、`firewalld`、`nftables` 和 `iptables` 状态会作为证据附加，帮助判断公网监听是否真的可能被外部访问。

每个 finding 都会补充统一 0-100 风险评分，评分来自严重等级、检测器置信度、规则自身评分、主动响应上下文、证据强度和可选威胁情报命中。证据评分是无状态的，只处理当前 finding：来源、数量、进程、网络、GPU、反取证和主动响应证据会提高置信度，软件包/维护上下文会降低容易误报的漂移噪声。扫描窗口内的时间线会在主动响应标注之后生成，按来源 IP、路径和进程身份聚合相关 finding，因此可以看到多阶段攻击链，而不需要常驻保存大型关系图。

攻击指纹会在 finding 合并和风险评分之后生成。指纹引擎会从 Web 探测、SSH 爆破用户字典、进程行为、持久化/文件变化 finding 中提取稳定特征；归一化数字 ID、路径变体和 URL 编码形式等易变内容；生成精确 BLAKE3 hash 和 64 位 SimHash 近似键；并把有界 observation 保存到 SQLite。来源 IP 不参与精确指纹计算，因此攻击者更换 IP 后仍可能按攻击手法聚合。`vs fingerprints explain <id>` 会输出该聚类的风险层级、强信号、限制条件、主要特征、近期观察和建议动作。如果启用 `privacy.mask_ip = true`，指纹库中保存的是稳定 IP 哈希而不是真实 IP。重复出现且评分较高的指纹可以给当前 finding 增加主动响应提示，但最终写防火墙仍然必须经过公网 IP、白名单、可信代理归因、响应策略和单轮封禁上限等安全过滤。

evidence 会在后续关联和响应逻辑消费前统一归一化。`ip`、`remote_ip`、`remote_addr` 等常见别名会归一到 `source_ip`；列表值会稳定去重；布尔值和计数字段会规范化；路径和命令字段会在后续资源预算中被限制大小。这样通知、incident、攻击指纹、主动响应和存储不会各自解释同一个字段。

内置规则元数据包含所有权矩阵：每条规则都有 owner、分类、默认等级、响应范围和预期 evidence 字段。规则引擎测试会校验矩阵兼容性，因此后续新增规则必须落到明确模块，不能悄悄形成重复或边界不清的规则族。`vs rules matrix` 可以输出该矩阵，方便审计和集成。

人工反馈会进入检测闭环。`vs fingerprints mark-benign <id>` 会阻止该指纹产生基于指纹的主动响应提示，并且对携带 benign 判定的 finding 抑制自动主动封禁；`mark-malicious` 会让后续命中更容易产生响应提示，但最终写防火墙仍然必须经过公网 IP、白名单、可信代理归因、响应策略和单轮封禁上限等安全过滤。

扫描管线会通过事件 kind/source 索引、SSH 失败日志按来源 IP 聚合、Web/SSH 日志时间窗口和每轮事件上限、以及基线对比后丢弃稳定普通文件快照来控制内存。文件变化、SSH key 文件不安全状态、WebShell marker 和 Web 目录可执行/脚本文件仍会保留并进入检测。

运行时资源预算会在响应处理前、响应注解后执行。如果主机在一轮扫描中产生极端数量的 finding 或 evidence 字段，vps-sentinel 会按严重等级、统一风险评分、置信度和时间保留高价值记录。evidence 会优先保留来源 IP、主动响应字段、攻击指纹、路径、进程身份、探测家族和风险评分，然后再丢弃低价值上下文，从而保护小内存 VPS 和通知预算。

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
| 文件和持久化漂移 | 使用 SQLite 保存本地基线，后续扫描做快照 diff；同一路径的文件/持久化 finding 会合并；对 SSH key、systemd unit、cron、sudoers 保存语义画像，并按敏感度、暴露面、变更幅度、语义变化和运维上下文生成漂移评分与复核层级。 | 能发现真实漂移，同时减少合法软件更新时的判断成本；SSH 密钥、UID 0、preload、高风险启动命令和 sudo 权限变化在确认前仍保持高风险。 |
| 日志篡改信号 | 采集敏感日志文件快照并与本地规则状态对比；高风险软链立即告警，日志截断需要满足配置的比例和字节阈值且没有近期轮转文件；曾经出现过的配置日志消失也会报告。 | 识别把认证日志重定向到 `/dev/null`、清空日志或删除日志等反取证行为，同时避免正常 logrotate 误报。 |
| WebShell 内容 | 对限定大小内的文件内容提取风险 marker，并结合 Web 路径、脚本类型和 marker 组合评分。 | 单个弱 marker 默认不告警，但能识别经典 Web 命令执行和编码 payload 组合。 |
| Web 探测 | `WEB-001` 按来源 IP 聚合，并在证据中保留全部探测家族、响应画像、样例路径、方法、状态码和可信代理上下文。404 PHPUnit 目录爆破等未命中探测默认为 Low；敏感路径成功响应或受保护的 exploit 路径会提升等级。 | 扫描器命中大量路径变体时只生成一条可读 finding，而不是几十条 Telegram 消息；CDN/反代地址不会在缺少真实客户端 IP 时被当作攻击源。 |
| 进程和 GPU 风险 | 读取 procfs argv、父进程、可执行路径、cwd、UID/EUID、deleted 状态、socket FD 数、生命周期 CPU 指标、启动时间漂移、cgroup/container 上下文、systemd unit/ExecStart、可执行文件元数据/hash、软件包归属、出站连接画像和 NVIDIA GPU 计算进程状态，并按规则评分、白名单、规则状态和同 PID 信号聚合处理。`PROC-001` 对可疑可执行路径做评分，不会只按路径机械放行或告警；`PROC-005` 必须先出现伪装、隐藏、可疑目录或 Web 路径等主风险信号，socket、出站连接、重启漂移和 root 上下文只能辅助加权；`PROC-006` 需要 GPU 计算活动叠加挖矿或高风险运行证据。 | 识别可疑可执行路径、可疑 deleted executable、网络 shell 桥接、已知挖矿/扫描器身份、改名行为聚类和可疑 GPU 挖矿负载，同时避免 PID、CPU、GPU、连接计数等波动字段、正常高连接业务服务或普通公网出站 fanout 导致重复/误报消息。 |
| 网络监听 | 解析 `/proc/net/tcp*` 和 `/proc/net/udp*`，通过 `/proc/<pid>/fd` 反查进程，与监听 owner 基线对比，附加进程/防火墙/出站连接上下文，并优先报告可疑 owner 行为而不是普通端口暴露。 | 22/80/443 等预期端口只降低通用噪音；进程变化或可疑进程仍会告警，高风险端口画像和防火墙状态会作为证据保留。 |
| 通知 | 将统一 `Finding` 模型按渠道模板渲染：Telegram HTML、Email HTML+纯文本、Markdown 或纯文本。 | 消息包含 VPS 名称、规范化时间、本地化字段、证据、影响和建议。 |
| 噪声控制 | 使用扫描内去重、跨扫描去重、状态提醒间隔、安静时段和小时级通知预算。 | 减少重复消息，同时保留高价值告警的可见性。 |
| 主动响应 | 在扫描内 finding 合并/去重后、跨扫描通知去重前评估封禁候选；只有不在 `[allowlist].ips` 中的公网 IP 才可能被封，且无法还原真实客户端 IP 的可信代理/CDN 来源不会成为封禁候选。Web/SSH/攻击指纹响应分层会按证据强度调整临时 TTL 和永久升级阈值。 | 可把明显扫描源丢进防火墙，同时避免每条告警都变成破坏性动作或误封 CDN 边缘。 |
| 响应策略 DSL | 在检测器产生主动响应候选之后应用配置化策略；策略可匹配规则 ID 或分类，并按最低严重等级、置信度、统一评分决定观察、临时封禁或永久封禁。 | 检测逻辑和响应决策解耦，用户无需改代码即可调节封禁策略。 |
| 攻击指纹 | 从 Web/SSH/进程/持久化 finding 中提取归一化特征，生成精确 hash 和 SimHash 近似键，保存有界 observation，把指纹证据写回 finding，并按需解释聚类依据。 | 按攻击手法聚合换 IP 的攻击，提供 `vs fingerprints` 时间线、解释和人工判定，并可让重复确认的攻击手法进入主动响应，而不是依赖 IP 黑名单。 |
| 证据字段模型 | 对常见 evidence 别名做 canonical 归一化，规范列表、布尔值和计数字段，并让扫描、攻击指纹、主动响应和测试复用同一套 evidence 访问入口。 | 避免 `ip`、`remote_addr`、`source_ip` 在不同模块里含义不一致，后续新增规则更容易保持一致。 |
| 规则所有权矩阵 | 每条内置规则声明 owner、分类、响应范围和预期 evidence 字段，并通过测试校验 owner/category 和 canonical 字段。 | 让规则按模块清晰归属，避免重复、混乱或作用范围不明的规则进入代码。 |
| 资源预算 | 按严重等级、统一评分、置信度和时间排序保留高价值 finding，并限制 finding 数量、evidence 数量和 evidence 值大小。 | 控制内存、通知量和存储体积，同时优先保留关键安全证据。 |
| Incident 与时间线 | 按 IP、路径、进程、可执行文件 hash、systemd unit、分类和时间窗口聚合相关 finding，提供 `incidents list/show/timeline`，并为多阶段链路生成按攻击阶段排序的扫描窗口时间线 finding。 | 把孤立 finding 组织成可读攻击链，同时保留原始 finding。 |
| 服务画像 | 保存监听服务的地址、端口、协议、进程名、可执行文件、命令行和暴露分类；动态 UDP/UDP6 高位端口可按进程身份建模，并忽略可配置的客户端临时 UDP 与本地 SSH 转发监听。 | 不盲信 80/443，也能发现常见端口背后的服务 owner 漂移，同时避免合法动态 UDP 端口每次变化都告警。 |
| 高级证据 | 可选 auditd、eBPF JSONL bridge、Sigma-like TOML 规则、外部规则校验、YARA CLI 和威胁情报 indicator 都进入同一 RawEvent/Finding 模型。 | 平台支持时可增加更深证据，默认安装仍保持轻量兼容。 |
| 维护与多 VPS 运维 | 在本地 rule state 中保存有界维护状态和 fleet 节点快照。 | 计划升级时压制低/中危漂移和预期的交互式 SSH 登录噪声，同时保留 SSH 爆破和攻击链信号，并可本地汇总多台 VPS 摘要。 |

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
| `ACTIVE_RESPONSE_ENABLED` | 空 | 覆盖 `active_response.enabled`；新默认配置会开启主动响应，升级时保留用户已有配置。需要禁用防火墙写入时设为 `no`。 |
| `ACTIVE_RESPONSE_FIREWALL_BACKEND` | 空 | 可选 `auto`、`nftables` 或 `iptables`。 |
| `ACTIVE_RESPONSE_BLOCK_TTL_SECONDS` | 空 | 可选临时封禁 TTL。 |
| `ACTIVE_RESPONSE_MAX_BLOCKS_PER_SCAN` | 空 | 可选单轮扫描新增封禁数量上限。 |
| `ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED` | 空 | 可选 `yes`/`no` 覆盖反复触发来源的永久封禁升级开关。 |
| `ACTIVE_RESPONSE_PERMANENT_BLOCK_THRESHOLD` | 空 | 可选同一 IP 触发多少次封禁候选后升级为永久封禁。 |
| `ACTIVE_RESPONSE_PERMANENT_BLOCK_WINDOW_SECONDS` | 空 | 可选重复触发计数窗口。 |
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

更新脚本默认优先下载 release artifact，并先用 `--version` 验证二进制能否在当前机器执行；只有 artifact 不存在或不兼容时，才回退到源码构建。源码回退路径会拉取指定分支，并在 `cargo` 缺失或配置异常时通过 rustup 修复 Rust toolchain。两条路径都会保留已有配置、写入 `.bak` 备份后删除废弃配置字段、追加当前版本缺失的默认配置项但不覆盖已有值、校验最终配置、刷新 systemd unit、更新 `vs` 简写，默认执行一次 `scan --no-notify` 预热去重和主动响应状态，并在服务正在运行或已启用时 restart 服务，确保新二进制真正生效。它默认不会刷新已有基线，避免 `authorized_keys` 等未确认漂移在更新时被静默吸收为可信状态。systemd unit 内容未变化时不会重写文件，避免例行更新造成 unit mtime 变化。只修改配置、不替换二进制时使用 `vps-sentinel reload` 或 `vs reload`。

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
| `POST_UPDATE_SCAN` | `yes` | 服务重启前执行一次 `scan --no-notify`，减少升级期间的重复通知。 |

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
| `vps-sentinel status --config <path>` | 查看启用功能、存储占用、最近 24 小时扫描健康度、通知渠道和主动响应封禁数量；加 `--json` 可用于自动化。 |
| `vps-sentinel doctor --config <path>` | 检查运行环境，并输出 root 可见性、procfs、SSH 日志、auditd、eBPF bridge、包归属、systemd、防火墙后端、GPU 工具和 YARA 的能力矩阵。 |
| `vps-sentinel check --json --config <path>` | 执行一次采集和检测，但不持久化结果、不发送通知、不执行主动响应；省略 `--json` 输出文本摘要。 |
| `vps-sentinel scan --config <path>` | 执行一次完整扫描，持久化精简 raw events/findings，记录通知日志，应用去重，发送已启用通知，并输出 RSS 与事件来源诊断。 |
| `vps-sentinel scan --no-notify --json --config <path>` | 持久化扫描结果但不发送通知、不执行主动响应；适合启用通知前试运行。省略 `--json` 输出文本摘要。 |
| `vps-sentinel daemon --config <path>` | 按 `agent.scan_interval_seconds` 持续扫描，适合交给 systemd 运行。 |
| `vps-sentinel baseline create --config <path>` | 将当前可信状态写入 SQLite 基线。建议安装后和确认合法变更后执行。 |
| `vps-sentinel baseline show --config <path>` | 输出已保存的最新基线。 |
| `vps-sentinel baseline diff --json --config <path>` | 将当前状态与已保存基线对比，并输出可审核的漂移审批 key、风险评分、层级、复核动作和原因。 |
| `vps-sentinel baseline approve <key\|all> --config <path>` | 将一个待处理漂移项，或当前全部漂移项，标记为已审核可接受。 |
| `vps-sentinel baseline refresh --config <path>` | 只把已审批漂移项应用到新的基线快照；只有确认当前主机状态全部可信时才使用 `--all`。 |
| `vps-sentinel baseline reset --config <path>` | 清空已保存基线。清空后需要重新执行 `baseline create`。 |
| `vps-sentinel blocks list --config <path>` | 列出当前记录的主动响应封禁 IP；默认会校验防火墙规则是否仍然存在。 |
| `vps-sentinel blocks why <ip> --config <path>` | 解释某个 IP 为什么被封禁：后端、TTL/永久状态、防火墙校验、来源规则、finding ID、封禁原因和已保存证据；加 `--json` 可用于自动化。 |
| `vps-sentinel blocks cleanup --config <path>` | 清理已过期封禁记录，以及 firewalld/ufw reload 或人工改动后防火墙规则已消失的失效记录。 |
| `vps-sentinel blocks unblock <ip> --config <path>` | 从可用防火墙后端和本地主动响应状态中解除单个 IP。 |
| `vps-sentinel blocks unblock-all --yes --config <path>` | 解除所有已记录的主动响应封禁；必须显式加 `--yes`，避免误操作。 |
| `vps-sentinel events list --config <path>` | 列出最近保存的 findings；可通过 `--limit <n>` 控制数量。 |
| `vps-sentinel events show <event_id> --config <path>` | 按 finding ID 输出单条已保存 finding 的 JSON。 |
| `vps-sentinel findings list --json --config <path>` | 列出最近保存的 findings，包含等级、置信度、规则 ID 和对象。 |
| `vps-sentinel findings explain <finding_id> --json --config <path>` | 解释单条 finding，展示规则元数据、证据、置信度、影响和建议。 |
| `vps-sentinel fingerprints list --config <path>` | 列出攻击指纹，包含类型、评分、观察次数、来源数量、主机数量、判定和摘要。 |
| `vps-sentinel fingerprints show <fingerprint_id> --config <path>` | 查看单个攻击指纹，包括精确 hash、SimHash、特征、来源数量、规则和时间戳。 |
| `vps-sentinel fingerprints timeline <fingerprint_id> --config <path>` | 查看某个指纹最近的命中观察记录。 |
| `vps-sentinel fingerprints explain <fingerprint_id> --config <path>` | 解释一个攻击指纹聚类的风险层级、强信号、限制条件、归一化特征、近期观察和建议动作。 |
| `vps-sentinel fingerprints mark-benign <fingerprint_id> --config <path>` | 将指纹标记为正常，后续匹配 finding 不会产生指纹响应提示或自动主动封禁。 |
| `vps-sentinel fingerprints mark-malicious <fingerprint_id> --config <path>` | 将指纹标记为确认恶意；后续命中且存在公网来源 IP 时可产生主动响应提示。 |
| `vps-sentinel fingerprints export --redacted --config <path>` | 以 JSON 导出指纹和近期 observation，可选择脱敏来源 IP。 |
| `vps-sentinel incidents list --config <path>` | 列出由相关 findings 聚合成的 incident；可加 `--json` 输出结构化结果。 |
| `vps-sentinel incidents show <incident_id> --config <path>` | 查看单个 incident 的对象、分类、规则和摘要。 |
| `vps-sentinel incidents timeline <incident_id> --config <path>` | 输出单个 incident 的 finding 时间线。 |
| `vps-sentinel service-profile list --config <path>` | 查看已保存的监听服务画像；可加 `--json`。 |
| `vps-sentinel service-profile refresh --config <path>` | 在确认服务变化合法后，用当前监听状态刷新服务画像。 |
| `vps-sentinel report show --config <path>` | 本地预览默认今日报告；加 `--json` 输出结构化数据，或用 `--period last24h` 查看过去 24 小时。 |
| `vps-sentinel report send --config <path>` | 通过所有已启用通知渠道发送默认今日报告；这是显式报告命令，不受各渠道最低告警等级过滤。 |
| `vps-sentinel maintenance start --duration-seconds <n> --config <path>` | 开启有时限维护窗口，用于计划变更期间压制低/中危基线漂移和交互式 SSH 登录噪声。 |
| `vps-sentinel maintenance status --config <path>` | 查看维护模式是否启用。 |
| `vps-sentinel maintenance end --config <path>` | 结束手动开启的维护窗口。 |
| `vps-sentinel fleet export --config <path>` | 导出本节点轻量级 fleet 快照到 stdout 或 `fleet.export_path`。 |
| `vps-sentinel fleet ingest <path> --config <path>` | 导入另一台节点的 fleet 快照到本地 SQLite。 |
| `vps-sentinel fleet list --config <path>` | 列出已导入的 fleet 节点快照。 |
| `vps-sentinel advice finding <finding_id> --config <path>` | 生成单条 finding 的处置建议。 |
| `vps-sentinel advice incident <incident_id> --config <path>` | 生成 incident 级处置建议。 |
| `vps-sentinel storage stats --config <path>` | 输出 SQLite 行数和数据库占用。 |
| `vps-sentinel storage prune --config <path>` | 手动执行普通扫描结束后同样会执行的保留期清理和数据库容量上限清理。 |
| `vps-sentinel storage clear <target> --yes --config <path>` | 手动清理指定历史数据，例如 `raw-events`、`findings`、`notifications`、`scan-runs`、`baselines` 或 `all-history`。 |
| `vps-sentinel storage vacuum --config <path>` | 不删除行，只执行 SQLite checkpoint/VACUUM/optimize。 |
| `vps-sentinel rules list` | 列出内置检测规则、默认等级和描述。 |
| `vps-sentinel rules matrix --json` | 输出内置规则所有权矩阵，包含 owner、分类、响应范围和 evidence 字段。 |
| `vps-sentinel rules test <rule_id>` | 检查指定内置规则 ID 是否存在并可加载。 |
| `vps-sentinel rules validate-external <path...>` | 部署前校验外部 TOML 规则，检查解析错误、缺少条件、重复 ID 和未知分类；加 `--json` 可用于 CI。 |
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

性能控制：

```toml
[performance]
collect_memory_metrics = true
store_raw_log_lines = false
store_all_web_access_events = false
max_stored_field_bytes = 4096
```

`collect_memory_metrics` 会在扫描报告和 JSON 输出中记录进程 RSS 的 before/after 值。`store_raw_log_lines = false` 会保留 IP、用户、路径、状态码、方法等结构化字段，但不把完整原始日志行写入 raw event 存储。`store_all_web_access_events = false` 默认只保存能支撑 Web 探测证据的 Web access 事件，避免公网网站把普通 404/静态资源访问写满 SQLite。`max_stored_field_bytes` 会截断异常大的落库字段，不影响本轮内存中的检测输入。

运行时资源预算：

```toml
[resource_budget]
enabled = true
max_findings_per_scan = 500
max_evidence_items_per_finding = 64
max_evidence_value_bytes = 2048
```

`resource_budget` 控制检测后 finding 的内存规模。超过 `max_findings_per_scan` 时，会按严重等级、统一风险评分、置信度和时间排序，优先保留高价值 finding。evidence 数量和值大小限制用于避免单条 finding 过大而拖累内存、通知 payload 或 SQLite 行；来源 IP、主动响应字段、攻击指纹、路径、进程身份、探测家族和风险评分会优先保留。`max_evidence_items_per_finding` 必须保持在 16 或以上，避免裁掉主动响应和通知所需的关键证据。

SSH 告警策略：

```toml
[ssh]
alert_on_root_login = true
alert_on_password_login = true
alert_on_successful_login = true
auth_log_lookback_seconds = 300
max_events_per_scan = 2000
trusted_admin_ips = []
alert_on_trusted_admin_login = false
```

`alert_on_successful_login` 覆盖未被 root 登录或密码登录规则覆盖的普通成功 SSH 登录，并不只针对陌生 IP。普通成功登录为 `Info`，root 登录仍为 `High`，密码登录仍为 `Medium`。`trusted_admin_ips` 支持精确 IP 或 CIDR；来自这些来源的 root `publickey` 登录默认不发高危告警，如果设置 `alert_on_trusted_admin_login = true` 则按 `SSH-004` 发送普通成功登录。root 密码登录和 SSH 爆破检测不会被这个设置压制。SSH 登录按“用户 + 来源 IP”去重，端口只作为证据展示；SSH 暴力破解按来源 IP 去重，失败次数上涨不会在每次扫描时生成新的去重 Key。`auth_log_lookback_seconds` 限制每次扫描读取认证日志时向前回看的时间窗口，避免旧登录日志反复产生通知。SSH 失败日志会先按来源 IP 聚合再进入检测；`max_events_per_scan` 用于限制极端日志量，同时保留聚合后的失败次数。当 `/var/log/auth.log` 和 `/var/log/secure` 等配置的认证日志文件不存在时，vps-sentinel 会回退读取 `ssh.service` 和 `sshd.service` 的 `journalctl` 日志。

文件完整性评分：

```toml
[file_integrity]
webshell_min_score = 70
incremental = true
```

`webshell_min_score` 控制何时产生 `FILE-002`。检测器会对 marker 组合和 Web 脚本上下文评分，而不是单独命中一个 marker 就告警，从而减少合法管理脚本误报，同时保留对经典 Web 命令执行和编码命令执行组合的识别能力。`incremental = true` 时，普通未变化文件快照会先参与基线对比，然后从检测和存储路径中移除；变化文件、`authorized_keys` 当前状态、WebShell marker、Web 根目录下可执行/脚本文件仍会保留。

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

近期软件包活动会作为证据附加到文件和持久化漂移 finding 中。它不是白名单，也不会自动刷新基线。`vs baseline diff` 会展示每个漂移项的评分、层级、复核动作和原因；普通变更应对照软件包日志确认，敏感对象或公网暴露相关漂移应先调查再考虑刷新基线。

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
public_outbound_fanout_threshold = 12
outbound_remote_addr_sample_size = 16
known_bad_tool_names = ["xmrig", "xmr-stak", "kinsing", "masscan", "zmap", "lolminer", "nbminer", "gminer", "t-rex", "trex", "teamredminer", "phoenixminer", "ethminer", "ccminer", "cpuminer", "bminer", "nanominer", "wildrig", "rigel", "bzminer"]
```

`deleted_executable_min_score` 控制何时产生 `PROC-002`。deleted executable 状态会结合路径、进程身份和命令行为评分；标准系统二进制在软件包升级后仍短暂运行，不会单独触发高危告警。`behavior_min_score` 控制 `PROC-005`，它会组合内核线程伪装、Web 根目录执行、隐藏可执行文件名、可疑工作目录、socket FD 活动、持续高 CPU、同一进程身份的 procfs 启动时间漂移、软件包归属、systemd `ExecStart` 不匹配、有界公网出站 fanout 和有效 root 权限等信号。启动时间漂移和公网出站 fanout 只会增强已经可疑的身份或位置证据；正常服务重启或繁忙业务服务不会单独告警。`high_cpu_threshold_percent` 和 `high_cpu_duration_seconds` 基于 procfs 的生命周期 CPU 时间与进程年龄定义持续高 CPU；高 CPU 是辅助信号，不是单独告警条件。`suspicious_socket_fd_threshold` 控制 socket 持有数量达到多少时成为更强的行为信号。`public_outbound_fanout_threshold` 控制公网出站连接数达到多少时成为 fanout 证据，`outbound_remote_addr_sample_size` 限制证据中保留的远端地址样本数量。`known_bad_tool_names` 控制 `PROC-004` 的已知挖矿/扫描器指标词表。它会匹配 `exe_path`、`executable`、进程名和结构化 `argv[0]` 等进程身份字段，并兼容 `.exe` 后缀；缺少结构化身份的旧事件才回退到命令 token basename 匹配。同一个 PID 同时命中多个进程规则时，扫描器会保留一条最高价值 finding，并合并进程信号、风险原因、影响和处置建议。

GPU 指标策略：

```toml
[gpu]
enabled = true
nvidia_smi_path = "nvidia-smi"
rocm_smi_path = "rocm-smi"
command_timeout_seconds = 2
min_memory_mb = 256
high_utilization_percent = 85
high_power_watts = 120.0
mining_min_score = 80
mining_pool_ports = [3333, 3334, 3335, 4444, 5555, 7777, 8888, 9999, 14444, 16000, 18081, 18082]
```

`PROC-006` 只有在服务能运行 `nvidia-smi` 或 `rocm-smi` 且能看到宿主机 GPU compute process 表时可用。单独 GPU 显存占用只作为正常工作负载上下文，不会告警。NVIDIA 主机在可用时还会补充 GPU 利用率和功耗证据；高利用率或高功耗仍然只是辅助信号。触发告警需要叠加配置中的 GPU 挖矿器身份、临时/deleted/匿名可执行文件、配置中的矿池端口、网络命令执行桥接、高利用率伴随矿池风格出站行为，或隐藏 GPU 可执行文件伴随公网出站连接等证据。如果把 vps-sentinel 放在容器里运行，需要具备宿主机 PID/procfs 和 GPU runtime 可见性，否则无法准确检查宿主机 GPU 挖矿进程。

持久化命令评分：

```toml
[persistence]
suspicious_command_min_score = 70
```

`suspicious_command_min_score` 控制何时产生 `PERSIST-002`。启动命令会按下载后管道执行、临时路径自启动、编码 shell payload、网络执行桥等组合特征评分。合法 systemd 单元中常见的普通 shell 包装命令不会单独超过默认阈值。

Web 日志策略：

```toml
[web]
max_log_tail_bytes = 1048576
max_events_per_scan = 5000
include_rotated = true
log_lookback_seconds = 900
error_burst_threshold = 20
trusted_proxy_cidrs = ["172.64.0.0/13", "2606:4700::/32"]
real_client_ip_fields = ["cf_connecting_ip", "x_forwarded_for", "headers.cf-connecting-ip"]
suppress_unresolved_trusted_proxy = true
```

`WEB-001` 会识别 `.env`、`.git`、PHPUnit `eval-stdin.php`、CGI shell traversal、命令注入、PHP 配置写入 payload、LFI 文件读取、PHP stream wrapper、JNDI 注入、云元数据 SSRF、模板注入、SQL 注入、反序列化探测、phpMyAdmin、WordPress admin、actuator、server-status 等探测家族。同一来源 IP 的相似路径会聚合为一条 finding，并在证据中保留全部探测家族和响应画像。采集器支持常见 access log、JSON access log 和 Nginx 风格 error log；`max_log_tail_bytes` 限制单文件读取尾部大小，`max_events_per_scan` 限制极端流量下的解析事件数量，`include_rotated` 会包含 `.1` 轮转文件，`log_lookback_seconds` 会避免旧轮转日志反复进入检测。`trusted_proxy_cidrs` 默认包含 Cloudflare 网段，也可以替换或扩展为用户自己的反代/CDN 网段；JSON 日志中的 `real_client_ip_fields` 用于还原真实客户端 IP。如果日志来源是可信代理但没有真实客户端 IP，`suppress_unresolved_trusted_proxy = true` 会压制该 finding 和封禁候选，避免把代理边缘误认为攻击源。纯 404/400/301 目录爆破默认是 Low；敏感路径成功响应会升为 High；被拒绝的主动 exploit payload 保持 Medium 上下文。

主动响应策略：

```toml
[active_response]
enabled = true
strategy = "balanced"
firewall_backend = "auto"
block_ttl_seconds = 3600
max_blocks_per_scan = 20
notification_detail_limit = 3
permanent_block_enabled = true
permanent_block_threshold = 3
permanent_block_window_seconds = 86400
web_probe_block_threshold = 25
web_exploit_block_threshold = 5
ssh_failed_login_block_threshold = 6
```

主动响应对新安装默认开启。升级时不会覆盖已有配置，因此已经显式写了 `active_response.enabled = false` 的主机会保持关闭，直到管理员手动修改。`strategy = "observe"` 只记录候选不写防火墙，`balanced` 是默认策略，`strict` 会对被拒绝的 Web 探测和 SSH 爆破要求更强证据。扫描器会在扫描内合并/去重之后、跨扫描通知去重之前执行封禁，因此同一来源计数升高时，即使重复通知会被压制，也仍能触发封禁。SSH 封禁覆盖 `SSH-003` 爆破 finding 和 `SSH-007` 爆破后成功登录 finding，默认扫描窗口内 6 次失败触发封禁。Web 封禁覆盖敏感路径成功响应、高置信 RCE 风格探测、重复低置信 exploit 探测、多家族扫描聚合和高频错误爆发，但标记为 `proxy_source_unresolved` 的 Web finding 不会进入封禁候选。响应分层会标注强信号，例如已确认 Web 暴露、爆破后成功登录、重复攻击指纹和人工标记恶意指纹；分层可以延长临时封禁 TTL、降低永久升级阈值，但显式配置的 `[response_policy]` 仍然可以覆盖 TTL 和永久阈值。安静时段和通知限流不会阻止封禁。后端优先使用 nftables，不可用时回退到 iptables/ip6tables。普通封禁是临时封禁；如果同一个公网来源 IP 在 `permanent_block_window_seconds` 窗口内至少 `permanent_block_threshold` 次成为封禁候选，则升级为无到期时间的永久封禁。永久升级仍然遵守 `[allowlist].ips`、可信代理归因安全、`strategy = "observe"` 和 `max_blocks_per_scan`，可以通过 `vs blocks unblock <ip>` 或 `vs blocks unblock-all --yes` 解除。只有公网可路由来源 IP 才会被考虑。

每次扫描都会先把主动响应状态和真实防火墙规则同步，再判断某个来源是否已经封禁。如果规则已过期、被 firewalld/ufw reload 清掉，或者被人工修改，程序会移除失效状态；如果该来源仍然满足高置信封禁条件，后续可以再次封禁。iptables 后端在插入前会用 `-C` 检查规则是否已存在，避免重复 DROP 规则；手动解除封禁会删除重复匹配规则。日常运维可以使用 `vs blocks list`、`vs blocks cleanup`、`vs blocks unblock <ip>` 和 `vs blocks unblock-all --yes`。

攻击指纹：

```toml
[attack_fingerprints]
enabled = true
similarity_enabled = true
similarity_hamming_distance = 6
max_match_candidates = 1000
max_features_per_fingerprint = 40
max_observations_per_fingerprint = 200
retention_days = 30
active_response_enabled = true
active_response_min_score = 75
active_response_min_observations = 2
active_response_min_distinct_ips = 2
```

`attack_fingerprints` 控制基于攻击手法的聚类。精确指纹使用归一化后的特征，故意不包含来源 IP；近似匹配使用 SimHash 汉明距离，并只在最近同类指纹中匹配，`max_match_candidates` 用于限制内存和 CPU 开销。`max_observations_per_fingerprint` 和 `retention_days` 用于限制存储增长。`vs fingerprints explain <id>` 只读取选中的指纹和有限条 observation 来解释聚类依据，不需要常驻大型内存模型。基于指纹的主动响应只会在评分、观察次数和不同来源数量达到阈值，或管理员将指纹标记为恶意后，给 finding 添加封禁提示；最终是否写防火墙仍由主动响应安全过滤决定。如果某个合法管理脚本或运维行为形成稳定指纹，可用 `vs fingerprints mark-benign <id>` 标记为正常，并抑制后续匹配 finding 的指纹提示和自动封禁。

响应策略：

```toml
[response_policy]
enabled = true

[response_policy.policies.ssh_bruteforce]
enabled = true
rule_ids = ["SSH-003", "SSH-007"]
action = "block"
min_severity = "High"
min_confidence = 70
min_unified_score = 70
```

响应策略在检测器产生主动响应候选之后执行，不会自行产生 finding。`action = "observe"` 只观察不写防火墙，`action = "block"` 使用 TTL 临时封禁，`action = "permanent_block"` 只建议用于你明确希望永久封禁的高置信证据。

Incident、报告和服务画像：

```toml
[incidents]
enabled = true
correlation_window_seconds = 900
max_findings_per_incident = 50

[service_profile]
enabled = true
drift_requires_public_exposure = false
dynamic_udp_enabled = true
dynamic_udp_min_port = 32768
ignored_dynamic_udp_process_names = ["systemd-timesyncd", "chronyd", "ntpd"]
ignore_loopback_ssh_forwarding = true

[reports]
scheduled_enabled = true
scheduled_hour = 8
scheduled_period = "today"
```

`incidents` 控制本地攻击链聚合；`service_profile` 控制监听服务 owner 漂移检测。启用动态 UDP/UDP6 建模后，高于 `dynamic_udp_min_port` 的公网 UDP 监听会按进程身份建模，因此 VPN/转发类软件更换高位 UDP 端口不会每次都告警。`ignored_dynamic_udp_process_names` 用于时间同步这类客户端式 UDP 进程，`ignore_loopback_ssh_forwarding` 会压制 `127.0.0.1:6010` 这类本地 SSH X11/转发监听。定时报表默认开启，会让 daemon 通过已启用通知渠道发送每日安全报告，并用 `min_interval_seconds` 避免重启后重复发送；如果没有配置任何通知渠道，daemon 会直接跳过定时报表，不构建也不发送。

高级采集和外部规则：

```toml
[advanced_collectors]
auditd_enabled = true
ebpf_bridge_enabled = true
ebpf_event_paths = []
ebpf_command = []

[external_rules]
enabled = true
sigma_paths = []
yara_enabled = true
yara_paths = []
yara_scan_roots = []
```

auditd 会在日志存在时读取配置的 audit 日志；audit EXECVE 事件会转换成标准化 RawEvent，并复用命令画像逻辑识别网络到 shell 的执行桥接、非交互式 sudo/su/pkexec shell 执行。eBPF bridge 接收 JSONL 文件或命令输出，方便接入你自己的 BPF 工具而不把内核探针作为硬依赖；常见 exec/connect/file 事件会归一化为内置规则使用的进程、出站连接和文件活动字段。Sigma-like 规则是 TOML 结构化事件字段条件，部署前可用 `vs rules validate-external <path...>` 校验解析错误、缺失条件、重复 ID 和未知分类。YARA 只有在配置了规则路径和扫描根目录时才会调用 `yara` 命令，因此默认启用规则引擎不会带来额外扫描开销。

威胁情报、fleet 和维护模式：

```toml
[threat_intel]
enabled = true
indicator_paths = []
url = ""

[fleet]
enabled = true
node_name = ""
export_path = "/var/lib/vps-sentinel/fleet-node.json"

[maintenance]
enabled = false
suppress_baseline_drift = true
suppress_interactive_logins = true
max_duration_seconds = 7200
```

威胁情报 indicator 可使用纯文本或带 `type`/`value` 的 JSON Lines。命中会作为证据并提升统一风险评分，但不会单独触发告警或封禁。Fleet 快照是用于多 VPS 本地汇总的 JSON 摘要。维护模式有时间上限，只压制配置允许的计划运维噪声：低/中危基线漂移和交互式 SSH 登录 finding（`SSH-001`、`SSH-002`、`SSH-004`）。SSH 爆破（`SSH-003`）以及爆破后成功登录（`SSH-007`）仍会保留。

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
- `SSH-007`：同一来源先出现 SSH 爆破失败，随后成功登录。
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
- `SERVICE-001`：发现新的服务画像条目。
- `SERVICE-002`：服务可执行文件相对画像发生漂移。
- `FILE-002`：WebShell 风格文件内容。
- `CONFIG-003`：高危服务端口公网暴露。
- `REPORT-001`：根据本地扫描历史生成的安全日报。
- `EXT-*`：用户提供的外部 TOML 规则命中。
- `YARA-*`：用户提供的 YARA 规则命中。

## 部署说明

部分采集器需要 root 级别可见性。如果不是 root 运行，`doctor` 会报告可见性降低，相关模块会降级而不是崩溃。

作为常驻 agent，运行时资源占用较小。在当前验证 VPS 集合上，默认 60 秒扫描循环下 daemon 进程 RSS 约为 13-21 MiB。systemd cgroup 的 `MemoryCurrent` 可能明显更高，从几十 MiB 到几百 MiB 都可能出现，因为 Linux 可能把近期触达的文件缓存和 cgroup 内存统计计入服务。实际内存压力会受日志尾部大小、文件完整性路径范围、内核统计方式和已启用通知渠道影响；判断 daemon 自身稳定占用时应优先看进程 RSS。`vs scan` 会输出 best-effort RSS before/after 和按来源统计的事件数量。raw event 存储会对重复事实使用稳定键和精简字段，普通 Web access 事件默认不入库，除非它支撑 Web 探测证据或用户显式打开完整保存；因此重复扫描同一段日志尾部或未变化主机状态时会覆盖旧行，而不是每分钟追加相同数据。通知日志会保存 rule、severity、subject、title 快照，因此旧 finding 被清理后仍可审计发送记录。SQLite 存储还会受 `storage.max_database_size_mb` 约束；超过上限时会裁剪旧的高容量数据并执行 `VACUUM` 回收磁盘空间。

systemd unit 使用：

- `NoNewPrivileges=true`
- `ProtectSystem=full`
- `ProtectHome=read-only`
- 仅允许配置的数据目录和日志目录写入

更多内容见 [docs/deployment.md](docs/deployment.md)。

## 隐私与安全边界

- 默认不上报日志；
- 默认不启用通知渠道；
- 默认不杀进程、不删除文件；主动响应默认只会对高置信公网来源 IP 写入防火墙封禁规则，并始终遵守 `[allowlist].ips`、公网 IP 校验和每次扫描封禁数量上限；
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
