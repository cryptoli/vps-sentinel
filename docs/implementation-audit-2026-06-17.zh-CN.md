# 实现审计报告 - 2026-06-17

本报告回答以下问题：每个功能如何实现、是否科学有效、是否可能误判、做了哪些测试、是否存在硬编码、是否遵守代码规范、日志格式是否合理。

## 总体结论

vps-sentinel 不能保证 100% 零误判或零漏报；主机入侵检测本质上需要在证据强度、噪音和可解释性之间取舍。当前实现遵循的是可解释、证据驱动、默认安全、可配置阈值、可回归测试的方案。

当前架构是分层的：

- Collectors 只采集事实，输出 `RawEvent`；
- Baseline 负责可信快照和漂移 diff；
- Detectors 负责规则、评分和 finding 生成；
- Scanner 负责采集、检测、合并、去重、脱敏、持久化和通知编排；
- Notify 负责按渠道模板渲染和投递；
- Storage 负责 SQLite 本地持久化。

代码使用了这些结构和模式：

- Trait 插件式扩展：`Collector`、`Detector`、`Notifier`；
- Strategy：不同通知渠道使用不同 `MessageTemplate`；
- Scoring model：进程、deleted executable、持久化命令、WebShell 内容使用风险评分，不靠单一字符串；
- Stable dedup key：finding 使用稳定证据生成去重 Key；
- BTreeMap/BTreeSet：用于稳定排序、去重和聚合；
- Config defaults：Linux 默认路径、端口和阈值集中在配置结构中，并能通过配置覆盖。

## 功能审计

| 功能 | 实现方式 | 科学性和误判边界 | 测试覆盖 |
| --- | --- | --- | --- |
| SSH 登录检测 | 解析 auth log 或 journalctl，生成 `ssh_auth` 事件；规则区分 root、密码、普通成功登录。 | 成功登录本身不等于入侵，所以按配置开关和严重级别表达风险。root/password 是高价值信号，但管理员操作也会触发。 | root 登录正例、密码登录正例、普通登录正例、root/password 不重复告警、非对应规则反例。 |
| SSH 爆破检测 | 按来源 IP 聚合失败次数和用户名集合，阈值来自 `ssh.failed_login_threshold`。 | 使用来源 IP 聚合比单条日志更稳；NAT 或扫描器会触发，但这是预期风险信号。 | 10 次失败触发，9 次失败不触发，失败次数变化不改变去重 Key。 |
| authorized_keys 监控 | 文件采集和基线 diff 监控 `.ssh/authorized_keys` 与 `authorized_keys2`。 | 对 SSH 持久化高度有效；计划内改 key 也会触发，需要用户确认后刷新基线。 | authorized_keys/authorized_keys2 漂移正例，`/tmp/authorized_keys` 反例。 |
| 关键文件完整性 | 对配置路径做哈希，基线对比后检测关键系统文件漂移；近期软件包活动作为上下文附加到 finding。 | 能发现持久化和权限相关文件变化；软件包更新不会被自动信任，而是提示先对照包管理器日志再刷新基线。 | `/etc/passwd` 漂移正例、非关键应用文件漂移反例、软件包活动上下文保留测试。 |
| WebShell 文件 | 文件采集限制大小，扫描 Web 路径内容 marker，并用动态执行、编码 payload、命令执行和 Web 脚本上下文进行评分。 | 单个 marker 不再直接告警；合法管理脚本仍可能需要人工确认，复杂无 marker WebShell 可能漏报。 | Web 脚本命令执行正例、编码动态执行正例、单独 `eval` 反例、非 Web 命令执行 helper 反例、干净 Web 文件反例、Web 目录可执行文件正例、非 Web 可执行文件反例。 |
| 用户与权限 | 基线对比 `/etc/passwd`，检测新增用户、UID 0 用户、用户属性变化。 | UID 0 非 root 是强信号；新增用户可能是正常运维。 | 新用户、UID 0、用户修改正例；普通快照和正常 UID 反例。 |
| 持久化文件 | 采集 cron、systemd、shell profile、ld.so.preload，做基线漂移检测；近期软件包活动作为上下文附加到 finding。 | 能发现新增/修改启动项；合法软件安装也可能触发，但不会被静默吸收到基线。 | systemd/cron 漂移、ld preload 漂移正例；当前快照和普通 systemd 漂移反例；软件包活动上下文保留测试。 |
| 可疑持久化命令 | 对启动命令进行评分：下载后管道 shell、临时路径、自解码 payload、网络执行桥。 | 使用组合特征，避免普通 `bash -c` 单独触发；复杂混淆仍可能漏报。 | download-to-shell、临时路径、网络执行桥正例；cloud-init shell wrapper 反例。 |
| 进程临时路径 | 从 procfs 读取 exe/cmdline/argv，检查可执行路径是否在配置的 suspicious dirs。 | 临时目录运行进程是强风险信号；少量合法临时运行程序可能触发，可 allowlist。 | `/tmp`/`/dev/shm` 正例，标准系统进程反例。 |
| Deleted executable | 不是看到 deleted 就告警，而是用 memfd、临时路径、隐藏文件、网络执行桥、已知工具身份等评分。 | 比单纯 deleted 字符串科学；软件升级残留会被压低风险。 | memfd、临时 deleted 正例；systemd/dockerd/python/vps-sentinel 升级残留反例。 |
| 网络命令执行桥 | 基于 argv 构建命令画像，要求网络通道加 shell/system/fd/TTY 等组合特征。 | 避免将普通 socat/gost/ssh 转发识别成反弹 shell；真正隐蔽的自研 payload 可能漏报。 | `/dev/tcp`、`nc -e`、`EXEC:/bin/sh` 正例；普通转发、ssh tunnel 反例。 |
| 挖矿/扫描器进程 | 优先匹配 exe_path、process name、argv[0] 等进程身份，不把普通参数里的词直接当命中。 | 降低“参数里有 xmrig 字样”的误报；改名后的恶意程序可能漏报，需要其它规则补充。 | xmrig/masscan/zmap 身份正例，`--profile xmrig` 参数反例。 |
| 进程行为聚类 | 从 procfs 读取 exe、cwd、socket FD 数、uid/euid 和 name，组合内核线程伪装、Web 根目录执行、隐藏可执行名、可疑 cwd、socket 活动和有效 root 权限。 | 用多个弱信号叠加补充改名恶意进程；单个弱信号不触发，完全伪装成正常路径和正常身份的恶意程序仍可能漏报。 | Web 路径伪装进程正例、root 权限内核线程伪装正例、普通 nginx 多 socket 反例。 |
| 网络监听 | 基线对比 TCP/TCP6 新公网监听；高风险端口和可疑进程单独识别。 | 80/443 不盲目信任，会继续看 owner drift 和可疑进程；普通 UDP 高端口不再直接触发。 | 新 TCP 端口正例，稳定端口反例，UDP 高端口反例，高风险 UDP 端口和可疑 UDP 进程正例。 |
| SSH 配置风险 | 解析 sshd_config 和 include 文件，识别 PasswordAuthentication、PermitRootLogin。 | 这是配置风险，不代表已经入侵；但暴露面更大。 | yes 正例，no 反例，注释行忽略。 |
| Web 日志探测 | 解析 access log，识别常见 probe path 和攻击 payload；聚合 403/404。 | 常见路径规则会有扫描器噪音；错误爆发阈值已配置化为 `web.error_burst_threshold`。 | `/.env`、phpunit、union select 正例，静态资源反例；阈值可配置测试。 |
| Docker 上下文 | 检测 docker.sock 存在，作为 Info 攻击面提示。 | 不是入侵证据；Telegram min severity 为 Info 时会通知。 | Docker socket 正例，无事件反例。 |
| Rootkit 信号 | 检查 ld.so.preload 活动条目。 | 这是 rootkit 信号，不是单独定罪证据。 | active entry 正例，空 preload 反例。 |
| 通知 | 统一 `Finding` 渲染，Telegram HTML、Email HTML+text、Markdown/plain text 按渠道模板选择。 | 技术字段默认隐藏，避免普通用户困惑；可配置显示。 | VPS 名称、中文、Telegram HTML、技术字段开关、无乱码测试。 |
| 噪声控制 | 扫描内去重、跨扫描去重、状态型提醒间隔、小时级限流、安静时段。 | 状态类和事件类分开处理，减少重复通知又不吞掉新的 SSH 登录事件。 | 状态类 24 小时提醒窗口、事件类普通窗口、限流绕过、quiet hours 测试。 |
| 存储 | SQLite 存储 raw events、findings、baseline、notification logs。 | 本地优先、可审计；长期历史受 retention 控制。 | findings 存取、notification count、baseline diff 测试。 |
| 脚本和部署 | install/update/stop 脚本，内置 `reload` 命令，systemd unit，配置校验后重载。 | 更新不默认刷新基线，避免把未审计漂移变成可信状态。 | shell `bash -n`、VPS update、config validate、scan --no-notify。 |

## 硬编码审计

不应存在机器相关绝对路径硬编码。当前存在的是安全产品默认策略值，例如 `/etc/passwd`、`/var/log/auth.log`、22/80/443、Redis/MongoDB 等高风险端口。这些属于 Linux 安全基线默认值，集中在配置默认值或规则 profile 中，并不是依赖某台机器路径。

业务阈值集中在配置中，不应散落在检测逻辑里。本轮涉及的新增/已配置化阈值包括：

```toml
[web]
error_burst_threshold = 20

[file_integrity]
webshell_min_score = 70

[process]
behavior_min_score = 70
suspicious_socket_fd_threshold = 20

[package_manager]
recent_activity_window_seconds = 3600
max_log_tail_bytes = 8192
```

配置校验会拒绝 `0`，避免误触发或把阈值调成没有意义的状态。上述 Linux 默认路径和阈值是安全策略默认值，可通过配置覆盖，不依赖某台测试机器。

## 日志审计

daemon 使用 `tracing` JSON 日志，字段化输出包括：

- scan start/end；
- collector 名称和采集数量；
- collector 错误；
- raw event 数量；
- diff event 数量；
- detected findings；
- suppressed duplicates；
- quiet-hours suppression；
- rate-limit suppression；
- notification attempts/success/failure；
- storage prune 数量。

CLI 命令保持人类可读输出，这是运维命令的预期行为；daemon/systemd 日志使用 JSON，便于 journalctl、日志采集器和后续 dashboard 解析。

## 当前仍可能误判或漏报的地方

- 合法管理员 root 登录会触发 `SSH-001`，这是设计选择，不是入侵结论。
- 合法软件包更新可能触发文件/持久化基线漂移；当前会附带近期包管理器日志上下文，但仍需要人工确认后刷新基线。
- WebShell marker 可能命中合法管理脚本；当前已改成组合评分，单个 marker 默认不触发，但消息仍建议确认后再隔离。
- 已改名、无明显网络执行桥、无临时路径的恶意进程现在由 `PROC-005` 行为聚类补充覆盖；如果攻击者完全伪装成正常路径、正常权限和正常进程行为，仍可能漏报。
- 只看本机日志和 procfs，不等价于完整 EDR 或云 SIEM。

## 本轮优化

- 将 `WEB-002` 的错误爆发阈值从代码硬编码迁移为 `web.error_burst_threshold`。
- 增加包管理器活动采集器，将近期软件包日志活动附加到文件/持久化漂移 finding。
- 将 WebShell 内容检测从单 marker 告警改为组合评分，新增 `file_integrity.webshell_min_score`。
- 增加 `PROC-005` 进程行为聚类，补充改名进程、Web 根执行、隐藏文件名、socket 活动和有效 root 权限组合识别。
- 增加配置校验，禁止新增阈值为 0。
- 增加 WebShell 评分、包管理器上下文、进程行为聚类、去重合并证据保留测试。
- 同步 README、中文 README 和配置参考。
