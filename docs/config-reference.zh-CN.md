# 配置参考

默认系统配置路径是 `/etc/vps-sentinel/config.toml`。用户级配置也可以放在 `~/.config/vps-sentinel/config.toml`。完整示例见 [config/config.example.toml](../config/config.example.toml)。

修改配置后建议执行：

```bash
sudo vs config validate
sudo vs reload
```

## 配置块

- `[agent]`：主机 ID、主机名、展示名、扫描间隔、数据目录和日志级别。通知标题优先使用 `display_name`，其次是 `hostname`、`host_id`、`local-host`。
- `[privacy]`：上传和脱敏控制。默认不上传面板遥测。
- `[storage]`：SQLite 路径、保留策略和数据库大小限制。
- `[ssh]`：认证日志路径、登录阈值、可信管理员 IP 和 `authorized_keys` 检测。成功登录、root 登录、密码登录、爆破和爆破后成功都有独立规则与去重逻辑。
- `[file_integrity]`：监控路径、扫描深度、最大文件大小和 WebShell 评分。`FILE-002` 只有在 WebShell 标记组合和 Web 脚本上下文达到阈值时才触发。
- `[web]`：Web 根目录、access log 路径、可信代理 CIDR、真实客户端 IP 字段、Web 探查分类和错误爆发阈值。启用可信代理后，agent 会尽量从 `CF-Connecting-IP`、`X-Forwarded-For`、`X-Real-IP` 等字段还原真实客户端 IP。
- `[process]` / `[gpu]`：进程画像、父进程链、执行文件属性、可疑目录、CPU/GPU 异常和已知矿工/扫描器身份。
- `[package_manager]`：软件包管理器上下文。近期 apt/dpkg/yum/dnf/pacman/apk 活动会作为文件或持久化漂移证据，帮助复核；它不是 allowlist，也不会自动刷新基线。
- `[network]`：监听端口策略。`expected_public_ports` 用于预期公网服务端口；`allowlist.listening_ports` 才会完全抑制某端口相关的网络发现。环回、RFC1918、IPv6 ULA 和链路本地监听不会被当作公网暴露。
- `[persistence]`：cron、systemd、shell profile、preload 等持久化入口。启动命令会按下载执行、临时路径、自编码 payload、网络执行桥等信号评分。
- `[active_response]`：主动封禁策略、nftables/iptables 后端、SSH/Web 阈值、临时/永久封禁升级和可信代理保护。命中 `[allowlist].ips` 或 `[web].trusted_proxy_cidrs` 的 IP 不会成为封禁候选。
- `[panel]`：推模式面板上报。`url` 和 `secret` 配置签名上报，`node_name` 是非敏感展示身份，`privacy_mode = "strict"` 会移除公网 IP、节点 ID、路径、命令行和原始证据。
- `[notifications]`：Telegram、邮件、Webhook、ntfy、Gotify、Bark、ServerChan、钉钉、飞书，以及通用通知语言、时区、超时和技术字段显示。钉钉/飞书会检查业务响应码，HTTP 200 但平台拒收时仍会作为通知失败处理。
- `[reports]`：每日安全报告。`scheduled_hour` 按 `notifications.time_zone` 的日历日固定小时发送，延迟扫描不会把第二天报告时间滚动推迟。
- `[noise_control]`：重复告警、状态提醒和每小时告警量控制。`rate_limit_bypass_min_severity` 和 `quiet_hours_bypass_min_severity` 默认是 `High`，高价值告警会绕过小时预算和静默时段。
- `[allowlist]`：可信用户、IP、进程路径、命令片段、监听端口、文件路径和 Web 路径。多个路径建议通过 `vs config allowlist add ...` 修改，避免手写 TOML 格式出错。
- `[suppress_rules]`：按规则 ID 静默已复核接受的风险。适合像 `CONFIG-004` 这类“业务上接受但仍要继续监控文件完整性”的配置风险；优先使用带 `subjects`、`path_patterns`、`expires_at`、`reason` 的 scoped entry，而不是全局静默。
- `[maintenance]`：运维窗口内抑制基线漂移或交互登录噪音。

## 常用操作

结构化配置修改：

```bash
sudo vs config allowlist add file-path '/etc/systemd/system/snap-*.mount'
sudo vs config allowlist add file-path '/etc/systemd/system/snap-*.scope'
sudo vs config trusted-admin add 203.0.113.10
sudo vs config suppress-rule add CONFIG-004 --global
sudo vs config normalize
sudo vs config validate
sudo vs reload
```

`config migrate`、`config sync-defaults` 和 `config normalize` 会把 `[allowlist]`、`[suppress_rules]` 规范化成稳定数组格式，避免自动化脚本写出重复 key 或单行/多行混用格式。

## 噪音控制与规则静默

`noise_control.quiet_hours` 使用服务器本地时间，格式为 `HH:MM-HH:MM`，可以跨午夜，例如 `["22:00-07:00"]`。静默时段内低于 bypass 阈值的告警会被抑制，高于或等于阈值的告警仍会通知。

`noise_control.dedup_window_seconds` 默认 3600 秒，用稳定 dedup key 抑制重复事件；`noise_control.state_reminder_interval_seconds` 默认 86400 秒，用于 SSH 风险配置、Docker socket、基线漂移、持久化进程、疑似 WebShell 等状态类告警。

规则静默发生在攻击指纹、主动响应、存储和通知之前。被 `[suppress_rules]` 静默的 finding 会从本次扫描结果中移除，所以不要随意静默 `SSH-003`、`WEB-001` 这类攻击规则。简单全局静默可以用：

```bash
sudo vs config suppress-rule add CONFIG-004 --global
```

更推荐在配置里使用 scoped entry，写明对象、路径、过期时间和原因。

## 面板位置与隐私

Agent 不需要手动配置国家、城市或公网 IP。启用 `panel.node_location_enabled` 后，agent 会通过 HTTPS 地域接口自动推导国家、地区和城市，并只上传这些展示字段，不上传用于推导的公网 IP。自建面板也可以配置 MaxMind/DB-IP MMDB 文件，通过真实远端请求 IP 补充地域；Cloudflare 面板会使用 Cloudflare 请求地域。

`panel.upload_hostname = true` 只允许上传不含 IP、不含危险字符、通过脱敏校验的主机名。节点 ID、主机 ID、服务器公网 IP、路径、命令行和原始证据仍然不会上报。
