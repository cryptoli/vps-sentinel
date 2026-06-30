# 误报处理

安全监控应该帮助用户聚焦真正值得处理的信号，而不是因为预期运维动作反复打扰。

## 常见来源

- 软件包升级导致 systemd unit、配置文件或关键文件变化。
- snap 包刷新生成带版本号的 systemd mount/scope unit，例如 `/etc/systemd/system/snap-core20-2890.mount`。
- 管理员手动创建用户、SSH key 或维护脚本。
- 业务需要公开 HTTP/HTTPS、面板、数据库、缓存或其他服务端口。
- 框架、运维脚本或部署脚本包含类似 WebShell 的字符串。
- Web 漏洞探测没有成功，但在 access log 中形成大量 404/403。
- 反向代理、CDN、VPN 或跳板机导致来源 IP 与真实客户端 IP 不一致。

## 处理建议

- 先阅读规则 ID、证据字段、节点名称、时间窗口、对象路径或来源 IP，不要只看标题。
- 对预期用户、IP、端口、文件路径或进程路径使用 `[allowlist]`。
- 对 snapd 管理的 systemd unit，使用窄路径模式 `/etc/systemd/system/snap-*.mount` 和 `/etc/systemd/system/snap-*.scope`；不要把整个 `/etc/systemd/system` 加入 allowlist。
- 对合法转发、隧道或代理进程，优先使用 `allowlist.process_paths`；只有在路径不稳定且片段足够精确时才使用 `allowlist.process_command_contains`。
- 对已知矿工/扫描器规则，先确认 `matched_tool`、`match_source`、`matched_value` 是否确实来自可执行文件名、进程名或结构化 `argv[0]`，再结合 CPU、进程年龄和业务用途判断是否是授权软件。
- 对带 `package_activity_recent=true` 的文件或持久化漂移，先对照包管理器日志；包管理器上下文只是复核证据，不是自动 allowlist。
- 对 WebShell 风格内容，检查文件位置、owner、最近部署记录和标记组合。默认评分会忽略单个弱标记，但合法管理脚本仍可能包含高风险字符串。
- 普通公网服务端口或业务上必须公开的高风险端口，应放入 `network.expected_public_ports`；只有想彻底抑制某端口所有网络发现时，才使用 `allowlist.listening_ports`。
- 计划维护后可以刷新基线，但应先复核漂移证据。`update.sh` 默认保留既有基线，只有 `REFRESH_BASELINE=yes` 时才刷新。
- 对已接受的配置风险，优先使用 `[suppress_rules]`，不要为了静默一个规则把底层配置文件排除出完整性监控。例如只有在确认并记录直接 root 登录需求后，才静默 `CONFIG-004`。
- 启用主动响应前，把管理员出口、办公固定 IP、VPN、监控系统、CDN 和反向代理来源加入合适的 allowlist 或 trusted proxy 配置。主动响应只考虑公网来源 IP，并有更严格阈值，但仍会改变防火墙状态。
- 对面板里的 `false_positive` 复核，应写清楚依据，避免后续攻击指纹和同类事件被错误归类。
- 在采取删除文件、kill 进程、封禁大网段等破坏性动作前，先从可信会话保全证据并交叉验证。

## 常用命令

```bash
sudo vs config allowlist add file-path '/etc/systemd/system/snap-*.mount'
sudo vs config allowlist add file-path '/etc/systemd/system/snap-*.scope'
sudo vs config suppress-rule add CONFIG-004 --global
sudo vs config normalize
sudo vs reload
```

需要引导式操作时可以使用：

```bash
sudo vs menu
```
