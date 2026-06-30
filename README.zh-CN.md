# vps-sentinel

面向 Linux VPS 的轻量级 Rust 入侵信号监控与多服务器安全面板。

[English README](README.md)

![CI](https://github.com/cryptoli/vps-sentinel/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 项目定位

`vps-sentinel` 是防御型监控工具，目标是尽早发现异常、给出证据、给出处置建议。

它不是杀毒软件、漏洞利用框架、密码爆破工具、第三方主机扫描器、C2/后门/隐蔽工具，也不是“主机绝对安全”的保证。

## 核心能力

| 模块 | 能力 |
| --- | --- |
| SSH 与账号 | 成功登录、密码登录、爆破、爆破后成功、`authorized_keys` 漂移、key 文件危险状态、新用户、UID 0 用户和权限相关变化。 |
| 基线漂移 | 对用户、SSH key、关键文件、持久化项、监听端口和服务身份建立本地基线；通过语义漂移评分减少软件包升级、动态端口和正常运维噪声。 |
| 进程与 GPU 行为 | procfs、父进程链、systemd 身份、包归属、可执行文件 hash/owner、出站画像、行为画像漂移、已知矿工/扫描器身份、NVIDIA/ROCm GPU 计算信号。 |
| 网络与 Web 探查 | 公网监听 owner、防火墙上下文、可信代理真实客户端 IP 还原、Web 探查家族分类、攻击路径聚合、错误爆发和封禁候选。 |
| 主动响应 | 对高置信 SSH/Web 攻击源执行可选 nftables/iptables 来源 IP 封禁，支持临时/永久升级、白名单、可信代理保护和 CLI 解封。 |
| 攻击指纹 | 使用精确 hash 和 SimHash 风格近似匹配聚合同一攻击手法，即使来源 IP 变化也能归类。 |
| 静默与本地运维 | 结构化配置迁移、allowlist 和 suppress_rules 规范化渲染、按规则 ID 的已接受风险静默，以及本地 `vs menu`，不把面板变成 SSH 控制面。 |
| 报告与通知 | 支持每日安全报告，以及 Telegram、Email SMTP、Webhook、ntfy、Gotify、Bark、ServerChan、钉钉和飞书；通知默认中文。 |
| 多 VPS 面板 | 推模式 Rust 自建面板或 Cloudflare Worker/D1 面板，支持公开/私有访问、隐私脱敏、节点指标、黑名单归属、复核流程、自建 WebSocket 刷新和主题扩展入口。 |
| 资源控制 | 有界日志解析、事件预算、SQLite 保留策略、数据库大小限制、原始证据裁剪，对小内存 VPS 友好。 |

## 部署

完整部署步骤请看文档：

- Agent 部署：[docs/deployment.zh-CN.md](docs/deployment.zh-CN.md) / [docs/deployment.md](docs/deployment.md)
- 面板部署：[docs/panel-deployment.zh-CN.md](docs/panel-deployment.zh-CN.md) / [docs/panel-deployment.md](docs/panel-deployment.md)
- 面板架构：[docs/panel-architecture.zh-CN.md](docs/panel-architecture.zh-CN.md) / [docs/panel-architecture.md](docs/panel-architecture.md)
- 面板主题扩展：[docs/panel-themes.zh-CN.md](docs/panel-themes.zh-CN.md) / [docs/panel-themes.md](docs/panel-themes.md)

推荐完整安装 agent：

```bash
sudo VPS_NAME="prod-web-1" \
  TELEGRAM_BOT_TOKEN="<telegram-bot-token>" \
  TELEGRAM_CHAT_ID="<telegram-chat-id>" \
  PANEL_URL="https://your-panel.example.com/api/v1/ingest" \
  PANEL_SHARED_SECRET="<panel-shared-secret>" \
  ACTIVE_RESPONSE_ENABLED="yes" \
  ACTIVE_RESPONSE_PERMANENT_BLOCK_ENABLED="yes" \
  STORAGE_MAX_DATABASE_SIZE_MB="256" \
  sh -c 'curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/install.sh | sh'
```

更短的 `curl ... | sudo sh` 仍然支持，但它只会安装本地守护进程，不会配置 Telegram 或面板上报。真实节点建议按部署教程使用完整命令。

快速升级：

```bash
curl -fsSL https://raw.githubusercontent.com/cryptoli/vps-sentinel/main/update.sh | sudo sh
```

安装和升级默认保留已有 `/etc/vps-sentinel/config.toml`，不会覆盖用户配置。

## 常用命令

| 命令 | 含义 |
| --- | --- |
| `vs doctor` | 检查运行可见性、配置、依赖和服务上下文。 |
| `vs scan` | 立即执行一次本地扫描。 |
| `vs reload` | 校验配置并重载 daemon。 |
| `vs baseline create` | 创建初始本地基线。 |
| `vs baseline diff` | 对比当前主机状态和基线。 |
| `vs blocks list` | 查看当前主动封禁。 |
| `vs blocks unblock <ip>` | 解除某个临时或永久封禁。 |
| `vs fingerprints explain <id>` | 解释攻击指纹聚类。 |
| `vs report send` | 通过已启用通知渠道发送默认日报。 |
| `vs panel push` | 向面板推送一次签名遥测。 |
| `vs menu` | 本地引导式运维：可信管理员 IP、allowlist 路径、刷新基线、查看/解除封禁、配置校验和服务重载。 |
| `vs config validate` | 校验配置文件。 |
| `vs config migrate` | 执行兼容配置迁移。 |
| `vs config normalize` | 将 `[allowlist]`、`[suppress_rules]` 等支持的配置块重写成规范数组格式。 |
| `vs config suppress-rule add CONFIG-004 --global` | 对已复核接受的风险按规则静默，不需要把底层文件排除出完整性监控。 |

## Token 类型

系统只保留少量必要 token，避免个人项目中过度分层：

| Token 或 secret | 使用方 | 用途 | 是否必须 |
| --- | --- | --- | --- |
| `panel.secret` / `PANEL_SHARED_SECRET` | Agent 和面板 | `POST /api/v1/ingest` HMAC 签名。 | 启用面板上报时必须 |
| `PANEL_NODE_SECRETS` | 面板 | 按非敏感节点名称配置单节点上报密钥。 | 可选 |
| `PANEL_TOKEN` | 浏览器和面板 | 私有访问 token，用于详情、复核、审计日志和管理入口。 | 使用私有面板功能时必须 |
| 通知渠道 token | Agent 和通知服务 | Telegram/Gotify/ntfy/Bark/ServerChan/钉钉/飞书/Webhook/邮件凭据。 | 仅启用对应渠道时需要 |

部署脚本复用旧凭据文件时，会把旧的 `PANEL_ADMIN_TOKEN`、`PANEL_OPERATOR_TOKEN` 或 `PANEL_VIEW_TOKEN` 迁移为新的 `PANEL_TOKEN`。

## 兼容性

Agent 面向常见 systemd Linux VPS，包括 Debian、Ubuntu、Alma/Rocky/RHEL 系、Fedora、Alpine、Arch 等。缺少平台工具时会降级而不是崩溃；部分采集器需要 root 可见性，`vs doctor` 会提示权限不足造成的能力下降。

常驻内存与启用模块、日志量、文件完整性范围有关。当前验证 VPS 集合中，daemon 进程 RSS 通常在个位数到二十 MiB 左右；systemd cgroup 内存可能因为文件缓存记账显得更高。

## 隐私

默认本地优先：不启用 `[panel]` 就不向面板上报，不配置通知就不发外部消息，文件扫描有大小限制，数据保存在本地 SQLite。面板遥测会移除节点 ID、主机 ID、服务器公网 IP、原始证据、路径、命令行和通用内部网络字段；节点名称、脱敏后的非 IP 主机名、国家、地区和城市等展示字段可以用于面板。已确认的外部攻击源 IP 可以在公开黑名单中展示，但公开黑名单不会展示节点名称。

面板不是远程命令或 SSH 管理平面。刷新基线、修改 allowlist、解除封禁等特权操作保留在各节点本地 `vs` 命令中，避免面板被攻破后直接变成整组服务器的 SSH 跳板。

token、密码、Webhook secret、SMTP 凭据、Cloudflare API token、面板 shared secret 应存放在本地配置、Worker secrets 或 systemd 环境文件中，源码仓库只保留示例占位符。

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=cryptoli/vps-sentinel&type=Date)](https://www.star-history.com/#cryptoli/vps-sentinel&Date)

## 许可证

MIT License。见 [LICENSE](LICENSE) 和 [docs/open-source-license.md](docs/open-source-license.md)。

## 贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。新规则必须是防御型、可解释、有证据、默认安全的。

## 安全反馈

请按照 [SECURITY.md](SECURITY.md) 私下报告安全漏洞。
