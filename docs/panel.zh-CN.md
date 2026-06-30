# 多服务器面板

多服务器面板是可选的推模式仪表盘。Agent 仍然以本地检测为主，只有在 `[panel].enabled = true` 时才上传签名、有界、已脱敏的摘要数据。

## 访问模型

面板浏览器访问只保留两层：

| 层级 | 用途 |
| --- | --- |
| 公开 | 可选的免登录页面，例如总览、黑名单和节点。公开接口不会暴露原始证据、节点 ID、主机 ID、被保护节点主机名、路径、命令行或内部网络字段。 |
| 私有 | 使用单一 `PANEL_TOKEN` 解锁详情、复核、审计日志、主动响应详情和管理入口。 |

Agent 上报是另一条信任边界：Agent 的 `panel.secret` 必须匹配面板的 `PANEL_SHARED_SECRET`，或匹配 `PANEL_NODE_SECRETS` 中按节点名称配置的单节点密钥。

面板不是远程命令或修复控制平面。它不会向 agent 下发 SSH 命令、allowlist 修改、基线刷新或解除封禁请求。特权修复操作保留在各节点本地 `vs` 命令中，避免面板被攻破后直接影响整组服务器。

## 遥测结构

Agent 使用 `node_name` 作为展示身份，并在上传前移除节点 ID、主机 ID、服务器公网 IP、原始日志、原始证据、路径、命令行和通用内部网络字段。面板接收端入库前会再做一次脱敏。

安全展示字段可以上传：不含 IP 的脱敏主机名、国家、地区和城市。Agent 侧节点地域探测会从可信 HTTPS 接口推导展示字段，然后丢弃公网 IP。Cloudflare 面板还可以使用 Cloudflare 请求地域；自建面板可以选择 MaxMind/DB-IP MMDB 文件补充真实远端请求 IP 的地域。

节点状态按最后一次成功上报计算：30 分钟内为正常，超过 30 分钟为延迟，超过 90 分钟为离线，超过 12 小时或占位节点记录为退役。

## 实时刷新

自建 Rust 面板支持 `/api/v1/stream-ticket` 和 `/api/v1/stream` 的 WebSocket 刷新事件。

Cloudflare Worker 模式目前提供相同 API 和 D1 存储，但 WebSocket ticket 会返回 `stream_unavailable`。前端会识别这一点并进入 fallback 状态，不会一直显示重连或反复请求。

对于个人或少量 VPS，面板不是必须的特权运维入口。建议在每台节点本地使用 `vs menu`，或从独立管理员工作站执行 SSH 运维；不要在面板服务器上保存 SSH 私钥，也不要把它当成通用 SSH 跳板。自建面板可绑定 `127.0.0.1:8858`、Tailscale 地址或其他内网地址，公网反代应作为明确选择而不是默认做法。

## 更多文档

- 部署：[panel-deployment.zh-CN.md](panel-deployment.zh-CN.md)
- 架构：[panel-architecture.zh-CN.md](panel-architecture.zh-CN.md)
- 主题扩展：[panel-themes.zh-CN.md](panel-themes.zh-CN.md)
- English: [panel.md](panel.md)
