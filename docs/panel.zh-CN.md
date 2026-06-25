# 多服务器面板

多服务器面板是可选的推模式仪表盘。Agent 仍然以本地检测为主，只有在 `[panel].enabled = true` 时才上传签名、有界、已脱敏的摘要数据。

## 访问模型

面板浏览器访问只保留两层：

| 层级 | 用途 |
| --- | --- |
| 公开 | 可选的免登录页面，例如总览、黑名单和节点。公开接口不会暴露原始证据、节点 ID、主机名、路径、命令行或内部网络字段。 |
| 私有 | 使用单一 `PANEL_TOKEN` 解锁详情、复核、审计日志、主动响应详情和管理入口。 |

Agent 上报是另一条信任边界：Agent 的 `panel.secret` 必须匹配面板的 `PANEL_SHARED_SECRET`，或匹配 `PANEL_NODE_SECRETS` 中按节点名称配置的单节点密钥。

## 遥测结构

Agent 使用 `node_name` 作为展示身份，并在上传前移除节点 ID、主机 ID、主机名、原始日志、原始证据、路径、命令行和通用内部网络字段。面板接收端入库前会再做一次脱敏。

节点国家、城市不再由 agent 配置。面板接收端会在可信反代元数据可用时自动补充，例如 Cloudflare 地理位置头。这个过程不需要 agent 上传公网 IP。

## 实时刷新

自建 Rust 面板支持 `/api/v1/stream-ticket` 和 `/api/v1/stream` 的 WebSocket 刷新事件。

Cloudflare Worker 模式目前提供相同 API 和 D1 存储，但 WebSocket ticket 会返回 `stream_unavailable`。前端会识别这一点并进入 fallback 状态，不会一直显示重连或反复请求。

## 更多文档

- 部署：[panel-deployment.zh-CN.md](panel-deployment.zh-CN.md)
- 架构：[panel-architecture.zh-CN.md](panel-architecture.zh-CN.md)
- 主题扩展：[panel-themes.zh-CN.md](panel-themes.zh-CN.md)
- English: [panel.md](panel.md)
