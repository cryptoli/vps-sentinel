# 面板架构

## 组件

| 组件 | 职责 |
| --- | --- |
| Agent 面板客户端 | 生成有界遥测信封，移除敏感主机身份字段，使用 HMAC 签名，并把失败上报写入本地队列。 |
| 接收端 | 校验签名、nonce、时间戳和 payload 大小；从可信代理元数据补充非敏感节点位置；入库前保存脱敏后的行数据。 |
| Repository | 为 SQLite、PostgreSQL、MySQL 或 Cloudflare D1 提供有界分页读取模型。 |
| Web UI | 读取固定 API 数据集，执行前端隐私兜底，并只更新变化的数据区块，不整页刷新。 |

## 共享契约

Rust 自建面板、Cloudflare Worker 和前端页面定义共享 `panel/shared/contract.json`。执行 `node scripts/generate-panel-contract.mjs` 会生成：

- `crates/sentinel-panel/src/panel_contract.rs`
- `panel/cloudflare/panel-contract.generated.js`
- `panel/ui/src/lib/panel-contract.generated.ts`
- `panel/shared/contract.env`

数据集、公开页、默认管理路径、公开黑名单脱敏字段和页面列定义都从这个契约生成。CI 会执行 `node scripts/generate-panel-contract.mjs --check`，防止三端实现漂移。

## 信任边界

`PANEL_SHARED_SECRET` 和 `PANEL_NODE_SECRETS` 是 agent 上报凭据。`PANEL_TOKEN` 是唯一浏览器私有访问 token。通知 token 和 Cloudflare 部署凭据是独立凭据，存放在本地配置、Worker secrets 或 systemd 环境文件中。

## 实时策略

自建 Rust 面板使用 WebSocket ticket，避免把浏览器 token 放进 WebSocket URL。Cloudflare Worker 部署当前使用 REST fallback，因为普通 Worker 没有持久广播状态；后续可以用 Durable Objects 扩展，不需要改变 agent 协议。

## 数据安全

面板 API 按数据集和列白名单返回数据。公开页面只暴露聚合信息或明确可公开的外部攻击源信息。私有页面可以查看复核和处置细节，但节点 ID、主机 ID、主机名和复核签名仍不会出现在浏览器列表接口中。
