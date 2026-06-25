# 配置参考

完整示例见 [config/config.example.toml](../config/config.example.toml)。修改配置后建议执行：

```bash
sudo vs config validate
sudo vs reload
```

## 常用配置块

| 配置块 | 说明 |
| --- | --- |
| `[agent]` | 扫描间隔、节点展示名、日志级别等基础运行配置。 |
| `[ssh]` | SSH 登录、失败尝试、可信管理员 IP 和授权密钥检测。 |
| `[web]` | Web 日志探查、攻击路径聚合、可信代理客户端 IP 还原。 |
| `[process]` / `[gpu]` | 进程行为、父进程链、执行文件属性、CPU/GPU 异常。 |
| `[network]` | 监听端口、服务身份和公网暴露辅助判断。 |
| `[active_response]` | 主动封禁策略、阈值、allowlist 和永久封禁升级。 |
| `[panel]` | 面板上报地址、节点名称、签名密钥、隐私模式和上报预算。 |
| `[notifications]` | Telegram、邮件、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| `[maintenance]` | 运维窗口内抑制基线漂移或交互登录噪音。 |

## 面板位置

Agent 不再配置国家、城市或公网 IP。节点位置由面板接收端在可信反代头可用时自动补充，例如 Cloudflare 地理位置头。
