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
| `[panel]` | 面板上报地址、节点名称、签名密钥、隐私模式、主机名脱敏上传和节点地域探测。 |
| `[notifications]` | Telegram、邮件、Webhook、ntfy、Gotify、Bark、ServerChan。 |
| `[reports]` | 每日安全报告。`scheduled_hour` 按 `notifications.time_zone` 中的日历日固定小时发送，记录的是当天具体发送槽位，延迟扫描不会把第二天报告时间滚动推迟。 |
| `[maintenance]` | 运维窗口内抑制基线漂移或交互登录噪音。 |

## 面板位置

Agent 不需要手动配置国家、城市或公网 IP。启用 `panel.node_location_enabled` 后，agent 会通过 HTTPS 地域接口自动推导国家、地区和城市，并只上传这些展示字段，不上传用于推导的公网 IP。自建面板也可以配置 MaxMind/DB-IP MMDB 文件，通过真实远端请求 IP 补充地域；Cloudflare 面板会使用 Cloudflare 请求地域。

`panel.upload_hostname = true` 只允许上传不含 IP、不含危险字符、通过脱敏校验的主机名。节点 ID、主机 ID、服务器公网 IP、路径、命令行和原始证据仍然不会上报。
