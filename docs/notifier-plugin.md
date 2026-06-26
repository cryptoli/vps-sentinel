# Notifier Plugin Guide

Notification channels implement the `Notifier` trait in `sentinel-agent::notify`.

```rust
#[async_trait]
pub trait Notifier: Send + Sync {
    fn name(&self) -> &'static str;
    fn minimum_severity(&self) -> Severity;
    async fn notify(&self, finding: &Finding, ctx: &NotifyContext) -> SentinelResult<()>;
}
```

## Rules

- Do not log tokens, passwords, secrets, or webhook credentials.
- Return a structured error when required configuration is missing.
- Use `MessageTemplate` for standard message content that honors `notifications.language`, localized built-in rule content, `notifications.time_zone`, `notifications.include_technical_fields`, and `agent.display_name`.
- Prefer the richest template the channel safely supports: Telegram-compatible HTML for Telegram, Markdown for Markdown-aware push channels, and plain text for simple push payloads.
- Honor `minimum_severity`.
- Keep retries and rate limiting outside the detector path.

MVP channels include Telegram, Email SMTP, Webhook, ntfy, Gotify, Bark, ServerChan, DingTalk, and Feishu.
