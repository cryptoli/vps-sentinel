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
- Use `render_finding_with_language` or `render_alert_with_language` for standard message content that honors `notifications.language`.
- Honor `minimum_severity`.
- Keep retries and rate limiting outside the detector path.

MVP channels include Telegram, Email SMTP, Webhook, ntfy, Gotify, Bark, and ServerChan.
