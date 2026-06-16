use async_trait::async_trait;
use sentinel_core::{Finding, SentinelConfig, SentinelError, SentinelResult, Severity};
use std::sync::Arc;
use std::time::Duration;

pub mod bark;
pub mod email;
pub mod gotify;
mod i18n;
pub mod ntfy;
mod render;
pub mod serverchan;
pub mod telegram;
mod template;
pub mod webhook;

pub use render::{
    render_alert, render_alert_for_config, render_alert_with_language, render_finding,
    render_finding_with_language, NotificationFormat, RenderedAlert,
};
pub use template::{ChannelMessage, MessageContentType, MessageTemplate};

/// Context shared by notifier implementations.
#[derive(Clone)]
pub struct NotifyContext {
    pub config: Arc<SentinelConfig>,
}

/// Pluggable notification channel.
#[async_trait]
pub trait Notifier: Send + Sync {
    fn name(&self) -> &'static str;

    fn minimum_severity(&self) -> Severity;

    async fn notify(&self, finding: &Finding, ctx: &NotifyContext) -> SentinelResult<()>;
}

pub(crate) fn transport_error(channel: &str, err: reqwest::Error) -> SentinelError {
    let reason = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connection failed"
    } else if err.is_redirect() {
        "redirect error"
    } else if err.is_builder() {
        "invalid request"
    } else if err.is_decode() {
        "response decode error"
    } else {
        "request failed"
    };
    SentinelError::Notify(format!("{channel} request failed: {reason}"))
}

pub(crate) fn http_client(timeout_seconds: u64) -> reqwest::Client {
    match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_seconds))
        .build()
    {
        Ok(client) => client,
        Err(_) => reqwest::Client::new(),
    }
}

/// Sends findings to all enabled channels that pass severity routing.
pub struct NotificationManager {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl NotificationManager {
    pub fn from_config(config: &SentinelConfig) -> Self {
        let mut notifiers: Vec<Box<dyn Notifier>> = Vec::new();
        let timeout_seconds = config.notifications.request_timeout_seconds;
        if config.notifications.telegram.enabled {
            notifiers.push(Box::new(telegram::TelegramNotifier::new(
                config.notifications.telegram.clone(),
                timeout_seconds,
            )));
        }
        if config.notifications.email.enabled {
            notifiers.push(Box::new(email::EmailNotifier::new(
                config.notifications.email.clone(),
            )));
        }
        if config.notifications.webhook.enabled {
            notifiers.push(Box::new(webhook::WebhookNotifier::new(
                config.notifications.webhook.clone(),
                timeout_seconds,
            )));
        }
        if config.notifications.ntfy.enabled {
            notifiers.push(Box::new(ntfy::NtfyNotifier::new(
                config.notifications.ntfy.clone(),
                timeout_seconds,
            )));
        }
        if config.notifications.gotify.enabled {
            notifiers.push(Box::new(gotify::GotifyNotifier::new(
                config.notifications.gotify.clone(),
                timeout_seconds,
            )));
        }
        if config.notifications.bark.enabled {
            notifiers.push(Box::new(bark::BarkNotifier::new(
                config.notifications.bark.clone(),
                timeout_seconds,
            )));
        }
        if config.notifications.serverchan.enabled {
            notifiers.push(Box::new(serverchan::ServerChanNotifier::new(
                config.notifications.serverchan.clone(),
                timeout_seconds,
            )));
        }
        Self { notifiers }
    }

    pub fn enabled_count(&self) -> usize {
        self.notifiers.len()
    }

    pub fn planned_delivery_count(&self, findings: &[Finding]) -> usize {
        findings
            .iter()
            .map(|finding| {
                self.notifiers
                    .iter()
                    .filter(|notifier| finding.severity.meets(notifier.minimum_severity()))
                    .count()
            })
            .sum()
    }

    pub async fn notify_all(
        &self,
        findings: &[Finding],
        ctx: &NotifyContext,
    ) -> Vec<(String, String, SentinelResult<()>)> {
        self.notify_all_limited(findings, ctx, None).await
    }

    pub async fn notify_all_limited(
        &self,
        findings: &[Finding],
        ctx: &NotifyContext,
        limit: Option<usize>,
    ) -> Vec<(String, String, SentinelResult<()>)> {
        let mut results = Vec::new();
        let mut attempted = 0;
        for finding in findings {
            for notifier in &self.notifiers {
                if finding.severity.meets(notifier.minimum_severity()) {
                    if limit.is_some_and(|limit| attempted >= limit) {
                        return results;
                    }
                    attempted += 1;
                    results.push((
                        finding.id.clone(),
                        notifier.name().to_string(),
                        notifier.notify(finding, ctx).await,
                    ));
                }
            }
        }
        results
    }

    pub async fn notify_test(
        &self,
        finding: &Finding,
        ctx: &NotifyContext,
    ) -> Vec<(String, String, SentinelResult<()>)> {
        let mut results = Vec::new();
        for notifier in &self.notifiers {
            results.push((
                finding.id.clone(),
                notifier.name().to_string(),
                notifier.notify(finding, ctx).await,
            ));
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::NotificationManager;
    use sentinel_core::{Category, Finding, SentinelConfig, Severity};

    #[test]
    fn planned_delivery_count_respects_channel_severity() {
        let mut config = SentinelConfig::default();
        config.notifications.telegram.enabled = true;
        config.notifications.telegram.min_severity = Severity::High;
        config.notifications.webhook.enabled = true;
        config.notifications.webhook.min_severity = Severity::Medium;
        let manager = NotificationManager::from_config(&config);
        let findings = vec![
            Finding::new(
                "host",
                "medium",
                "desc",
                Severity::Medium,
                Category::System,
                "T-1",
                "a",
            ),
            Finding::new(
                "host",
                "high",
                "desc",
                Severity::High,
                Category::System,
                "T-2",
                "b",
            ),
        ];
        assert_eq!(manager.planned_delivery_count(&findings), 3);
    }
}
