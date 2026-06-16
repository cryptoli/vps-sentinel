use async_trait::async_trait;
use sentinel_core::{Finding, SentinelConfig, SentinelError, SentinelResult, Severity};
use std::sync::Arc;
use std::time::Duration;

pub mod bark;
pub mod email;
pub mod gotify;
pub mod ntfy;
pub mod serverchan;
pub mod telegram;
pub mod webhook;

/// Output format for rendered notification bodies.
#[derive(Debug, Clone, Copy)]
pub enum NotificationFormat {
    Markdown,
    PlainText,
}

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

    pub async fn notify_all(
        &self,
        findings: &[Finding],
        ctx: &NotifyContext,
    ) -> Vec<(String, String, SentinelResult<()>)> {
        let mut results = Vec::new();
        for finding in findings {
            for notifier in &self.notifiers {
                if finding.severity.meets(notifier.minimum_severity()) {
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
}

/// Render a finding in the standard alert shape.
pub fn render_finding(finding: &Finding, format: NotificationFormat) -> String {
    let bullet = match format {
        NotificationFormat::Markdown => "-",
        NotificationFormat::PlainText => "-",
    };
    let mut out = String::new();
    out.push_str(&format!("[{}] {}\n\n", finding.severity, finding.title));
    out.push_str(&format!("Host: {}\n", finding.host_id));
    out.push_str(&format!("Time: {}\n", finding.timestamp.to_rfc3339()));
    out.push_str(&format!("Module: {}\n", finding.category));
    out.push_str(&format!("Rule: {}\n", finding.rule_id));
    out.push_str(&format!("Subject: {}\n", finding.subject));
    out.push_str("Evidence:\n");
    for item in &finding.evidence {
        out.push_str(&format!("{bullet} {}: {}\n", item.key, item.value));
    }
    if !finding.impact.is_empty() {
        out.push_str("Impact:\n");
        for item in &finding.impact {
            out.push_str(&format!("{bullet} {item}\n"));
        }
    }
    out.push_str("Recommendations:\n");
    for (index, item) in finding.recommendations.iter().enumerate() {
        out.push_str(&format!("{}. {}\n", index + 1, item));
    }
    out.push_str(&format!("\nEvent ID: {}\n", finding.id));
    out
}

#[cfg(test)]
mod tests {
    use super::{render_finding, NotificationFormat};
    use sentinel_core::{Category, Evidence, Finding, Severity};

    #[test]
    fn renders_standard_alert_body() {
        let finding = Finding::new(
            "host",
            "Root login",
            "desc",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root",
        )
        .with_evidence(vec![Evidence::new("user", "root")])
        .with_recommendations(vec!["Review login.".to_string()]);
        let body = render_finding(&finding, NotificationFormat::PlainText);
        assert!(body.contains("[High] Root login"));
        assert!(body.contains("Rule: SSH-001"));
        assert!(body.contains("Evidence:"));
    }
}
