use crate::notify::{render_finding, NotificationFormat, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{GotifyConfig, SentinelError, SentinelResult, Severity};
use serde_json::json;

pub struct GotifyNotifier {
    config: GotifyConfig,
    client: reqwest::Client,
}

impl GotifyNotifier {
    pub fn new(config: GotifyConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for GotifyNotifier {
    fn name(&self) -> &'static str {
        "gotify"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        _ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.server.trim().is_empty() || self.config.token.trim().is_empty() {
            return Err(SentinelError::Config(
                "gotify server and token are required when gotify is enabled".to_string(),
            ));
        }
        let url = format!(
            "{}/message?token={}",
            self.config.server.trim_end_matches('/'),
            self.config.token
        );
        let response = self
            .client
            .post(url)
            .json(&json!({
                "title": finding.title,
                "message": render_finding(finding, NotificationFormat::PlainText),
                "priority": gotify_priority(finding.severity),
            }))
            .send()
            .await
            .map_err(|err| SentinelError::Notify(err.to_string()))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "gotify returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}

fn gotify_priority(severity: Severity) -> i32 {
    match severity {
        Severity::Info => 1,
        Severity::Low => 2,
        Severity::Medium => 4,
        Severity::High => 7,
        Severity::Critical => 10,
    }
}
