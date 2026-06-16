use crate::notify::{
    http_client, render_alert_with_language, transport_error, Notifier, NotifyContext,
};
use async_trait::async_trait;
use sentinel_core::{GotifyConfig, SentinelError, SentinelResult, Severity};
use serde_json::json;

pub struct GotifyNotifier {
    config: GotifyConfig,
    client: reqwest::Client,
}

impl GotifyNotifier {
    pub fn new(config: GotifyConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
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
        ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.server.trim().is_empty() || self.config.token.trim().is_empty() {
            return Err(SentinelError::Config(
                "gotify server and token are required when gotify is enabled".to_string(),
            ));
        }
        let alert = render_alert_with_language(finding, ctx.config.notifications.language);
        let url = format!(
            "{}/message?token={}",
            self.config.server.trim_end_matches('/'),
            self.config.token
        );
        let response = self
            .client
            .post(url)
            .json(&json!({
                "title": alert.subject,
                "message": alert.plain_text,
                "priority": gotify_priority(finding.severity),
            }))
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
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
