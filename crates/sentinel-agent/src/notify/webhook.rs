use crate::notify::{Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{SentinelError, SentinelResult, Severity, WebhookConfig};

pub struct WebhookNotifier {
    config: WebhookConfig,
    client: reqwest::Client,
}

impl WebhookNotifier {
    pub fn new(config: WebhookConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        _ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.url.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.webhook.url is required when webhook is enabled".to_string(),
            ));
        }
        let mut request = self.client.post(&self.config.url).json(finding);
        if !self.config.secret.is_empty() {
            request = request.header("X-Vps-Sentinel-Secret", &self.config.secret);
        }
        let response = request
            .send()
            .await
            .map_err(|err| SentinelError::Notify(err.to_string()))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "webhook returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
