use crate::notify::{http_client, render_alert, transport_error, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{BarkConfig, SentinelError, SentinelResult, Severity};
use serde_json::json;

pub struct BarkNotifier {
    config: BarkConfig,
    client: reqwest::Client,
}

impl BarkNotifier {
    pub fn new(config: BarkConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
        }
    }
}

#[async_trait]
impl Notifier for BarkNotifier {
    fn name(&self) -> &'static str {
        "bark"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        _ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.device_key.trim().is_empty() {
            return Err(SentinelError::Config(
                "bark device_key is required when bark is enabled".to_string(),
            ));
        }
        let alert = render_alert(finding);
        let url = format!("{}/push", self.config.server.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .json(&json!({
                "device_key": self.config.device_key,
                "title": alert.subject,
                "body": alert.plain_text,
            }))
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "bark returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
