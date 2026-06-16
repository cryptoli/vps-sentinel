use crate::notify::{http_client, transport_error, MessageTemplate, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{NtfyConfig, SentinelError, SentinelResult, Severity};

pub struct NtfyNotifier {
    config: NtfyConfig,
    client: reqwest::Client,
}

impl NtfyNotifier {
    pub fn new(config: NtfyConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
        }
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    fn name(&self) -> &'static str {
        "ntfy"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.topic.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.ntfy.topic is required when ntfy is enabled".to_string(),
            ));
        }
        let message = MessageTemplate::PlainText.render(finding, ctx);
        let url = format!(
            "{}/{}",
            self.config.server.trim_end_matches('/'),
            self.config.topic
        );
        let mut request = self
            .client
            .post(url)
            .header("Title", message.subject.as_str())
            .header("Tags", finding.severity.to_string())
            .body(message.body);
        if !self.config.token.is_empty() {
            request = request.bearer_auth(&self.config.token);
        }
        let response = request
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "ntfy returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
