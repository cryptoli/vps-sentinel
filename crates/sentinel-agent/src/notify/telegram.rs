use crate::notify::{render_finding, NotificationFormat, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{SentinelError, SentinelResult, Severity, TelegramConfig};
use serde_json::json;

pub struct TelegramNotifier {
    config: TelegramConfig,
    client: reqwest::Client,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        _ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.bot_token.trim().is_empty() || self.config.chat_id.trim().is_empty() {
            return Err(SentinelError::Config(
                "telegram bot_token and chat_id are required when telegram is enabled".to_string(),
            ));
        }
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.config.bot_token
        );
        let body = json!({
            "chat_id": self.config.chat_id,
            "text": render_finding(finding, NotificationFormat::PlainText),
            "disable_web_page_preview": true
        });
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|err| SentinelError::Notify(err.to_string()))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "telegram returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
