use crate::notify::{http_client, render_alert, transport_error, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{SentinelError, SentinelResult, Severity, TelegramConfig};
use serde::Deserialize;
use serde_json::json;

pub struct TelegramNotifier {
    config: TelegramConfig,
    client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct TelegramErrorResponse {
    description: Option<String>,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
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
        let alert = render_alert(finding);
        let body = json!({
            "chat_id": self.config.chat_id,
            "text": alert.plain_text,
            "disable_web_page_preview": true
        });
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
        let status = response.status();
        if !status.is_success() {
            let description = response
                .json::<TelegramErrorResponse>()
                .await
                .ok()
                .and_then(|body| body.description)
                .filter(|text| !text.trim().is_empty())
                .unwrap_or_else(|| "no response description".to_string());
            return Err(SentinelError::Notify(format!(
                "telegram returned HTTP {status}: {description}"
            )));
        }
        Ok(())
    }
}
