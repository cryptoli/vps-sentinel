use crate::notify::{MessageTemplate, Notifier, NotifyContext};
use async_trait::async_trait;
use frankenstein::client_reqwest::Bot;
use frankenstein::methods::SendMessageParams;
use frankenstein::types::{ChatId, LinkPreviewOptions};
use frankenstein::{AsyncTelegramApi, ParseMode};
use sentinel_core::{SentinelError, SentinelResult, Severity, TelegramConfig};
use std::time::Duration;

pub struct TelegramNotifier {
    config: TelegramConfig,
    bot: Bot,
}

impl TelegramNotifier {
    pub fn new(config: TelegramConfig, timeout_seconds: u64) -> Self {
        let client = frankenstein::reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .unwrap_or_default();
        let api_url = format!("{}{}", frankenstein::BASE_API_URL, config.bot_token);
        let bot = Bot { api_url, client };
        Self { config, bot }
    }

    fn chat_id(&self) -> ChatId {
        match self.config.chat_id.trim().parse::<i64>() {
            Ok(id) => ChatId::Integer(id),
            Err(_) => ChatId::String(self.config.chat_id.clone()),
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
        ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.bot_token.trim().is_empty() || self.config.chat_id.trim().is_empty() {
            return Err(SentinelError::Config(
                "telegram bot_token and chat_id are required when telegram is enabled".to_string(),
            ));
        }
        let message = MessageTemplate::TelegramHtml.render(finding, ctx);
        let params = SendMessageParams::builder()
            .chat_id(self.chat_id())
            .text(message.body)
            .parse_mode(ParseMode::Html)
            .link_preview_options(LinkPreviewOptions::builder().is_disabled(true).build())
            .build();
        self.bot
            .send_message(&params)
            .await
            .map_err(telegram_error)?;
        Ok(())
    }
}

fn telegram_error(err: frankenstein::Error) -> SentinelError {
    match err {
        frankenstein::Error::Api(response) => {
            let description = if response.description.trim().is_empty() {
                "no response description".to_string()
            } else {
                response.description
            };
            SentinelError::Notify(format!(
                "telegram returned API error {}: {description}",
                response.error_code
            ))
        }
        other => SentinelError::Notify(format!("telegram request failed: {other}")),
    }
}
