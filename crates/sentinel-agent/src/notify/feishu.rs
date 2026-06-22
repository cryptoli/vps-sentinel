use crate::notify::{http_client, transport_error, MessageTemplate, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{FeishuConfig, SentinelError, SentinelResult, Severity};
use serde_json::json;

pub struct FeishuNotifier {
    config: FeishuConfig,
    client: reqwest::Client,
}

impl FeishuNotifier {
    pub fn new(config: FeishuConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
        }
    }
}

#[async_trait]
impl Notifier for FeishuNotifier {
    fn name(&self) -> &'static str {
        "feishu"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.webhook_url.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.feishu.webhook_url is required when feishu is enabled".to_string(),
            ));
        }
        let message = MessageTemplate::Markdown.render(finding, ctx);
        let response = self
            .client
            .post(self.config.webhook_url.trim())
            .json(&json!({
                "msg_type": "interactive",
                "card": {
                    "header": {
                        "title": {
                            "tag": "plain_text",
                            "content": message.subject,
                        }
                    },
                    "elements": [
                        {
                            "tag": "div",
                            "text": {
                                "tag": "lark_md",
                                "content": message.body,
                            }
                        }
                    ]
                },
            }))
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "feishu returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
