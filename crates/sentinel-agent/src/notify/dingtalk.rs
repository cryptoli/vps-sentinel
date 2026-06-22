use crate::notify::{http_client, transport_error, MessageTemplate, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{DingTalkConfig, SentinelError, SentinelResult, Severity};
use serde_json::json;

pub struct DingTalkNotifier {
    config: DingTalkConfig,
    client: reqwest::Client,
}

impl DingTalkNotifier {
    pub fn new(config: DingTalkConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
        }
    }
}

#[async_trait]
impl Notifier for DingTalkNotifier {
    fn name(&self) -> &'static str {
        "dingtalk"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.access_token.trim().is_empty() {
            return Err(SentinelError::Config(
                "dingtalk access_token is required when dingtalk is enabled".to_string(),
            ));
        }
        let message = MessageTemplate::Markdown.render(finding, ctx);
        let url = format!(
            "https://oapi.dingtalk.com/robot/send?access_token={}",
            self.config.access_token
        );
        let response = self
            .client
            .post(url)
            .json(&json!({
                "msgtype": "markdown",
                "markdown": {
                    "title": message.subject,
                    "text": message.body,
                },
            }))
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "dingtalk returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
