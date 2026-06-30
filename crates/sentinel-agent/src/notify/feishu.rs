use crate::notify::{http_client, transport_error, MessageTemplate, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{FeishuConfig, SentinelError, SentinelResult, Severity};
use serde_json::{json, Value};

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

        // Check the business response code from Feishu.
        // A successful HTTP response does not guarantee that the message was accepted by Feishu,
        // as it may still return a business error code in the JSON body.
        // for more information, see https://github.com/cryptoli/vps-sentinel/pull/1
        validate_feishu_response(
            response
                .json::<Value>()
                .await
                .map_err(|err| transport_error(self.name(), err))?,
        )?;
        Ok(())
    }
}

fn validate_feishu_response(body: Value) -> SentinelResult<()> {
    let code = body
        .get("code")
        .or_else(|| body.get("StatusCode"))
        .and_then(Value::as_i64);
    match code {
        Some(0) => Ok(()),
        Some(code) => Err(SentinelError::Notify(format!(
            "feishu returned business error {code}: {}",
            body.get("msg")
                .or_else(|| body.get("StatusMessage"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        ))),
        None => Err(SentinelError::Notify(
            "feishu response missing business code".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_feishu_response;
    use serde_json::json;

    #[test]
    fn accepts_code_success() {
        assert!(validate_feishu_response(json!({ "code": 0, "msg": "success" })).is_ok());
    }

    #[test]
    fn accepts_status_code_success() {
        assert!(
            validate_feishu_response(json!({ "StatusCode": 0, "StatusMessage": "success" }))
                .is_ok()
        );
    }

    #[test]
    fn rejects_failed_business_code() {
        let err = validate_feishu_response(json!({ "code": 19001, "msg": "invalid webhook" }))
            .expect_err("business failure should be an error");

        assert!(err.to_string().contains("business error 19001"));
    }
}
