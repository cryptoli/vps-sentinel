use crate::notify::{http_client, transport_error, MessageTemplate, Notifier, NotifyContext};
use async_trait::async_trait;
use sentinel_core::{DingTalkConfig, SentinelError, SentinelResult, Severity};
use serde_json::{json, Value};

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

        // Check the business response code from DingTalk.
        // A successful HTTP response does not guarantee that the message was accepted by DingTalk,
        // as it may still return a business error code in the JSON body.
        // for more information, see https://github.com/cryptoli/vps-sentinel/pull/1
        validate_dingtalk_response(
            response
                .json::<Value>()
                .await
                .map_err(|err| transport_error(self.name(), err))?,
        )?;
        Ok(())
    }
}

fn validate_dingtalk_response(body: Value) -> SentinelResult<()> {
    match body.get("errcode").and_then(Value::as_i64) {
        Some(0) => Ok(()),
        Some(code) => Err(SentinelError::Notify(format!(
            "dingtalk returned business error {code}: {}",
            body.get("errmsg")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        ))),
        None => Err(SentinelError::Notify(
            "dingtalk response missing errcode".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_dingtalk_response;
    use serde_json::json;

    #[test]
    fn accepts_success_business_code() {
        assert!(validate_dingtalk_response(json!({ "errcode": 0, "errmsg": "ok" })).is_ok());
    }

    #[test]
    fn rejects_failed_business_code() {
        let err = validate_dingtalk_response(
            json!({ "errcode": 310000, "errmsg": "keywords not in content" }),
        )
        .expect_err("business failure should be an error");

        assert!(err.to_string().contains("business error 310000"));
    }
}
