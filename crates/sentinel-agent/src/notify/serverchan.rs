use crate::notify::{
    http_client, render_finding, transport_error, NotificationFormat, Notifier, NotifyContext,
};
use async_trait::async_trait;
use sentinel_core::{SentinelError, SentinelResult, ServerChanConfig, Severity};

pub struct ServerChanNotifier {
    config: ServerChanConfig,
    client: reqwest::Client,
}

impl ServerChanNotifier {
    pub fn new(config: ServerChanConfig, timeout_seconds: u64) -> Self {
        Self {
            config,
            client: http_client(timeout_seconds),
        }
    }
}

#[async_trait]
impl Notifier for ServerChanNotifier {
    fn name(&self) -> &'static str {
        "serverchan"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        _ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        if self.config.send_key.trim().is_empty() {
            return Err(SentinelError::Config(
                "serverchan send_key is required when serverchan is enabled".to_string(),
            ));
        }
        let url = format!("https://sctapi.ftqq.com/{}.send", self.config.send_key);
        let response = self
            .client
            .post(url)
            .form(&[
                ("title", finding.title.as_str()),
                (
                    "desp",
                    render_finding(finding, NotificationFormat::Markdown).as_str(),
                ),
            ])
            .send()
            .await
            .map_err(|err| transport_error(self.name(), err))?;
        if !response.status().is_success() {
            return Err(SentinelError::Notify(format!(
                "serverchan returned HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}
