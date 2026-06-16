use crate::notify::{render_finding, NotificationFormat, Notifier, NotifyContext};
use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use sentinel_core::{EmailConfig, SentinelError, SentinelResult, Severity};

pub struct EmailNotifier {
    config: EmailConfig,
}

impl EmailNotifier {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    fn name(&self) -> &'static str {
        "email"
    }

    fn minimum_severity(&self) -> Severity {
        self.config.min_severity
    }

    async fn notify(
        &self,
        finding: &sentinel_core::Finding,
        _ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        validate(&self.config)?;
        let from: Mailbox =
            self.config.from.parse().map_err(|err| {
                SentinelError::Notify(format!("invalid email from address: {err}"))
            })?;
        let mut builder = Message::builder()
            .from(from)
            .subject(format!("[{}] {}", finding.severity, finding.title));
        for recipient in &self.config.to {
            let mailbox: Mailbox = recipient
                .parse()
                .map_err(|err| SentinelError::Notify(format!("invalid email recipient: {err}")))?;
            builder = builder.to(mailbox);
        }
        let message = builder
            .body(render_finding(finding, NotificationFormat::PlainText))
            .map_err(|err| SentinelError::Notify(err.to_string()))?;

        let mut transport_builder =
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.config.smtp_host)
                .map_err(|err| SentinelError::Notify(err.to_string()))?
                .port(self.config.smtp_port);
        if !self.config.username.is_empty() {
            transport_builder = transport_builder.credentials(Credentials::new(
                self.config.username.clone(),
                self.config.password.clone(),
            ));
        }
        let transport = transport_builder.build();
        transport
            .send(message)
            .await
            .map_err(|err| SentinelError::Notify(err.to_string()))?;
        Ok(())
    }
}

fn validate(config: &EmailConfig) -> SentinelResult<()> {
    if config.smtp_host.trim().is_empty() || config.from.trim().is_empty() || config.to.is_empty() {
        return Err(SentinelError::Config(
            "email smtp_host, from, and to are required when email is enabled".to_string(),
        ));
    }
    Ok(())
}
