use crate::notify::{render_alert_for_config, Notifier, NotifyContext};
use async_trait::async_trait;
use lettre::message::{Mailbox, Message, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::Tls;
use lettre::transport::smtp::{AsyncSmtpTransport, AsyncSmtpTransportBuilder};
use lettre::{AsyncTransport, Tokio1Executor};
use sentinel_core::{
    EmailConfig, EmailTlsMode, SentinelConfig, SentinelError, SentinelResult, Severity,
};
use std::time::Duration;

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
        ctx: &NotifyContext,
    ) -> SentinelResult<()> {
        validate(&self.config)?;
        let message = build_message(&self.config, finding, &ctx.config)?;
        let mut transport_builder = smtp_transport_builder(&self.config)?.timeout(Some(
            Duration::from_secs(ctx.config.notifications.request_timeout_seconds),
        ));
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
            .map_err(email_transport_error)?;
        Ok(())
    }
}

fn validate(config: &EmailConfig) -> SentinelResult<()> {
    if config.smtp_host.trim().is_empty() || config.from.trim().is_empty() || config.to.is_empty() {
        return Err(SentinelError::Config(
            "email smtp_host, from, and to are required when email is enabled".to_string(),
        ));
    }
    if config.username.trim().is_empty() != config.password.trim().is_empty() {
        return Err(SentinelError::Config(
            "email username and password must be configured together".to_string(),
        ));
    }
    if config.tls_mode == EmailTlsMode::None && !config.username.trim().is_empty() {
        return Err(SentinelError::Config(
            "email plaintext SMTP cannot be used with credentials".to_string(),
        ));
    }
    Ok(())
}

fn build_message(
    config: &EmailConfig,
    finding: &sentinel_core::Finding,
    sentinel_config: &SentinelConfig,
) -> SentinelResult<Message> {
    let alert = render_alert_for_config(finding, sentinel_config);
    let from: Mailbox = config
        .from
        .parse()
        .map_err(|err| SentinelError::Notify(format!("invalid email from address: {err}")))?;
    let subject = if config.subject_prefix.trim().is_empty() {
        alert.subject.clone()
    } else {
        format!("{} {}", config.subject_prefix.trim(), alert.subject)
    };
    let mut builder = Message::builder().from(from).subject(subject);
    for recipient in &config.to {
        let mailbox: Mailbox = recipient
            .parse()
            .map_err(|err| SentinelError::Notify(format!("invalid email recipient: {err}")))?;
        builder = builder.to(mailbox);
    }
    builder
        .multipart(MultiPart::alternative_plain_html(
            alert.plain_text,
            alert.html,
        ))
        .map_err(|_| SentinelError::Notify("email message build failed".to_string()))
}

fn smtp_transport_builder(config: &EmailConfig) -> SentinelResult<AsyncSmtpTransportBuilder> {
    let builder = match config.tls_mode {
        EmailTlsMode::StartTls => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|_| {
                    SentinelError::Notify("email STARTTLS configuration failed".to_string())
                })?
                .port(config.smtp_port)
        }
        EmailTlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|_| SentinelError::Notify("email TLS configuration failed".to_string()))?
            .port(config.smtp_port),
        EmailTlsMode::None => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.smtp_host.clone())
                .tls(Tls::None)
                .port(config.smtp_port)
        }
    };
    Ok(builder)
}

fn email_transport_error(err: lettre::transport::smtp::Error) -> SentinelError {
    let reason = if err.is_timeout() {
        "timeout"
    } else if err.is_tls() {
        "tls failed"
    } else if err.is_response() {
        "smtp server rejected the message"
    } else {
        "send failed"
    };
    SentinelError::Notify(format!("email {reason}"))
}

#[cfg(test)]
mod tests {
    use super::{build_message, smtp_transport_builder};
    use sentinel_core::{
        Category, EmailConfig, EmailTlsMode, Evidence, Finding, SentinelConfig, Severity,
    };

    #[test]
    fn builds_multipart_email_message() {
        let config = email_config();
        let sentinel_config = SentinelConfig::default();
        let message = match build_message(&config, &sample_finding(), &sentinel_config) {
            Ok(message) => message,
            Err(err) => panic!("message should build: {err}"),
        };
        let formatted = String::from_utf8_lossy(&message.formatted()).to_string();
        assert!(formatted.contains("multipart/alternative"));
        assert!(formatted.contains("VPS Sentinel Alert"));
        assert!(formatted.contains("text/html"));
    }

    #[test]
    fn builds_plaintext_local_transport() {
        let mut config = email_config();
        config.tls_mode = EmailTlsMode::None;
        config.username.clear();
        config.password.clear();
        assert!(smtp_transport_builder(&config).is_ok());
    }

    fn email_config() -> EmailConfig {
        EmailConfig {
            enabled: true,
            smtp_host: "smtp.example.com".to_string(),
            smtp_port: 587,
            tls_mode: EmailTlsMode::StartTls,
            username: "user".to_string(),
            password: "secret".to_string(),
            from: "sentinel@example.com".to_string(),
            to: vec!["ops@example.com".to_string()],
            subject_prefix: "[vps-sentinel]".to_string(),
            min_severity: Severity::Info,
        }
    }

    fn sample_finding() -> Finding {
        Finding::new(
            "host",
            "Root login",
            "Root logged in through SSH.",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root",
        )
        .with_evidence(vec![Evidence::new("user", "root")])
        .with_recommendations(vec!["Review login.".to_string()])
    }
}
