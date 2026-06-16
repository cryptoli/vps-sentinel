use super::render::{render_alert_for_config, RenderedAlert};
use super::NotifyContext;
use sentinel_core::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageTemplate {
    PlainText,
    Markdown,
    TelegramHtml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageContentType {
    PlainText,
    Markdown,
    Html,
}

#[derive(Debug, Clone)]
pub struct ChannelMessage {
    pub subject: String,
    pub body: String,
    pub content_type: MessageContentType,
    pub parse_mode: Option<&'static str>,
}

impl MessageTemplate {
    pub fn render(self, finding: &Finding, ctx: &NotifyContext) -> ChannelMessage {
        let alert = render_alert_for_config(finding, &ctx.config);
        self.select(alert)
    }

    fn select(self, alert: RenderedAlert) -> ChannelMessage {
        match self {
            Self::PlainText => ChannelMessage {
                subject: alert.subject,
                body: alert.plain_text,
                content_type: MessageContentType::PlainText,
                parse_mode: None,
            },
            Self::Markdown => ChannelMessage {
                subject: alert.subject,
                body: alert.markdown,
                content_type: MessageContentType::Markdown,
                parse_mode: None,
            },
            Self::TelegramHtml => ChannelMessage {
                subject: alert.subject,
                body: alert.telegram_html,
                content_type: MessageContentType::Html,
                parse_mode: Some("HTML"),
            },
        }
    }
}
