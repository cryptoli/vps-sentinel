use super::content::{localized_finding, LocalizedFinding};
use super::i18n::{catalog, evidence_label, severity_label, MessageCatalog};
use chrono::Local;
use sentinel_core::{Finding, NotificationLanguage, NotificationTimeZone, SentinelConfig};
use std::borrow::Cow;

mod escape;
mod html;
mod telegram;
mod text;

/// Output format for rendered notification bodies.
#[derive(Debug, Clone, Copy)]
pub enum NotificationFormat {
    Markdown,
    Html,
    TelegramHtml,
    PlainText,
}

#[derive(Debug, Clone)]
pub struct RenderedAlert {
    pub subject: String,
    pub plain_text: String,
    pub markdown: String,
    pub html: String,
    pub telegram_html: String,
}

#[derive(Debug, Clone)]
pub struct AlertRenderOptions {
    pub language: NotificationLanguage,
    pub time_zone: NotificationTimeZone,
    pub include_technical_fields: bool,
    pub vps_name: String,
}

impl AlertRenderOptions {
    pub fn new(language: NotificationLanguage, vps_name: impl Into<String>) -> Self {
        let vps_name = vps_name.into();
        Self {
            language,
            time_zone: NotificationTimeZone::Local,
            include_technical_fields: false,
            vps_name,
        }
    }

    pub fn from_config(config: &SentinelConfig) -> Self {
        Self {
            language: config.notifications.language,
            time_zone: config.notifications.time_zone,
            include_technical_fields: config.notifications.include_technical_fields,
            vps_name: config.display_name(),
        }
    }
}

/// Render a finding in the standard alert shape.
pub fn render_finding(finding: &Finding, format: NotificationFormat) -> String {
    render_finding_with_language(finding, format, NotificationLanguage::En)
}

pub fn render_finding_with_language(
    finding: &Finding,
    format: NotificationFormat,
    language: NotificationLanguage,
) -> String {
    let alert = render_alert_with_language(finding, language);
    match format {
        NotificationFormat::Markdown => alert.markdown,
        NotificationFormat::Html => alert.html,
        NotificationFormat::TelegramHtml => alert.telegram_html,
        NotificationFormat::PlainText => alert.plain_text,
    }
}

pub fn render_alert(finding: &Finding) -> RenderedAlert {
    render_alert_with_language(finding, NotificationLanguage::En)
}

pub fn render_alert_with_language(
    finding: &Finding,
    language: NotificationLanguage,
) -> RenderedAlert {
    render_alert_with_options(
        finding,
        &AlertRenderOptions::new(language, finding.host_id.clone()),
    )
}

pub fn render_alert_for_config(finding: &Finding, config: &SentinelConfig) -> RenderedAlert {
    render_alert_with_options(finding, &AlertRenderOptions::from_config(config))
}

pub fn render_alert_with_options(finding: &Finding, options: &AlertRenderOptions) -> RenderedAlert {
    let catalog = catalog(options.language);
    let display = localized_finding(finding, options.language);
    let subject = format!(
        "[{}][{}] {}",
        options.vps_name,
        severity_label(finding.severity, options.language),
        display.title
    );
    RenderedAlert {
        subject: subject.clone(),
        plain_text: text::render_plain_text(finding, &display, &subject, &catalog, options),
        markdown: text::render_markdown(finding, &display, &subject, &catalog, options),
        html: html::render_html(finding, &display, &subject, &catalog, options),
        telegram_html: telegram::render_telegram_html(
            finding, &display, &subject, &catalog, options,
        ),
    }
}

pub(super) struct AlertField<'a> {
    pub(super) label: &'static str,
    pub(super) value: Cow<'a, str>,
}

pub(super) struct AlertList {
    pub(super) title: &'static str,
    pub(super) style: ListStyle,
    pub(super) items: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum ListStyle {
    Bulleted,
    Numbered,
}

pub(super) fn alert_fields<'a>(
    finding: &'a Finding,
    display: &'a LocalizedFinding,
    catalog: &MessageCatalog,
    options: &'a AlertRenderOptions,
) -> Vec<AlertField<'a>> {
    let mut fields = vec![
        borrowed_field(catalog.vps, &options.vps_name),
        borrowed_value_field(
            catalog.severity,
            severity_label(finding.severity, options.language),
        ),
        borrowed_field(catalog.host_id, &finding.host_id),
        owned_field(catalog.time, format_timestamp(finding, options.time_zone)),
        owned_field(
            catalog.category,
            category_label(&finding.category, options.language),
        ),
        borrowed_field(catalog.subject, &finding.subject),
        borrowed_field(catalog.description, &display.description),
    ];
    fields.retain(|field| !field.value.trim().is_empty());
    fields
}

pub(super) fn alert_lists(
    finding: &Finding,
    display: &LocalizedFinding,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
) -> Vec<AlertList> {
    let mut lists = vec![
        AlertList {
            title: catalog.evidence,
            style: ListStyle::Bulleted,
            items: finding
                .evidence
                .iter()
                .map(|item| {
                    format!(
                        "{}: {}",
                        evidence_label(&item.key, options.language),
                        item.value
                    )
                })
                .collect(),
        },
        AlertList {
            title: catalog.impact,
            style: ListStyle::Bulleted,
            items: display.impact.clone(),
        },
        AlertList {
            title: catalog.recommendations,
            style: ListStyle::Numbered,
            items: display.recommendations.clone(),
        },
    ];
    for list in &mut lists {
        list.items.retain(|item| !item.trim().is_empty());
    }
    lists.retain(|list| !list.items.is_empty());
    lists
}

pub(super) fn technical_fields<'a>(
    finding: &'a Finding,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
) -> Vec<AlertField<'a>> {
    if !options.include_technical_fields {
        return Vec::new();
    }
    vec![
        borrowed_field(catalog.rule, &finding.rule_id),
        borrowed_field(catalog.event_id, &finding.id),
        borrowed_field(catalog.dedup_key, &finding.dedup_key),
    ]
}

pub(super) fn non_empty_items<I>(items: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    items
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect()
}

fn borrowed_field<'a>(label: &'static str, value: &'a str) -> AlertField<'a> {
    AlertField {
        label,
        value: Cow::Borrowed(value),
    }
}

fn borrowed_value_field(label: &'static str, value: &'static str) -> AlertField<'static> {
    AlertField {
        label,
        value: Cow::Borrowed(value),
    }
}

fn owned_field(label: &'static str, value: String) -> AlertField<'static> {
    AlertField {
        label,
        value: Cow::Owned(value),
    }
}

fn format_timestamp(finding: &Finding, time_zone: NotificationTimeZone) -> String {
    match time_zone {
        NotificationTimeZone::Local => finding
            .timestamp
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S %:z")
            .to_string(),
        NotificationTimeZone::Utc => finding
            .timestamp
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
    }
}

fn category_label(category: &sentinel_core::Category, language: NotificationLanguage) -> String {
    match language {
        NotificationLanguage::En => category.to_string(),
        NotificationLanguage::ZhCn => match category {
            sentinel_core::Category::Ssh => "SSH".to_string(),
            sentinel_core::Category::User => "用户".to_string(),
            sentinel_core::Category::Privilege => "权限".to_string(),
            sentinel_core::Category::Persistence => "持久化".to_string(),
            sentinel_core::Category::Process => "进程".to_string(),
            sentinel_core::Category::Network => "网络".to_string(),
            sentinel_core::Category::FileIntegrity => "文件完整性".to_string(),
            sentinel_core::Category::Web => "Web".to_string(),
            sentinel_core::Category::Docker => "Docker".to_string(),
            sentinel_core::Category::Rootkit => "Rootkit 信号".to_string(),
            sentinel_core::Category::ConfigRisk => "配置风险".to_string(),
            sentinel_core::Category::System => "系统".to_string(),
        },
    }
}

#[cfg(test)]
mod tests;
