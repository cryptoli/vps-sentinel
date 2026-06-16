use super::content::{localized_finding, LocalizedFinding};
use super::i18n::{catalog, evidence_label, severity_label, MessageCatalog};
use chrono::Local;
use sentinel_core::{Finding, NotificationLanguage, NotificationTimeZone, SentinelConfig};
use std::borrow::Cow;

mod escape;
mod html;
mod telegram;
use escape::markdown_escape;

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
        plain_text: render_plain_text(finding, &display, &subject, &catalog, options),
        markdown: render_markdown(finding, &display, &subject, &catalog, options),
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

fn alert_fields<'a>(
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

fn alert_lists(
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

fn render_plain_text(
    finding: &Finding,
    display: &LocalizedFinding,
    subject: &str,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
) -> String {
    let mut out = String::new();
    out.push_str(catalog.heading);
    out.push('\n');
    out.push_str("==================\n\n");
    out.push_str(subject);
    out.push_str("\n\n");
    for field in alert_fields(finding, display, catalog, options) {
        write_plain_field(&mut out, field.label, field.value.as_ref());
    }
    for list in alert_lists(finding, display, catalog, options) {
        match list.style {
            ListStyle::Bulleted => write_plain_list(&mut out, list.title, list.items),
            ListStyle::Numbered => write_plain_numbered_list(&mut out, list.title, list.items),
        }
    }
    for field in technical_fields(finding, catalog, options) {
        write_plain_field(&mut out, field.label, field.value.as_ref());
    }
    out
}

fn render_markdown(
    finding: &Finding,
    display: &LocalizedFinding,
    subject: &str,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
) -> String {
    let mut out = String::new();
    out.push_str("## ");
    out.push_str(catalog.heading);
    out.push_str("\n\n");
    out.push_str("**");
    out.push_str(&markdown_escape(subject));
    out.push_str("**\n\n");
    for field in alert_fields(finding, display, catalog, options) {
        write_markdown_field(&mut out, field.label, field.value.as_ref());
    }
    for list in alert_lists(finding, display, catalog, options) {
        match list.style {
            ListStyle::Bulleted => write_markdown_list(&mut out, list.title, list.items),
            ListStyle::Numbered => write_markdown_numbered_list(&mut out, list.title, list.items),
        }
    }
    for field in technical_fields(finding, catalog, options) {
        write_markdown_field(&mut out, field.label, field.value.as_ref());
    }
    out
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

fn write_plain_field(out: &mut String, label: &str, value: &str) {
    if !value.trim().is_empty() {
        out.push_str(&format!("{label}: {value}\n"));
    }
}

fn write_plain_list<I>(out: &mut String, title: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    let items: Vec<_> = items
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect();
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n{title}:\n"));
    for item in items {
        out.push_str(&format!("- {item}\n"));
    }
}

fn write_plain_numbered_list<I>(out: &mut String, title: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    let items: Vec<_> = items
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect();
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n{title}:\n"));
    for (index, item) in items.into_iter().enumerate() {
        out.push_str(&format!("{}. {item}\n", index + 1));
    }
}

fn write_markdown_field(out: &mut String, label: &str, value: &str) {
    if !value.trim().is_empty() {
        out.push_str(&format!("**{label}:** {}\n", markdown_escape(value)));
    }
}

fn write_markdown_list<I>(out: &mut String, title: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    let items: Vec<_> = items
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect();
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n**{title}**\n"));
    for item in items {
        out.push_str(&format!("- {}\n", markdown_escape(&item)));
    }
}

fn write_markdown_numbered_list<I>(out: &mut String, title: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    let items: Vec<_> = items
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect();
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n**{title}**\n"));
    for (index, item) in items.into_iter().enumerate() {
        out.push_str(&format!("{}. {}\n", index + 1, markdown_escape(&item)));
    }
}

#[cfg(test)]
mod tests;
