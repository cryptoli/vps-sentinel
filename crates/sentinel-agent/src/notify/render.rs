use super::i18n::{catalog, severity_label, MessageCatalog};
use sentinel_core::{Finding, NotificationLanguage, Severity};
use std::borrow::Cow;

/// Output format for rendered notification bodies.
#[derive(Debug, Clone, Copy)]
pub enum NotificationFormat {
    Markdown,
    Html,
    PlainText,
}

#[derive(Debug, Clone)]
pub struct RenderedAlert {
    pub subject: String,
    pub plain_text: String,
    pub markdown: String,
    pub html: String,
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
    let catalog = catalog(language);
    let subject = format!(
        "[{}] {}",
        severity_label(finding.severity, language),
        finding.title
    );
    RenderedAlert {
        subject: subject.clone(),
        plain_text: render_plain_text(finding, &subject, &catalog, language),
        markdown: render_markdown(finding, &subject, &catalog, language),
        html: render_html(finding, &subject, &catalog, language),
    }
}

struct AlertField<'a> {
    label: &'static str,
    value: Cow<'a, str>,
}

struct AlertList {
    title: &'static str,
    style: ListStyle,
    items: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum ListStyle {
    Bulleted,
    Numbered,
}

fn alert_fields<'a>(
    finding: &'a Finding,
    catalog: &MessageCatalog,
    language: NotificationLanguage,
) -> Vec<AlertField<'a>> {
    let mut fields = vec![
        borrowed_value_field(catalog.severity, severity_label(finding.severity, language)),
        borrowed_field(catalog.host, &finding.host_id),
        owned_field(catalog.time, finding.timestamp.to_rfc3339()),
        owned_field(catalog.category, finding.category.to_string()),
        borrowed_field(catalog.rule, &finding.rule_id),
        borrowed_field(catalog.subject, &finding.subject),
        borrowed_field(catalog.description, &finding.description),
    ];
    fields.retain(|field| !field.value.trim().is_empty());
    fields
}

fn alert_lists(finding: &Finding, catalog: &MessageCatalog) -> Vec<AlertList> {
    let mut lists = vec![
        AlertList {
            title: catalog.evidence,
            style: ListStyle::Bulleted,
            items: finding
                .evidence
                .iter()
                .map(|item| format!("{}: {}", item.key, item.value))
                .collect(),
        },
        AlertList {
            title: catalog.impact,
            style: ListStyle::Bulleted,
            items: finding.impact.clone(),
        },
        AlertList {
            title: catalog.recommendations,
            style: ListStyle::Numbered,
            items: finding.recommendations.clone(),
        },
    ];
    for list in &mut lists {
        list.items.retain(|item| !item.trim().is_empty());
    }
    lists.retain(|list| !list.items.is_empty());
    lists
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
    subject: &str,
    catalog: &MessageCatalog,
    language: NotificationLanguage,
) -> String {
    let mut out = String::new();
    out.push_str(catalog.heading);
    out.push('\n');
    out.push_str("==================\n\n");
    out.push_str(subject);
    out.push_str("\n\n");
    for field in alert_fields(finding, catalog, language) {
        write_plain_field(&mut out, field.label, field.value.as_ref());
    }
    for list in alert_lists(finding, catalog) {
        match list.style {
            ListStyle::Bulleted => write_plain_list(&mut out, list.title, list.items),
            ListStyle::Numbered => write_plain_numbered_list(&mut out, list.title, list.items),
        }
    }
    out.push('\n');
    write_plain_field(&mut out, catalog.event_id, &finding.id);
    write_plain_field(&mut out, catalog.dedup_key, &finding.dedup_key);
    out
}

fn render_markdown(
    finding: &Finding,
    subject: &str,
    catalog: &MessageCatalog,
    language: NotificationLanguage,
) -> String {
    let mut out = String::new();
    out.push_str("## ");
    out.push_str(catalog.heading);
    out.push_str("\n\n");
    out.push_str("**");
    out.push_str(&markdown_escape(subject));
    out.push_str("**\n\n");
    for field in alert_fields(finding, catalog, language) {
        write_markdown_field(&mut out, field.label, field.value.as_ref());
    }
    for list in alert_lists(finding, catalog) {
        match list.style {
            ListStyle::Bulleted => write_markdown_list(&mut out, list.title, list.items),
            ListStyle::Numbered => write_markdown_numbered_list(&mut out, list.title, list.items),
        }
    }
    out.push('\n');
    write_markdown_field(&mut out, catalog.event_id, &finding.id);
    write_markdown_field(&mut out, catalog.dedup_key, &finding.dedup_key);
    out
}

fn render_html(
    finding: &Finding,
    subject: &str,
    catalog: &MessageCatalog,
    language: NotificationLanguage,
) -> String {
    let accent = severity_color(&finding.severity);
    let mut out = String::new();
    out.push_str("<!doctype html><html><body style=\"margin:0;background:#f6f8fb;font-family:Arial,Helvetica,sans-serif;color:#17202a;\">");
    out.push_str("<div style=\"max-width:720px;margin:0 auto;padding:24px;\">");
    out.push_str(&format!(
        "<div style=\"border:1px solid #dde3ea;border-radius:8px;background:#ffffff;overflow:hidden;\">\
         <div style=\"padding:18px 22px;background:{accent};color:#ffffff;\">\
         <div style=\"font-size:13px;letter-spacing:.04em;text-transform:uppercase;opacity:.9;\">{}</div>\
         <h1 style=\"margin:6px 0 0;font-size:22px;line-height:1.25;\">{}</h1>\
         </div>",
        html_escape(catalog.heading),
        html_escape(subject)
    ));
    out.push_str("<div style=\"padding:20px 22px;\">");
    out.push_str("<table style=\"width:100%;border-collapse:collapse;font-size:14px;\">");
    for field in alert_fields(finding, catalog, language) {
        write_html_field(&mut out, field.label, field.value.as_ref());
    }
    out.push_str("</table>");
    for list in alert_lists(finding, catalog) {
        match list.style {
            ListStyle::Bulleted => write_html_list(&mut out, list.title, list.items),
            ListStyle::Numbered => write_html_numbered_list(&mut out, list.title, list.items),
        }
    }
    out.push_str("<div style=\"margin-top:18px;padding-top:14px;border-top:1px solid #edf0f4;color:#596675;font-size:12px;\">");
    out.push_str(&format!(
        "{}: {}<br>",
        html_escape(catalog.event_id),
        html_escape(&finding.id)
    ));
    out.push_str(&format!(
        "{}: {}",
        html_escape(catalog.dedup_key),
        html_escape(&finding.dedup_key)
    ));
    out.push_str("</div></div></div></div></body></html>");
    out
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

fn write_html_field(out: &mut String, label: &str, value: &str) {
    if value.trim().is_empty() {
        return;
    }
    out.push_str(&format!(
        "<tr><td style=\"width:130px;padding:7px 0;color:#657386;font-weight:700;vertical-align:top;\">{}</td>\
         <td style=\"padding:7px 0;color:#17202a;vertical-align:top;\">{}</td></tr>",
        html_escape(label),
        html_escape(value)
    ));
}

fn write_html_list<I>(out: &mut String, title: &str, items: I)
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
    out.push_str(&format!("<h2 style=\"font-size:16px;margin:22px 0 8px;\">{}</h2><ul style=\"margin:0;padding-left:20px;line-height:1.55;\">", html_escape(title)));
    for item in items {
        out.push_str(&format!("<li>{}</li>", html_escape(&item)));
    }
    out.push_str("</ul>");
}

fn write_html_numbered_list<I>(out: &mut String, title: &str, items: I)
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
    out.push_str(&format!("<h2 style=\"font-size:16px;margin:22px 0 8px;\">{}</h2><ol style=\"margin:0;padding-left:20px;line-height:1.55;\">", html_escape(title)));
    for item in items {
        out.push_str(&format!("<li>{}</li>", html_escape(&item)));
    }
    out.push_str("</ol>");
}

fn severity_color(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "#9f1239",
        Severity::High => "#b45309",
        Severity::Medium => "#2563eb",
        Severity::Low => "#047857",
        Severity::Info => "#475569",
    }
}

fn markdown_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('`', "\\`")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests;
