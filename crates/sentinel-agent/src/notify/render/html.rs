use super::escape::html_escape;
use super::{
    alert_fields, alert_lists, non_empty_items, technical_fields, AlertRenderOptions, ListStyle,
};
use crate::notify::content::LocalizedFinding;
use crate::notify::i18n::MessageCatalog;
use sentinel_core::{Finding, Severity};

pub(super) fn render_html(
    finding: &Finding,
    display: &LocalizedFinding,
    subject: &str,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
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
    for field in alert_fields(finding, display, catalog, options) {
        write_field(&mut out, field.label, field.value.as_ref());
    }
    out.push_str("</table>");
    for list in alert_lists(finding, display, catalog, options) {
        match list.style {
            ListStyle::Bulleted => write_list(&mut out, list.title, list.items),
            ListStyle::Numbered => write_numbered_list(&mut out, list.title, list.items),
        }
    }
    write_technical_details(&mut out, finding, catalog, options);
    out.push_str("</div></div></div></body></html>");
    out
}

fn write_field(out: &mut String, label: &str, value: &str) {
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

fn write_list<I>(out: &mut String, title: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    let items = non_empty_items(items);
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("<h2 style=\"font-size:16px;margin:22px 0 8px;\">{}</h2><ul style=\"margin:0;padding-left:20px;line-height:1.55;\">", html_escape(title)));
    for item in items {
        out.push_str(&format!("<li>{}</li>", html_escape(&item)));
    }
    out.push_str("</ul>");
}

fn write_numbered_list<I>(out: &mut String, title: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    let items = non_empty_items(items);
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("<h2 style=\"font-size:16px;margin:22px 0 8px;\">{}</h2><ol style=\"margin:0;padding-left:20px;line-height:1.55;\">", html_escape(title)));
    for item in items {
        out.push_str(&format!("<li>{}</li>", html_escape(&item)));
    }
    out.push_str("</ol>");
}

fn write_technical_details(
    out: &mut String,
    finding: &Finding,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
) {
    let technical = technical_fields(finding, catalog, options);
    if technical.is_empty() {
        return;
    }
    out.push_str("<div style=\"margin-top:18px;padding-top:14px;border-top:1px solid #edf0f4;color:#596675;font-size:12px;\">");
    out.push_str(&format!(
        "<strong>{}</strong><br>",
        html_escape(catalog.technical_details)
    ));
    for field in technical {
        out.push_str(&format!(
            "{}: {}<br>",
            html_escape(field.label),
            html_escape(field.value.as_ref())
        ));
    }
    out.push_str("</div>");
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
