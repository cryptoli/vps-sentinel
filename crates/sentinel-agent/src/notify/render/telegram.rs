use super::escape::html_escape;
use super::{alert_fields, alert_lists, technical_fields, AlertRenderOptions};
use crate::notify::content::LocalizedFinding;
use crate::notify::i18n::MessageCatalog;
use sentinel_core::Finding;

pub(super) fn render_telegram_html(
    finding: &Finding,
    display: &LocalizedFinding,
    subject: &str,
    catalog: &MessageCatalog,
    options: &AlertRenderOptions,
) -> String {
    let mut out = String::new();
    out.push_str("<b>");
    out.push_str(&html_escape(catalog.heading));
    out.push_str("</b>\n");
    out.push_str("<b>");
    out.push_str(&html_escape(subject));
    out.push_str("</b>\n\n");
    for field in alert_fields(finding, display, catalog, options) {
        write_field(&mut out, field.label, field.value.as_ref());
    }
    for list in alert_lists(finding, display, catalog, options) {
        write_list(&mut out, list.title, list.items);
    }
    for field in technical_fields(finding, catalog, options) {
        write_field(&mut out, field.label, field.value.as_ref());
    }
    out
}

fn write_field(out: &mut String, label: &str, value: &str) {
    if !value.trim().is_empty() {
        out.push_str(&format!(
            "<b>{}:</b> {}\n",
            html_escape(label),
            html_escape(value)
        ));
    }
}

fn write_list<I>(out: &mut String, title: &str, items: I)
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
    out.push_str(&format!("\n<b>{}</b>\n", html_escape(title)));
    for item in items {
        out.push_str(&format!("- {}\n", html_escape(&item)));
    }
}
