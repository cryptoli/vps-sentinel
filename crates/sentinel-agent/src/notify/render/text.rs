use super::escape::markdown_escape;
use super::{
    alert_fields, alert_lists, non_empty_items, technical_fields, AlertRenderOptions, ListStyle,
};
use crate::notify::content::LocalizedFinding;
use crate::notify::i18n::MessageCatalog;
use sentinel_core::Finding;

pub(super) fn render_plain_text(
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
            ListStyle::Numbered => {
                write_plain_numbered_list(&mut out, list.title, list.items);
            }
        }
    }
    for field in technical_fields(finding, catalog, options) {
        write_plain_field(&mut out, field.label, field.value.as_ref());
    }
    out
}

pub(super) fn render_markdown(
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
            ListStyle::Numbered => {
                write_markdown_numbered_list(&mut out, list.title, list.items);
            }
        }
    }
    for field in technical_fields(finding, catalog, options) {
        write_markdown_field(&mut out, field.label, field.value.as_ref());
    }
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
    let items = non_empty_items(items);
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
    let items = non_empty_items(items);
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
    let items = non_empty_items(items);
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
    let items = non_empty_items(items);
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n**{title}**\n"));
    for (index, item) in items.into_iter().enumerate() {
        out.push_str(&format!("{}. {}\n", index + 1, markdown_escape(&item)));
    }
}
