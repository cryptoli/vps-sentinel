use super::{
    render_alert, render_alert_for_config, render_finding, render_finding_with_language,
    NotificationFormat,
};
use sentinel_core::{Category, Evidence, Finding, NotificationLanguage, SentinelConfig, Severity};

#[test]
fn renders_standard_alert_body() {
    let finding = sample_finding();
    let body = render_finding(&finding, NotificationFormat::PlainText);
    assert!(body.contains("VPS Sentinel Alert"));
    assert!(body.contains("[High] Root login"));
    assert!(body.contains("Rule: SSH-001"));
    assert!(body.contains("Evidence:"));
}

#[test]
fn renders_chinese_alert_body() {
    let finding = sample_finding();
    let body = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );
    assert!(body.contains("VPS Sentinel 告警"));
    assert!(body.contains("[高危] Root login"));
    assert!(body.contains("规则: SSH-001"));
    assert!(body.contains("证据:"));
}

#[test]
fn renders_html_without_raw_markup_in_values() {
    let finding = sample_finding().with_evidence(vec![Evidence::new("path", "<script>")]);
    let alert = render_alert(&finding);
    assert!(alert.html.contains("&lt;script&gt;"));
    assert!(!alert.html.contains("<script>"));
}

#[test]
fn renders_configured_vps_name_in_subject() {
    let mut config = SentinelConfig::default();
    config.agent.display_name = "prod-web-1".to_string();
    let alert = render_alert_for_config(&sample_finding(), &config);
    assert!(alert.subject.starts_with("[prod-web-1][High]"));
    assert!(alert.plain_text.contains("VPS: prod-web-1"));
}

#[test]
fn renders_telegram_html_without_full_html_document() {
    let finding = sample_finding().with_evidence(vec![Evidence::new("path", "<script>")]);
    let mut config = SentinelConfig::default();
    config.agent.display_name = "prod-web-1".to_string();
    let alert = render_alert_for_config(&finding, &config);
    assert!(alert.telegram_html.contains("<b>VPS Sentinel Alert</b>"));
    assert!(alert.telegram_html.contains("&lt;script&gt;"));
    assert!(!alert.telegram_html.contains("<table"));
    assert!(!alert.telegram_html.contains("<script>"));
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
