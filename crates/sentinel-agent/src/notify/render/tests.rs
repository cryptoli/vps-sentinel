use super::{
    render_alert, render_alert_for_config, render_finding, render_finding_with_language,
    NotificationFormat,
};
use sentinel_core::{Category, Evidence, Finding, NotificationLanguage, SentinelConfig, Severity};

#[test]
fn renders_standard_alert_body() {
    let finding = sample_finding();
    let body = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::En,
    );
    assert!(body.contains("VPS Sentinel Alert"));
    assert!(body.contains("[High] Root login"));
    assert!(!body.contains("Rule: SSH-001"));
    assert!(!body.contains("Dedup Key:"));
    assert!(body.contains("Evidence:"));
}

#[test]
fn default_render_helpers_use_chinese() {
    let finding = sample_finding();
    let body = render_finding(&finding, NotificationFormat::PlainText);

    assert!(body.contains("VPS Sentinel 告警"));
    assert!(body.contains("[高危] 检测到 root SSH 登录"));
    assert!(!body.contains("VPS Sentinel Alert"));
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
    assert!(body.contains("[高危] 检测到 root SSH 登录"));
    assert!(body.contains("root 账号刚刚通过 SSH 成功认证"));
    assert!(!body.contains("规则: SSH-001"));
    assert!(body.contains("证据:"));
}

#[test]
fn renders_chinese_root_password_login_as_single_combined_alert() {
    let finding = sample_finding().with_evidence(vec![
        Evidence::new("user", "root"),
        Evidence::new("method", "password"),
    ]);
    let body = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );

    assert!(body.contains("[高危] 检测到 root SSH 密码登录"));
    assert!(body.contains("root 账号刚刚通过 SSH 密码认证成功登录"));
    assert!(body.contains("关闭 SSH 密码登录"));
    assert!(!body.contains("检测到 SSH 密码登录\n"));
}

#[test]
fn localizes_process_start_drift_evidence_value() {
    let finding = Finding::new(
        "host",
        "Suspicious process behavior cluster",
        "Suspicious process behavior.",
        Severity::High,
        Category::Process,
        "PROC-005",
        "/usr/local/bin/.sysd",
    )
    .with_evidence(vec![Evidence::new("process_start_drift", "changed")]);
    let english = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::En,
    );
    let chinese = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );

    assert!(english.contains("process start drift: changed since previous scan"));
    assert!(chinese.contains("进程启动变化: 较上一轮扫描发生变化"));
}

#[test]
fn localizes_web_probe_family_evidence_value() {
    let finding = Finding::new(
        "host",
        "Web vulnerability probing detected",
        "Web requests match a known probing family.",
        Severity::Medium,
        Category::Web,
        "WEB-001",
        "203.0.113.40",
    )
    .with_evidence(vec![Evidence::new("probe_family", "command_injection")]);
    let english = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::En,
    );
    let chinese = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );

    assert!(english.contains("probe family: command-injection payload"));
    assert!(chinese.contains("探测类型: 命令注入 payload"));
    assert!(!english.contains("command_injection"));
    assert!(!chinese.contains("command_injection"));
}

#[test]
fn renders_html_without_raw_markup_in_values() {
    let finding = sample_finding().with_evidence(vec![Evidence::new("path", "<script>")]);
    let alert = render_alert(&finding);
    assert!(alert.html.contains("&lt;script&gt;"));
    assert!(!alert.html.contains("<script>"));
}

#[test]
fn renders_unknown_rule_in_chinese_without_raw_english_message() {
    let finding = Finding::new(
        "host",
        "Unexpected scheduler entry",
        "English description should not leak in Chinese mode.",
        Severity::Medium,
        Category::System,
        "CUSTOM-001",
        "job",
    )
    .with_impact(vec!["English impact".to_string()])
    .with_recommendations(vec!["English recommendation".to_string()]);

    let body = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );

    assert!(body.contains("检测到规则 CUSTOM-001"));
    assert!(body.contains("该规则尚未配置中文消息模板"));
    assert!(!body.contains("Unexpected scheduler entry"));
    assert!(!body.contains("English description"));
    assert!(!body.contains("English impact"));
    assert!(!body.contains("English recommendation"));
}

#[test]
fn localizes_common_evidence_keys_and_values() {
    let finding = Finding::new(
        "host",
        "Custom test",
        "Custom description",
        Severity::Medium,
        Category::System,
        "CUSTOM-002",
        "subject",
    )
    .with_evidence(vec![
        Evidence::new("change", "file_modified"),
        Evidence::new("method", "password"),
        Evidence::new("exists", "true"),
        Evidence::new("risk_features", "network_execution_bridge, temporary_path"),
        Evidence::new(
            "risk_reasons",
            "network shell bridge; temporary executable path",
        ),
        Evidence::new("content_markers", "system_call, base64_decode"),
    ]);

    let body = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );

    assert!(body.contains("变化类型: 文件修改"));
    assert!(body.contains("方式: 密码认证"));
    assert!(body.contains("是否存在: 是"));
    assert!(body.contains("风险特征: 网络命令执行桥接，临时路径"));
    assert!(body.contains("风险原因: 网络 Shell 桥接，临时目录可执行文件"));
    assert!(body.contains("内容特征: system 调用，base64 解码"));
    assert!(!body.contains("file_modified"));
    assert!(!body.contains("network_execution_bridge"));
}

#[test]
fn renders_active_response_status_in_chinese_alert() {
    let finding = Finding::new(
        "host",
        "SSH brute force pattern detected",
        "bruteforce",
        Severity::High,
        Category::Ssh,
        "SSH-003",
        "47.242.23.111",
    )
    .with_evidence(vec![
        Evidence::new("source_ip", "47.242.23.111"),
        Evidence::new("failure_count", "16"),
        Evidence::new("active_response_status", "blocked"),
        Evidence::new("active_response_ip", "47.242.23.111"),
        Evidence::new("active_response_backend", "iptables"),
        Evidence::new("active_response_expires_at", "2026-06-18 02:53:00 +08:00"),
    ]);

    let body = render_finding_with_language(
        &finding,
        NotificationFormat::PlainText,
        NotificationLanguage::ZhCn,
    );

    assert!(body.contains("主动响应状态: 已临时封禁"));
    assert!(body.contains("封禁 IP: 47.242.23.111"));
    assert!(body.contains("主动响应后端: iptables"));
    assert!(body.contains("封禁到期时间: 2026-06-18 02:53:00 +08:00"));
}

#[test]
fn renders_configured_vps_name_in_subject() {
    let mut config = SentinelConfig::default();
    config.agent.display_name = "prod-web-1".to_string();
    config.notifications.language = NotificationLanguage::En;
    let alert = render_alert_for_config(&sample_finding(), &config);
    assert!(alert.subject.starts_with("[prod-web-1][High]"));
    assert!(alert.plain_text.contains("VPS: prod-web-1"));
}

#[test]
fn renders_technical_fields_only_when_enabled() {
    let mut config = SentinelConfig::default();
    config.notifications.language = NotificationLanguage::En;
    let hidden = render_alert_for_config(&sample_finding(), &config);
    assert!(!hidden.plain_text.contains("Dedup Key:"));

    config.notifications.include_technical_fields = true;
    let visible = render_alert_for_config(&sample_finding(), &config);
    assert!(visible.plain_text.contains("Rule: SSH-001"));
    assert!(visible.plain_text.contains("Dedup Key:"));
}

#[test]
fn renders_normalized_utc_time() {
    let mut config = SentinelConfig::default();
    config.notifications.language = NotificationLanguage::En;
    config.notifications.time_zone = sentinel_core::NotificationTimeZone::Utc;
    let alert = render_alert_for_config(&sample_finding(), &config);
    let time_line = alert
        .plain_text
        .lines()
        .find(|line| line.starts_with("Time: "));
    assert!(matches!(
        time_line,
        Some(line) if line
            .strip_prefix("Time: ")
            .and_then(|value| value.strip_suffix(" UTC"))
            .is_some_and(|value| !value.contains('T'))
    ));
}

#[test]
fn renders_telegram_html_without_full_html_document() {
    let finding = sample_finding().with_evidence(vec![Evidence::new("path", "<script>")]);
    let mut config = SentinelConfig::default();
    config.agent.display_name = "prod-web-1".to_string();
    config.notifications.language = NotificationLanguage::En;
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
