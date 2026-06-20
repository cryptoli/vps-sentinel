use sentinel_core::{SentinelConfig, Severity};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityWizardReport {
    pub status: WizardStatus,
    pub checks: Vec<WizardCheck>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WizardStatus {
    Ready,
    NeedsReview,
    Risky,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WizardCheck {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub status: &'static str,
    pub detail: String,
    pub recommendation: String,
}

pub fn evaluate_config(config: &SentinelConfig) -> SecurityWizardReport {
    let mut checks = Vec::new();
    check_notifications(config, &mut checks);
    check_detection_surface(config, &mut checks);
    check_response(config, &mut checks);
    check_storage_and_memory(config, &mut checks);
    check_panel(config, &mut checks);
    let status = if checks.iter().any(|item| item.severity.meets(Severity::High)) {
        WizardStatus::Risky
    } else if checks.iter().any(|item| item.severity.meets(Severity::Low)) {
        WizardStatus::NeedsReview
    } else {
        WizardStatus::Ready
    };
    SecurityWizardReport { status, checks }
}

fn check_notifications(config: &SentinelConfig, checks: &mut Vec<WizardCheck>) {
    let channels = [
        config.notifications.telegram.enabled,
        config.notifications.email.enabled,
        config.notifications.webhook.enabled,
        config.notifications.ntfy.enabled,
        config.notifications.gotify.enabled,
        config.notifications.bark.enabled,
        config.notifications.serverchan.enabled,
    ];
    if !channels.iter().any(|enabled| *enabled) {
        checks.push(check(
            "notification.none",
            Severity::High,
            "No notification channel is enabled",
            "risk",
            "The agent can detect findings but the operator may not see them in time.",
            "Enable at least one channel such as Telegram, Email, ntfy, Gotify, Bark, ServerChan, or Webhook.",
        ));
    }
}

fn check_detection_surface(config: &SentinelConfig, checks: &mut Vec<WizardCheck>) {
    let disabled = [
        ("ssh", config.ssh.enabled),
        ("file_integrity", config.file_integrity.enabled),
        ("process", config.process.enabled),
        ("network", config.network.enabled),
        ("persistence", config.persistence.enabled),
        ("web", config.web.enabled),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| (!enabled).then_some(name))
    .collect::<Vec<_>>();
    if !disabled.is_empty() {
        checks.push(check(
            "detection.disabled_core",
            Severity::High,
            "Core detection modules are disabled",
            "risk",
            format!("Disabled modules: {}.", disabled.join(", ")),
            "Keep core modules enabled unless this host cannot provide the required Linux signals.",
        ));
    }
    if !config.ssh.alert_on_successful_login {
        checks.push(check(
            "ssh.success_login_suppressed",
            Severity::Medium,
            "Successful SSH login notification is disabled",
            "review",
            "Interactive login visibility is reduced.",
            "Use trusted_admin_ips and maintenance windows instead of fully disabling login visibility.",
        ));
    }
}

fn check_response(config: &SentinelConfig, checks: &mut Vec<WizardCheck>) {
    if !config.active_response.enabled {
        checks.push(check(
            "active_response.disabled",
            Severity::Medium,
            "Active response is disabled",
            "review",
            "The agent will not write firewall blocks for high-confidence abuse sources.",
            "Use strategy=observe during evaluation, then balanced once allowlists are reviewed.",
        ));
    }
    if config.allowlist.ips.is_empty() {
        checks.push(check(
            "allowlist.empty_ips",
            Severity::Low,
            "IP allowlist is empty",
            "review",
            "No administrative or monitoring IP is protected from active-response blocking.",
            "Add trusted office, VPN, jump-host, and monitoring source IPs to allowlist.ips.",
        ));
    }
}

fn check_storage_and_memory(config: &SentinelConfig, checks: &mut Vec<WizardCheck>) {
    if !config.resource_budget.enabled {
        checks.push(check(
            "resource_budget.disabled",
            Severity::High,
            "Resource budget is disabled",
            "risk",
            "A noisy host can accumulate too many events, findings, or evidence values in one scan.",
            "Keep resource_budget.enabled=true, especially on small-memory VPS hosts.",
        ));
    }
    if config.resource_budget.max_raw_events_per_scan > 50_000 {
        checks.push(check(
            "resource_budget.raw_events_high",
            Severity::Medium,
            "Raw-event budget is high",
            "review",
            format!(
                "max_raw_events_per_scan is {}.",
                config.resource_budget.max_raw_events_per_scan
            ),
            "Use the default 20000 unless this host has enough memory and very high log volume.",
        ));
    }
    if config.storage.max_database_size_mb == 0 {
        checks.push(check(
            "storage.unbounded",
            Severity::High,
            "Database size limit is disabled",
            "risk",
            "SQLite history can grow until the disk is full.",
            "Set storage.max_database_size_mb to a bounded value such as 256.",
        ));
    }
}

fn check_panel(config: &SentinelConfig, checks: &mut Vec<WizardCheck>) {
    if config.panel.enabled {
        if config.panel.url.trim().is_empty() || config.panel.secret.trim().is_empty() {
            checks.push(check(
                "panel.incomplete",
                Severity::High,
                "Panel push is enabled but incomplete",
                "risk",
                "panel.url or panel.secret is empty.",
                "Set panel.url and panel.secret, then run vs panel push to verify delivery.",
            ));
        }
        if config.panel.privacy_mode == "normal" && !config.privacy.mask_ip {
            checks.push(check(
                "panel.privacy_normal",
                Severity::Low,
                "Panel privacy mode may expose operational details",
                "review",
                "Panel payloads can include node identifiers, subjects, and source IP evidence.",
                "Use panel.privacy_mode=strict or privacy.mask_ip=true for public/shared panels.",
            ));
        }
    }
}

fn check(
    id: &'static str,
    severity: Severity,
    title: &'static str,
    status: &'static str,
    detail: impl Into<String>,
    recommendation: impl Into<String>,
) -> WizardCheck {
    WizardCheck {
        id,
        severity,
        title,
        status,
        detail: detail.into(),
        recommendation: recommendation.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_config, WizardStatus};
    use sentinel_core::SentinelConfig;

    #[test]
    fn reports_missing_notification_channel() {
        let config = SentinelConfig::default();
        let report = evaluate_config(&config);

        assert_eq!(report.status, WizardStatus::Risky);
        assert!(report
            .checks
            .iter()
            .any(|check| check.id == "notification.none"));
    }

    #[test]
    fn ready_when_core_defaults_are_notified_and_allowlisted() {
        let mut config = SentinelConfig::default();
        config.notifications.telegram.enabled = true;
        config.notifications.telegram.bot_token = "token".to_string();
        config.notifications.telegram.chat_id = "chat".to_string();
        config.allowlist.ips.push("203.0.113.10".to_string());

        let report = evaluate_config(&config);

        assert_eq!(report.status, WizardStatus::Ready);
    }
}
