use crate::storage::SqliteStore;
use chrono::{DateTime, Duration, Utc};
use sentinel_core::{Finding, SentinelConfig, SentinelResult, Severity};
use serde::{Deserialize, Serialize};

const STATE_RULE_ID: &str = "maintenance_mode";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaintenanceState {
    pub started_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceDecision {
    pub active: bool,
    pub suppressed_count: usize,
}

pub fn start_maintenance(
    store: &SqliteStore,
    config: &SentinelConfig,
    duration_seconds: Option<u64>,
    reason: String,
) -> SentinelResult<MaintenanceState> {
    let now = Utc::now();
    let seconds = duration_seconds
        .unwrap_or(config.maintenance.max_duration_seconds)
        .min(config.maintenance.max_duration_seconds)
        .max(1);
    let state = MaintenanceState {
        started_at: Some(now),
        expires_at: Some(now + Duration::seconds(duration_seconds_i64(seconds))),
        reason,
    };
    store.save_rule_state(STATE_RULE_ID, &state)?;
    Ok(state)
}

pub fn end_maintenance(store: &SqliteStore) -> SentinelResult<()> {
    store.save_rule_state(STATE_RULE_ID, &MaintenanceState::default())
}

pub fn maintenance_state(store: &SqliteStore) -> SentinelResult<Option<MaintenanceState>> {
    Ok(store
        .load_rule_state::<MaintenanceState>(STATE_RULE_ID)?
        .filter(|state| state.started_at.is_some()))
}

pub fn apply_maintenance_policy(
    findings: Vec<Finding>,
    config: &SentinelConfig,
    store: Option<&SqliteStore>,
) -> SentinelResult<(Vec<Finding>, MaintenanceDecision)> {
    let active = maintenance_active(config, store)?;
    if !active
        || (!config.maintenance.suppress_baseline_drift
            && !config.maintenance.suppress_interactive_logins)
    {
        return Ok((
            findings,
            MaintenanceDecision {
                active,
                suppressed_count: 0,
            },
        ));
    }
    let before = findings.len();
    let retained = findings
        .into_iter()
        .filter(|finding| !suppressible_maintenance_finding(finding, config))
        .collect::<Vec<_>>();
    let suppressed_count = before.saturating_sub(retained.len());
    Ok((
        retained,
        MaintenanceDecision {
            active,
            suppressed_count,
        },
    ))
}

fn maintenance_active(
    config: &SentinelConfig,
    store: Option<&SqliteStore>,
) -> SentinelResult<bool> {
    if config.maintenance.enabled {
        return Ok(true);
    }
    let Some(store) = store else {
        return Ok(false);
    };
    let Some(state) = maintenance_state(store)? else {
        return Ok(false);
    };
    Ok(state
        .expires_at
        .map(|expires_at| expires_at > Utc::now())
        .unwrap_or(false))
}

fn suppressible_maintenance_finding(finding: &Finding, config: &SentinelConfig) -> bool {
    (config.maintenance.suppress_baseline_drift && suppressible_drift_finding(finding))
        || (config.maintenance.suppress_interactive_logins
            && suppressible_interactive_login_finding(finding))
}

fn suppressible_drift_finding(finding: &Finding) -> bool {
    matches!(
        finding.severity,
        Severity::Info | Severity::Low | Severity::Medium
    ) && matches!(
        finding.rule_id.as_str(),
        "FILE-001"
            | "PERSIST-001"
            | "PERSIST-002"
            | "NET-001"
            | "NET-002"
            | "SERVICE-001"
            | "SERVICE-002"
    )
}

fn suppressible_interactive_login_finding(finding: &Finding) -> bool {
    matches!(finding.rule_id.as_str(), "SSH-001" | "SSH-002" | "SSH-004")
}

fn duration_seconds_i64(seconds: u64) -> i64 {
    if seconds > i64::MAX as u64 {
        i64::MAX
    } else {
        seconds as i64
    }
}

#[cfg(test)]
mod tests {
    use super::apply_maintenance_policy;
    use sentinel_core::{Category, Finding, SentinelConfig, Severity};

    #[test]
    fn maintenance_suppresses_only_lower_severity_baseline_drift() {
        let mut config = SentinelConfig::default();
        config.maintenance.enabled = true;
        let low = Finding::new(
            "host",
            "service",
            "service",
            Severity::Medium,
            Category::Network,
            "SERVICE-001",
            "8080",
        );
        let high = Finding::new(
            "host",
            "ssh",
            "ssh",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            "8.8.8.8",
        );

        let (findings, decision) =
            apply_maintenance_policy(vec![low, high], &config, None).unwrap();

        assert!(decision.active);
        assert_eq!(decision.suppressed_count, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SSH-003");
    }

    #[test]
    fn maintenance_suppresses_interactive_logins_but_keeps_ssh_attack_signals() {
        let mut config = SentinelConfig::default();
        config.maintenance.enabled = true;
        config.maintenance.suppress_interactive_logins = true;
        let root_login = Finding::new(
            "host",
            "Root SSH login detected",
            "root login",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root@203.0.113.10",
        );
        let password_login = Finding::new(
            "host",
            "Password SSH login detected",
            "password login",
            Severity::Medium,
            Category::Ssh,
            "SSH-002",
            "deploy@203.0.113.10",
        );
        let normal_login = Finding::new(
            "host",
            "SSH login detected",
            "normal login",
            Severity::Info,
            Category::Ssh,
            "SSH-004",
            "deploy@203.0.113.10",
        );
        let brute_force = Finding::new(
            "host",
            "SSH brute force pattern detected",
            "brute force",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            "203.0.113.20",
        );
        let brute_force_success = Finding::new(
            "host",
            "SSH brute force followed by successful login",
            "brute force success",
            Severity::High,
            Category::Ssh,
            "SSH-007",
            "203.0.113.20",
        );

        let (findings, decision) = apply_maintenance_policy(
            vec![
                root_login,
                password_login,
                normal_login,
                brute_force,
                brute_force_success,
            ],
            &config,
            None,
        )
        .unwrap();

        assert_eq!(decision.suppressed_count, 3);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SSH-003", "SSH-007"]
        );
    }

    #[test]
    fn maintenance_can_keep_interactive_login_notifications_enabled() {
        let mut config = SentinelConfig::default();
        config.maintenance.enabled = true;
        config.maintenance.suppress_baseline_drift = false;
        config.maintenance.suppress_interactive_logins = false;
        let root_login = Finding::new(
            "host",
            "Root SSH login detected",
            "root login",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root@203.0.113.10",
        );

        let (findings, decision) =
            apply_maintenance_policy(vec![root_login], &config, None).unwrap();

        assert_eq!(decision.suppressed_count, 0);
        assert_eq!(findings.len(), 1);
    }
}
