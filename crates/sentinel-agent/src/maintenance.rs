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
    if !active || !config.maintenance.suppress_baseline_drift {
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
        .filter(|finding| !suppressible_drift_finding(finding))
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
}
