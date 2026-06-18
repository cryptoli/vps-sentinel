use crate::storage::SqliteStore;
use chrono::{DateTime, Utc};
use sentinel_core::{SentinelConfig, SentinelResult, Severity};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::BTreeMap;

const STATE_RULE_ID: &str = "fleet_nodes";
const MAX_FLEET_NODES: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetNodeSnapshot {
    pub node_id: String,
    pub display_name: String,
    pub exported_at: DateTime<Utc>,
    pub agent_version: String,
    pub database_bytes: u64,
    pub finding_count: usize,
    pub high_or_critical_findings: usize,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FleetIndex {
    nodes: BTreeMap<String, FleetNodeSnapshot>,
}

pub fn build_local_snapshot(
    config: &SentinelConfig,
    store: &SqliteStore,
    version: &str,
) -> SentinelResult<FleetNodeSnapshot> {
    let stats = store.stats()?;
    let since = Utc::now() - chrono::Duration::hours(24);
    let findings = store.list_findings_between(since, Utc::now())?;
    let high_or_critical_findings = findings
        .iter()
        .filter(|finding| matches!(finding.severity, Severity::High | Severity::Critical))
        .count();
    let scan_summary = store.scan_run_summary_between(since, Utc::now())?;
    Ok(FleetNodeSnapshot {
        node_id: if config.fleet.node_name.trim().is_empty() {
            config.host_id()
        } else {
            config.fleet.node_name.trim().to_string()
        },
        display_name: config.display_name(),
        exported_at: Utc::now(),
        agent_version: version.to_string(),
        database_bytes: stats.database_bytes,
        finding_count: findings.len(),
        high_or_critical_findings,
        last_scan_at: scan_summary.last_finished_at,
    })
}

pub fn save_fleet_snapshot(store: &SqliteStore, snapshot: FleetNodeSnapshot) -> SentinelResult<()> {
    let mut index = store
        .load_rule_state::<FleetIndex>(STATE_RULE_ID)?
        .unwrap_or_default();
    index.nodes.insert(snapshot.node_id.clone(), snapshot);
    if index.nodes.len() > MAX_FLEET_NODES {
        let mut nodes = index.nodes.into_values().collect::<Vec<_>>();
        nodes.sort_by_key(|node| Reverse(node.exported_at));
        nodes.truncate(MAX_FLEET_NODES);
        index.nodes = nodes
            .into_iter()
            .map(|node| (node.node_id.clone(), node))
            .collect();
    }
    store.save_rule_state(STATE_RULE_ID, &index)
}

pub fn list_fleet_nodes(store: &SqliteStore) -> SentinelResult<Vec<FleetNodeSnapshot>> {
    let mut nodes = store
        .load_rule_state::<FleetIndex>(STATE_RULE_ID)?
        .unwrap_or_default()
        .nodes
        .into_values()
        .collect::<Vec<_>>();
    nodes.sort_by_key(|node| Reverse(node.exported_at));
    Ok(nodes)
}

pub fn get_fleet_node(
    store: &SqliteStore,
    node_id: &str,
) -> SentinelResult<Option<FleetNodeSnapshot>> {
    Ok(store
        .load_rule_state::<FleetIndex>(STATE_RULE_ID)?
        .unwrap_or_default()
        .nodes
        .remove(node_id))
}

#[cfg(test)]
mod tests {
    use super::{build_local_snapshot, save_fleet_snapshot};
    use crate::storage::SqliteStore;
    use sentinel_core::SentinelConfig;

    #[test]
    fn stores_imported_fleet_snapshot() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let snapshot = build_local_snapshot(&SentinelConfig::default(), &store, "test")?;

        save_fleet_snapshot(&store, snapshot.clone())?;
        let loaded = super::get_fleet_node(&store, &snapshot.node_id)?;

        assert!(loaded.is_some());
        Ok(())
    }
}
