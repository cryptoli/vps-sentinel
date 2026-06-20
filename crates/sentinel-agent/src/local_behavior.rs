use crate::storage::SqliteStore;
use chrono::{DateTime, Duration, Utc};
use sentinel_core::{RawEvent, SentinelConfig, SentinelResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const STATE_RULE_ID: &str = "local_behavior_profile";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LocalBehaviorState {
    version: u32,
    updated_at: Option<DateTime<Utc>>,
    identities: BTreeMap<String, BehaviorIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BehaviorIdentity {
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    observations: u32,
    executable_samples: Vec<String>,
    remote_ports: Vec<String>,
    max_public_outbound_per_scan: usize,
}

#[derive(Debug, Clone, Default)]
struct ScanObservation {
    process_event_count: usize,
    executable_samples: BTreeSet<String>,
    remote_ports: BTreeSet<String>,
    total_outbound_count: usize,
    public_outbound_count: usize,
}

pub(crate) fn enrich_local_behavior(
    events: &mut [RawEvent],
    config: &SentinelConfig,
    store: &SqliteStore,
) -> SentinelResult<()> {
    if !config.behavior_profile.enabled {
        return Ok(());
    }
    let previous = store
        .load_rule_state::<LocalBehaviorState>(STATE_RULE_ID)?
        .unwrap_or_default();
    let observations = scan_observations(events);
    if observations.is_empty() {
        return Ok(());
    }
    enrich_events(events, &observations, &previous, config);
    let next = next_state(previous, observations, config);
    store.save_rule_state(STATE_RULE_ID, &next)
}

fn scan_observations(events: &[RawEvent]) -> BTreeMap<String, ScanObservation> {
    let mut pid_to_identity = BTreeMap::<String, String>::new();
    let mut observations = BTreeMap::<String, ScanObservation>::new();

    for event in events.iter().filter(|event| is_process_event(event)) {
        let Some(identity) = process_identity(event) else {
            continue;
        };
        if let Some(pid) = non_empty_field(event, "pid") {
            pid_to_identity.insert(pid.to_string(), identity.clone());
        }
        let observation = observations.entry(identity).or_default();
        observation.process_event_count += 1;
        if let Some(executable) = executable_sample(event) {
            observation.executable_samples.insert(executable);
        }
    }

    for event in events
        .iter()
        .filter(|event| event.kind == "outbound_connection")
    {
        let identity = non_empty_field(event, "pid")
            .and_then(|pid| pid_to_identity.get(pid).cloned())
            .or_else(|| process_identity(event));
        let Some(identity) = identity else {
            continue;
        };
        let observation = observations.entry(identity).or_default();
        observation.total_outbound_count += 1;
        if event.field("remote_public") == Some("true") {
            observation.public_outbound_count += 1;
        }
        if let Some(port) = non_empty_field(event, "remote_port") {
            observation.remote_ports.insert(port.to_string());
        }
    }

    observations
}

fn enrich_events(
    events: &mut [RawEvent],
    observations: &BTreeMap<String, ScanObservation>,
    previous: &LocalBehaviorState,
    config: &SentinelConfig,
) {
    for event in events.iter_mut().filter(|event| is_process_event(event)) {
        let Some(identity) = process_identity(event) else {
            continue;
        };
        let Some(observation) = observations.get(&identity) else {
            continue;
        };
        event
            .fields
            .insert("behavior_profile_identity".to_string(), identity.clone());

        let Some(record) = previous.identities.get(&identity) else {
            event.fields.insert(
                "behavior_profile_first_seen".to_string(),
                "true".to_string(),
            );
            continue;
        };
        event.fields.insert(
            "behavior_profile_observations".to_string(),
            record.observations.to_string(),
        );
        if record.observations < config.behavior_profile.min_observations_before_drift {
            continue;
        }

        let profile_ports_saturated =
            record.remote_ports.len() >= config.behavior_profile.max_remote_ports_per_identity;
        let new_ports = difference(&observation.remote_ports, &record.remote_ports);
        if !new_ports.is_empty() && !profile_ports_saturated {
            event
                .fields
                .insert("behavior_profile_drift".to_string(), "true".to_string());
            event.fields.insert(
                "behavior_profile_new_remote_ports".to_string(),
                new_ports.join(", "),
            );
            event.fields.insert(
                "behavior_profile_known_remote_port_count".to_string(),
                record.remote_ports.len().to_string(),
            );
        }
        if public_fanout_drift(
            observation.public_outbound_count,
            record.max_public_outbound_per_scan,
            config,
        ) {
            event
                .fields
                .insert("behavior_profile_drift".to_string(), "true".to_string());
            event.fields.insert(
                "behavior_profile_public_fanout_drift".to_string(),
                "true".to_string(),
            );
            event.fields.insert(
                "behavior_profile_previous_public_outbound_max".to_string(),
                record.max_public_outbound_per_scan.to_string(),
            );
            event.fields.insert(
                "behavior_profile_current_public_outbound".to_string(),
                observation.public_outbound_count.to_string(),
            );
        }
    }
}

fn next_state(
    mut state: LocalBehaviorState,
    observations: BTreeMap<String, ScanObservation>,
    config: &SentinelConfig,
) -> LocalBehaviorState {
    let now = Utc::now();
    state.version = 1;
    state.updated_at = Some(now);
    for (identity, observation) in observations {
        let record = state
            .identities
            .entry(identity)
            .or_insert_with(|| BehaviorIdentity {
                first_seen_at: now,
                last_seen_at: now,
                observations: 0,
                executable_samples: Vec::new(),
                remote_ports: Vec::new(),
                max_public_outbound_per_scan: 0,
            });
        record.last_seen_at = now;
        record.observations = record.observations.saturating_add(1);
        record.max_public_outbound_per_scan = record
            .max_public_outbound_per_scan
            .max(observation.public_outbound_count);
        merge_bounded_sorted(
            &mut record.executable_samples,
            observation.executable_samples,
            config.behavior_profile.max_executable_samples_per_identity,
        );
        merge_bounded_sorted(
            &mut record.remote_ports,
            observation.remote_ports,
            config.behavior_profile.max_remote_ports_per_identity,
        );
    }
    prune_state(&mut state, config);
    state
}

fn process_identity(event: &RawEvent) -> Option<String> {
    let executable = executable_sample(event);
    let unit = non_empty_field(event, "systemd_unit");
    let container = non_empty_field(event, "container_id")
        .or_else(|| non_empty_field(event, "container_cgroup"));
    let name = non_empty_field(event, "name")
        .or_else(|| non_empty_field(event, "process_name"))
        .or_else(|| non_empty_field(event, "comm"));

    if let Some(unit) = unit {
        return Some(format!(
            "unit={unit}|exe={}|name={}",
            executable.as_deref().unwrap_or(""),
            name.unwrap_or("")
        ));
    }
    if let Some(container) = container {
        return Some(format!(
            "container={container}|exe={}|name={}",
            executable.as_deref().unwrap_or(""),
            name.unwrap_or("")
        ));
    }
    if let Some(executable) = executable {
        return Some(format!("exe={executable}|name={}", name.unwrap_or("")));
    }
    name.map(|name| format!("name={name}"))
}

fn executable_sample(event: &RawEvent) -> Option<String> {
    ["exe_path", "executable", "exe", "path"]
        .into_iter()
        .find_map(|key| non_empty_field(event, key))
        .map(normalize_deleted_suffix)
}

fn normalize_deleted_suffix(value: &str) -> String {
    value
        .trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| value.trim())
        .to_string()
}

fn non_empty_field<'a>(event: &'a RawEvent, key: &str) -> Option<&'a str> {
    event.field(key).filter(|value| !value.trim().is_empty())
}

fn is_process_event(event: &RawEvent) -> bool {
    matches!(event.kind.as_str(), "process_snapshot" | "process_exec")
}

fn difference(current: &BTreeSet<String>, previous: &[String]) -> Vec<String> {
    let previous = previous.iter().cloned().collect::<BTreeSet<_>>();
    current
        .difference(&previous)
        .cloned()
        .collect::<Vec<String>>()
}

fn public_fanout_drift(current: usize, previous_max: usize, config: &SentinelConfig) -> bool {
    if current == 0 {
        return false;
    }
    let threshold = previous_max
        .saturating_mul(config.behavior_profile.public_fanout_multiplier)
        .saturating_add(config.behavior_profile.public_fanout_min_delta);
    current > threshold
}

fn merge_bounded_sorted(target: &mut Vec<String>, values: BTreeSet<String>, limit: usize) {
    let mut merged = target.iter().cloned().collect::<BTreeSet<_>>();
    merged.extend(values.into_iter().filter(|value| !value.trim().is_empty()));
    *target = merged.into_iter().take(limit).collect();
}

fn prune_state(state: &mut LocalBehaviorState, config: &SentinelConfig) {
    let cutoff = Utc::now() - Duration::days(config.behavior_profile.max_age_days as i64);
    state
        .identities
        .retain(|_, record| record.last_seen_at >= cutoff);
    if state.identities.len() <= config.behavior_profile.max_process_identities {
        return;
    }
    let mut retained = state
        .identities
        .iter()
        .map(|(identity, record)| (identity.clone(), record.last_seen_at))
        .collect::<Vec<_>>();
    retained.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let retained = retained
        .into_iter()
        .take(config.behavior_profile.max_process_identities)
        .map(|(identity, _)| identity)
        .collect::<BTreeSet<_>>();
    state
        .identities
        .retain(|identity, _| retained.contains(identity));
}

#[cfg(test)]
mod tests {
    use super::{
        enrich_events, next_state, public_fanout_drift, scan_observations, BehaviorIdentity,
        LocalBehaviorState,
    };
    use chrono::{Duration, Utc};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::collections::BTreeMap;

    #[test]
    fn first_seen_process_is_enriched_but_not_marked_as_drift() {
        let config = SentinelConfig::default();
        let mut events = vec![process_event("/usr/local/bin/app", "app")];
        let observations = scan_observations(&events);

        enrich_events(
            &mut events,
            &observations,
            &LocalBehaviorState::default(),
            &config,
        );

        assert_eq!(events[0].field("behavior_profile_first_seen"), Some("true"));
        assert_eq!(events[0].field("behavior_profile_drift"), None);
    }

    #[test]
    fn mature_profile_marks_new_remote_ports_as_supporting_drift() {
        let config = SentinelConfig::default();
        let process = process_event("/usr/local/bin/app", "app");
        let outbound = outbound_event("42", "8443", true);
        let mut events = vec![process, outbound];
        let observations = scan_observations(&events);
        let identity = observations.keys().next().expect("identity").clone();
        let mut state = LocalBehaviorState::default();
        state.identities.insert(
            identity,
            BehaviorIdentity {
                first_seen_at: Utc::now() - Duration::days(1),
                last_seen_at: Utc::now() - Duration::minutes(1),
                observations: 3,
                executable_samples: vec!["/usr/local/bin/app".to_string()],
                remote_ports: vec!["443".to_string()],
                max_public_outbound_per_scan: 1,
            },
        );

        enrich_events(&mut events, &observations, &state, &config);

        assert_eq!(events[0].field("behavior_profile_drift"), Some("true"));
        assert_eq!(
            events[0].field("behavior_profile_new_remote_ports"),
            Some("8443")
        );
    }

    #[test]
    fn public_fanout_requires_multiplier_and_delta() {
        let config = SentinelConfig::default();

        assert!(!public_fanout_drift(12, 2, &config));
        assert!(public_fanout_drift(15, 2, &config));
    }

    #[test]
    fn saturated_remote_port_profile_does_not_report_new_port_drift() {
        let mut config = SentinelConfig::default();
        config.behavior_profile.max_remote_ports_per_identity = 1;
        let process = process_event("/usr/local/bin/app", "app");
        let outbound = outbound_event("42", "8443", true);
        let mut events = vec![process, outbound];
        let observations = scan_observations(&events);
        let identity = observations.keys().next().expect("identity").clone();
        let mut state = LocalBehaviorState::default();
        state.identities.insert(
            identity,
            BehaviorIdentity {
                first_seen_at: Utc::now() - Duration::days(1),
                last_seen_at: Utc::now() - Duration::minutes(1),
                observations: 3,
                executable_samples: vec!["/usr/local/bin/app".to_string()],
                remote_ports: vec!["443".to_string()],
                max_public_outbound_per_scan: 1,
            },
        );

        enrich_events(&mut events, &observations, &state, &config);

        assert_eq!(events[0].field("behavior_profile_new_remote_ports"), None);
        assert_eq!(events[0].field("behavior_profile_drift"), None);
    }

    #[test]
    fn profile_state_is_bounded_by_recent_identities() {
        let mut config = SentinelConfig::default();
        config.behavior_profile.max_process_identities = 1;
        let now = Utc::now();
        let mut state = LocalBehaviorState {
            version: 1,
            updated_at: Some(now),
            identities: BTreeMap::new(),
        };
        state.identities.insert(
            "exe=/old|name=old".to_string(),
            BehaviorIdentity {
                first_seen_at: now - Duration::days(1),
                last_seen_at: now - Duration::minutes(10),
                observations: 1,
                executable_samples: vec!["/old".to_string()],
                remote_ports: Vec::new(),
                max_public_outbound_per_scan: 0,
            },
        );
        let observations = scan_observations(&[process_event("/new", "new")]);

        let state = next_state(state, observations, &config);

        assert_eq!(state.identities.len(), 1);
        assert!(state.identities.contains_key("exe=/new|name=new"));
    }

    fn process_event(exe_path: &str, name: &str) -> RawEvent {
        RawEvent::new("process", "process_snapshot")
            .with_field("pid", "42")
            .with_field("name", name)
            .with_field("exe_path", exe_path)
    }

    fn outbound_event(pid: &str, port: &str, public: bool) -> RawEvent {
        RawEvent::new("network", "outbound_connection")
            .with_field("pid", pid)
            .with_field("remote_addr", "8.8.8.8")
            .with_field("remote_port", port)
            .with_field("remote_public", public.to_string())
    }
}
