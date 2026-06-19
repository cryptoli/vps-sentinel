use crate::rules::model::RuleMetadata;
use sentinel_core::{Evidence, Finding, RawEvent, SentinelConfig};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

pub mod command_profile;
pub mod config_rules;
pub mod docker_rules;
pub mod external_rules;
pub mod file_rules;
pub mod network_rules;
pub mod persistence_rules;
pub mod process_rules;
pub mod risk;
pub mod rootkit_rules;
pub mod ssh_rules;
pub mod tamper_rules;
pub mod user_rules;
pub mod web_rules;

#[cfg(test)]
mod rule_matrix_tests;

pub(crate) const RESOURCE_DRIFT_DEDUP_KEYS: &[&str] = &["path", "change", "current_hash"];

/// Immutable detection context.
#[derive(Clone)]
pub struct DetectContext {
    pub config: Arc<SentinelConfig>,
    pub host_id: String,
}

impl DetectContext {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        let host_id = config.host_id();
        Self { config, host_id }
    }
}

/// Per-scan event index used by detectors that only need specific event kinds.
///
/// RawEvent remains the compatibility model, but this index avoids forcing every
/// detector to repeatedly scan the full event vector as more collectors are
/// added.
pub struct EventIndex<'a> {
    by_kind: BTreeMap<&'a str, Vec<&'a RawEvent>>,
    by_source: BTreeMap<&'a str, Vec<&'a RawEvent>>,
}

impl<'a> EventIndex<'a> {
    pub fn new(events: &'a [RawEvent]) -> Self {
        let mut by_kind = BTreeMap::<&'a str, Vec<&'a RawEvent>>::new();
        let mut by_source = BTreeMap::<&'a str, Vec<&'a RawEvent>>::new();
        for event in events {
            by_kind.entry(event.kind.as_str()).or_default().push(event);
            by_source
                .entry(event.source.as_str())
                .or_default()
                .push(event);
        }
        Self { by_kind, by_source }
    }

    pub fn kind(&self, kind: &str) -> impl Iterator<Item = &'a RawEvent> + '_ {
        self.by_kind
            .get(kind)
            .into_iter()
            .flat_map(|events| events.iter().copied())
    }

    pub fn source(&self, source: &str) -> impl Iterator<Item = &'a RawEvent> + '_ {
        self.by_source
            .get(source)
            .into_iter()
            .flat_map(|events| events.iter().copied())
    }
}

/// A detector converts raw facts into risk findings.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;

    fn rules(&self) -> Vec<RuleMetadata>;

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding>;

    fn detect_indexed(
        &self,
        events: &[RawEvent],
        index: &EventIndex<'_>,
        ctx: &DetectContext,
    ) -> Vec<Finding> {
        let _ = index;
        self.detect(events, ctx)
    }
}

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    crate::registry::DetectorRegistry::with_builtin_detectors().into_detectors()
}

fn evidence(key: &str, value: impl Into<String>) -> Evidence {
    Evidence::new(key, value)
}

fn string_field(event: &RawEvent, key: &str) -> String {
    event.field(key).unwrap_or("").to_string()
}

fn path_is_allowlisted(path: &str, allowlist: &[PathBuf]) -> bool {
    allowlist.iter().any(|allowed| {
        let allowed = allowed.to_string_lossy().replace('\\', "/");
        path == allowed || path.starts_with(&format!("{allowed}/"))
    })
}

pub(crate) fn field_is_allowlisted(value: &str, allowlist: &[String]) -> bool {
    allowlist.iter().any(|allowed| allowed == value)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PackageActivityContext {
    sources: Vec<String>,
}

impl PackageActivityContext {
    pub(crate) fn is_active(&self) -> bool {
        !self.sources.is_empty()
    }

    pub(crate) fn evidence(&self) -> Vec<Evidence> {
        if self.sources.is_empty() {
            return Vec::new();
        }
        vec![
            Evidence::new("package_activity_recent", "true"),
            Evidence::new("package_activity_sources", self.sources.join(", ")),
        ]
    }

    pub(crate) fn recommendation(&self) -> Option<String> {
        self.is_active().then(|| {
            "Recent package-manager activity was observed; compare the change with package logs before refreshing the baseline.".to_string()
        })
    }
}

pub(crate) fn package_activity_context(events: &[RawEvent]) -> PackageActivityContext {
    package_activity_context_from_events(
        events
            .iter()
            .filter(|event| event.kind == "package_manager_activity"),
    )
}

pub(crate) fn package_activity_context_from_events<'a>(
    events: impl IntoIterator<Item = &'a RawEvent>,
) -> PackageActivityContext {
    let mut sources = BTreeSet::new();
    for event in events {
        if let Some(path) = event.field("path").filter(|path| !path.trim().is_empty()) {
            sources.insert(path.to_string());
        }
    }
    PackageActivityContext {
        sources: sources.into_iter().collect(),
    }
}
