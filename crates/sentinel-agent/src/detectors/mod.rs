use crate::rules::model::RuleMetadata;
use sentinel_core::{Evidence, Finding, RawEvent, SentinelConfig};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

pub mod command_profile;
pub mod config_rules;
pub mod docker_rules;
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

/// A detector converts raw facts into risk findings.
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;

    fn rules(&self) -> Vec<RuleMetadata>;

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding>;
}

pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(ssh_rules::SshDetector),
        Box::new(file_rules::FileDetector),
        Box::new(user_rules::UserDetector),
        Box::new(persistence_rules::PersistenceDetector),
        Box::new(process_rules::ProcessDetector),
        Box::new(network_rules::NetworkDetector),
        Box::new(web_rules::WebDetector),
        Box::new(config_rules::ConfigRiskDetector),
        Box::new(docker_rules::DockerDetector),
        Box::new(rootkit_rules::RootkitDetector),
        Box::new(tamper_rules::TamperDetector),
    ]
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
    let mut sources = BTreeSet::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "package_manager_activity")
    {
        if let Some(path) = event.field("path").filter(|path| !path.trim().is_empty()) {
            sources.insert(path.to_string());
        }
    }
    PackageActivityContext {
        sources: sources.into_iter().collect(),
    }
}
