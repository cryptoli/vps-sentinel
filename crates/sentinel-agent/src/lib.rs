//! Runtime implementation for the VPS Sentinel agent.

pub mod active_response;
pub mod advice;
pub mod attack_fingerprint;
pub mod baseline;
pub mod collectors;
pub mod daemon;
pub mod detectors;
pub mod evidence_score;
pub(crate) mod findings;
pub mod fleet;
pub mod incident;
pub(crate) mod local_behavior;
pub mod maintenance;
pub mod node_metrics;
pub mod notify;
pub mod panel;
pub(crate) mod path_match;
pub mod registry;
pub mod report;
pub mod resource_budget;
pub mod risk_score;
pub mod rules;
pub mod runtime_probe;
pub mod scanner;
pub mod security_wizard;
pub mod service_profile;
pub mod storage;
pub mod suppress_rules;
pub mod threat_intel;
pub mod timeline;
pub mod utils;

#[cfg(test)]
mod scenario_tests;

pub use scanner::{run_scan, ScanOptions, ScanReport};
