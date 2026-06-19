//! Runtime implementation for the VPS Sentinel agent.

pub mod active_response;
pub mod advice;
pub mod attack_fingerprint;
pub mod baseline;
pub mod collectors;
pub mod daemon;
pub mod detectors;
pub(crate) mod findings;
pub mod fleet;
pub mod incident;
pub mod maintenance;
pub mod notify;
pub mod registry;
pub mod report;
pub mod resource_budget;
pub mod risk_score;
pub mod rules;
pub mod scanner;
pub mod service_profile;
pub mod storage;
pub mod threat_intel;
pub mod utils;

#[cfg(test)]
mod scenario_tests;

pub use scanner::{run_scan, ScanOptions, ScanReport};
