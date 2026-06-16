use crate::scanner::{run_scan, ScanOptions, ScanReport};
use sentinel_core::{SentinelConfig, SentinelResult};

/// Run a single scheduled scan. This small wrapper keeps daemon scheduling testable.
pub async fn run_once(config: SentinelConfig) -> SentinelResult<ScanReport> {
    run_scan(config, ScanOptions::default()).await
}
