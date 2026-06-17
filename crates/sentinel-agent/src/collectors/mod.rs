use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelConfig, SentinelResult};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub mod config_risk;
pub mod docker;
pub mod file_integrity;
pub mod firewall;
pub mod gpu;
pub mod network;
pub mod package_manager;
pub mod persistence;
pub mod process;
pub mod rootkit;
pub mod ssh;
pub mod users;
pub mod web_logs;

/// Immutable context shared by collectors during one scan.
#[derive(Clone)]
pub struct CollectContext {
    pub config: Arc<SentinelConfig>,
    pub scan_root: PathBuf,
}

impl CollectContext {
    pub fn new(config: Arc<SentinelConfig>) -> Self {
        Self {
            config,
            scan_root: PathBuf::from("/"),
        }
    }

    pub fn with_scan_root(mut self, scan_root: PathBuf) -> Self {
        self.scan_root = scan_root;
        self
    }

    pub fn resolve(&self, system_path: &Path) -> PathBuf {
        crate::utils::fs::resolve_under_root(&self.scan_root, system_path)
    }
}

/// A collector gathers host facts without deciding risk.
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>>;
}

pub fn default_collectors() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(ssh::SshLogCollector),
        Box::new(file_integrity::FileIntegrityCollector),
        Box::new(users::UserCollector),
        Box::new(package_manager::PackageManagerCollector),
        Box::new(persistence::PersistenceCollector),
        Box::new(process::ProcessCollector),
        Box::new(gpu::GpuCollector),
        Box::new(network::NetworkCollector),
        Box::new(firewall::FirewallCollector),
        Box::new(web_logs::WebLogCollector),
        Box::new(config_risk::ConfigRiskCollector),
        Box::new(docker::DockerCollector),
        Box::new(rootkit::RootkitSignalCollector),
    ]
}
