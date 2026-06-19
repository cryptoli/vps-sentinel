use crate::collectors::{
    audit, config_risk, docker, ebpf_bridge, file_integrity, firewall, gpu, log_integrity, network,
    package_manager, persistence, process, rootkit, ssh, users, web_logs, Collector,
};
use crate::detectors::{
    audit_rules, config_rules, docker_rules, external_rules, file_rules, network_rules,
    persistence_rules, process_rules, rootkit_rules, ssh_rules, tamper_rules, user_rules,
    web_rules, Detector,
};

/// Registry for host fact collectors.
///
/// The current implementation registers built-in collectors, but the type keeps
/// registration centralized so optional collectors can be enabled without
/// editing scan orchestration.
#[derive(Default)]
pub struct CollectorRegistry {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_builtin_collectors() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(ssh::SshLogCollector));
        registry.register(Box::new(file_integrity::FileIntegrityCollector));
        registry.register(Box::new(users::UserCollector));
        registry.register(Box::new(package_manager::PackageManagerCollector));
        registry.register(Box::new(log_integrity::LogIntegrityCollector));
        registry.register(Box::new(persistence::PersistenceCollector));
        registry.register(Box::new(process::ProcessCollector));
        registry.register(Box::new(gpu::GpuCollector));
        registry.register(Box::new(network::NetworkCollector));
        registry.register(Box::new(firewall::FirewallCollector));
        registry.register(Box::new(web_logs::WebLogCollector));
        registry.register(Box::new(config_risk::ConfigRiskCollector));
        registry.register(Box::new(docker::DockerCollector));
        registry.register(Box::new(rootkit::RootkitSignalCollector));
        registry.register(Box::new(audit::AuditLogCollector));
        registry.register(Box::new(ebpf_bridge::EbpfBridgeCollector));
        registry
    }

    pub fn register(&mut self, collector: Box<dyn Collector>) {
        self.collectors.push(collector);
    }

    pub fn into_collectors(self) -> Vec<Box<dyn Collector>> {
        self.collectors
    }
}

/// Registry for risk detectors.
#[derive(Default)]
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_builtin_detectors() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(ssh_rules::SshDetector));
        registry.register(Box::new(file_rules::FileDetector));
        registry.register(Box::new(user_rules::UserDetector));
        registry.register(Box::new(persistence_rules::PersistenceDetector));
        registry.register(Box::new(process_rules::ProcessDetector));
        registry.register(Box::new(network_rules::NetworkDetector));
        registry.register(Box::new(web_rules::WebDetector));
        registry.register(Box::new(config_rules::ConfigRiskDetector));
        registry.register(Box::new(docker_rules::DockerDetector));
        registry.register(Box::new(rootkit_rules::RootkitDetector));
        registry.register(Box::new(tamper_rules::TamperDetector));
        registry.register(Box::new(audit_rules::AuditDetector));
        registry.register(Box::new(external_rules::ExternalRulesDetector));
        registry
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn into_detectors(self) -> Vec<Box<dyn Detector>> {
        self.detectors
    }
}
