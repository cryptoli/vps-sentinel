mod notifications;
mod sections;

use crate::error::{SentinelError, SentinelResult};
use crate::MinuteWindow;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub use notifications::{
    BarkConfig, EmailConfig, EmailTlsMode, GotifyConfig, NotificationLanguage,
    NotificationTimeZone, NotificationsConfig, NtfyConfig, ServerChanConfig, TelegramConfig,
    WebhookConfig,
};
pub use sections::{
    ActiveResponseConfig, AdvancedCollectorsConfig, AgentConfig, AllowlistConfig, DockerConfig,
    ExternalRulesConfig, FileIntegrityConfig, FleetConfig, GpuConfig, IncidentConfig,
    LogIntegrityConfig, MaintenanceConfig, NetworkConfig, NoiseControlConfig, PackageManagerConfig,
    PersistenceConfig, PrivacyConfig, ProcessConfig, ReportsConfig, ResponsePolicyConfig,
    ResponsePolicyRule, SentinelPaths, ServiceProfileConfig, SshConfig, StorageConfig,
    ThreatIntelConfig, WebConfig,
};

/// Top-level TOML configuration for the agent and CLI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    pub agent: AgentConfig,
    pub privacy: PrivacyConfig,
    pub storage: StorageConfig,
    pub ssh: SshConfig,
    pub file_integrity: FileIntegrityConfig,
    pub log_integrity: LogIntegrityConfig,
    pub web: WebConfig,
    pub process: ProcessConfig,
    pub gpu: GpuConfig,
    pub package_manager: PackageManagerConfig,
    pub network: NetworkConfig,
    pub persistence: PersistenceConfig,
    pub docker: DockerConfig,
    pub notifications: NotificationsConfig,
    pub noise_control: NoiseControlConfig,
    pub active_response: ActiveResponseConfig,
    pub response_policy: ResponsePolicyConfig,
    pub incidents: IncidentConfig,
    pub service_profile: ServiceProfileConfig,
    pub reports: ReportsConfig,
    pub advanced_collectors: AdvancedCollectorsConfig,
    pub external_rules: ExternalRulesConfig,
    pub threat_intel: ThreatIntelConfig,
    pub fleet: FleetConfig,
    pub maintenance: MaintenanceConfig,
    pub allowlist: AllowlistConfig,
}

impl SentinelConfig {
    /// Load configuration from TOML.
    pub fn load(path: &Path) -> SentinelResult<Self> {
        let text = fs::read_to_string(path).map_err(|err| SentinelError::io(path, err))?;
        let config: Self =
            toml::from_str(&text).map_err(|err| SentinelError::Config(err.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Serialize the default configuration as TOML.
    pub fn default_toml() -> SentinelResult<String> {
        toml::to_string_pretty(&Self::default())
            .map_err(|err| SentinelError::Config(err.to_string()))
    }

    /// Validate cross-field requirements.
    pub fn validate(&self) -> SentinelResult<()> {
        if self.agent.scan_interval_seconds == 0 {
            return Err(SentinelError::Config(
                "agent.scan_interval_seconds must be greater than 0".to_string(),
            ));
        }
        if self.storage.r#type != "sqlite" {
            return Err(SentinelError::Unsupported(format!(
                "storage.type '{}' is not supported",
                self.storage.r#type
            )));
        }
        if self.storage.retention_days == 0 {
            return Err(SentinelError::Config(
                "storage.retention_days must be greater than 0".to_string(),
            ));
        }
        if self.storage.max_database_size_mb < 16 {
            return Err(SentinelError::Config(
                "storage.max_database_size_mb must be at least 16".to_string(),
            ));
        }
        if self.ssh.failed_login_threshold == 0 {
            return Err(SentinelError::Config(
                "ssh.failed_login_threshold must be greater than 0".to_string(),
            ));
        }
        if self.ssh.auth_log_lookback_seconds == 0 {
            return Err(SentinelError::Config(
                "ssh.auth_log_lookback_seconds must be greater than 0".to_string(),
            ));
        }
        if self.ssh.failed_login_window_seconds == 0 {
            return Err(SentinelError::Config(
                "ssh.failed_login_window_seconds must be greater than 0".to_string(),
            ));
        }
        if self.file_integrity.max_file_size_mb == 0 {
            return Err(SentinelError::Config(
                "file_integrity.max_file_size_mb must be greater than 0".to_string(),
            ));
        }
        if self.file_integrity.max_depth == 0 {
            return Err(SentinelError::Config(
                "file_integrity.max_depth must be greater than 0".to_string(),
            ));
        }
        if self.file_integrity.webshell_min_score == 0 {
            return Err(SentinelError::Config(
                "file_integrity.webshell_min_score must be greater than 0".to_string(),
            ));
        }
        if self.log_integrity.truncate_drop_percent == 0
            || self.log_integrity.truncate_drop_percent > 100
        {
            return Err(SentinelError::Config(
                "log_integrity.truncate_drop_percent must be between 1 and 100".to_string(),
            ));
        }
        if self.log_integrity.truncate_min_drop_bytes == 0 {
            return Err(SentinelError::Config(
                "log_integrity.truncate_min_drop_bytes must be greater than 0".to_string(),
            ));
        }
        if self.log_integrity.rotation_grace_seconds == 0 {
            return Err(SentinelError::Config(
                "log_integrity.rotation_grace_seconds must be greater than 0".to_string(),
            ));
        }
        if self.web.error_burst_threshold == 0 {
            return Err(SentinelError::Config(
                "web.error_burst_threshold must be greater than 0".to_string(),
            ));
        }
        if self.web.max_log_tail_bytes == 0 {
            return Err(SentinelError::Config(
                "web.max_log_tail_bytes must be greater than 0".to_string(),
            ));
        }
        if self.process.behavior_min_score == 0 {
            return Err(SentinelError::Config(
                "process.behavior_min_score must be greater than 0".to_string(),
            ));
        }
        if !self.process.high_cpu_threshold_percent.is_finite()
            || self.process.high_cpu_threshold_percent <= 0.0
        {
            return Err(SentinelError::Config(
                "process.high_cpu_threshold_percent must be a positive finite number".to_string(),
            ));
        }
        if self.process.high_cpu_duration_seconds == 0 {
            return Err(SentinelError::Config(
                "process.high_cpu_duration_seconds must be greater than 0".to_string(),
            ));
        }
        if self.process.suspicious_socket_fd_threshold == 0 {
            return Err(SentinelError::Config(
                "process.suspicious_socket_fd_threshold must be greater than 0".to_string(),
            ));
        }
        for dir in &self.process.suspicious_dirs {
            let normalized = dir.to_string_lossy().replace('\\', "/");
            let normalized = normalized.trim_end_matches('/');
            if normalized.trim().is_empty() || normalized == "/" {
                return Err(SentinelError::Config(
                    "process.suspicious_dirs entries must not be empty or root".to_string(),
                ));
            }
            if !normalized.starts_with('/') {
                return Err(SentinelError::Config(
                    "process.suspicious_dirs entries must be absolute Linux paths".to_string(),
                ));
            }
        }
        if self.gpu.enabled
            && self.gpu.nvidia_smi_path.trim().is_empty()
            && self.gpu.rocm_smi_path.trim().is_empty()
        {
            return Err(SentinelError::Config(
                "gpu.nvidia_smi_path or gpu.rocm_smi_path is required when gpu.enabled is true"
                    .to_string(),
            ));
        }
        if self.gpu.command_timeout_seconds == 0 {
            return Err(SentinelError::Config(
                "gpu.command_timeout_seconds must be greater than 0".to_string(),
            ));
        }
        if self.gpu.min_memory_mb == 0 {
            return Err(SentinelError::Config(
                "gpu.min_memory_mb must be greater than 0".to_string(),
            ));
        }
        if self.gpu.mining_min_score == 0 {
            return Err(SentinelError::Config(
                "gpu.mining_min_score must be greater than 0".to_string(),
            ));
        }
        if self.package_manager.recent_activity_window_seconds == 0 {
            return Err(SentinelError::Config(
                "package_manager.recent_activity_window_seconds must be greater than 0".to_string(),
            ));
        }
        if self.package_manager.max_log_tail_bytes == 0 {
            return Err(SentinelError::Config(
                "package_manager.max_log_tail_bytes must be greater than 0".to_string(),
            ));
        }
        if self.notifications.request_timeout_seconds == 0 {
            return Err(SentinelError::Config(
                "notifications.request_timeout_seconds must be greater than 0".to_string(),
            ));
        }
        if self.noise_control.max_alerts_per_hour == 0 {
            return Err(SentinelError::Config(
                "noise_control.max_alerts_per_hour must be greater than 0".to_string(),
            ));
        }
        validate_active_response(&self.active_response, &self.ssh)?;
        validate_response_policy(&self.response_policy)?;
        validate_incidents(&self.incidents)?;
        validate_service_profile(&self.service_profile)?;
        validate_reports(&self.reports)?;
        validate_advanced_collectors(&self.advanced_collectors)?;
        validate_external_rules(&self.external_rules)?;
        validate_threat_intel(&self.threat_intel)?;
        validate_fleet(&self.fleet)?;
        validate_maintenance(&self.maintenance)?;
        for quiet_hour in &self.noise_control.quiet_hours {
            quiet_hour.parse::<MinuteWindow>().map_err(|err| {
                SentinelError::Config(format!(
                    "noise_control.quiet_hours entry '{quiet_hour}' is invalid: {err}"
                ))
            })?;
        }
        validate_notifications(&self.notifications)?;
        Ok(())
    }

    /// Resolve the host identifier, falling back to the configured hostname.
    pub fn host_id(&self) -> String {
        if !self.agent.host_id.trim().is_empty() {
            return self.agent.host_id.trim().to_string();
        }
        if !self.agent.hostname.trim().is_empty() {
            return self.agent.hostname.trim().to_string();
        }
        "local-host".to_string()
    }

    /// Resolve the human-readable VPS name shown in alerts.
    pub fn display_name(&self) -> String {
        if !self.agent.display_name.trim().is_empty() {
            return self.agent.display_name.trim().to_string();
        }
        if !self.agent.hostname.trim().is_empty() {
            return self.agent.hostname.trim().to_string();
        }
        self.host_id()
    }
}

fn validate_response_policy(config: &ResponsePolicyConfig) -> SentinelResult<()> {
    for (name, policy) in &config.policies {
        let name = name.trim();
        if name.is_empty() {
            return Err(SentinelError::Config(
                "response_policy.policies keys must not be empty".to_string(),
            ));
        }
        match policy.action.as_str() {
            "observe" | "block" | "permanent_block" => {}
            other => {
                return Err(SentinelError::Config(format!(
                    "response_policy.policies.{name}.action '{other}' is invalid; use observe, block, or permanent_block"
                )));
            }
        }
        if policy.min_confidence > 100 {
            return Err(SentinelError::Config(format!(
                "response_policy.policies.{name}.min_confidence must be between 0 and 100"
            )));
        }
        if policy.min_unified_score > 100 {
            return Err(SentinelError::Config(format!(
                "response_policy.policies.{name}.min_unified_score must be between 0 and 100"
            )));
        }
        if policy.ttl_seconds == Some(0) {
            return Err(SentinelError::Config(format!(
                "response_policy.policies.{name}.ttl_seconds must be greater than 0 when set"
            )));
        }
        if policy.permanent_after == Some(0) {
            return Err(SentinelError::Config(format!(
                "response_policy.policies.{name}.permanent_after must be greater than 0 when set"
            )));
        }
    }
    Ok(())
}

fn validate_incidents(config: &IncidentConfig) -> SentinelResult<()> {
    if config.correlation_window_seconds == 0 {
        return Err(SentinelError::Config(
            "incidents.correlation_window_seconds must be greater than 0".to_string(),
        ));
    }
    if config.max_findings_per_incident == 0 {
        return Err(SentinelError::Config(
            "incidents.max_findings_per_incident must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_service_profile(_config: &ServiceProfileConfig) -> SentinelResult<()> {
    Ok(())
}

fn validate_reports(config: &ReportsConfig) -> SentinelResult<()> {
    if config.scheduled_hour > 23 {
        return Err(SentinelError::Config(
            "reports.scheduled_hour must be between 0 and 23".to_string(),
        ));
    }
    match config.scheduled_period.as_str() {
        "today" | "last24h" => {}
        other => {
            return Err(SentinelError::Config(format!(
                "reports.scheduled_period '{other}' is invalid; use today or last24h"
            )));
        }
    }
    if config.min_interval_seconds == 0 {
        return Err(SentinelError::Config(
            "reports.min_interval_seconds must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_advanced_collectors(config: &AdvancedCollectorsConfig) -> SentinelResult<()> {
    if config.audit_max_tail_bytes == 0 {
        return Err(SentinelError::Config(
            "advanced_collectors.audit_max_tail_bytes must be greater than 0".to_string(),
        ));
    }
    if config.command_timeout_seconds == 0 {
        return Err(SentinelError::Config(
            "advanced_collectors.command_timeout_seconds must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_external_rules(config: &ExternalRulesConfig) -> SentinelResult<()> {
    if config.command_timeout_seconds == 0 {
        return Err(SentinelError::Config(
            "external_rules.command_timeout_seconds must be greater than 0".to_string(),
        ));
    }
    if config.max_file_size_mb == 0 {
        return Err(SentinelError::Config(
            "external_rules.max_file_size_mb must be greater than 0".to_string(),
        ));
    }
    if config.yara_enabled && config.yara_command.trim().is_empty() {
        return Err(SentinelError::Config(
            "external_rules.yara_command is required when YARA is enabled".to_string(),
        ));
    }
    Ok(())
}

fn validate_threat_intel(config: &ThreatIntelConfig) -> SentinelResult<()> {
    if config.request_timeout_seconds == 0 {
        return Err(SentinelError::Config(
            "threat_intel.request_timeout_seconds must be greater than 0".to_string(),
        ));
    }
    if config.cache_ttl_seconds == 0 {
        return Err(SentinelError::Config(
            "threat_intel.cache_ttl_seconds must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_fleet(config: &FleetConfig) -> SentinelResult<()> {
    if config.enabled && config.export_path.as_os_str().is_empty() {
        return Err(SentinelError::Config(
            "fleet.export_path is required when fleet.enabled is true".to_string(),
        ));
    }
    Ok(())
}

fn validate_maintenance(config: &MaintenanceConfig) -> SentinelResult<()> {
    if config.max_duration_seconds == 0 {
        return Err(SentinelError::Config(
            "maintenance.max_duration_seconds must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

fn validate_active_response(config: &ActiveResponseConfig, ssh: &SshConfig) -> SentinelResult<()> {
    match config.firewall_backend.as_str() {
        "auto" | "nftables" | "iptables" => {}
        other => {
            return Err(SentinelError::Config(format!(
                "active_response.firewall_backend '{other}' is invalid; use auto, nftables, or iptables"
            )));
        }
    }
    match config.strategy.as_str() {
        "observe" | "balanced" | "strict" => {}
        other => {
            return Err(SentinelError::Config(format!(
                "active_response.strategy '{other}' is invalid; use observe, balanced, or strict"
            )));
        }
    }
    if config.block_ttl_seconds == 0 {
        return Err(SentinelError::Config(
            "active_response.block_ttl_seconds must be greater than 0".to_string(),
        ));
    }
    if config.command_timeout_seconds == 0 {
        return Err(SentinelError::Config(
            "active_response.command_timeout_seconds must be greater than 0".to_string(),
        ));
    }
    if config.max_blocks_per_scan == 0 {
        return Err(SentinelError::Config(
            "active_response.max_blocks_per_scan must be greater than 0".to_string(),
        ));
    }
    if config.notification_detail_limit == 0 {
        return Err(SentinelError::Config(
            "active_response.notification_detail_limit must be greater than 0".to_string(),
        ));
    }
    if config.permanent_block_threshold == 0 {
        return Err(SentinelError::Config(
            "active_response.permanent_block_threshold must be greater than 0".to_string(),
        ));
    }
    if config.permanent_block_window_seconds == 0 {
        return Err(SentinelError::Config(
            "active_response.permanent_block_window_seconds must be greater than 0".to_string(),
        ));
    }
    if config.web_probe_block_threshold == 0 {
        return Err(SentinelError::Config(
            "active_response.web_probe_block_threshold must be greater than 0".to_string(),
        ));
    }
    if config.web_exploit_block_threshold == 0 {
        return Err(SentinelError::Config(
            "active_response.web_exploit_block_threshold must be greater than 0".to_string(),
        ));
    }
    if config.ssh_failed_login_block_threshold == 0 {
        return Err(SentinelError::Config(
            "active_response.ssh_failed_login_block_threshold must be greater than 0".to_string(),
        ));
    }
    if config.ssh_enabled && config.ssh_failed_login_block_threshold < ssh.failed_login_threshold {
        return Err(SentinelError::Config(format!(
            "active_response.ssh_failed_login_block_threshold must be greater than or equal to ssh.failed_login_threshold ({})",
            ssh.failed_login_threshold
        )));
    }
    Ok(())
}

fn validate_notifications(config: &NotificationsConfig) -> SentinelResult<()> {
    if config.telegram.enabled {
        if config.telegram.bot_token.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.telegram.bot_token is required when telegram is enabled".to_string(),
            ));
        }
        if config.telegram.chat_id.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.telegram.chat_id is required when telegram is enabled".to_string(),
            ));
        }
    }
    if config.email.enabled {
        if config.email.smtp_host.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.email.smtp_host is required when email is enabled".to_string(),
            ));
        }
        if config.email.smtp_port == 0 {
            return Err(SentinelError::Config(
                "notifications.email.smtp_port must be greater than 0".to_string(),
            ));
        }
        if config.email.from.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.email.from is required when email is enabled".to_string(),
            ));
        }
        if config.email.to.is_empty() {
            return Err(SentinelError::Config(
                "notifications.email.to must contain at least one recipient when email is enabled"
                    .to_string(),
            ));
        }
        if config.email.username.trim().is_empty() != config.email.password.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.email.username and password must be configured together".to_string(),
            ));
        }
        if config.email.tls_mode == EmailTlsMode::None && !config.email.username.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.email.tls_mode = 'none' cannot be used with SMTP credentials"
                    .to_string(),
            ));
        }
    }
    if config.webhook.enabled && config.webhook.url.trim().is_empty() {
        return Err(SentinelError::Config(
            "notifications.webhook.url is required when webhook is enabled".to_string(),
        ));
    }
    if config.ntfy.enabled && config.ntfy.topic.trim().is_empty() {
        return Err(SentinelError::Config(
            "notifications.ntfy.topic is required when ntfy is enabled".to_string(),
        ));
    }
    if config.ntfy.enabled && config.ntfy.server.trim().is_empty() {
        return Err(SentinelError::Config(
            "notifications.ntfy.server is required when ntfy is enabled".to_string(),
        ));
    }
    if config.gotify.enabled {
        if config.gotify.server.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.gotify.server is required when gotify is enabled".to_string(),
            ));
        }
        if config.gotify.token.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.gotify.token is required when gotify is enabled".to_string(),
            ));
        }
    }
    if config.bark.enabled {
        if config.bark.server.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.bark.server is required when bark is enabled".to_string(),
            ));
        }
        if config.bark.device_key.trim().is_empty() {
            return Err(SentinelError::Config(
                "notifications.bark.device_key is required when bark is enabled".to_string(),
            ));
        }
    }
    if config.serverchan.enabled && config.serverchan.send_key.trim().is_empty() {
        return Err(SentinelError::Config(
            "notifications.serverchan.send_key is required when serverchan is enabled".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EmailTlsMode, NotificationLanguage, SentinelConfig};

    #[test]
    fn default_config_round_trips_as_toml() -> Result<(), Box<dyn std::error::Error>> {
        let text = SentinelConfig::default_toml()?;
        let decoded: SentinelConfig = toml::from_str(&text)?;
        decoded.validate()?;
        assert_eq!(decoded.storage.r#type, "sqlite");
        assert_eq!(decoded.notifications.language, NotificationLanguage::ZhCn);
        assert!(text.contains("language = \"zh_cn\""));
        assert!(!decoded.ssh.auth_log_paths.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_storage_type_is_rejected() {
        let mut config = SentinelConfig::default();
        config.storage.r#type = "postgres".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_storage_retention_is_rejected() {
        let mut config = SentinelConfig::default();
        config.storage.retention_days = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.storage.max_database_size_mb = 15;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_notification_timeout_is_rejected() {
        let mut config = SentinelConfig::default();
        config.notifications.request_timeout_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn display_name_prefers_configured_vps_name() {
        let mut config = SentinelConfig::default();
        config.agent.host_id = "host-001".to_string();
        config.agent.hostname = "linux-host".to_string();
        config.agent.display_name = "prod-web-1".to_string();
        assert_eq!(config.host_id(), "host-001");
        assert_eq!(config.display_name(), "prod-web-1");
    }

    #[test]
    fn legacy_config_missing_network_lists_uses_policy_defaults(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config: SentinelConfig = toml::from_str("[network]\nenabled = true\n")?;
        assert!(config.network.expected_public_ports.contains(&443));
        assert!(config.network.high_risk_public_ports.contains(&6379));
        assert!(config.network.public_listen_allowlist.contains(&80));
        Ok(())
    }

    #[test]
    fn invalid_quiet_hour_window_is_rejected() {
        let mut config = SentinelConfig::default();
        config.noise_control.quiet_hours = vec!["25:00-26:00".to_string()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_ssh_time_windows_are_rejected() {
        let mut config = SentinelConfig::default();
        config.ssh.auth_log_lookback_seconds = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.ssh.failed_login_window_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_web_error_threshold_is_rejected() {
        let mut config = SentinelConfig::default();
        config.web.error_burst_threshold = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_risk_thresholds_are_rejected() {
        let mut config = SentinelConfig::default();
        config.file_integrity.max_depth = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.file_integrity.webshell_min_score = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.behavior_min_score = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.high_cpu_threshold_percent = 0.0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.high_cpu_threshold_percent = f32::NAN;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.high_cpu_duration_seconds = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.suspicious_socket_fd_threshold = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_process_suspicious_dirs_are_rejected() {
        let mut config = SentinelConfig::default();
        config.process.suspicious_dirs = vec!["".into()];
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.suspicious_dirs = vec!["/".into()];
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.process.suspicious_dirs = vec!["tmp".into()];
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_package_manager_windows_are_rejected() {
        let mut config = SentinelConfig::default();
        config.package_manager.recent_activity_window_seconds = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.package_manager.max_log_tail_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_active_response_settings_are_rejected() {
        let mut config = SentinelConfig::default();
        config.active_response.firewall_backend = "pf".to_string();
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.block_ttl_seconds = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.web_probe_block_threshold = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.notification_detail_limit = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.permanent_block_threshold = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.permanent_block_window_seconds = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.ssh_failed_login_block_threshold = 0;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.active_response.ssh_failed_login_block_threshold =
            config.ssh.failed_login_threshold - 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_advanced_settings_are_rejected() {
        let mut config = SentinelConfig::default();
        config.response_policy.policies.insert(
            "bad".to_string(),
            super::ResponsePolicyRule {
                action: "delete".to_string(),
                ..super::ResponsePolicyRule::default()
            },
        );
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.reports.scheduled_hour = 24;
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.external_rules.yara_enabled = true;
        config.external_rules.yara_command.clear();
        assert!(config.validate().is_err());

        let mut config = SentinelConfig::default();
        config.maintenance.max_duration_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn enabled_email_requires_delivery_settings() {
        let mut config = SentinelConfig::default();
        config.notifications.email.enabled = true;
        assert!(config.validate().is_err());

        config.notifications.email.smtp_host = "smtp.example.com".to_string();
        config.notifications.email.from = "sentinel@example.com".to_string();
        config.notifications.email.to = vec!["ops@example.com".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn enabled_notification_channels_require_delivery_settings() {
        let mut config = SentinelConfig::default();
        config.notifications.telegram.enabled = true;
        assert!(config.validate().is_err());
        config.notifications.telegram.bot_token = "token".to_string();
        config.notifications.telegram.chat_id = "chat".to_string();
        assert!(config.validate().is_ok());

        let mut config = SentinelConfig::default();
        config.notifications.webhook.enabled = true;
        assert!(config.validate().is_err());
        config.notifications.webhook.url = "https://example.com/hook".to_string();
        assert!(config.validate().is_ok());

        let mut config = SentinelConfig::default();
        config.notifications.ntfy.enabled = true;
        assert!(config.validate().is_err());
        config.notifications.ntfy.topic = "topic".to_string();
        assert!(config.validate().is_ok());

        let mut config = SentinelConfig::default();
        config.notifications.gotify.enabled = true;
        assert!(config.validate().is_err());
        config.notifications.gotify.server = "https://gotify.example.com".to_string();
        config.notifications.gotify.token = "token".to_string();
        assert!(config.validate().is_ok());

        let mut config = SentinelConfig::default();
        config.notifications.bark.enabled = true;
        assert!(config.validate().is_err());
        config.notifications.bark.device_key = "device".to_string();
        assert!(config.validate().is_ok());

        let mut config = SentinelConfig::default();
        config.notifications.serverchan.enabled = true;
        assert!(config.validate().is_err());
        config.notifications.serverchan.send_key = "key".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn plaintext_email_rejects_credentials() {
        let mut config = SentinelConfig::default();
        config.notifications.email.enabled = true;
        config.notifications.email.smtp_host = "localhost".to_string();
        config.notifications.email.from = "sentinel@example.com".to_string();
        config.notifications.email.to = vec!["ops@example.com".to_string()];
        config.notifications.email.tls_mode = EmailTlsMode::None;
        config.notifications.email.username = "user".to_string();
        config.notifications.email.password = "secret".to_string();
        assert!(config.validate().is_err());
    }
}
