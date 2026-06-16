use crate::error::{SentinelError, SentinelResult};
use crate::Severity;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Top-level TOML configuration for the agent and CLI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelConfig {
    pub agent: AgentConfig,
    pub privacy: PrivacyConfig,
    pub storage: StorageConfig,
    pub ssh: SshConfig,
    pub file_integrity: FileIntegrityConfig,
    pub web: WebConfig,
    pub process: ProcessConfig,
    pub network: NetworkConfig,
    pub persistence: PersistenceConfig,
    pub docker: DockerConfig,
    pub notifications: NotificationsConfig,
    pub noise_control: NoiseControlConfig,
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
        if self.ssh.failed_login_threshold == 0 {
            return Err(SentinelError::Config(
                "ssh.failed_login_threshold must be greater than 0".to_string(),
            ));
        }
        if self.file_integrity.max_file_size_mb == 0 {
            return Err(SentinelError::Config(
                "file_integrity.max_file_size_mb must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve the host identifier, falling back to the configured hostname.
    pub fn host_id(&self) -> String {
        if !self.agent.host_id.trim().is_empty() {
            return self.agent.host_id.clone();
        }
        if !self.agent.hostname.trim().is_empty() {
            return self.agent.hostname.clone();
        }
        "local-host".to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub host_id: String,
    pub hostname: String,
    pub scan_interval_seconds: u64,
    pub full_scan_interval_seconds: u64,
    pub data_dir: PathBuf,
    pub log_level: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            host_id: String::new(),
            hostname: String::new(),
            scan_interval_seconds: 60,
            full_scan_interval_seconds: 3600,
            data_dir: PathBuf::from("/var/lib/vps-sentinel"),
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    pub upload_logs: bool,
    pub mask_ip: bool,
    pub mask_command_args: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub r#type: String,
    pub path: PathBuf,
    pub retention_days: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            r#type: "sqlite".to_string(),
            path: PathBuf::from("/var/lib/vps-sentinel/sentinel.db"),
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SshConfig {
    pub enabled: bool,
    pub auth_log_paths: Vec<PathBuf>,
    pub monitor_authorized_keys: bool,
    pub alert_on_root_login: bool,
    pub alert_on_password_login: bool,
    pub failed_login_threshold: usize,
    pub failed_login_window_seconds: u64,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auth_log_paths: vec![
                PathBuf::from("/var/log/auth.log"),
                PathBuf::from("/var/log/secure"),
            ],
            monitor_authorized_keys: true,
            alert_on_root_login: true,
            alert_on_password_login: true,
            failed_login_threshold: 10,
            failed_login_window_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileIntegrityConfig {
    pub enabled: bool,
    pub max_file_size_mb: u64,
    pub max_depth: usize,
    pub paths: Vec<PathBuf>,
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_file_size_mb: 5,
            max_depth: 8,
            paths: vec![
                PathBuf::from("/etc/passwd"),
                PathBuf::from("/etc/shadow"),
                PathBuf::from("/etc/group"),
                PathBuf::from("/etc/sudoers"),
                PathBuf::from("/etc/sudoers.d"),
                PathBuf::from("/etc/ssh/sshd_config"),
                PathBuf::from("/etc/ssh/sshd_config.d"),
                PathBuf::from("/etc/systemd/system"),
                PathBuf::from("/etc/crontab"),
                PathBuf::from("/etc/cron.d"),
                PathBuf::from("/var/spool/cron"),
                PathBuf::from("/root/.ssh"),
                PathBuf::from("/home/*/.ssh"),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    pub enabled: bool,
    pub web_roots: Vec<PathBuf>,
    pub log_paths: Vec<PathBuf>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            web_roots: vec![
                PathBuf::from("/var/www"),
                PathBuf::from("/srv"),
                PathBuf::from("/opt"),
            ],
            log_paths: vec![
                PathBuf::from("/var/log/nginx/access.log"),
                PathBuf::from("/var/log/nginx/error.log"),
                PathBuf::from("/var/log/caddy/access.log"),
                PathBuf::from("/var/log/apache2/access.log"),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessConfig {
    pub enabled: bool,
    pub scan_interval_seconds: u64,
    pub high_cpu_threshold_percent: f32,
    pub high_cpu_duration_seconds: u64,
    pub suspicious_dirs: Vec<PathBuf>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_seconds: 30,
            high_cpu_threshold_percent: 80.0,
            high_cpu_duration_seconds: 120,
            suspicious_dirs: vec![
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
                PathBuf::from("/dev/shm"),
                PathBuf::from("/run"),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub scan_interval_seconds: u64,
    pub alert_on_new_listening_port: bool,
    pub public_listen_allowlist: Vec<u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_seconds: 30,
            alert_on_new_listening_port: true,
            public_listen_allowlist: vec![22, 80, 443],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub monitor_cron: bool,
    pub monitor_systemd: bool,
    pub monitor_shell_profile: bool,
    pub monitor_ld_preload: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_cron: true,
            monitor_systemd: true,
            monitor_shell_profile: true,
            monitor_ld_preload: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerConfig {
    pub enabled: bool,
    pub alert_on_privileged_container: bool,
    pub alert_on_docker_socket_mount: bool,
    pub alert_on_host_network: bool,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            alert_on_privileged_container: true,
            alert_on_docker_socket_mount: true,
            alert_on_host_network: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NotificationsConfig {
    pub telegram: TelegramConfig,
    pub email: EmailConfig,
    pub webhook: WebhookConfig,
    pub ntfy: NtfyConfig,
    pub gotify: GotifyConfig,
    pub bark: BarkConfig,
    pub serverchan: ServerChanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    pub min_severity: Severity,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: String::new(),
            chat_id: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
    pub min_severity: Severity,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            smtp_host: String::new(),
            smtp_port: 587,
            username: String::new(),
            password: String::new(),
            from: String::new(),
            to: Vec::new(),
            min_severity: Severity::High,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookConfig {
    pub enabled: bool,
    pub url: String,
    pub secret: String,
    pub min_severity: Severity,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            secret: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NtfyConfig {
    pub enabled: bool,
    pub server: String,
    pub topic: String,
    pub token: String,
    pub min_severity: Severity,
}

impl Default for NtfyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "https://ntfy.sh".to_string(),
            topic: String::new(),
            token: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GotifyConfig {
    pub enabled: bool,
    pub server: String,
    pub token: String,
    pub min_severity: Severity,
}

impl Default for GotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: String::new(),
            token: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BarkConfig {
    pub enabled: bool,
    pub server: String,
    pub device_key: String,
    pub min_severity: Severity,
}

impl Default for BarkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "https://api.day.app".to_string(),
            device_key: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerChanConfig {
    pub enabled: bool,
    pub send_key: String,
    pub min_severity: Severity,
}

impl Default for ServerChanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            send_key: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NoiseControlConfig {
    pub dedup_window_seconds: u64,
    pub max_alerts_per_hour: u32,
    pub quiet_hours: Vec<String>,
}

impl Default for NoiseControlConfig {
    fn default() -> Self {
        Self {
            dedup_window_seconds: 600,
            max_alerts_per_hour: 30,
            quiet_hours: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AllowlistConfig {
    pub users: Vec<String>,
    pub ips: Vec<String>,
    pub process_paths: Vec<PathBuf>,
    pub listening_ports: Vec<u16>,
    pub file_paths: Vec<PathBuf>,
    pub web_paths: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::SentinelConfig;

    #[test]
    fn default_config_round_trips_as_toml() -> Result<(), Box<dyn std::error::Error>> {
        let text = SentinelConfig::default_toml()?;
        let decoded: SentinelConfig = toml::from_str(&text)?;
        decoded.validate()?;
        assert_eq!(decoded.storage.r#type, "sqlite");
        assert!(!decoded.ssh.auth_log_paths.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_storage_type_is_rejected() {
        let mut config = SentinelConfig::default();
        config.storage.r#type = "postgres".to_string();
        assert!(config.validate().is_err());
    }
}
