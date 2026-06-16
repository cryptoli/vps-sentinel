use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default Linux paths used by the built-in configuration.
pub struct SentinelPaths;

impl SentinelPaths {
    pub const DATA_DIR: &'static str = "/var/lib/vps-sentinel";
    pub const DB_PATH: &'static str = "/var/lib/vps-sentinel/sentinel.db";
    pub const AUTH_LOG_UBUNTU: &'static str = "/var/log/auth.log";
    pub const AUTH_LOG_RHEL: &'static str = "/var/log/secure";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub host_id: String,
    pub hostname: String,
    pub display_name: String,
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
            display_name: String::new(),
            scan_interval_seconds: 60,
            full_scan_interval_seconds: 3600,
            data_dir: PathBuf::from(SentinelPaths::DATA_DIR),
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
            path: PathBuf::from(SentinelPaths::DB_PATH),
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
                PathBuf::from(SentinelPaths::AUTH_LOG_UBUNTU),
                PathBuf::from(SentinelPaths::AUTH_LOG_RHEL),
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
            paths: default_file_integrity_paths(),
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
            suspicious_dirs: ["/tmp", "/var/tmp", "/dev/shm", "/run"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub scan_interval_seconds: u64,
    pub alert_on_new_listening_port: bool,
    #[serde(default = "default_expected_public_ports")]
    pub expected_public_ports: Vec<u16>,
    #[serde(default = "default_high_risk_public_ports")]
    pub high_risk_public_ports: Vec<u16>,
    #[serde(default = "default_public_listen_allowlist")]
    pub public_listen_allowlist: Vec<u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_interval_seconds: 30,
            alert_on_new_listening_port: true,
            expected_public_ports: default_expected_public_ports(),
            high_risk_public_ports: default_high_risk_public_ports(),
            public_listen_allowlist: default_public_listen_allowlist(),
        }
    }
}

fn default_expected_public_ports() -> Vec<u16> {
    vec![22, 80, 443]
}

fn default_high_risk_public_ports() -> Vec<u16> {
    vec![
        11211, 2375, 2376, 2379, 2380, 3000, 3306, 3389, 5432, 5601, 5672, 5900, 5901, 5984, 5985,
        5986, 6379, 6443, 9090, 9200, 9300, 10250, 10255, 15672, 27017, 27018, 27019,
    ]
}

fn default_public_listen_allowlist() -> Vec<u16> {
    vec![22, 80, 443]
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
    pub process_command_contains: Vec<String>,
    pub listening_ports: Vec<u16>,
    pub file_paths: Vec<PathBuf>,
    pub web_paths: Vec<PathBuf>,
}

fn default_file_integrity_paths() -> Vec<PathBuf> {
    [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d",
        "/etc/systemd/system",
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/root/.ssh",
        "/home/*/.ssh",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}
