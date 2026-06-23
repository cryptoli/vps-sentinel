use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::severity::Severity;

/// Default Linux paths used by the built-in configuration.
pub struct SentinelPaths;

impl SentinelPaths {
    pub const DATA_DIR: &'static str = "/var/lib/vps-sentinel";
    pub const DB_PATH: &'static str = "/var/lib/vps-sentinel/sentinel.db";
    pub const AUTH_LOG_UBUNTU: &'static str = "/var/log/auth.log";
    pub const AUTH_LOG_RHEL: &'static str = "/var/log/secure";
}

const DEFAULT_SSH_FAILED_LOGIN_THRESHOLD: usize = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    pub host_id: String,
    pub hostname: String,
    pub display_name: String,
    pub scan_interval_seconds: u64,
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
    pub max_database_size_mb: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            r#type: "sqlite".to_string(),
            path: PathBuf::from(SentinelPaths::DB_PATH),
            retention_days: 30,
            max_database_size_mb: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    pub collect_memory_metrics: bool,
    pub store_raw_log_lines: bool,
    pub store_all_web_access_events: bool,
    pub max_stored_field_bytes: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            collect_memory_metrics: true,
            store_raw_log_lines: false,
            store_all_web_access_events: false,
            max_stored_field_bytes: 4096,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceBudgetConfig {
    pub enabled: bool,
    pub max_raw_events_per_scan: usize,
    pub max_findings_per_scan: usize,
    pub max_evidence_items_per_finding: usize,
    pub max_evidence_value_bytes: usize,
}

impl Default for ResourceBudgetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_raw_events_per_scan: 20_000,
            max_findings_per_scan: 500,
            max_evidence_items_per_finding: 64,
            max_evidence_value_bytes: 2048,
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
    pub alert_on_successful_login: bool,
    pub auth_log_lookback_seconds: u64,
    pub failed_login_threshold: usize,
    pub failed_login_window_seconds: u64,
    pub max_events_per_scan: usize,
    pub trusted_admin_ips: Vec<String>,
    pub alert_on_trusted_admin_login: bool,
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
            alert_on_successful_login: true,
            auth_log_lookback_seconds: 300,
            failed_login_threshold: DEFAULT_SSH_FAILED_LOGIN_THRESHOLD,
            failed_login_window_seconds: 300,
            max_events_per_scan: 2000,
            trusted_admin_ips: Vec::new(),
            alert_on_trusted_admin_login: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileIntegrityConfig {
    pub enabled: bool,
    pub max_file_size_mb: u64,
    pub max_depth: usize,
    pub webshell_min_score: u16,
    pub incremental: bool,
    pub paths: Vec<PathBuf>,
}

impl Default for FileIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_file_size_mb: 5,
            max_depth: 8,
            webshell_min_score: 70,
            incremental: true,
            paths: default_file_integrity_paths(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogIntegrityConfig {
    pub enabled: bool,
    pub paths: Vec<PathBuf>,
    pub truncate_drop_percent: u8,
    pub truncate_min_drop_bytes: u64,
    pub rotation_grace_seconds: u64,
}

impl Default for LogIntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: vec![
                PathBuf::from("/var/log/auth.log"),
                PathBuf::from("/var/log/secure"),
                PathBuf::from("/var/log/wtmp"),
                PathBuf::from("/var/log/btmp"),
                PathBuf::from("/var/log/lastlog"),
            ],
            truncate_drop_percent: 90,
            truncate_min_drop_bytes: 262_144,
            rotation_grace_seconds: 900,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    pub enabled: bool,
    pub web_roots: Vec<PathBuf>,
    pub log_paths: Vec<PathBuf>,
    pub max_log_tail_bytes: u64,
    pub max_events_per_scan: usize,
    pub include_rotated: bool,
    pub log_lookback_seconds: u64,
    pub error_burst_threshold: usize,
    pub trusted_proxy_cidrs: Vec<String>,
    pub real_client_ip_fields: Vec<String>,
    pub suppress_unresolved_trusted_proxy: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            web_roots: vec![
                PathBuf::from("/var/www"),
                PathBuf::from("/srv"),
                PathBuf::from("/usr/share/nginx/html"),
                PathBuf::from("/usr/share/httpd/noindex"),
            ],
            log_paths: vec![
                PathBuf::from("/var/log/nginx/access.log"),
                PathBuf::from("/var/log/nginx/error.log"),
                PathBuf::from("/var/log/caddy/access.log"),
                PathBuf::from("/var/log/apache2/access.log"),
            ],
            max_log_tail_bytes: 1024 * 1024,
            max_events_per_scan: 5000,
            include_rotated: true,
            log_lookback_seconds: 900,
            error_burst_threshold: 20,
            trusted_proxy_cidrs: default_trusted_proxy_cidrs(),
            real_client_ip_fields: default_real_client_ip_fields(),
            suppress_unresolved_trusted_proxy: true,
        }
    }
}

fn default_trusted_proxy_cidrs() -> Vec<String> {
    [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_real_client_ip_fields() -> Vec<String> {
    [
        "cf_connecting_ip",
        "http_cf_connecting_ip",
        "x_forwarded_for",
        "http_x_forwarded_for",
        "x_real_ip",
        "http_x_real_ip",
        "request.headers.cf-connecting-ip",
        "request.headers.x-forwarded-for",
        "request.headers.x-real-ip",
        "headers.cf-connecting-ip",
        "headers.x-forwarded-for",
        "headers.x-real-ip",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessConfig {
    pub enabled: bool,
    pub high_cpu_threshold_percent: f32,
    pub high_cpu_duration_seconds: u64,
    pub deleted_executable_min_score: u16,
    pub behavior_min_score: u16,
    pub suspicious_socket_fd_threshold: usize,
    pub public_outbound_fanout_threshold: usize,
    pub outbound_remote_addr_sample_size: usize,
    pub suspicious_dirs: Vec<PathBuf>,
    #[serde(default = "default_known_bad_tool_names")]
    pub known_bad_tool_names: Vec<String>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            high_cpu_threshold_percent: 80.0,
            high_cpu_duration_seconds: 120,
            deleted_executable_min_score: 70,
            behavior_min_score: 70,
            suspicious_socket_fd_threshold: 20,
            public_outbound_fanout_threshold: 12,
            outbound_remote_addr_sample_size: 16,
            suspicious_dirs: ["/tmp", "/var/tmp", "/dev/shm", "/run"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            known_bad_tool_names: default_known_bad_tool_names(),
        }
    }
}

fn default_known_bad_tool_names() -> Vec<String> {
    [
        "xmrig",
        "xmr-stak",
        "kinsing",
        "masscan",
        "zmap",
        "lolminer",
        "nbminer",
        "gminer",
        "t-rex",
        "trex",
        "teamredminer",
        "phoenixminer",
        "ethminer",
        "ccminer",
        "cpuminer",
        "bminer",
        "nanominer",
        "wildrig",
        "rigel",
        "bzminer",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GpuConfig {
    pub enabled: bool,
    pub nvidia_smi_path: String,
    pub rocm_smi_path: String,
    pub command_timeout_seconds: u64,
    pub min_memory_mb: u64,
    pub high_utilization_percent: u8,
    pub high_power_watts: f32,
    pub mining_min_score: u16,
    pub mining_pool_ports: Vec<u16>,
}

impl Default for GpuConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            nvidia_smi_path: "nvidia-smi".to_string(),
            rocm_smi_path: "rocm-smi".to_string(),
            command_timeout_seconds: 2,
            min_memory_mb: 256,
            high_utilization_percent: 85,
            high_power_watts: 120.0,
            mining_min_score: 80,
            mining_pool_ports: vec![
                3333, 3334, 3335, 4444, 5555, 7777, 8888, 9999, 14444, 16000, 18081, 18082,
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PackageManagerConfig {
    pub enabled: bool,
    pub log_paths: Vec<PathBuf>,
    pub recent_activity_window_seconds: u64,
    pub max_log_tail_bytes: u64,
}

impl Default for PackageManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_paths: vec![
                PathBuf::from("/var/log/dpkg.log"),
                PathBuf::from("/var/log/apt/history.log"),
                PathBuf::from("/var/log/yum.log"),
                PathBuf::from("/var/log/dnf.log"),
                PathBuf::from("/var/log/pacman.log"),
                PathBuf::from("/var/log/apk.log"),
            ],
            recent_activity_window_seconds: 3600,
            max_log_tail_bytes: 8192,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub enabled: bool,
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
    pub suspicious_command_min_score: u16,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_cron: true,
            monitor_systemd: true,
            monitor_shell_profile: true,
            monitor_ld_preload: true,
            suspicious_command_min_score: 70,
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
    pub state_reminder_interval_seconds: u64,
    pub max_alerts_per_hour: u32,
    pub rate_limit_bypass_min_severity: Severity,
    pub quiet_hours_bypass_min_severity: Severity,
    pub quiet_hours: Vec<String>,
}

impl Default for NoiseControlConfig {
    fn default() -> Self {
        Self {
            dedup_window_seconds: 3600,
            state_reminder_interval_seconds: 86400,
            max_alerts_per_hour: 30,
            rate_limit_bypass_min_severity: Severity::High,
            quiet_hours_bypass_min_severity: Severity::High,
            quiet_hours: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ActiveResponseConfig {
    pub enabled: bool,
    pub strategy: String,
    pub firewall_backend: String,
    pub cleanup_legacy_port_guards: bool,
    pub block_ttl_seconds: u64,
    pub command_timeout_seconds: u64,
    pub max_blocks_per_scan: usize,
    pub notification_detail_limit: usize,
    pub permanent_block_enabled: bool,
    pub permanent_block_threshold: usize,
    pub permanent_block_window_seconds: u64,
    pub web_enabled: bool,
    pub web_probe_block_threshold: usize,
    pub web_exploit_block_threshold: usize,
    pub ssh_enabled: bool,
    pub ssh_failed_login_block_threshold: usize,
}

impl Default for ActiveResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strategy: "balanced".to_string(),
            firewall_backend: "auto".to_string(),
            cleanup_legacy_port_guards: true,
            block_ttl_seconds: 3600,
            command_timeout_seconds: 3,
            max_blocks_per_scan: 20,
            notification_detail_limit: 3,
            permanent_block_enabled: true,
            permanent_block_threshold: 3,
            permanent_block_window_seconds: 86_400,
            web_enabled: true,
            web_probe_block_threshold: 25,
            web_exploit_block_threshold: 5,
            ssh_enabled: true,
            ssh_failed_login_block_threshold: DEFAULT_SSH_FAILED_LOGIN_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AttackFingerprintConfig {
    pub enabled: bool,
    pub similarity_enabled: bool,
    pub similarity_hamming_distance: u32,
    pub max_match_candidates: usize,
    pub max_features_per_fingerprint: usize,
    pub max_observations_per_fingerprint: usize,
    pub retention_days: u32,
    pub active_response_enabled: bool,
    pub active_response_min_score: u16,
    pub active_response_min_observations: usize,
    pub active_response_min_distinct_ips: usize,
}

impl Default for AttackFingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            similarity_enabled: true,
            similarity_hamming_distance: 6,
            max_match_candidates: 1000,
            max_features_per_fingerprint: 40,
            max_observations_per_fingerprint: 200,
            retention_days: 30,
            active_response_enabled: true,
            active_response_min_score: 75,
            active_response_min_observations: 2,
            active_response_min_distinct_ips: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponsePolicyConfig {
    pub enabled: bool,
    pub policies: BTreeMap<String, ResponsePolicyRule>,
}

impl Default for ResponsePolicyConfig {
    fn default() -> Self {
        let mut policies = BTreeMap::new();
        policies.insert(
            "ssh_bruteforce".to_string(),
            ResponsePolicyRule {
                enabled: true,
                rule_ids: vec!["SSH-003".to_string(), "SSH-007".to_string()],
                categories: Vec::new(),
                action: "block".to_string(),
                min_severity: Severity::High,
                min_confidence: 70,
                min_unified_score: 70,
                ttl_seconds: None,
                permanent_after: None,
            },
        );
        policies.insert(
            "web_attack".to_string(),
            ResponsePolicyRule {
                enabled: true,
                rule_ids: vec!["WEB-001".to_string(), "WEB-002".to_string()],
                categories: Vec::new(),
                action: "block".to_string(),
                min_severity: Severity::Low,
                min_confidence: 35,
                min_unified_score: 30,
                ttl_seconds: None,
                permanent_after: None,
            },
        );
        Self {
            enabled: true,
            policies,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponsePolicyRule {
    pub enabled: bool,
    pub rule_ids: Vec<String>,
    pub categories: Vec<String>,
    pub action: String,
    pub min_severity: Severity,
    pub min_confidence: u16,
    pub min_unified_score: u16,
    pub ttl_seconds: Option<u64>,
    pub permanent_after: Option<usize>,
}

impl Default for ResponsePolicyRule {
    fn default() -> Self {
        Self {
            enabled: true,
            rule_ids: Vec::new(),
            categories: Vec::new(),
            action: "observe".to_string(),
            min_severity: Severity::High,
            min_confidence: 70,
            min_unified_score: 70,
            ttl_seconds: None,
            permanent_after: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IncidentConfig {
    pub enabled: bool,
    pub correlation_window_seconds: u64,
    pub max_findings_per_incident: usize,
}

impl Default for IncidentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            correlation_window_seconds: 900,
            max_findings_per_incident: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceProfileConfig {
    pub enabled: bool,
    pub drift_requires_public_exposure: bool,
    pub baseline_refresh_after_package_activity: bool,
    pub dynamic_udp_enabled: bool,
    pub dynamic_udp_min_port: u16,
    pub dynamic_udp_max_port_samples: usize,
    pub unknown_owner_grace_observations: u32,
    pub ignored_dynamic_udp_process_names: Vec<String>,
    pub ignore_loopback_ssh_forwarding: bool,
}

pub const DEFAULT_DYNAMIC_UDP_MIN_PORT: u16 = 1024;

impl Default for ServiceProfileConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            drift_requires_public_exposure: false,
            baseline_refresh_after_package_activity: false,
            dynamic_udp_enabled: true,
            dynamic_udp_min_port: DEFAULT_DYNAMIC_UDP_MIN_PORT,
            dynamic_udp_max_port_samples: 32,
            unknown_owner_grace_observations: 3,
            ignored_dynamic_udp_process_names: default_ignored_dynamic_udp_process_names(),
            ignore_loopback_ssh_forwarding: true,
        }
    }
}

fn default_ignored_dynamic_udp_process_names() -> Vec<String> {
    ["systemd-timesyncd", "chronyd", "ntpd"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviorProfileConfig {
    pub enabled: bool,
    pub min_observations_before_drift: u32,
    pub max_process_identities: usize,
    pub max_remote_ports_per_identity: usize,
    pub max_executable_samples_per_identity: usize,
    pub max_age_days: u32,
    pub public_fanout_multiplier: usize,
    pub public_fanout_min_delta: usize,
}

impl Default for BehaviorProfileConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_observations_before_drift: 3,
            max_process_identities: 512,
            max_remote_ports_per_identity: 32,
            max_executable_samples_per_identity: 8,
            max_age_days: 30,
            public_fanout_multiplier: 3,
            public_fanout_min_delta: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportsConfig {
    pub scheduled_enabled: bool,
    pub scheduled_hour: u8,
    pub scheduled_period: String,
    pub min_interval_seconds: u64,
}

impl Default for ReportsConfig {
    fn default() -> Self {
        Self {
            scheduled_enabled: true,
            scheduled_hour: 8,
            scheduled_period: "today".to_string(),
            min_interval_seconds: 82_800,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedCollectorsConfig {
    pub auditd_enabled: bool,
    pub audit_log_paths: Vec<PathBuf>,
    pub audit_max_tail_bytes: u64,
    pub ebpf_bridge_enabled: bool,
    pub ebpf_event_paths: Vec<PathBuf>,
    pub ebpf_command: Vec<String>,
    pub ebpf_runtime_probe_enabled: bool,
    pub ebpf_runtime_probe_output_path: PathBuf,
    pub ebpf_runtime_probe_command: String,
    pub ebpf_runtime_probe_capture_files: bool,
    pub command_timeout_seconds: u64,
}

impl Default for AdvancedCollectorsConfig {
    fn default() -> Self {
        Self {
            auditd_enabled: true,
            audit_log_paths: vec![PathBuf::from("/var/log/audit/audit.log")],
            audit_max_tail_bytes: 1024 * 1024,
            ebpf_bridge_enabled: true,
            ebpf_event_paths: vec![PathBuf::from("/var/lib/vps-sentinel/ebpf-runtime.jsonl")],
            ebpf_command: Vec::new(),
            ebpf_runtime_probe_enabled: false,
            ebpf_runtime_probe_output_path: PathBuf::from(
                "/var/lib/vps-sentinel/ebpf-runtime.jsonl",
            ),
            ebpf_runtime_probe_command: "bpftrace".to_string(),
            ebpf_runtime_probe_capture_files: false,
            command_timeout_seconds: 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExternalRulesConfig {
    pub enabled: bool,
    pub sigma_paths: Vec<PathBuf>,
    pub yara_enabled: bool,
    pub yara_paths: Vec<PathBuf>,
    pub yara_scan_roots: Vec<PathBuf>,
    pub yara_command: String,
    pub command_timeout_seconds: u64,
    pub max_file_size_mb: u64,
}

impl Default for ExternalRulesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sigma_paths: Vec::new(),
            yara_enabled: true,
            yara_paths: Vec::new(),
            yara_scan_roots: Vec::new(),
            yara_command: "yara".to_string(),
            command_timeout_seconds: 10,
            max_file_size_mb: 16,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub indicator_paths: Vec<PathBuf>,
    pub url: String,
    pub api_key_env: String,
    pub request_timeout_seconds: u64,
    pub cache_ttl_seconds: u64,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            indicator_paths: Vec::new(),
            url: String::new(),
            api_key_env: String::new(),
            request_timeout_seconds: 5,
            cache_ttl_seconds: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FleetConfig {
    pub enabled: bool,
    pub node_name: String,
    pub export_path: PathBuf,
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            node_name: String::new(),
            export_path: PathBuf::from("/var/lib/vps-sentinel/fleet-node.json"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PanelConfig {
    pub enabled: bool,
    pub url: String,
    pub node_id: String,
    pub node_name: String,
    pub location: PanelLocationConfig,
    pub secret: String,
    pub min_severity: Severity,
    pub batch_size: usize,
    pub push_interval_seconds: u64,
    pub request_timeout_seconds: u64,
    pub outbox_max_items: usize,
    pub max_payload_bytes: usize,
    pub privacy_mode: String,
    pub ip_intel_paths: Vec<PathBuf>,
    pub ip_intel_max_entries: usize,
    pub ip_intel_remote_enabled: bool,
    pub ip_intel_remote_endpoint: String,
    pub ip_intel_remote_timeout_ms: u64,
    pub ip_intel_remote_max_lookups: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PanelLocationConfig {
    pub country_code: String,
    pub country: String,
    pub region: String,
    pub city: String,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            node_id: String::new(),
            node_name: String::new(),
            location: PanelLocationConfig::default(),
            secret: String::new(),
            min_severity: Severity::Medium,
            batch_size: 100,
            push_interval_seconds: 60,
            request_timeout_seconds: 60,
            outbox_max_items: 128,
            max_payload_bytes: 512 * 1024,
            privacy_mode: "strict".to_string(),
            ip_intel_paths: Vec::new(),
            ip_intel_max_entries: 20_000,
            ip_intel_remote_enabled: true,
            ip_intel_remote_endpoint: "whois.cymru.com:43".to_string(),
            ip_intel_remote_timeout_ms: 1200,
            ip_intel_remote_max_lookups: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MaintenanceConfig {
    pub enabled: bool,
    pub suppress_baseline_drift: bool,
    pub suppress_interactive_logins: bool,
    pub max_duration_seconds: u64,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            suppress_baseline_drift: true,
            suppress_interactive_logins: true,
            max_duration_seconds: 7200,
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
