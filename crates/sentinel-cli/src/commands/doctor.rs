use anyhow::Result;
use sentinel_agent::utils::command::command_output;
use sentinel_core::SentinelConfig;
use std::fs;
use std::path::Path;
use std::time::Duration;

const JOURNALCTL_DOCTOR_TIMEOUT: Duration = Duration::from_secs(3);

pub fn run_doctor(config: SentinelConfig) -> Result<()> {
    println!("vps-sentinel doctor");
    println!("host_id: {}", config.host_id());
    println!("storage: {}", config.storage.path.display());
    println!("running_as_root: {}", running_as_root());
    println!("target_family_unix: {}", cfg!(unix));

    if let Some(parent) = config.storage.path.parent() {
        match fs::create_dir_all(parent) {
            Ok(()) => println!("storage_parent_writable: true"),
            Err(err) => println!("storage_parent_writable: false ({err})"),
        }
    }

    let readable_logs = config
        .ssh
        .auth_log_paths
        .iter()
        .filter(|path| path.exists())
        .count();
    println!("configured_auth_logs_existing: {readable_logs}");
    println!("journalctl_ssh_available: {}", journalctl_ssh_available());
    println!(
        "active_response_enabled: {}",
        config.active_response.enabled
    );
    println!(
        "active_response_ssh_enabled: {}",
        config.active_response.ssh_enabled
    );
    println!(
        "ssh_failed_login_alert_threshold: {}",
        config.ssh.failed_login_threshold
    );
    println!(
        "ssh_failed_login_block_threshold: {}",
        config.active_response.ssh_failed_login_block_threshold
    );
    if !config.active_response.enabled {
        println!("warning: active response is disabled; findings will not write firewall blocks");
    }
    if config.active_response.enabled {
        println!("nftables_available: {}", command_available("nft"));
        println!("iptables_available: {}", command_available("iptables"));
    }

    if !running_as_root() {
        println!("warning: some modules need root permissions for full visibility");
    }
    println!("capability_matrix:");
    for check in capability_checks(&config) {
        println!("{}", format_capability_line(&check));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityStatus {
    Ok,
    Degraded,
    Disabled,
    Missing,
}

impl CapabilityStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Disabled => "disabled",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapabilityCheck {
    name: &'static str,
    status: CapabilityStatus,
    detail: String,
    affects: &'static str,
}

fn capability_checks(config: &SentinelConfig) -> Vec<CapabilityCheck> {
    let root = running_as_root();
    let auth_logs = config
        .ssh
        .auth_log_paths
        .iter()
        .filter(|path| path.exists())
        .count();
    let package_managers = available_package_managers();
    vec![
        CapabilityCheck {
            name: "procfs",
            status: if Path::new("/proc").exists() {
                CapabilityStatus::Ok
            } else {
                CapabilityStatus::Missing
            },
            detail: "/proc process visibility".to_string(),
            affects: "process, network owner, cpu, container context",
        },
        CapabilityCheck {
            name: "root_visibility",
            status: if root {
                CapabilityStatus::Ok
            } else {
                CapabilityStatus::Degraded
            },
            detail: format!("running_as_root={root}"),
            affects: "process metadata, socket ownership, protected logs",
        },
        CapabilityCheck {
            name: "ssh_logs",
            status: if !config.ssh.enabled {
                CapabilityStatus::Disabled
            } else if auth_logs > 0 || journalctl_ssh_available() {
                CapabilityStatus::Ok
            } else {
                CapabilityStatus::Missing
            },
            detail: format!(
                "auth_log_files={auth_logs} journalctl={}",
                journalctl_ssh_available()
            ),
            affects: "ssh login and brute-force detection",
        },
        CapabilityCheck {
            name: "auditd",
            status: auditd_status(config),
            detail: auditd_detail(config),
            affects: "short-lived exec evidence",
        },
        CapabilityCheck {
            name: "ebpf_bridge",
            status: ebpf_status(config),
            detail: ebpf_detail(config),
            affects: "short-lived exec/connect/file events",
        },
        CapabilityCheck {
            name: "package_ownership",
            status: if package_managers.is_empty() {
                CapabilityStatus::Degraded
            } else {
                CapabilityStatus::Ok
            },
            detail: format!(
                "available={}",
                if package_managers.is_empty() {
                    "none".to_string()
                } else {
                    package_managers.join(",")
                }
            ),
            affects: "false-positive reduction for packaged files and processes",
        },
        CapabilityCheck {
            name: "systemd",
            status: if command_available("systemctl") || Path::new("/run/systemd/system").exists() {
                CapabilityStatus::Ok
            } else {
                CapabilityStatus::Degraded
            },
            detail: "systemd unit and ExecStart context".to_string(),
            affects: "service-profile and persistence drift evidence",
        },
        CapabilityCheck {
            name: "firewall_backend",
            status: firewall_status(config),
            detail: format!(
                "configured={} nft={} iptables={}",
                config.active_response.firewall_backend,
                command_available("nft"),
                command_available("iptables")
            ),
            affects: "active response IP blocking",
        },
        CapabilityCheck {
            name: "gpu",
            status: gpu_status(config),
            detail: format!(
                "nvidia_smi={} rocm_smi={}",
                command_available(&config.gpu.nvidia_smi_path),
                command_available(&config.gpu.rocm_smi_path)
            ),
            affects: "GPU mining and resource-abuse detection",
        },
        CapabilityCheck {
            name: "yara",
            status: if !config.external_rules.enabled || !config.external_rules.yara_enabled {
                CapabilityStatus::Disabled
            } else if command_available(&config.external_rules.yara_command) {
                CapabilityStatus::Ok
            } else {
                CapabilityStatus::Missing
            },
            detail: format!("command={}", config.external_rules.yara_command),
            affects: "external file signature scanning",
        },
    ]
}

fn format_capability_line(check: &CapabilityCheck) -> String {
    format!(
        "- {} status={} detail=\"{}\" affects=\"{}\"",
        check.name,
        check.status.as_str(),
        check.detail.replace('"', "'"),
        check.affects.replace('"', "'")
    )
}

fn auditd_status(config: &SentinelConfig) -> CapabilityStatus {
    if !config.advanced_collectors.auditd_enabled {
        return CapabilityStatus::Disabled;
    }
    if config
        .advanced_collectors
        .audit_log_paths
        .iter()
        .any(|path| path.exists())
    {
        CapabilityStatus::Ok
    } else {
        CapabilityStatus::Missing
    }
}

fn auditd_detail(config: &SentinelConfig) -> String {
    let existing = config
        .advanced_collectors
        .audit_log_paths
        .iter()
        .filter(|path| path.exists())
        .count();
    format!(
        "configured_paths={} existing={existing}",
        config.advanced_collectors.audit_log_paths.len()
    )
}

fn ebpf_status(config: &SentinelConfig) -> CapabilityStatus {
    if !config.advanced_collectors.ebpf_bridge_enabled {
        return CapabilityStatus::Disabled;
    }
    let has_file = config
        .advanced_collectors
        .ebpf_event_paths
        .iter()
        .any(|path| path.exists());
    let has_command = config
        .advanced_collectors
        .ebpf_command
        .first()
        .is_some_and(|program| command_available(program));
    if has_file || has_command {
        CapabilityStatus::Ok
    } else {
        CapabilityStatus::Degraded
    }
}

fn ebpf_detail(config: &SentinelConfig) -> String {
    format!(
        "event_paths={} command_configured={}",
        config.advanced_collectors.ebpf_event_paths.len(),
        !config.advanced_collectors.ebpf_command.is_empty()
    )
}

fn firewall_status(config: &SentinelConfig) -> CapabilityStatus {
    if !config.active_response.enabled {
        return CapabilityStatus::Disabled;
    }
    match config.active_response.firewall_backend.as_str() {
        "nftables" if command_available("nft") => CapabilityStatus::Ok,
        "iptables" if command_available("iptables") => CapabilityStatus::Ok,
        "auto" if command_available("nft") || command_available("iptables") => CapabilityStatus::Ok,
        _ => CapabilityStatus::Missing,
    }
}

fn gpu_status(config: &SentinelConfig) -> CapabilityStatus {
    if !config.gpu.enabled {
        return CapabilityStatus::Disabled;
    }
    if command_available(&config.gpu.nvidia_smi_path)
        || command_available(&config.gpu.rocm_smi_path)
    {
        CapabilityStatus::Ok
    } else {
        CapabilityStatus::Missing
    }
}

fn available_package_managers() -> Vec<&'static str> {
    [
        ("dpkg", "dpkg-query"),
        ("rpm", "rpm"),
        ("apk", "apk"),
        ("pacman", "pacman"),
    ]
    .into_iter()
    .filter_map(|(name, program)| command_available(program).then_some(name))
    .collect()
}

fn journalctl_ssh_available() -> bool {
    command_output(
        "journalctl",
        &[
            "-u",
            "ssh.service",
            "-u",
            "sshd.service",
            "-n",
            "1",
            "--no-pager",
        ],
        JOURNALCTL_DOCTOR_TIMEOUT,
    )
    .map(|output| output.status_success)
    .unwrap_or(false)
}

fn command_available(program: &str) -> bool {
    if program.trim().is_empty() {
        return false;
    }
    command_output(program, &["--version"], JOURNALCTL_DOCTOR_TIMEOUT)
        .map(|output| output.status_success)
        .unwrap_or(false)
}

fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("Uid:").and_then(|value| {
                        value
                            .split_whitespace()
                            .next()
                            .map(|effective_uid| effective_uid == "0")
                    })
                })
            })
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{format_capability_line, CapabilityCheck, CapabilityStatus};

    #[test]
    fn formats_capability_line_without_raw_quotes() {
        let line = format_capability_line(&CapabilityCheck {
            name: "gpu",
            status: CapabilityStatus::Degraded,
            detail: "nvidia=\"false\"".to_string(),
            affects: "gpu detection",
        });

        assert!(line.contains("gpu"));
        assert!(line.contains("status=degraded"));
        assert!(line.contains("nvidia='false'"));
    }
}
