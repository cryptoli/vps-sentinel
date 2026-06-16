use anyhow::Result;
use sentinel_core::SentinelConfig;
use std::fs;

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

    if !running_as_root() {
        println!("warning: some modules need root permissions for full visibility");
    }
    Ok(())
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
