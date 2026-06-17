use anyhow::{bail, Result};
use sentinel_agent::utils::command::command_output;
use sentinel_core::SentinelConfig;
use std::path::PathBuf;
use std::time::Duration;

const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(10);

pub fn run_reload(config_path: Option<PathBuf>, service_name: &str) -> Result<()> {
    let Some(config_path) = config_path else {
        bail!(
            "reload requires a config file; pass --config or create /etc/vps-sentinel/config.toml"
        );
    };
    let config = SentinelConfig::load(&config_path)?;
    config.validate()?;
    println!("configuration is valid: {}", config_path.display());

    if !systemd_service_exists(service_name) {
        println!("systemd service not found; configuration is valid");
        return Ok(());
    }
    if !systemd_service_is_active(service_name) {
        println!("{service_name} is not active; configuration is valid");
        return Ok(());
    }

    let Some(output) = command_output("systemctl", &["reload", service_name], SYSTEMCTL_TIMEOUT)
    else {
        bail!("systemctl reload timed out or could not be executed");
    };
    if !output.status_success {
        bail!("systemctl reload failed for {service_name}");
    }
    println!("reloaded {service_name} with {}", config_path.display());
    Ok(())
}

fn systemd_service_exists(service_name: &str) -> bool {
    systemctl_success(&["cat", service_name])
}

fn systemd_service_is_active(service_name: &str) -> bool {
    systemctl_success(&["is-active", service_name])
}

fn systemctl_success(args: &[&str]) -> bool {
    command_output("systemctl", args, SYSTEMCTL_TIMEOUT)
        .map(|output| output.status_success)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::run_reload;

    #[test]
    fn reload_requires_config_path() {
        assert!(run_reload(None, "vps-sentinel").is_err());
    }
}
