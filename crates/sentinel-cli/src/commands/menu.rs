use crate::commands::baseline::{run_baseline, BaselineCommand};
use crate::commands::blocks::{run_blocks, BlocksCommand};
use crate::commands::config::{
    add_allowlist_file_path, add_trusted_admin_ip, remove_allowlist_file_path,
    remove_trusted_admin_ip, resolve_config_path, run_config, ConfigCommand,
};
use crate::commands::reload::run_reload;
use anyhow::{bail, Result};
use sentinel_core::SentinelConfig;
use std::io::{self, Write};
use std::path::Path;

pub async fn run_menu(config_path: Option<&Path>) -> Result<()> {
    let Some(path) = resolve_config_path(config_path) else {
        bail!("no configuration file found; pass --config or create /etc/vps-sentinel/config.toml");
    };
    loop {
        print_menu(&path);
        let choice = prompt("Select")?;
        match choice.trim() {
            "1" => add_trusted_admin(&path)?,
            "2" => remove_trusted_admin(&path)?,
            "3" => add_allowlist_path(&path)?,
            "4" => remove_allowlist_path(&path)?,
            "5" => refresh_baseline(&path).await?,
            "6" => run_blocks(
                load_config(&path)?,
                BlocksCommand::List { no_verify: false },
            )?,
            "7" => unblock_ip(&path)?,
            "8" => run_config(Some(&path), ConfigCommand::Validate)?,
            "9" => run_reload(Some(path.clone()), "vps-sentinel")?,
            "0" | "q" | "quit" | "exit" => return Ok(()),
            _ => println!("unknown selection: {}", choice.trim()),
        }
    }
}

fn print_menu(path: &Path) {
    println!();
    println!("vps-sentinel operations menu");
    println!("config={}", path.display());
    println!("1. Add trusted admin IP");
    println!("2. Remove trusted admin IP");
    println!("3. Add allowlist file path");
    println!("4. Remove allowlist file path");
    println!("5. Refresh baseline");
    println!("6. List active blocks");
    println!("7. Unblock IP");
    println!("8. Validate config");
    println!("9. Reload service");
    println!("0. Exit");
}

fn add_trusted_admin(path: &Path) -> Result<()> {
    let ip = prompt_non_empty("Trusted admin IP or CIDR")?;
    add_trusted_admin_ip(path, &ip)
}

fn remove_trusted_admin(path: &Path) -> Result<()> {
    let ip = prompt_non_empty("Trusted admin IP or CIDR")?;
    remove_trusted_admin_ip(path, &ip)
}

fn add_allowlist_path(path: &Path) -> Result<()> {
    let value = prompt_non_empty("Allowlist file path or glob")?;
    add_allowlist_file_path(path, &value)
}

fn remove_allowlist_path(path: &Path) -> Result<()> {
    let value = prompt_non_empty("Allowlist file path or glob")?;
    remove_allowlist_file_path(path, &value)
}

async fn refresh_baseline(path: &Path) -> Result<()> {
    let all = prompt_yes_no("Refresh with all current host facts?")?;
    run_baseline(load_config(path)?, BaselineCommand::Refresh { all }).await
}

fn unblock_ip(path: &Path) -> Result<()> {
    let ip = prompt_non_empty("IP to unblock")?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IP address"))?;
    run_blocks(load_config(path)?, BlocksCommand::Unblock { ip })
}

fn load_config(path: &Path) -> Result<SentinelConfig> {
    Ok(SentinelConfig::load(path)?)
}

fn prompt_non_empty(label: &str) -> Result<String> {
    let value = prompt(label)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} must not be empty");
    }
    Ok(trimmed.to_string())
}

fn prompt_yes_no(label: &str) -> Result<bool> {
    let value = prompt(&format!("{label} [y/N]"))?;
    Ok(prompt_yes_no_value(&value))
}

fn prompt_yes_no_value(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::prompt_yes_no_value;

    #[test]
    fn yes_no_parser_defaults_to_false() {
        assert!(prompt_yes_no_value("yes"));
        assert!(prompt_yes_no_value("Y"));
        assert!(!prompt_yes_no_value(""));
        assert!(!prompt_yes_no_value("no"));
    }
}
