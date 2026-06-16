use anyhow::Result;
use clap::Subcommand;
use sentinel_core::SentinelConfig;
use std::path::{Path, PathBuf};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate,
    PrintDefault,
}

pub fn run_config(path: Option<&Path>, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Validate => {
            if let Some(path) = resolve_config_path(path) {
                let config = SentinelConfig::load(&path)?;
                config.validate()?;
                println!("configuration is valid: {}", path.display());
            } else {
                let config = SentinelConfig::default();
                config.validate()?;
                println!("configuration is valid: built-in defaults");
            };
        }
        ConfigCommand::PrintDefault => {
            println!("{}", SentinelConfig::default_toml()?);
        }
    }
    Ok(())
}

fn resolve_config_path(path: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = path {
        return Some(path.to_path_buf());
    }
    let mut candidates = vec![PathBuf::from("config.toml")];
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".config/vps-sentinel/config.toml"));
    }
    candidates.push(PathBuf::from("/etc/vps-sentinel/config.toml"));
    candidates.into_iter().find(|candidate| candidate.exists())
}
