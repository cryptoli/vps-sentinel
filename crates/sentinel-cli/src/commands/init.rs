use anyhow::{bail, Result};
use sentinel_core::SentinelConfig;
use std::fs;
use std::path::PathBuf;

pub fn run_init(path: Option<PathBuf>, force: bool) -> Result<()> {
    let path = path.unwrap_or_else(|| PathBuf::from("config.toml"));
    if path.exists() && !force {
        bail!(
            "configuration already exists at {}; pass --force to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&path, SentinelConfig::default_toml()?)?;
    println!("created configuration at {}", path.display());
    Ok(())
}
