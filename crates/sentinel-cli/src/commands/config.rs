use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_core::SentinelConfig;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEPRECATED_KEYS: &[&str] = &[
    "agent.full_scan_interval_seconds",
    "process.scan_interval_seconds",
    "network.scan_interval_seconds",
];

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate,
    PrintDefault,
    DiffDefault,
    Migrate {
        #[arg(long)]
        dry_run: bool,
    },
}

pub fn run_config(path: Option<&Path>, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Validate => {
            if let Some(path) = resolve_config_path(path) {
                print_deprecated_warnings(&path)?;
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
        ConfigCommand::DiffDefault => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            print_config_diff(&path)?;
        }
        ConfigCommand::Migrate { dry_run } => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            migrate_config(&path, dry_run)?;
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

fn print_deprecated_warnings(path: &Path) -> Result<()> {
    for key in deprecated_keys_in_file(path)? {
        eprintln!("warning: deprecated config key ignored: {key}");
    }
    Ok(())
}

fn print_config_diff(path: &Path) -> Result<()> {
    let current_text = fs::read_to_string(path)?;
    let default_text = SentinelConfig::default_toml()?;
    let current_keys = flatten_toml_keys(&current_text)?;
    let default_keys = flatten_toml_keys(&default_text)?;
    let deprecated = deprecated_keys_in_text(&current_text);

    let missing = default_keys
        .difference(&current_keys)
        .cloned()
        .collect::<Vec<_>>();
    let unknown = current_keys
        .difference(&default_keys)
        .filter(|key| !DEPRECATED_KEYS.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();

    println!("config diff against defaults: {}", path.display());
    print_key_list("missing_default_keys", &missing);
    print_key_list("unknown_keys", &unknown);
    print_key_list(
        "deprecated_keys",
        &deprecated.into_iter().collect::<Vec<_>>(),
    );
    Ok(())
}

fn print_key_list(label: &str, keys: &[String]) {
    if keys.is_empty() {
        println!("{label}: none");
        return;
    }
    println!("{label}:");
    for key in keys {
        println!("- {key}");
    }
}

fn migrate_config(path: &Path, dry_run: bool) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let deprecated = deprecated_keys_in_text(&text);
    if deprecated.is_empty() {
        println!(
            "configuration does not contain deprecated keys: {}",
            path.display()
        );
        return Ok(());
    }
    let migrated = remove_deprecated_keys(&text);
    let _: SentinelConfig = toml::from_str(&migrated)?;
    if dry_run {
        println!("deprecated keys that would be removed:");
        for key in deprecated {
            println!("- {key}");
        }
        return Ok(());
    }
    let backup = path.with_extension("toml.bak");
    fs::write(&backup, text)?;
    fs::write(path, migrated)?;
    SentinelConfig::load(path)?;
    println!("configuration migrated: {}", path.display());
    println!("backup written: {}", backup.display());
    Ok(())
}

fn deprecated_keys_in_file(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    Ok(deprecated_keys_in_text(&text))
}

fn deprecated_keys_in_text(text: &str) -> Vec<String> {
    let keys = flatten_toml_keys(text).unwrap_or_default();
    DEPRECATED_KEYS
        .iter()
        .filter(|key| keys.contains(**key))
        .map(|key| (*key).to_string())
        .collect()
}

fn remove_deprecated_keys(text: &str) -> String {
    let mut section = String::new();
    let mut output = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.starts_with("[[") {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_string();
            output.push(line.to_string());
            continue;
        }
        let key = trimmed
            .split_once('=')
            .map(|(key, _)| key.trim())
            .filter(|key| !key.is_empty() && !key.starts_with('#'));
        if let Some(key) = key {
            let full = if section.is_empty() {
                key.to_string()
            } else {
                format!("{section}.{key}")
            };
            if DEPRECATED_KEYS.contains(&full.as_str()) {
                continue;
            }
        }
        output.push(line.to_string());
    }
    let mut migrated = output.join("\n");
    migrated.push('\n');
    migrated
}

fn flatten_toml_keys(text: &str) -> Result<BTreeSet<String>> {
    let value: toml::Value = toml::from_str(text)?;
    let mut keys = BTreeSet::new();
    flatten_value("", &value, &mut keys);
    Ok(keys)
}

fn flatten_value(prefix: &str, value: &toml::Value, keys: &mut BTreeSet<String>) {
    if let Some(table) = value.as_table() {
        for (key, value) in table {
            let next = if prefix.is_empty() {
                key.to_string()
            } else {
                format!("{prefix}.{key}")
            };
            flatten_value(&next, value, keys);
        }
    } else if !prefix.is_empty() {
        keys.insert(prefix.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{deprecated_keys_in_text, flatten_toml_keys, remove_deprecated_keys};

    #[test]
    fn detects_and_removes_deprecated_keys() {
        let text = "[agent]\nfull_scan_interval_seconds = 3600\nscan_interval_seconds = 60\n[process]\nscan_interval_seconds = 30\n";
        let deprecated = deprecated_keys_in_text(text);
        assert_eq!(
            deprecated,
            vec![
                "agent.full_scan_interval_seconds".to_string(),
                "process.scan_interval_seconds".to_string()
            ]
        );
        let migrated = remove_deprecated_keys(text);
        assert!(!migrated.contains("full_scan_interval_seconds"));
        assert!(!migrated.contains("process]\nscan_interval_seconds"));
        assert!(migrated.contains("scan_interval_seconds = 60"));
    }

    #[test]
    fn flattens_toml_keys() {
        let keys = flatten_toml_keys("[a]\nb = 1\n[a.c]\nd = true\n").unwrap();
        assert!(keys.contains("a.b"));
        assert!(keys.contains("a.c.d"));
    }
}
