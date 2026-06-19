use anyhow::{bail, Result};
use clap::Subcommand;
use sentinel_core::SentinelConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const DEPRECATED_KEYS: &[&str] = &[
    "agent.full_scan_interval_seconds",
    "process.scan_interval_seconds",
    "network.scan_interval_seconds",
];
const LEGACY_DEFAULT_LANGUAGE_KEY: &str = "notifications.language";
const LEGACY_SSH_RESPONSE_POLICY_KEY: &str = "response_policy.policies.ssh_bruteforce.rule_ids";

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    Validate,
    PrintDefault,
    DiffDefault,
    Migrate {
        #[arg(long)]
        dry_run: bool,
    },
    SyncDefaults {
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
        ConfigCommand::SyncDefaults { dry_run } => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            sync_config_defaults(&path, dry_run)?;
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
    let legacy_default_language = contains_legacy_default_language(&text);
    let legacy_ssh_response_policy = contains_legacy_ssh_response_policy(&text);
    if deprecated.is_empty() && !legacy_default_language && !legacy_ssh_response_policy {
        println!(
            "configuration does not require migration: {}",
            path.display()
        );
        return Ok(());
    }
    let migrated = migrate_legacy_ssh_response_policy(&migrate_legacy_default_language(
        &remove_deprecated_keys(&text),
    ));
    let _: SentinelConfig = toml::from_str(&migrated)?;
    if dry_run {
        if !deprecated.is_empty() {
            println!("deprecated keys that would be removed:");
        }
        for key in deprecated {
            println!("- {key}");
        }
        if legacy_default_language {
            println!("legacy defaults that would be updated:");
            println!("- {LEGACY_DEFAULT_LANGUAGE_KEY}: en -> zh_cn");
        }
        if legacy_ssh_response_policy {
            println!("legacy defaults that would be updated:");
            println!("- {LEGACY_SSH_RESPONSE_POLICY_KEY}: [SSH-003] -> [SSH-003, SSH-007]");
        }
        return Ok(());
    }
    let backup = write_config_backup(path, &text)?;
    fs::write(path, migrated)?;
    SentinelConfig::load(path)?;
    println!("configuration migrated: {}", path.display());
    println!("backup written: {}", backup.display());
    Ok(())
}

fn sync_config_defaults(path: &Path, dry_run: bool) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let missing = missing_default_entries(&text)?;
    if missing.is_empty() {
        println!(
            "configuration already contains all default keys: {}",
            path.display()
        );
        return Ok(());
    }

    let updated = insert_missing_default_keys(&text, &missing)?;
    let config: SentinelConfig = toml::from_str(&updated)?;
    config.validate()?;

    if dry_run {
        println!("default keys that would be added:");
        for entry in missing {
            println!("- {}", entry.path);
        }
        return Ok(());
    }

    let backup = write_config_backup(path, &text)?;
    fs::write(path, updated)?;
    SentinelConfig::load(path)?;
    println!("configuration defaults synchronized: {}", path.display());
    println!("backup written: {}", backup.display());
    Ok(())
}

fn deprecated_keys_in_file(path: &Path) -> Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    Ok(deprecated_keys_in_text(&text))
}

fn write_config_backup(path: &Path, text: &str) -> Result<PathBuf> {
    let backup = next_backup_path(path);
    fs::write(&backup, text)?;
    Ok(backup)
}

fn next_backup_path(path: &Path) -> PathBuf {
    let extension = path.extension().and_then(|value| value.to_str());
    let backup_extension = extension
        .map(|value| format!("{value}.bak"))
        .unwrap_or_else(|| "bak".to_string());
    let first = path.with_extension(&backup_extension);
    if !first.exists() {
        return first;
    }
    for index in 1.. {
        let candidate = path.with_extension(format!("{backup_extension}.{index}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("unbounded backup path search should always find a candidate")
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
        if let Some(next_section) = parse_toml_section_header(line) {
            section = next_section;
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

fn contains_legacy_default_language(text: &str) -> bool {
    let mut section = String::new();
    text.lines().any(|line| {
        if let Some(next_section) = parse_toml_section_header(line) {
            section = next_section;
            return false;
        }
        section == "notifications" && is_legacy_default_language_line(line)
    })
}

fn migrate_legacy_default_language(text: &str) -> String {
    let mut section = String::new();
    let mut output = Vec::new();
    for line in text.lines() {
        if let Some(next_section) = parse_toml_section_header(line) {
            section = next_section;
            output.push(line.to_string());
            continue;
        }
        if section == "notifications" && is_legacy_default_language_line(line) {
            output.push("language = \"zh_cn\" # zh_cn or en".to_string());
            continue;
        }
        output.push(line.to_string());
    }
    let mut migrated = output.join("\n");
    migrated.push('\n');
    migrated
}

fn is_legacy_default_language_line(line: &str) -> bool {
    let trimmed = line.trim();
    let Some((key, tail)) = trimmed.split_once('=') else {
        return false;
    };
    let Some((value, comment)) = tail.split_once('#') else {
        return false;
    };
    key.trim() == "language"
        && value.trim() == "\"en\""
        && comment.to_ascii_lowercase().contains("en or zh_cn")
}

fn contains_legacy_ssh_response_policy(text: &str) -> bool {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return false;
    };
    let Some(rule_ids) =
        toml_value_at_path(&value, LEGACY_SSH_RESPONSE_POLICY_KEY).and_then(toml::Value::as_array)
    else {
        return false;
    };
    rule_ids.len() == 1 && rule_ids[0].as_str() == Some("SSH-003")
}

fn migrate_legacy_ssh_response_policy(text: &str) -> String {
    let mut section = String::new();
    let mut output = Vec::new();
    for line in text.lines() {
        if let Some(next_section) = parse_toml_section_header(line) {
            section = next_section;
            output.push(line.to_string());
            continue;
        }
        if section == "response_policy.policies.ssh_bruteforce"
            && is_legacy_ssh_response_policy_rule_ids_line(line)
        {
            let indent = line
                .chars()
                .take_while(|ch| ch.is_whitespace())
                .collect::<String>();
            let comment = line
                .split_once('#')
                .map(|(_, comment)| format!(" #{}", comment))
                .unwrap_or_default();
            output.push(format!(
                "{indent}rule_ids = [\"SSH-003\", \"SSH-007\"]{comment}"
            ));
            continue;
        }
        output.push(line.to_string());
    }
    let mut migrated = output.join("\n");
    migrated.push('\n');
    migrated
}

fn is_legacy_ssh_response_policy_rule_ids_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return false;
    }
    let Some((key, tail)) = trimmed.split_once('=') else {
        return false;
    };
    if key.trim() != "rule_ids" {
        return false;
    }
    let value = tail
        .split_once('#')
        .map(|(value, _)| value)
        .unwrap_or(tail)
        .trim()
        .replace(char::is_whitespace, "");
    value == "[\"SSH-003\"]"
}

#[derive(Debug, Clone)]
struct MissingDefaultEntry {
    path: String,
    section: String,
    key: String,
    value: toml::Value,
}

fn missing_default_entries(text: &str) -> Result<Vec<MissingDefaultEntry>> {
    let default_text = SentinelConfig::default_toml()?;
    let current_value: toml::Value = toml::from_str(text)?;
    let default_value: toml::Value = toml::from_str(&default_text)?;
    let mut current_keys = BTreeSet::new();
    let mut default_keys = BTreeSet::new();

    flatten_value("", &current_value, &mut current_keys);
    flatten_value("", &default_value, &mut default_keys);

    let mut entries = Vec::new();
    for path in default_keys.difference(&current_keys) {
        let Some(value) = toml_value_at_path(&default_value, path).cloned() else {
            continue;
        };
        let (section, key) = path
            .rsplit_once('.')
            .map(|(section, key)| (section.to_string(), key.to_string()))
            .unwrap_or_else(|| (String::new(), path.to_string()));
        entries.push(MissingDefaultEntry {
            path: path.to_string(),
            section,
            key,
            value,
        });
    }
    Ok(entries)
}

fn insert_missing_default_keys(text: &str, missing: &[MissingDefaultEntry]) -> Result<String> {
    let mut groups: BTreeMap<String, Vec<&MissingDefaultEntry>> = BTreeMap::new();
    for entry in missing {
        groups.entry(entry.section.clone()).or_default().push(entry);
    }

    let mut output = Vec::new();
    let mut emitted = BTreeSet::new();
    let mut current_section = String::new();

    for line in text.lines() {
        if let Some(next_section) = parse_toml_section_header(line) {
            emit_missing_for_section(&mut output, &groups, &mut emitted, &current_section)?;
            current_section = next_section;
        }
        output.push(line.to_string());
    }
    emit_missing_for_section(&mut output, &groups, &mut emitted, &current_section)?;

    for (section, entries) in &groups {
        if emitted.contains(section) {
            continue;
        }
        ensure_blank_separator(&mut output);
        push_sync_defaults_header(&mut output);
        if !section.is_empty() {
            output.push(format!("[{section}]"));
        }
        push_default_entry_lines(&mut output, entries)?;
        emitted.insert(section.clone());
    }

    let mut updated = output.join("\n");
    updated.push('\n');
    Ok(updated)
}

fn emit_missing_for_section(
    output: &mut Vec<String>,
    groups: &BTreeMap<String, Vec<&MissingDefaultEntry>>,
    emitted: &mut BTreeSet<String>,
    section: &str,
) -> Result<()> {
    let Some(entries) = groups.get(section) else {
        return Ok(());
    };
    if emitted.contains(section) {
        return Ok(());
    }
    ensure_blank_separator(output);
    push_sync_defaults_header(output);
    push_default_entry_lines(output, entries)?;
    emitted.insert(section.to_string());
    Ok(())
}

fn ensure_blank_separator(output: &mut Vec<String>) {
    if !output.last().map_or(true, |line| line.trim().is_empty()) {
        output.push(String::new());
    }
}

fn push_sync_defaults_header(output: &mut Vec<String>) {
    output.push("# Added by vps-sentinel config sync-defaults.".to_string());
    output.push(
        "# Existing values are preserved; only missing default keys are appended.".to_string(),
    );
}

fn push_default_entry_lines(
    output: &mut Vec<String>,
    entries: &[&MissingDefaultEntry],
) -> Result<()> {
    for entry in entries {
        output.push(format!(
            "{} = {}",
            entry.key,
            format_toml_value(&entry.value)?
        ));
    }
    Ok(())
}

fn format_toml_value(value: &toml::Value) -> Result<String> {
    let mut table = toml::map::Map::new();
    table.insert("value".to_string(), value.clone());
    let rendered = toml::to_string(&toml::Value::Table(table))?;
    let Some(line) = rendered.lines().next() else {
        bail!("failed to render TOML value");
    };
    let Some((_, value_text)) = line.split_once('=') else {
        bail!("failed to render TOML value");
    };
    Ok(value_text.trim().to_string())
}

fn toml_value_at_path<'a>(value: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_table()?.get(segment)?;
    }
    Some(current)
}

fn parse_toml_section_header(line: &str) -> Option<String> {
    let trimmed = line.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with("[[") || !trimmed.starts_with('[') {
        return None;
    }
    let end = trimmed.find(']')?;
    let trailing = trimmed[end + 1..].trim();
    if !trailing.is_empty() && !trailing.starts_with('#') {
        return None;
    }
    let section = trimmed[1..end].trim();
    if section.is_empty() {
        return None;
    }
    Some(section.to_string())
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
    use super::{
        contains_legacy_default_language, contains_legacy_ssh_response_policy,
        deprecated_keys_in_text, flatten_toml_keys, insert_missing_default_keys,
        migrate_legacy_default_language, migrate_legacy_ssh_response_policy,
        missing_default_entries, next_backup_path, remove_deprecated_keys,
    };
    use sentinel_core::SentinelConfig;
    use std::fs;

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
    fn migrates_legacy_default_notification_language() {
        let text = "[notifications]\nlanguage = \"en\" # en or zh_cn\n";

        assert!(contains_legacy_default_language(text));
        let migrated = migrate_legacy_default_language(text);

        assert!(migrated.contains("language = \"zh_cn\" # zh_cn or en"));
    }

    #[test]
    fn preserves_explicit_english_notification_language() {
        let text = "[notifications]\nlanguage = \"en\"\n";

        assert!(!contains_legacy_default_language(text));
        assert_eq!(migrate_legacy_default_language(text), text);
    }

    #[test]
    fn migrates_legacy_ssh_response_policy_rule_ids() {
        let text = "[response_policy.policies.ssh_bruteforce]\nrule_ids = [\"SSH-003\"] # legacy default\n";

        assert!(contains_legacy_ssh_response_policy(text));
        let migrated = migrate_legacy_ssh_response_policy(text);

        assert!(migrated.contains("rule_ids = [\"SSH-003\", \"SSH-007\"] # legacy default"));
    }

    #[test]
    fn preserves_custom_ssh_response_policy_rule_ids() {
        let text =
            "[response_policy.policies.ssh_bruteforce]\nrule_ids = [\"SSH-003\", \"CUSTOM-001\"]\n";

        assert!(!contains_legacy_ssh_response_policy(text));
        assert_eq!(migrate_legacy_ssh_response_policy(text), text);
    }

    #[test]
    fn flattens_toml_keys() {
        let keys = flatten_toml_keys("[a]\nb = 1\n[a.c]\nd = true\n").unwrap();
        assert!(keys.contains("a.b"));
        assert!(keys.contains("a.c.d"));
    }

    #[test]
    fn sync_defaults_adds_missing_keys_without_overwriting_existing_values() {
        let text = "[agent]\nscan_interval_seconds = 120\n\n[notifications]\nlanguage = \"en\"\n";
        let missing = missing_default_entries(text).unwrap();
        assert!(missing
            .iter()
            .any(|entry| entry.path == "active_response.enabled"));
        let synced = insert_missing_default_keys(text, &missing).unwrap();
        assert!(synced.contains("scan_interval_seconds = 120"));
        assert!(synced.contains("language = \"en\""));
        assert!(synced.contains("[active_response]"));
        assert!(synced.contains("enabled = true"));

        let config: SentinelConfig = toml::from_str(&synced).unwrap();
        config.validate().unwrap();
        assert_eq!(config.agent.scan_interval_seconds, 120);
    }

    #[test]
    fn sync_defaults_is_noop_for_full_default_config() {
        let text = SentinelConfig::default_toml().unwrap();
        let missing = missing_default_entries(&text).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn sync_defaults_handles_utf8_bom_without_duplicate_sections() {
        let text =
            "\u{feff}[agent]\nscan_interval_seconds = 120\n\n[notifications]\nlanguage = \"en\"\n";
        let missing = missing_default_entries(text).unwrap();
        let synced = insert_missing_default_keys(text, &missing).unwrap();
        let agent_headers = synced
            .lines()
            .filter(|line| line.trim_start_matches('\u{feff}').trim() == "[agent]")
            .count();

        assert_eq!(agent_headers, 1);
        let config: SentinelConfig = toml::from_str(&synced).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn backup_path_does_not_overwrite_existing_backups() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let first_backup = config_path.with_extension("toml.bak");
        fs::write(&first_backup, "existing").unwrap();

        let next = next_backup_path(&config_path);

        assert_eq!(next, config_path.with_extension("toml.bak.1"));
    }
}
