use anyhow::{bail, Result};
use clap::{Subcommand, ValueEnum};
use sentinel_core::{AllowlistConfig, SentinelConfig, DEFAULT_DYNAMIC_UDP_MIN_PORT};
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
const LEGACY_EMPTY_EBPF_EVENT_PATHS_KEY: &str = "advanced_collectors.ebpf_event_paths";
const LEGACY_SSH_FAILED_LOGIN_THRESHOLD: usize = 10;
const LEGACY_DYNAMIC_UDP_MIN_PORT: usize = 32768;
const SSH_FAILED_LOGIN_THRESHOLD_KEY: &str = "ssh.failed_login_threshold";
const ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD_KEY: &str =
    "active_response.ssh_failed_login_block_threshold";
const SERVICE_PROFILE_DYNAMIC_UDP_MIN_PORT_KEY: &str = "service_profile.dynamic_udp_min_port";

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
    Normalize {
        #[arg(long)]
        dry_run: bool,
    },
    Allowlist {
        #[command(subcommand)]
        command: AllowlistCommand,
    },
    TrustedAdmin {
        #[command(subcommand)]
        command: TrustedAdminCommand,
    },
    SuppressRule {
        #[command(subcommand)]
        command: SuppressRuleCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum AllowlistCommand {
    Add {
        field: AllowlistField,
        value: String,
    },
    Remove {
        field: AllowlistField,
        value: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AllowlistField {
    User,
    Ip,
    ProcessPath,
    ProcessCommand,
    ListeningPort,
    FilePath,
    WebPath,
}

#[derive(Debug, Subcommand)]
pub enum TrustedAdminCommand {
    Add { ip: String },
    Remove { ip: String },
}

#[derive(Debug, Subcommand)]
pub enum SuppressRuleCommand {
    Add { rule_id: String },
    Remove { rule_id: String },
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
        ConfigCommand::Normalize { dry_run } => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            normalize_config(&path, dry_run)?;
        }
        ConfigCommand::Allowlist { command } => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            update_allowlist(&path, command)?;
        }
        ConfigCommand::TrustedAdmin { command } => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            update_trusted_admin_ips(&path, command)?;
        }
        ConfigCommand::SuppressRule { command } => {
            let Some(path) = resolve_config_path(path) else {
                bail!("no configuration file found");
            };
            update_suppress_rule_ids(&path, command)?;
        }
    }
    Ok(())
}

pub(crate) fn resolve_config_path(path: Option<&Path>) -> Option<PathBuf> {
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
    let legacy_empty_ebpf_event_paths = contains_legacy_empty_ebpf_event_paths(&text);
    let legacy_dynamic_udp_min_port = contains_legacy_dynamic_udp_min_port(&text);
    let threshold_migration = legacy_ssh_threshold_migration(&text)?;
    let allowlist_needs_normalization = normalize_allowlist_section(&text)? != text;
    if deprecated.is_empty()
        && !legacy_default_language
        && !legacy_ssh_response_policy
        && !legacy_empty_ebpf_event_paths
        && !legacy_dynamic_udp_min_port
        && threshold_migration.changes.is_empty()
        && !allowlist_needs_normalization
    {
        println!(
            "configuration does not require migration: {}",
            path.display()
        );
        return Ok(());
    }
    let without_deprecated = remove_deprecated_keys(&text);
    let migrated_thresholds =
        migrate_legacy_ssh_thresholds(&without_deprecated, &threshold_migration)?;
    let migrated_ebpf = migrate_legacy_empty_ebpf_event_paths(&migrated_thresholds)?;
    let migrated_language = migrate_legacy_default_language(&migrated_ebpf);
    let migrated_policy = migrate_legacy_ssh_response_policy(&migrated_language);
    let migrated_udp = migrate_legacy_dynamic_udp_min_port(&migrated_policy)?;
    let migrated = normalize_allowlist_section(&migrated_udp)?;
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
        if legacy_empty_ebpf_event_paths {
            println!("legacy defaults that would be updated:");
            println!(
                "- {LEGACY_EMPTY_EBPF_EVENT_PATHS_KEY}: [] -> {}",
                default_ebpf_event_paths_text()?
            );
        }
        if legacy_dynamic_udp_min_port {
            println!("legacy defaults that would be updated:");
            println!(
                "- {SERVICE_PROFILE_DYNAMIC_UDP_MIN_PORT_KEY}: {LEGACY_DYNAMIC_UDP_MIN_PORT} -> {DEFAULT_DYNAMIC_UDP_MIN_PORT}"
            );
        }
        if !threshold_migration.changes.is_empty() {
            println!("legacy defaults that would be updated:");
            for change in threshold_migration.changes {
                println!("- {}: {} -> {}", change.path, change.old, change.new);
            }
        }
        if allowlist_needs_normalization {
            println!("sections that would be normalized:");
            println!("- allowlist");
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
    let threshold_migration = legacy_ssh_threshold_migration(&text)?;
    let normalized_thresholds = migrate_legacy_ssh_thresholds(&text, &threshold_migration)?;
    let legacy_empty_ebpf_event_paths =
        contains_legacy_empty_ebpf_event_paths(&normalized_thresholds);
    let normalized_paths = migrate_legacy_empty_ebpf_event_paths(&normalized_thresholds)?;
    let legacy_dynamic_udp_min_port = contains_legacy_dynamic_udp_min_port(&normalized_paths);
    let normalized = migrate_legacy_dynamic_udp_min_port(&normalized_paths)?;
    let missing = missing_default_entries(&normalized)?;
    let missing_inserted = insert_missing_default_keys(&normalized, &missing)?;
    let updated = normalize_allowlist_section(&missing_inserted)?;
    let allowlist_needs_normalization = updated != missing_inserted;
    if missing.is_empty()
        && threshold_migration.changes.is_empty()
        && !legacy_empty_ebpf_event_paths
        && !legacy_dynamic_udp_min_port
        && !allowlist_needs_normalization
    {
        println!(
            "configuration already contains all default keys: {}",
            path.display()
        );
        return Ok(());
    }

    let config: SentinelConfig = toml::from_str(&updated)?;
    config.validate()?;

    if dry_run {
        if !threshold_migration.changes.is_empty() {
            println!("legacy defaults that would be updated:");
            for change in threshold_migration.changes {
                println!("- {}: {} -> {}", change.path, change.old, change.new);
            }
        }
        if legacy_empty_ebpf_event_paths {
            println!("legacy defaults that would be updated:");
            println!(
                "- {LEGACY_EMPTY_EBPF_EVENT_PATHS_KEY}: [] -> {}",
                default_ebpf_event_paths_text()?
            );
        }
        if legacy_dynamic_udp_min_port {
            println!("legacy defaults that would be updated:");
            println!(
                "- {SERVICE_PROFILE_DYNAMIC_UDP_MIN_PORT_KEY}: {LEGACY_DYNAMIC_UDP_MIN_PORT} -> {DEFAULT_DYNAMIC_UDP_MIN_PORT}"
            );
        }
        if !missing.is_empty() {
            println!("default keys that would be added:");
            for entry in missing {
                println!("- {}", entry.path);
            }
        }
        if allowlist_needs_normalization {
            println!("sections that would be normalized:");
            println!("- allowlist");
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

pub(crate) fn add_allowlist_file_path(path: &Path, value: &str) -> Result<()> {
    update_allowlist(
        path,
        AllowlistCommand::Add {
            field: AllowlistField::FilePath,
            value: value.to_string(),
        },
    )
}

pub(crate) fn remove_allowlist_file_path(path: &Path, value: &str) -> Result<()> {
    update_allowlist(
        path,
        AllowlistCommand::Remove {
            field: AllowlistField::FilePath,
            value: value.to_string(),
        },
    )
}

pub(crate) fn add_trusted_admin_ip(path: &Path, ip: &str) -> Result<()> {
    update_trusted_admin_ips(path, TrustedAdminCommand::Add { ip: ip.to_string() })
}

pub(crate) fn remove_trusted_admin_ip(path: &Path, ip: &str) -> Result<()> {
    update_trusted_admin_ips(path, TrustedAdminCommand::Remove { ip: ip.to_string() })
}

fn normalize_config(path: &Path, dry_run: bool) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let normalized = normalize_allowlist_section(&text)?;
    let config: SentinelConfig = toml::from_str(&normalized)?;
    config.validate()?;
    if normalized == text {
        println!("configuration already normalized: {}", path.display());
        return Ok(());
    }
    if dry_run {
        println!("configuration would be normalized: {}", path.display());
        return Ok(());
    }
    let backup = write_config_backup(path, &text)?;
    fs::write(path, normalized)?;
    println!("configuration normalized: {}", path.display());
    println!("backup written: {}", backup.display());
    Ok(())
}

fn update_allowlist(path: &Path, command: AllowlistCommand) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: toml::Value = toml::from_str(&text)?;
    match command {
        AllowlistCommand::Add { field, value: item } => {
            update_allowlist_value(&mut value, field, item, ListEdit::Add)?;
        }
        AllowlistCommand::Remove { field, value: item } => {
            update_allowlist_value(&mut value, field, item, ListEdit::Remove)?;
        }
    }
    let config: SentinelConfig = value.clone().try_into()?;
    config.validate()?;
    let updated = replace_or_insert_section(
        &text,
        "allowlist",
        &render_allowlist_section(&config.allowlist),
    );
    write_updated_config(path, &text, &updated, "allowlist updated")
}

fn update_trusted_admin_ips(path: &Path, command: TrustedAdminCommand) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: toml::Value = toml::from_str(&text)?;
    let item = match command {
        TrustedAdminCommand::Add { ip } => {
            update_array_path(
                &mut value,
                "ssh.trusted_admin_ips",
                ListValue::String(ip.clone()),
                ListEdit::Add,
            )?;
            ip
        }
        TrustedAdminCommand::Remove { ip } => {
            update_array_path(
                &mut value,
                "ssh.trusted_admin_ips",
                ListValue::String(ip.clone()),
                ListEdit::Remove,
            )?;
            ip
        }
    };
    let config: SentinelConfig = value.try_into()?;
    config.validate()?;
    let rendered = render_string_array(&config.ssh.trusted_admin_ips);
    let updated = replace_or_insert_key(&text, "ssh", "trusted_admin_ips", &rendered);
    write_updated_config(
        path,
        &text,
        &updated,
        &format!("trusted admin IPs updated: {item}"),
    )
}

fn update_suppress_rule_ids(path: &Path, command: SuppressRuleCommand) -> Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: toml::Value = toml::from_str(&text)?;
    let item = match command {
        SuppressRuleCommand::Add { rule_id } => {
            update_array_path(
                &mut value,
                "suppress_rules.rule_ids",
                ListValue::String(rule_id.clone()),
                ListEdit::Add,
            )?;
            rule_id
        }
        SuppressRuleCommand::Remove { rule_id } => {
            update_array_path(
                &mut value,
                "suppress_rules.rule_ids",
                ListValue::String(rule_id.clone()),
                ListEdit::Remove,
            )?;
            rule_id
        }
    };
    let config: SentinelConfig = value.try_into()?;
    config.validate()?;
    let rendered = render_string_array(&config.suppress_rules.rule_ids);
    let mut updated = replace_or_insert_key(&text, "suppress_rules", "enabled", "true");
    updated = replace_or_insert_key(&updated, "suppress_rules", "rule_ids", &rendered);
    write_updated_config(
        path,
        &text,
        &updated,
        &format!("suppressed rule IDs updated: {item}"),
    )
}

#[derive(Debug, Clone, Copy)]
enum ListEdit {
    Add,
    Remove,
}

#[derive(Debug, Clone)]
enum ListValue {
    String(String),
    Integer(i64),
}

fn update_allowlist_value(
    root: &mut toml::Value,
    field: AllowlistField,
    raw_value: String,
    edit: ListEdit,
) -> Result<()> {
    let path = match field {
        AllowlistField::User => "allowlist.users",
        AllowlistField::Ip => "allowlist.ips",
        AllowlistField::ProcessPath => "allowlist.process_paths",
        AllowlistField::ProcessCommand => "allowlist.process_command_contains",
        AllowlistField::ListeningPort => "allowlist.listening_ports",
        AllowlistField::FilePath => "allowlist.file_paths",
        AllowlistField::WebPath => "allowlist.web_paths",
    };
    let value = match field {
        AllowlistField::ListeningPort => {
            let port = raw_value
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("listening port must be between 0 and 65535"))?;
            ListValue::Integer(i64::from(port))
        }
        _ => ListValue::String(non_empty_config_value(&raw_value)?),
    };
    update_array_path(root, path, value, edit)
}

fn update_array_path(
    root: &mut toml::Value,
    path: &str,
    value: ListValue,
    edit: ListEdit,
) -> Result<()> {
    let (section, key) = path
        .rsplit_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid config array path: {path}"))?;
    let table = ensure_table_path(root, section)?;
    let entry = table
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let array = entry
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("{path} must be an array"))?;
    let toml_value = match value {
        ListValue::String(value) => toml::Value::String(value),
        ListValue::Integer(value) => toml::Value::Integer(value),
    };
    match edit {
        ListEdit::Add => {
            if !array.iter().any(|item| item == &toml_value) {
                array.push(toml_value);
            }
        }
        ListEdit::Remove => {
            array.retain(|item| item != &toml_value);
        }
    }
    sort_toml_array(array);
    Ok(())
}

fn ensure_table_path<'a>(
    root: &'a mut toml::Value,
    section: &str,
) -> Result<&'a mut toml::map::Map<String, toml::Value>> {
    let mut current = root
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("configuration root must be a TOML table"))?;
    for segment in section.split('.') {
        let value = current
            .entry(segment.to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        current = value
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("{section} must be a TOML table"))?;
    }
    Ok(current)
}

fn sort_toml_array(array: &mut [toml::Value]) {
    array.sort_by(|left, right| toml_value_sort_key(left).cmp(&toml_value_sort_key(right)));
}

fn toml_value_sort_key(value: &toml::Value) -> String {
    match value {
        toml::Value::String(value) => format!("s:{value}"),
        toml::Value::Integer(value) => format!("i:{value:020}"),
        other => format!("z:{other:?}"),
    }
}

fn non_empty_config_value(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("config list value must not be empty");
    }
    Ok(trimmed.to_string())
}

fn write_updated_config(path: &Path, previous: &str, updated: &str, label: &str) -> Result<()> {
    if previous == updated {
        println!("configuration unchanged: {}", path.display());
        return Ok(());
    }
    let backup = write_config_backup(path, previous)?;
    fs::write(path, updated)?;
    SentinelConfig::load(path)?.validate()?;
    println!("{label}: {}", path.display());
    println!("backup written: {}", backup.display());
    Ok(())
}

fn normalize_allowlist_section(text: &str) -> Result<String> {
    let config: SentinelConfig = toml::from_str(text)?;
    Ok(replace_or_insert_section(
        text,
        "allowlist",
        &render_allowlist_section(&config.allowlist),
    ))
}

fn render_allowlist_section(allowlist: &AllowlistConfig) -> String {
    format!(
        "[allowlist]\nusers = {}\nips = {}\nprocess_paths = {}\nprocess_command_contains = {}\nlistening_ports = {}\nfile_paths = {}\nweb_paths = {}",
        render_string_array(&allowlist.users),
        render_string_array(&allowlist.ips),
        render_path_array(&allowlist.process_paths),
        render_string_array(&allowlist.process_command_contains),
        render_u16_array(&allowlist.listening_ports),
        render_path_array(&allowlist.file_paths),
        render_path_array(&allowlist.web_paths),
    )
}

fn render_string_array(values: &[String]) -> String {
    render_array(
        values
            .iter()
            .map(|value| toml::Value::String(value.clone())),
    )
}

fn render_path_array(values: &[PathBuf]) -> String {
    render_array(
        values
            .iter()
            .map(|value| toml::Value::String(value.to_string_lossy().into_owned())),
    )
}

fn render_u16_array(values: &[u16]) -> String {
    let mut values = values.to_vec();
    values.sort_unstable();
    values.dedup();
    render_array(
        values
            .iter()
            .map(|value| toml::Value::Integer(i64::from(*value))),
    )
}

fn render_array(values: impl IntoIterator<Item = toml::Value>) -> String {
    let mut rendered = values
        .into_iter()
        .map(|value| format_toml_value(&value).unwrap_or_else(|_| "\"\"".to_string()))
        .collect::<Vec<_>>();
    rendered.sort();
    rendered.dedup();
    if rendered.is_empty() {
        return "[]".to_string();
    }
    let mut output = String::from("[\n");
    for value in rendered {
        output.push_str("  ");
        output.push_str(&value);
        output.push_str(",\n");
    }
    output.push(']');
    output
}

fn replace_or_insert_section(text: &str, section: &str, replacement: &str) -> String {
    let mut output = Vec::new();
    let mut in_target = false;
    let mut replaced = false;

    for line in text.lines() {
        if let Some(next_section) = parse_toml_section_header(line) {
            if in_target {
                in_target = false;
            }
            if next_section == section {
                if !output
                    .last()
                    .map_or(true, |line: &String| line.trim().is_empty())
                {
                    output.push(String::new());
                }
                output.extend(replacement.lines().map(str::to_string));
                in_target = true;
                replaced = true;
                continue;
            }
        }
        if !in_target {
            output.push(line.to_string());
        }
    }

    if !replaced {
        ensure_blank_separator(&mut output);
        output.extend(replacement.lines().map(str::to_string));
    }

    let mut updated = output.join("\n");
    updated.push('\n');
    updated
}

fn replace_or_insert_key(text: &str, section: &str, key: &str, rendered_value: &str) -> String {
    let mut output = Vec::new();
    let mut current_section = String::new();
    let mut inserted = false;
    let mut skipping_multiline_array = false;

    for line in text.lines() {
        if skipping_multiline_array {
            if line.contains(']') {
                skipping_multiline_array = false;
            }
            continue;
        }
        if let Some(next_section) = parse_toml_section_header(line) {
            if current_section == section && !inserted {
                output.push(format!("{key} = {rendered_value}"));
                inserted = true;
            }
            current_section = next_section;
            output.push(line.to_string());
            continue;
        }
        if current_section == section && toml_line_key(line) == Some(key) {
            output.push(format!("{key} = {rendered_value}"));
            inserted = true;
            skipping_multiline_array = toml_array_value_is_multiline(line);
            continue;
        }
        output.push(line.to_string());
    }

    if !inserted {
        if current_section != section {
            ensure_blank_separator(&mut output);
            output.push(format!("[{section}]"));
        }
        output.push(format!("{key} = {rendered_value}"));
    }

    let mut updated = output.join("\n");
    updated.push('\n');
    updated
}

fn toml_array_value_is_multiline(line: &str) -> bool {
    let Some((_, value)) = line.split_once('=') else {
        return false;
    };
    value.contains('[') && !value.contains(']')
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

fn contains_legacy_empty_ebpf_event_paths(text: &str) -> bool {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return false;
    };
    let Some(paths) = toml_value_at_path(&value, LEGACY_EMPTY_EBPF_EVENT_PATHS_KEY)
        .and_then(toml::Value::as_array)
    else {
        return false;
    };
    paths.is_empty()
}

fn migrate_legacy_empty_ebpf_event_paths(text: &str) -> Result<String> {
    if !contains_legacy_empty_ebpf_event_paths(text) {
        return Ok(text.to_string());
    }
    replace_toml_array_value(
        text,
        LEGACY_EMPTY_EBPF_EVENT_PATHS_KEY,
        &default_ebpf_event_paths_value(),
    )
}

fn default_ebpf_event_paths_text() -> Result<String> {
    format_toml_value(&default_ebpf_event_paths_value())
}

fn default_ebpf_event_paths_value() -> toml::Value {
    toml::Value::Array(
        SentinelConfig::default()
            .advanced_collectors
            .ebpf_event_paths
            .iter()
            .map(|path| toml::Value::String(path.to_string_lossy().into_owned()))
            .collect(),
    )
}

fn contains_legacy_dynamic_udp_min_port(text: &str) -> bool {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return false;
    };
    toml_usize_at_path(&value, SERVICE_PROFILE_DYNAMIC_UDP_MIN_PORT_KEY)
        == Some(LEGACY_DYNAMIC_UDP_MIN_PORT)
}

fn migrate_legacy_dynamic_udp_min_port(text: &str) -> Result<String> {
    if !contains_legacy_dynamic_udp_min_port(text) {
        return Ok(text.to_string());
    }
    replace_toml_usize_value(
        text,
        SERVICE_PROFILE_DYNAMIC_UDP_MIN_PORT_KEY,
        LEGACY_DYNAMIC_UDP_MIN_PORT,
        DEFAULT_DYNAMIC_UDP_MIN_PORT as usize,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacyDefaultChange {
    path: &'static str,
    old: usize,
    new: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LegacySshThresholdMigration {
    changes: Vec<LegacyDefaultChange>,
}

fn legacy_ssh_threshold_migration(text: &str) -> Result<LegacySshThresholdMigration> {
    let value: toml::Value = toml::from_str(text)?;
    let current_default = SentinelConfig::default().ssh.failed_login_threshold;
    let ssh_threshold = toml_usize_at_path(&value, SSH_FAILED_LOGIN_THRESHOLD_KEY);
    let active_threshold =
        toml_usize_at_path(&value, ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD_KEY);
    let mut changes = Vec::new();

    if ssh_threshold == Some(LEGACY_SSH_FAILED_LOGIN_THRESHOLD)
        && active_threshold
            .map(|threshold| {
                threshold == current_default || threshold == LEGACY_SSH_FAILED_LOGIN_THRESHOLD
            })
            .unwrap_or(true)
    {
        changes.push(LegacyDefaultChange {
            path: SSH_FAILED_LOGIN_THRESHOLD_KEY,
            old: LEGACY_SSH_FAILED_LOGIN_THRESHOLD,
            new: current_default,
        });
    }

    if active_threshold == Some(LEGACY_SSH_FAILED_LOGIN_THRESHOLD)
        && ssh_threshold
            .map(|threshold| {
                threshold == current_default || threshold == LEGACY_SSH_FAILED_LOGIN_THRESHOLD
            })
            .unwrap_or(true)
    {
        changes.push(LegacyDefaultChange {
            path: ACTIVE_RESPONSE_SSH_FAILED_LOGIN_BLOCK_THRESHOLD_KEY,
            old: LEGACY_SSH_FAILED_LOGIN_THRESHOLD,
            new: current_default,
        });
    }

    Ok(LegacySshThresholdMigration { changes })
}

fn migrate_legacy_ssh_thresholds(
    text: &str,
    migration: &LegacySshThresholdMigration,
) -> Result<String> {
    let mut migrated = text.to_string();
    for change in &migration.changes {
        migrated = replace_toml_usize_value(&migrated, change.path, change.old, change.new)?;
    }
    Ok(migrated)
}

fn replace_toml_usize_value(
    text: &str,
    path: &str,
    old_value: usize,
    new_value: usize,
) -> Result<String> {
    let (target_section, target_key) = path.rsplit_once('.').unwrap_or(("", path));
    let mut section = String::new();
    let mut changed = false;
    let mut output = Vec::new();

    for line in text.lines() {
        if let Some(next_section) = parse_toml_section_header(line) {
            section = next_section;
            output.push(line.to_string());
            continue;
        }
        if section == target_section
            && !line.trim_start().starts_with('#')
            && toml_line_key(line) == Some(target_key)
            && toml_line_usize_value(line) == Some(old_value)
        {
            output.push(rewrite_toml_scalar_line(line, new_value));
            changed = true;
            continue;
        }
        output.push(line.to_string());
    }

    if !changed {
        bail!("could not migrate legacy default key: {path}");
    }
    let mut migrated = output.join("\n");
    migrated.push('\n');
    Ok(migrated)
}

fn replace_toml_array_value(text: &str, path: &str, new_value: &toml::Value) -> Result<String> {
    let (target_section, target_key) = path.rsplit_once('.').unwrap_or(("", path));
    let mut section = String::new();
    let mut changed = false;
    let mut output = Vec::new();
    let rendered = format_toml_value(new_value)?;

    for line in text.lines() {
        if let Some(next_section) = parse_toml_section_header(line) {
            section = next_section;
            output.push(line.to_string());
            continue;
        }
        let matches_section_key =
            section == target_section && toml_line_key(line) == Some(target_key);
        let matches_dotted_key = section.is_empty() && toml_line_key(line) == Some(path);
        if (matches_section_key || matches_dotted_key) && toml_line_array_is_empty(line) {
            output.push(rewrite_toml_value_line(line, &rendered));
            changed = true;
            continue;
        }
        output.push(line.to_string());
    }

    if !changed {
        bail!("could not migrate legacy default key: {path}");
    }
    let mut migrated = output.join("\n");
    migrated.push('\n');
    Ok(migrated)
}

fn rewrite_toml_scalar_line(line: &str, new_value: usize) -> String {
    rewrite_toml_value_line(line, &new_value.to_string())
}

fn rewrite_toml_value_line(line: &str, new_value: &str) -> String {
    let indent = line
        .chars()
        .take_while(|ch| ch.is_whitespace())
        .collect::<String>();
    let key = toml_line_key(line).unwrap_or_default();
    let comment = line
        .split_once('#')
        .map(|(_, comment)| format!(" #{}", comment))
        .unwrap_or_default();
    format!("{indent}{key} = {new_value}{comment}")
}

fn toml_line_key(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return None;
    }
    trimmed
        .split_once('=')
        .map(|(key, _)| key.trim())
        .filter(|key| !key.is_empty())
}

fn toml_line_usize_value(line: &str) -> Option<usize> {
    let (_, value) = line.trim().split_once('=')?;
    let value = value
        .split_once('#')
        .map(|(value, _)| value)
        .unwrap_or(value)
        .trim();
    value.parse().ok()
}

fn toml_line_array_is_empty(line: &str) -> bool {
    let (_, value) = match line.trim().split_once('=') {
        Some(pair) => pair,
        None => return false,
    };
    let value = value
        .split_once('#')
        .map(|(value, _)| value)
        .unwrap_or(value)
        .trim()
        .replace(char::is_whitespace, "");
    value == "[]"
}

fn toml_usize_at_path(value: &toml::Value, path: &str) -> Option<usize> {
    let value = toml_value_at_path(value, path)?;
    value
        .as_integer()
        .and_then(|value| usize::try_from(value).ok())
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
        add_allowlist_file_path, contains_legacy_default_language,
        contains_legacy_dynamic_udp_min_port, contains_legacy_empty_ebpf_event_paths,
        contains_legacy_ssh_response_policy, deprecated_keys_in_text, flatten_toml_keys,
        insert_missing_default_keys, legacy_ssh_threshold_migration,
        migrate_legacy_default_language, migrate_legacy_dynamic_udp_min_port,
        migrate_legacy_empty_ebpf_event_paths, migrate_legacy_ssh_response_policy,
        migrate_legacy_ssh_thresholds, missing_default_entries, next_backup_path,
        normalize_allowlist_section, remove_deprecated_keys,
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
    fn migrates_legacy_empty_ebpf_event_paths() {
        let text = "[advanced_collectors]\nebpf_event_paths = [] # old empty default\n";

        assert!(contains_legacy_empty_ebpf_event_paths(text));
        let migrated = migrate_legacy_empty_ebpf_event_paths(text).unwrap();

        assert!(migrated.contains(
            "ebpf_event_paths = [\"/var/lib/vps-sentinel/ebpf-runtime.jsonl\"] # old empty default"
        ));
    }

    #[test]
    fn preserves_custom_ebpf_event_paths() {
        let text = "[advanced_collectors]\nebpf_event_paths = [\"/tmp/custom-runtime.jsonl\"]\n";

        assert!(!contains_legacy_empty_ebpf_event_paths(text));
        assert_eq!(migrate_legacy_empty_ebpf_event_paths(text).unwrap(), text);
    }

    #[test]
    fn migrates_legacy_default_ssh_thresholds_together() {
        let text = "[ssh]\nfailed_login_threshold = 10 # old default\n\n[active_response]\nssh_failed_login_block_threshold = 10 # old default\n";
        let migration = legacy_ssh_threshold_migration(text).unwrap();

        let migrated = migrate_legacy_ssh_thresholds(text, &migration).unwrap();

        assert_eq!(migration.changes.len(), 2);
        assert!(migrated.contains("failed_login_threshold = 6 # old default"));
        assert!(migrated.contains("ssh_failed_login_block_threshold = 6 # old default"));
        let config: SentinelConfig = toml::from_str(&migrated).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn repairs_partially_synced_ssh_threshold_defaults() {
        let text = "[ssh]\nfailed_login_threshold = 10\n\n[active_response]\nssh_failed_login_block_threshold = 6\n";
        let migration = legacy_ssh_threshold_migration(text).unwrap();

        let migrated = migrate_legacy_ssh_thresholds(text, &migration).unwrap();

        assert_eq!(migration.changes.len(), 1);
        assert!(migrated.contains("failed_login_threshold = 6"));
        let config: SentinelConfig = toml::from_str(&migrated).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn preserves_custom_ssh_thresholds() {
        let text = "[ssh]\nfailed_login_threshold = 10\n\n[active_response]\nssh_failed_login_block_threshold = 20\n";

        let migration = legacy_ssh_threshold_migration(text).unwrap();

        assert!(migration.changes.is_empty());
        assert_eq!(
            migrate_legacy_ssh_thresholds(text, &migration).unwrap(),
            text
        );
    }

    #[test]
    fn migrates_legacy_dynamic_udp_min_port_default() {
        let text = "[service_profile]\ndynamic_udp_min_port = 32768 # old default\n";

        assert!(contains_legacy_dynamic_udp_min_port(text));
        let migrated = migrate_legacy_dynamic_udp_min_port(text).unwrap();

        assert!(migrated.contains("dynamic_udp_min_port = 1024 # old default"));
        let config: SentinelConfig = toml::from_str(&migrated).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn preserves_custom_dynamic_udp_min_port() {
        let text = "[service_profile]\ndynamic_udp_min_port = 2048\n";

        assert!(!contains_legacy_dynamic_udp_min_port(text));
        assert_eq!(migrate_legacy_dynamic_udp_min_port(text).unwrap(), text);
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
    fn normalizes_allowlist_section_to_canonical_multiline_arrays() {
        let text = "[allowlist]\nfile_paths = [\"/var/lib/app\", \"/etc/systemd/system/snap-*.mount\"]\nips = []\nusers = []\nprocess_paths = []\nprocess_command_contains = []\nlistening_ports = []\nweb_paths = []\n";

        let normalized = normalize_allowlist_section(text).unwrap();

        assert!(normalized.contains("[allowlist]\n"));
        assert!(normalized.contains("file_paths = [\n"));
        assert!(normalized.contains("  \"/etc/systemd/system/snap-*.mount\",\n"));
        assert!(normalized.contains("  \"/var/lib/app\",\n"));
        let config: SentinelConfig = toml::from_str(&normalized).unwrap();
        assert_eq!(config.allowlist.file_paths.len(), 2);
    }

    #[test]
    fn allowlist_add_file_path_deduplicates_and_validates_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(
            &config_path,
            "[allowlist]\nfile_paths = [\"/etc/systemd/system/snap-*.mount\"]\n",
        )
        .unwrap();

        add_allowlist_file_path(&config_path, "/etc/systemd/system/snap-*.mount").unwrap();
        add_allowlist_file_path(&config_path, "/etc/systemd/system/snap-*.scope").unwrap();

        let text = fs::read_to_string(&config_path).unwrap();
        assert_eq!(text.matches("snap-*.mount").count(), 1);
        assert_eq!(text.matches("snap-*.scope").count(), 1);
        let config: SentinelConfig = toml::from_str(&text).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn sync_defaults_repairs_legacy_empty_ebpf_event_paths() {
        let text = SentinelConfig::default_toml().unwrap().replace(
            "ebpf_event_paths = [\"/var/lib/vps-sentinel/ebpf-runtime.jsonl\"]",
            "ebpf_event_paths = []",
        );
        let normalized = migrate_legacy_empty_ebpf_event_paths(&text).unwrap();
        let missing = missing_default_entries(&normalized).unwrap();

        assert!(missing.is_empty());
        assert!(normalized
            .contains("ebpf_event_paths = [\"/var/lib/vps-sentinel/ebpf-runtime.jsonl\"]"));
        let config: SentinelConfig = toml::from_str(&normalized).unwrap();
        assert_eq!(config.advanced_collectors.ebpf_event_paths.len(), 1);
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
