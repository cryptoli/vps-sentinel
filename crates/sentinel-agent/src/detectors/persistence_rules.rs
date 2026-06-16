use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct PersistenceDetector;

impl Detector for PersistenceDetector {
    fn name(&self) -> &'static str {
        "persistence_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "PERSIST-001",
                "New or changed persistence entry",
                Category::Persistence,
                Severity::High,
                "A startup-related file changed relative to the baseline.",
            ),
            RuleMetadata::new(
                "PERSIST-002",
                "Suspicious cron or startup command",
                Category::Persistence,
                Severity::High,
                "A persistence file contains suspicious command fragments.",
            ),
            RuleMetadata::new(
                "PERSIST-003",
                "ld.so.preload modified",
                Category::Persistence,
                Severity::High,
                "Dynamic linker preload configuration changed or contains entries.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events {
            match event.kind.as_str() {
                "persistence_created" | "persistence_modified" => {
                    if event.field("type") == Some("ld_preload") {
                        findings.push(ld_preload_changed(event, ctx));
                    } else {
                        findings.push(persistence_changed(event, ctx));
                    }
                }
                "persistence_entry"
                    if event
                        .field("suspicious_lines")
                        .map(|value| !value.trim().is_empty())
                        .unwrap_or(false) =>
                {
                    findings.push(suspicious_entry(event, ctx));
                }
                _ => {}
            }
        }
        findings
    }
}

fn persistence_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Persistence-related file changed",
        "A cron, systemd, or shell startup file changed compared with the baseline.",
        Severity::High,
        Category::Persistence,
        "PERSIST-001",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_recommendations(vec![
        "Inspect the startup entry and verify it was added by an administrator or package update."
            .to_string(),
        "Check whether the referenced executable lives in temporary or web-writable paths."
            .to_string(),
    ])
}

fn suspicious_entry(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "Suspicious startup command detected",
        "A startup-related file contains command fragments commonly used for persistence.",
        Severity::High,
        Category::Persistence,
        "PERSIST-002",
        &path,
    )
    .with_evidence(vec![
        evidence("path", path),
        evidence("type", string_field(event, "type")),
        evidence("suspicious_lines", string_field(event, "suspicious_lines")),
    ])
    .with_impact(vec![
        "The host may run attacker-controlled code automatically after reboot or login."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Review the command target and network destination.".to_string(),
        "Preserve the file before removing unknown startup entries.".to_string(),
    ])
}

fn ld_preload_changed(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let path = string_field(event, "path");
    Finding::new(
        &ctx.host_id,
        "ld.so.preload changed",
        "Dynamic linker preload configuration changed relative to the baseline.",
        Severity::High,
        Category::Persistence,
        "PERSIST-003",
        &path,
    )
    .with_evidence(diff_evidence(event))
    .with_recommendations(vec![
        "Inspect preload entries and verify every referenced library.".to_string(),
        "Treat unknown entries as a possible rootkit signal, not a confirmed rootkit by itself."
            .to_string(),
    ])
}

fn diff_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("change", event.kind.clone()),
        evidence("type", string_field(event, "type")),
        evidence("path", string_field(event, "path")),
        evidence("previous_hash", string_field(event, "previous_hash")),
        evidence("current_hash", string_field(event, "current_hash")),
    ]
}
