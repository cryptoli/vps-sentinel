use crate::detectors::{evidence, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct ConfigRiskDetector;

impl Detector for ConfigRiskDetector {
    fn name(&self) -> &'static str {
        "config_risk_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "CONFIG-001",
                "SSH password login enabled",
                Category::ConfigRisk,
                Severity::Medium,
                "sshd_config enables password authentication.",
            ),
            RuleMetadata::new(
                "CONFIG-004",
                "Root SSH login enabled",
                Category::ConfigRisk,
                Severity::High,
                "sshd_config allows direct root login.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.kind == "ssh_config_option")
        {
            let key = string_field(event, "key");
            let value = string_field(event, "value").to_ascii_lowercase();
            if key.eq_ignore_ascii_case("PasswordAuthentication") && value == "yes" {
                findings.push(password_auth_enabled(event, ctx));
            }
            if key.eq_ignore_ascii_case("PermitRootLogin")
                && matches!(
                    value.as_str(),
                    "yes" | "without-password" | "prohibit-password"
                )
            {
                findings.push(root_login_enabled(event, ctx));
            }
        }
        findings
    }
}

fn password_auth_enabled(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "SSH password authentication enabled",
        "The effective sshd configuration includes PasswordAuthentication yes.",
        Severity::Medium,
        Category::ConfigRisk,
        "CONFIG-001",
        string_field(event, "path"),
    )
    .with_evidence(config_evidence(event))
    .with_recommendations(vec![
        "Prefer key-based authentication and disable password login when operationally feasible."
            .to_string(),
        "Ensure fail2ban or equivalent throttling is active if password login remains enabled."
            .to_string(),
    ])
}

fn root_login_enabled(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Direct root SSH login enabled",
        "The effective sshd configuration allows direct root login.",
        Severity::High,
        Category::ConfigRisk,
        "CONFIG-004",
        string_field(event, "path"),
    )
    .with_evidence(config_evidence(event))
    .with_recommendations(vec![
        "Disable PermitRootLogin unless a documented operational need exists.".to_string(),
        "Use a named sudo-capable account for auditability.".to_string(),
    ])
}

fn config_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("path", string_field(event, "path")),
        evidence("key", string_field(event, "key")),
        evidence("value", string_field(event, "value")),
    ]
}
