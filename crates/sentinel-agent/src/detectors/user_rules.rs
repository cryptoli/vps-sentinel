use crate::detectors::{evidence, field_is_allowlisted, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct UserDetector;

impl Detector for UserDetector {
    fn name(&self) -> &'static str {
        "user_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "USER-001",
                "New user created",
                Category::User,
                Severity::Medium,
                "A user account was added relative to the baseline.",
            ),
            RuleMetadata::new(
                "USER-002",
                "UID 0 user added",
                Category::Privilege,
                Severity::Critical,
                "A non-root UID 0 account was added or changed.",
            ),
            RuleMetadata::new(
                "USER-003",
                "User privilege changed",
                Category::Privilege,
                Severity::High,
                "A user account changed in a way that may affect privileges.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events {
            let name = string_field(event, "name");
            if name.is_empty() || field_is_allowlisted(&name, &ctx.config.allowlist.users) {
                continue;
            }
            match event.kind.as_str() {
                "user_created" => {
                    if event.field("uid") == Some("0") && name != "root" {
                        findings.push(uid_zero_user(event, ctx));
                    } else {
                        findings.push(new_user(event, ctx));
                    }
                }
                "user_uid_changed_to_zero" => findings.push(uid_zero_user(event, ctx)),
                "user_modified" => findings.push(user_modified(event, ctx)),
                _ => {}
            }
        }
        findings
    }
}

fn new_user(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let name = string_field(event, "name");
    Finding::new(
        &ctx.host_id,
        "New local user account detected",
        "A local user account appeared compared with the stored baseline.",
        Severity::Medium,
        Category::User,
        "USER-001",
        &name,
    )
    .with_evidence(user_evidence(event))
    .with_recommendations(vec![
        "Confirm the account was created intentionally.".to_string(),
        "Review shell, home directory, and recent login activity for this user.".to_string(),
    ])
}

fn uid_zero_user(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let name = string_field(event, "name");
    Finding::new(
        &ctx.host_id,
        "UID 0 user detected",
        "A non-root account has UID 0 or changed to UID 0.",
        Severity::Critical,
        Category::Privilege,
        "USER-002",
        &name,
    )
    .with_evidence(user_evidence(event))
    .with_impact(vec![
        "UID 0 grants root-equivalent privileges and is a common persistence technique."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Validate the account in /etc/passwd from a trusted session.".to_string(),
        "Disable unknown UID 0 accounts after preserving evidence.".to_string(),
    ])
}

fn user_modified(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let name = string_field(event, "name");
    Finding::new(
        &ctx.host_id,
        "Local user account changed",
        "A local user account changed relative to the baseline.",
        Severity::High,
        Category::Privilege,
        "USER-003",
        &name,
    )
    .with_evidence(user_evidence(event))
    .with_recommendations(vec![
        "Review the account diff and correlate it with administrative activity.".to_string(),
    ])
}

fn user_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("change", event.kind.clone()),
        evidence("name", string_field(event, "name")),
        evidence("uid", string_field(event, "uid")),
        evidence("previous_uid", string_field(event, "previous_uid")),
    ]
}
