use crate::detectors::{
    evidence, field_is_allowlisted, package_activity_context, string_field, DetectContext,
    Detector, PackageActivityContext,
};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct UserDetector;

const LINUX_REGULAR_USER_UID_MIN: u32 = 1000;
const USER_ACCOUNT_DEDUP_KEYS: &[&str] = &["change", "name", "uid", "previous_uid"];

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
        let package_context = package_activity_context(events);
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
                        findings.push(new_user(event, ctx, &package_context));
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

fn new_user(
    event: &RawEvent,
    ctx: &DetectContext,
    package_context: &PackageActivityContext,
) -> Finding {
    let name = string_field(event, "name");
    let package_managed_system_user = likely_package_managed_system_user(event, package_context);
    let mut evidence = user_evidence(event);
    evidence.extend(package_context.evidence());
    if package_managed_system_user {
        evidence.push(sentinel_core::Evidence::new(
            "package_managed_system_user",
            "true",
        ));
    }
    let mut recommendations = vec![
        "Confirm the account was created intentionally.".to_string(),
        "Review shell, home directory, and recent login activity for this user.".to_string(),
    ];
    if let Some(recommendation) = package_context.recommendation() {
        recommendations.push(recommendation);
    }
    Finding::new(
        &ctx.host_id,
        "New local user account detected",
        "A local user account appeared compared with the stored baseline.",
        if package_managed_system_user {
            Severity::Low
        } else {
            Severity::Medium
        },
        Category::User,
        "USER-001",
        &name,
    )
    .with_evidence_deduped_by(evidence, USER_ACCOUNT_DEDUP_KEYS)
    .with_recommendations(recommendations)
}

fn likely_package_managed_system_user(
    event: &RawEvent,
    package_context: &PackageActivityContext,
) -> bool {
    let Some(uid) = event
        .field("uid")
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    package_context.is_active() && uid > 0 && uid < LINUX_REGULAR_USER_UID_MIN
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

#[cfg(test)]
mod tests {
    use super::UserDetector;
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig, Severity};
    use std::sync::Arc;

    #[test]
    fn package_created_system_user_is_low_with_package_context() {
        let detector = UserDetector;
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let user = RawEvent::new("users", "user_created")
            .with_field("name", "service-user")
            .with_field("uid", "988");
        let events = vec![
            RawEvent::new("package_manager", "package_manager_activity")
                .with_field("path", "/var/log/dpkg.log"),
            user.clone(),
        ];

        let findings = detector.detect(&events, &ctx);
        let without_package_context = detector.detect(&[user], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(without_package_context.len(), 1);
        assert_eq!(findings[0].dedup_key, without_package_context[0].dedup_key);
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "package_activity_recent" && item.value == "true"));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "package_managed_system_user" && item.value == "true"));
    }

    #[test]
    fn uid_zero_user_is_not_downgraded_by_package_context() {
        let detector = UserDetector;
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let events = vec![
            RawEvent::new("package_manager", "package_manager_activity")
                .with_field("path", "/var/log/dpkg.log"),
            RawEvent::new("users", "user_created")
                .with_field("name", "backdoor")
                .with_field("uid", "0"),
        ];

        let findings = detector.detect(&events, &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "USER-002");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
