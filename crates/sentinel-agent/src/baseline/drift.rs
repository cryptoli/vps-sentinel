use sentinel_core::{
    evidence_value, Category, Confidence, Evidence, Finding, RawEvent, SentinelConfig, Severity,
    DEFAULT_DYNAMIC_UDP_MIN_PORT,
};
use std::collections::BTreeSet;

const DRIFT_SCORE_KEY: &str = "baseline_drift_score";
const DRIFT_TIER_KEY: &str = "baseline_drift_tier";
const REVIEW_ACTION_KEY: &str = "baseline_review_action";
const REASONS_KEY: &str = "baseline_drift_reasons";
const DOWNGRADES_KEY: &str = "baseline_drift_downgrades";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineDriftAssessment {
    pub score: u16,
    pub tier: &'static str,
    pub review_action: &'static str,
    pub reasons: Vec<String>,
    pub downgrades: Vec<String>,
    pub review_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftPolicy {
    dynamic_udp_enabled: bool,
    dynamic_udp_min_port: u16,
}

impl Default for DriftPolicy {
    fn default() -> Self {
        Self {
            dynamic_udp_enabled: true,
            dynamic_udp_min_port: DEFAULT_DYNAMIC_UDP_MIN_PORT,
        }
    }
}

impl From<&SentinelConfig> for DriftPolicy {
    fn from(config: &SentinelConfig) -> Self {
        Self {
            dynamic_udp_enabled: config.service_profile.dynamic_udp_enabled,
            dynamic_udp_min_port: config.service_profile.dynamic_udp_min_port,
        }
    }
}

pub fn assess_event(event: &RawEvent) -> Option<BaselineDriftAssessment> {
    assess_event_with_policy(event, &DriftPolicy::default())
}

pub fn assess_event_with_policy(
    event: &RawEvent,
    policy: &DriftPolicy,
) -> Option<BaselineDriftAssessment> {
    if !baseline_event_kind(&event.kind) {
        return None;
    }
    let mut assessment = DriftBuilder::new(event_base_score(event));
    assessment.add_reason("baseline change detected");
    event_signals(event, &mut assessment, policy);
    Some(assessment.finish())
}

pub fn enrich_findings(findings: &mut [Finding]) {
    for finding in findings {
        let Some(assessment) = assess_finding(finding) else {
            continue;
        };
        apply_assessment_to_finding(finding, &assessment);
    }
}

fn assess_finding(finding: &Finding) -> Option<BaselineDriftAssessment> {
    if !baseline_drift_finding(finding) {
        return None;
    }
    let mut assessment = DriftBuilder::new(finding_base_score(finding));
    assessment.add_reason("baseline drift finding");
    finding_signals(finding, &mut assessment);
    Some(assessment.finish())
}

fn apply_assessment_to_finding(finding: &mut Finding, assessment: &BaselineDriftAssessment) {
    upsert_evidence(
        &mut finding.evidence,
        DRIFT_SCORE_KEY,
        assessment.score.to_string(),
    );
    upsert_evidence(&mut finding.evidence, DRIFT_TIER_KEY, assessment.tier);
    upsert_evidence(
        &mut finding.evidence,
        REVIEW_ACTION_KEY,
        assessment.review_action,
    );
    upsert_evidence(
        &mut finding.evidence,
        REASONS_KEY,
        assessment.reasons.join(", "),
    );
    if !assessment.downgrades.is_empty() {
        upsert_evidence(
            &mut finding.evidence,
            DOWNGRADES_KEY,
            assessment.downgrades.join(", "),
        );
    }
    merge_recommendations(finding, assessment);
    adjust_drift_severity(finding, assessment);
}

fn merge_recommendations(finding: &mut Finding, assessment: &BaselineDriftAssessment) {
    let action = format!(
        "Baseline review action: {}.",
        assessment.review_action.replace('_', " ")
    );
    if !finding.recommendations.iter().any(|item| item == &action) {
        finding.recommendations.push(action);
    }
    for step in &assessment.review_steps {
        if !finding.recommendations.iter().any(|item| item == step) {
            finding.recommendations.push(step.clone());
        }
    }
}

fn adjust_drift_severity(finding: &mut Finding, assessment: &BaselineDriftAssessment) {
    if protected_high_signal(finding) {
        return;
    }
    match assessment.tier {
        "routine" => {
            finding.severity = Severity::Low;
            finding.confidence = Confidence::Low;
        }
        "review" => {
            if finding.severity.meets(Severity::High) {
                finding.severity = Severity::Medium;
            }
            if finding.confidence == Confidence::High {
                finding.confidence = Confidence::Medium;
            }
        }
        _ => {}
    }
}

fn baseline_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "file_created"
            | "file_modified"
            | "file_deleted"
            | "user_created"
            | "user_modified"
            | "user_uid_changed_to_zero"
            | "persistence_created"
            | "persistence_modified"
            | "listening_socket"
            | "listening_socket_owner_changed"
    )
}

fn baseline_drift_finding(finding: &Finding) -> bool {
    matches!(
        finding.rule_id.as_str(),
        "FILE-001"
            | "SSH-005"
            | "USER-001"
            | "USER-002"
            | "USER-003"
            | "PERSIST-001"
            | "PERSIST-003"
            | "NET-001"
            | "NET-002"
            | "SERVICE-001"
            | "SERVICE-002"
    ) || finding.evidence.iter().any(baseline_change_evidence)
        || evidence_value(&finding.evidence, "service_profile_identity").is_some()
}

fn baseline_change_evidence(item: &Evidence) -> bool {
    item.key == "change"
        && matches!(
            item.value.as_str(),
            "file_created"
                | "file_modified"
                | "file_deleted"
                | "persistence_created"
                | "persistence_modified"
                | "listening_socket"
                | "listening_socket_owner_changed"
                | "user_created"
                | "user_modified"
                | "user_uid_changed_to_zero"
        )
}

fn event_base_score(event: &RawEvent) -> u16 {
    match event.kind.as_str() {
        "user_uid_changed_to_zero" => 90,
        "user_created" | "user_modified" => 65,
        "persistence_created" | "persistence_modified" => 70,
        "listening_socket_owner_changed" => 60,
        "listening_socket" => 50,
        "file_created" | "file_deleted" => 55,
        "file_modified" => 50,
        _ => 45,
    }
}

fn finding_base_score(finding: &Finding) -> u16 {
    match finding.category {
        Category::Ssh => 85,
        Category::User => 70,
        Category::Persistence => 70,
        Category::Network => 55,
        Category::FileIntegrity => 55,
        _ => 45,
    }
}

fn event_signals(event: &RawEvent, assessment: &mut DriftBuilder, policy: &DriftPolicy) {
    if security_sensitive_event(event) {
        assessment.add_signal(35, "security-sensitive drift");
    }
    if event.field("type") == Some("ld_preload") {
        assessment.add_signal(25, "dynamic linker preload changed");
    }
    if event.kind == "user_uid_changed_to_zero" || event.field("uid") == Some("0") {
        assessment.add_signal(25, "privileged account state changed");
    }
    if event.kind == "listening_socket_owner_changed" {
        assessment.add_signal(15, "listener owner changed");
    }
    if event.field("semantic_delta").is_some() {
        assessment.add_signal(18, "semantic content changed");
    }
    if risky_semantic_features(
        event
            .field("current_semantic_features")
            .or_else(|| event.field("semantic_features"))
            .unwrap_or_default(),
    ) {
        assessment.add_signal(25, "risky semantic traits present");
    }
    if public_listener_event(event) {
        assessment.add_signal(12, "public listener exposure");
    }
    if non_public_listener_event(event) {
        assessment.add_downgrade(18, "not publicly exposed");
    }
    if dynamic_udp_listener_event(event, policy) {
        assessment.add_downgrade(25, "dynamic UDP listener");
    }
    if large_file_size_change(event) {
        assessment.add_signal(8, "large file size delta");
    }
    if executable_state_changed(event) {
        assessment.add_signal(8, "executable state changed");
    }
}

fn finding_signals(finding: &Finding, assessment: &mut DriftBuilder) {
    let protected = protected_high_signal(finding);
    if protected {
        assessment.add_signal(35, "security-sensitive drift");
    }
    if evidence_value(&finding.evidence, "type") == Some("ld_preload") {
        assessment.add_signal(25, "dynamic linker preload changed");
    }
    if evidence_value(&finding.evidence, "public_exposure") == Some("true")
        || public_listener_evidence(finding)
    {
        assessment.add_signal(12, "public listener exposure");
    }
    if evidence_value(&finding.evidence, "previous_process_name").is_some()
        || evidence_value(&finding.evidence, "previous_executable").is_some()
    {
        assessment.add_signal(12, "service owner changed");
    }
    if evidence_value(&finding.evidence, "semantic_delta").is_some() {
        assessment.add_signal(18, "semantic content changed");
    }
    if evidence_value(&finding.evidence, "current_semantic_features")
        .or_else(|| evidence_value(&finding.evidence, "semantic_features"))
        .is_some_and(risky_semantic_features)
    {
        assessment.add_signal(25, "risky semantic traits present");
    }
    if evidence_value(&finding.evidence, "risk_score")
        .and_then(|value| value.parse::<u16>().ok())
        .is_some_and(|score| score >= 70)
    {
        assessment.add_signal(25, "risk-scored suspicious traits present");
    }
    if evidence_value(&finding.evidence, "risk_features").is_some()
        || evidence_value(&finding.evidence, "risk_reasons").is_some()
    {
        assessment.add_signal(15, "risk evidence attached");
    }
    if !protected {
        if evidence_value(&finding.evidence, "package_activity_recent") == Some("true") {
            assessment.add_downgrade(25, "recent package manager activity");
        }
        if evidence_value(&finding.evidence, "public_exposure") == Some("false") {
            assessment.add_downgrade(18, "not publicly exposed");
        }
        if dynamic_udp_finding(finding) {
            assessment.add_downgrade(40, "dynamic UDP listener");
        }
        if evidence_value(&finding.evidence, "firewall_status").is_some_and(|value| {
            value.contains("protected") || value.contains("active") || value.contains("observed")
        }) {
            assessment.add_downgrade(8, "local firewall context is present");
        }
    }
}

fn protected_high_signal(finding: &Finding) -> bool {
    matches!(
        finding.rule_id.as_str(),
        "SSH-005" | "USER-002" | "PERSIST-003"
    ) || evidence_value(&finding.evidence, "identity_files").is_some()
        || evidence_value(&finding.evidence, "uid") == Some("0")
        || evidence_value(&finding.evidence, "path").is_some_and(security_sensitive_path)
}

fn security_sensitive_event(event: &RawEvent) -> bool {
    event.kind == "user_uid_changed_to_zero"
        || event.field("uid") == Some("0")
        || event.field("type") == Some("ld_preload")
        || event.field("path").is_some_and(security_sensitive_path)
}

fn security_sensitive_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.ends_with("/authorized_keys")
        || normalized.ends_with("/authorized_keys2")
        || matches!(
            normalized.as_str(),
            "/etc/passwd" | "/etc/group" | "/etc/shadow" | "/etc/gshadow" | "/etc/sudoers"
        )
        || normalized.starts_with("/etc/sudoers.d/")
}

fn risky_semantic_features(value: &str) -> bool {
    value.split(',').map(str::trim).any(|feature| {
        matches!(
            feature,
            "network_or_shell_command"
                | "temporary_path"
                | "reboot_entry"
                | "nopasswd"
                | "broad_privilege"
        )
    })
}

fn public_listener_event(event: &RawEvent) -> bool {
    event
        .field("local_addr")
        .is_some_and(crate::utils::ip::is_public_listener_addr)
}

fn non_public_listener_event(event: &RawEvent) -> bool {
    matches!(
        event.kind.as_str(),
        "listening_socket" | "listening_socket_owner_changed"
    ) && event
        .field("local_addr")
        .is_some_and(|addr| !crate::utils::ip::is_public_listener_addr(addr))
}

fn dynamic_udp_listener_event(event: &RawEvent, policy: &DriftPolicy) -> bool {
    policy.dynamic_udp_enabled
        && matches!(
            event.kind.as_str(),
            "listening_socket" | "listening_socket_owner_changed"
        )
        && event.field("protocol").is_some_and(is_udp_protocol)
        && event
            .field("local_port")
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|port| port >= policy.dynamic_udp_min_port)
}

fn is_udp_protocol(protocol: &str) -> bool {
    protocol.eq_ignore_ascii_case("udp") || protocol.eq_ignore_ascii_case("udp6")
}

fn public_listener_evidence(finding: &Finding) -> bool {
    evidence_value(&finding.evidence, "local_addr")
        .is_some_and(crate::utils::ip::is_public_listener_addr)
}

fn dynamic_udp_finding(finding: &Finding) -> bool {
    evidence_value(&finding.evidence, "dynamic_udp_listener") == Some("true")
        || (evidence_value(&finding.evidence, "protocol").is_some_and(is_udp_protocol)
            && evidence_value(&finding.evidence, "local_port")
                .and_then(|value| value.parse::<u16>().ok())
                .is_some_and(|port| port >= DEFAULT_DYNAMIC_UDP_MIN_PORT))
}

fn large_file_size_change(event: &RawEvent) -> bool {
    let previous = event
        .field("previous_size")
        .and_then(|value| value.parse::<u64>().ok());
    let current = event
        .field("current_size")
        .or_else(|| event.field("size"))
        .and_then(|value| value.parse::<u64>().ok());
    let (Some(previous), Some(current)) = (previous, current) else {
        return false;
    };
    let delta = previous.abs_diff(current);
    delta >= 1024 * 1024 || (previous > 0 && delta.saturating_mul(100) / previous >= 50)
}

fn executable_state_changed(event: &RawEvent) -> bool {
    matches!(
        (
            event.field("previous_executable"),
            event.field("current_executable")
        ),
        (Some(previous), Some(current)) if previous != current
    )
}

fn upsert_evidence(evidence: &mut Vec<Evidence>, key: &str, value: impl Into<String>) {
    sentinel_core::upsert_evidence(evidence, key, value);
}

#[derive(Debug, Clone)]
struct DriftBuilder {
    score: u16,
    reasons: BTreeSet<String>,
    downgrades: BTreeSet<String>,
}

impl DriftBuilder {
    fn new(score: u16) -> Self {
        Self {
            score,
            reasons: BTreeSet::new(),
            downgrades: BTreeSet::new(),
        }
    }

    fn add_signal(&mut self, weight: u16, reason: &str) {
        self.score = self.score.saturating_add(weight).min(100);
        self.add_reason(reason);
    }

    fn add_downgrade(&mut self, weight: u16, reason: &str) {
        self.score = self.score.saturating_sub(weight);
        self.downgrades.insert(reason.to_string());
    }

    fn add_reason(&mut self, reason: &str) {
        self.reasons.insert(reason.to_string());
    }

    fn finish(self) -> BaselineDriftAssessment {
        let tier = drift_tier(self.score);
        BaselineDriftAssessment {
            score: self.score,
            tier,
            review_action: review_action(tier),
            reasons: self.reasons.into_iter().collect(),
            downgrades: self.downgrades.into_iter().collect(),
            review_steps: review_steps(tier),
        }
    }
}

fn drift_tier(score: u16) -> &'static str {
    match score {
        0..=39 => "routine",
        40..=64 => "review",
        65..=84 => "suspicious",
        _ => "critical",
    }
}

fn review_action(tier: &str) -> &'static str {
    match tier {
        "routine" => "confirm_context_then_refresh",
        "review" => "review_change_before_refresh",
        "suspicious" => "investigate_before_refresh",
        _ => "treat_as_incident_before_refresh",
    }
}

fn review_steps(tier: &str) -> Vec<String> {
    match tier {
        "routine" => vec![
            "Compare the change with package logs or planned maintenance notes before refreshing the baseline.".to_string(),
        ],
        "review" => vec![
            "Review the changed resource and approve the baseline only after confirming ownership and intent.".to_string(),
        ],
        "suspicious" => vec![
            "Do not refresh the baseline until the changed resource, owner, and related process/network evidence are understood.".to_string(),
        ],
        _ => vec![
            "Treat this drift as a possible compromise signal; preserve evidence before cleanup or baseline refresh.".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::{assess_event, enrich_findings};
    use sentinel_core::{Category, Evidence, Finding, RawEvent, Severity};

    #[test]
    fn package_context_downgrades_generic_file_drift() {
        let mut findings = vec![Finding::new(
            "host",
            "file",
            "file",
            Severity::High,
            Category::FileIntegrity,
            "FILE-001",
            "/usr/bin/app",
        )
        .with_evidence(vec![
            Evidence::new("change", "file_modified"),
            Evidence::new("path", "/usr/bin/app"),
            Evidence::new("package_activity_recent", "true"),
        ])];

        enrich_findings(&mut findings);

        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "baseline_drift_tier" && item.value == "routine"));
    }

    #[test]
    fn authorized_keys_drift_stays_high_risk_with_package_context() {
        let mut findings = vec![Finding::new(
            "host",
            "keys",
            "keys",
            Severity::High,
            Category::Ssh,
            "SSH-005",
            "/root/.ssh/authorized_keys",
        )
        .with_evidence(vec![
            Evidence::new("change", "file_modified"),
            Evidence::new("path", "/root/.ssh/authorized_keys"),
            Evidence::new("package_activity_recent", "true"),
        ])];

        enrich_findings(&mut findings);

        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "baseline_drift_tier" && item.value == "critical"));
    }

    #[test]
    fn approval_event_assessment_uses_change_magnitude_without_path_allowlists() {
        let event = RawEvent::new("baseline", "file_modified")
            .with_field("path", "/opt/app/config.toml")
            .with_field("previous_size", "100")
            .with_field("current_size", "1000000");

        let assessment = assess_event(&event).expect("assessment");

        assert!(assessment.score > 50);
        assert!(assessment
            .reasons
            .contains(&"large file size delta".to_string()));
    }

    #[test]
    fn approval_event_treats_authorized_keys_as_sensitive_drift() {
        let event = RawEvent::new("baseline", "file_modified")
            .with_field("path", "/root/.ssh/authorized_keys")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new");

        let assessment = assess_event(&event).expect("assessment");

        assert_eq!(assessment.tier, "critical");
        assert!(assessment
            .reasons
            .contains(&"security-sensitive drift".to_string()));
    }

    #[test]
    fn approval_event_scores_semantic_persistence_traits() {
        let event = RawEvent::new("baseline", "persistence_modified")
            .with_field("path", "/etc/systemd/system/app.service")
            .with_field("type", "systemd")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new")
            .with_field("semantic_delta", "systemd_unit: commands=1 -> commands=2")
            .with_field("current_semantic_features", "network_or_shell_command");

        let assessment = assess_event(&event).expect("assessment");

        assert_eq!(assessment.tier, "critical");
        assert!(assessment
            .reasons
            .contains(&"semantic content changed".to_string()));
        assert!(assessment
            .reasons
            .contains(&"risky semantic traits present".to_string()));
    }

    #[test]
    fn approval_event_scores_sudoers_privilege_traits() {
        let event = RawEvent::new("baseline", "file_modified")
            .with_field("path", "/etc/sudoers.d/admin")
            .with_field("previous_hash", "old")
            .with_field("current_hash", "new")
            .with_field("semantic_delta", "sudoers: rules=1 -> rules=2")
            .with_field("current_semantic_features", "broad_privilege, nopasswd");

        let assessment = assess_event(&event).expect("assessment");

        assert_eq!(assessment.tier, "critical");
        assert!(assessment
            .reasons
            .contains(&"risky semantic traits present".to_string()));
    }

    #[test]
    fn approval_event_downgrades_non_public_listener_drift() {
        let event = RawEvent::new("baseline", "listening_socket")
            .with_field("protocol", "tcp6")
            .with_field("local_addr", "::1")
            .with_field("local_port", "25");

        let assessment = assess_event(&event).expect("assessment");

        assert_eq!(assessment.tier, "routine");
        assert!(assessment
            .downgrades
            .contains(&"not publicly exposed".to_string()));
    }

    #[test]
    fn approval_event_downgrades_dynamic_udp_listener_drift() {
        let event = RawEvent::new("baseline", "listening_socket")
            .with_field("protocol", "udp")
            .with_field("local_addr", "0.0.0.0")
            .with_field("local_port", "51659")
            .with_field("process_name", "v2ray")
            .with_field("executable", "/usr/bin/v2ray/v2ray");

        let assessment = assess_event(&event).expect("assessment");

        assert_eq!(assessment.tier, "routine");
        assert!(assessment
            .reasons
            .contains(&"public listener exposure".to_string()));
        assert!(assessment
            .downgrades
            .contains(&"dynamic UDP listener".to_string()));
    }

    #[test]
    fn approval_event_keeps_low_udp_listener_reviewable() {
        let event = RawEvent::new("baseline", "listening_socket")
            .with_field("protocol", "udp")
            .with_field("local_addr", "0.0.0.0")
            .with_field("local_port", "11211")
            .with_field("process_name", "memcached")
            .with_field("executable", "/usr/bin/memcached");

        let assessment = assess_event(&event).expect("assessment");

        assert_eq!(assessment.tier, "review");
        assert!(!assessment
            .downgrades
            .contains(&"dynamic UDP listener".to_string()));
    }

    #[test]
    fn dynamic_udp_service_profile_finding_stays_routine() {
        let mut findings = vec![Finding::new(
            "host",
            "service",
            "service",
            Severity::Medium,
            Category::Network,
            "SERVICE-001",
            "0.0.0.0:51659/udp",
        )
        .with_evidence(vec![
            Evidence::new("protocol", "udp"),
            Evidence::new("local_addr", "0.0.0.0"),
            Evidence::new("local_port", "51659"),
            Evidence::new("public_exposure", "true"),
            Evidence::new("dynamic_udp_listener", "true"),
        ])];

        enrich_findings(&mut findings);

        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "baseline_drift_tier" && item.value == "routine"));
    }

    #[test]
    fn non_baseline_previous_fields_are_not_reclassified_as_drift() {
        let mut findings = vec![Finding::new(
            "host",
            "log",
            "log",
            Severity::High,
            Category::System,
            "TAMPER-002",
            "/var/log/auth.log",
        )
        .with_evidence(vec![
            Evidence::new("previous_size", "524288"),
            Evidence::new("current_size", "128"),
        ])];

        enrich_findings(&mut findings);

        assert!(!findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "baseline_drift_tier"));
        assert_eq!(findings[0].severity, Severity::High);
    }
}
