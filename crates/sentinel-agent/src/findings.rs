use sentinel_core::{Evidence, Finding};
use std::collections::{BTreeMap, BTreeSet};

/// Coalesce findings that describe the same underlying resource change.
///
/// Detectors intentionally stay independent, so a systemd unit change can be
/// recognized by both file-integrity and persistence detectors. This pass keeps
/// detection modular while preventing users from receiving several messages for
/// one changed file.
pub(crate) fn coalesce_related_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut grouped = BTreeMap::<String, Vec<Finding>>::new();
    let mut retained = Vec::new();

    for finding in findings {
        if is_file_persistence_drift(&finding) {
            grouped
                .entry(resource_group_key(&finding))
                .or_default()
                .push(finding);
        } else {
            retained.push(finding);
        }
    }

    retained.extend(grouped.into_values().map(merge_resource_findings));
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

fn merge_resource_findings(mut findings: Vec<Finding>) -> Finding {
    if findings.len() == 1 {
        return findings.remove(0);
    }

    findings.sort_by_key(|finding| rule_priority(&finding.rule_id));
    let mut primary = findings.remove(0);
    let evidence = merge_evidence(&primary, &findings);
    primary = primary.with_evidence(evidence);
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
}
