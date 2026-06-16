use super::{redact_findings, suppress_in_scan_duplicates};
use sentinel_core::{Category, Evidence, Finding, SentinelConfig, Severity};

#[test]
fn redacts_finding_subject_and_evidence() {
    let mut config = SentinelConfig::default();
    config.privacy.mask_ip = true;
    config.privacy.mask_command_args = true;

    let finding = Finding::new(
        "host",
        "Suspicious command",
        "Command line matched.",
        Severity::Critical,
        Category::Process,
        "PROC-003",
        "root@203.0.113.10",
    )
    .with_evidence(vec![
        Evidence::new("source_ip", "203.0.113.10"),
        Evidence::new("cmdline", "/bin/bash -c whoami"),
        Evidence::new("raw", "203.0.113.10 /bin/bash -c whoami"),
    ]);

    let redacted = redact_findings(vec![finding], &config);
    assert_eq!(redacted[0].subject, "root@203.0.x.x");
    assert_eq!(redacted[0].evidence[0].value, "203.0.x.x");
    assert_eq!(redacted[0].evidence[1].value, "/bin/bash [args masked]");
    assert_eq!(redacted[0].evidence[2].value, "[masked by privacy config]");
}

#[test]
fn suppresses_duplicate_findings_within_one_scan() {
    let finding = Finding::new(
        "host",
        "Root SSH login detected",
        "Root logged in through SSH.",
        Severity::High,
        Category::Ssh,
        "SSH-001",
        "root@203.0.113.10",
    )
    .with_evidence_deduped_by(
        vec![
            Evidence::new("user", "root"),
            Evidence::new("source_ip", "203.0.113.10"),
            Evidence::new("port", "42100"),
        ],
        &["user", "source_ip"],
    );
    let mut duplicate = finding.clone();
    duplicate.id = "another-id".to_string();

    let (retained, suppressed) = suppress_in_scan_duplicates(vec![finding, duplicate]);

    assert_eq!(retained.len(), 1);
    assert_eq!(suppressed, 1);
}
