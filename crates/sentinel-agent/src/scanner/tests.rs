use super::redact_findings;
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
