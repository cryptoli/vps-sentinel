use sentinel_core::RawEvent;
use std::collections::BTreeSet;

mod parsing;
use parsing::{contains_ipv4_literal, normalize_text, split_shell_like};

const SUSPICIOUS_NETWORK_EXECUTION_SCORE: u16 = 70;
const NETWORK_CHANNEL_MARKERS: &[&str] = &[
    "tcp:",
    "tcp4:",
    "tcp6:",
    "udp:",
    "udp4:",
    "udp6:",
    "tcp-listen:",
    "tcp4-listen:",
    "tcp6-listen:",
    "udp-listen:",
    "udp4-listen:",
    "udp6-listen:",
    "connect:",
    "listen:",
    "://",
];
const EXEC_BRIDGE_MARKERS: &[&str] = &["exec:", ",exec:", "shell:", ",shell:"];
const SYSTEM_BRIDGE_MARKERS: &[&str] = &["system:", ",system:"];
const SHELL_TARGET_MARKERS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/bash",
    "busybox sh",
    "busybox ash",
    "cmd.exe",
    "powershell",
];
const SHELL_TARGET_NAMES: &[&str] = &["sh", "bash", "dash", "zsh", "ash"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CommandFeature {
    DevTcp,
    ExecBridge,
    FdDuplication,
    InlineInterpreter,
    InteractiveShell,
    NetworkChannel,
    ShellTarget,
    SocketApi,
    SystemBridge,
    TtyAllocation,
}

impl CommandFeature {
    fn as_str(self) -> &'static str {
        match self {
            Self::DevTcp => "dev_tcp",
            Self::ExecBridge => "exec_bridge",
            Self::FdDuplication => "fd_duplication",
            Self::InlineInterpreter => "inline_interpreter",
            Self::InteractiveShell => "interactive_shell",
            Self::NetworkChannel => "network_channel",
            Self::ShellTarget => "shell_target",
            Self::SocketApi => "socket_api",
            Self::SystemBridge => "system_bridge",
            Self::TtyAllocation => "tty_allocation",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CommandAssessment {
    pub(crate) score: u16,
    pub(crate) reasons: Vec<&'static str>,
    features: BTreeSet<CommandFeature>,
}

impl CommandAssessment {
    pub(crate) fn is_suspicious(&self) -> bool {
        self.score >= SUSPICIOUS_NETWORK_EXECUTION_SCORE
    }

    pub(crate) fn feature_names(&self) -> String {
        self.features
            .iter()
            .map(|feature| feature.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(crate) fn reason_text(&self) -> String {
        self.reasons.join("; ")
    }
}

pub(crate) fn network_execution_assessment_from_event(event: &RawEvent) -> CommandAssessment {
    let cmdline = event.field("cmdline").unwrap_or_default();
    let profile = CommandProfile::from_event(event, cmdline);
    assess_network_execution(&profile)
}

pub(crate) fn assess_network_execution_command(command: &str) -> CommandAssessment {
    let profile = CommandProfile::from_command(command);
    assess_network_execution(&profile)
}

#[derive(Debug, Clone)]
struct CommandProfile {
    lowered: String,
    args: Vec<String>,
}

impl CommandProfile {
    fn from_event(event: &RawEvent, command: &str) -> Self {
        let args = event
            .field("argv_json")
            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
            .filter(|args| !args.is_empty())
            .unwrap_or_else(|| split_shell_like(command));
        Self::from_args_or_command(args, command)
    }

    fn from_command(command: &str) -> Self {
        Self::from_args_or_command(split_shell_like(command), command)
    }

    fn from_args_or_command(args: Vec<String>, command: &str) -> Self {
        let lowered_args = args
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(|arg| arg.to_ascii_lowercase())
            .collect::<Vec<_>>();
        let lowered = if lowered_args.is_empty() {
            normalize_text(command)
        } else {
            lowered_args.join(" ")
        };
        Self {
            lowered,
            args: lowered_args,
        }
    }

    fn contains_text(&self, marker: &str) -> bool {
        self.lowered.contains(marker)
    }

    fn has_arg(&self, marker: &str) -> bool {
        self.args.iter().any(|arg| arg == marker)
    }

    fn any_arg_contains(&self, markers: &[&str]) -> bool {
        self.args
            .iter()
            .any(|arg| markers.iter().any(|marker| arg.contains(marker)))
    }
}

fn assess_network_execution(profile: &CommandProfile) -> CommandAssessment {
    let mut assessment = CommandAssessment::default();
    collect_features(profile, &mut assessment);

    if is_dev_tcp_shell_bridge(&assessment) {
        assessment.score = assessment.score.max(90);
        assessment
            .reasons
            .push("/dev/tcp is combined with an interactive shell and fd redirection");
    }
    if is_socket_dup_shell(&assessment) {
        assessment.score = assessment.score.max(90);
        assessment
            .reasons
            .push("inline script uses socket APIs, fd duplication, and a shell target");
    }
    if is_network_shell_exec_bridge(&assessment) {
        assessment.score = assessment.score.max(85);
        assessment
            .reasons
            .push("network channel is bridged directly into a shell execution target");
    }
    if is_network_system_bridge(&assessment) {
        assessment.score = assessment.score.max(75);
        assessment
            .reasons
            .push("network channel is bridged into a system command runner");
    }
    if is_tty_shell_bridge(&assessment) {
        assessment.score = assessment.score.max(80);
        assessment
            .reasons
            .push("network command allocates a TTY for an interactive shell");
    }

    assessment
}

fn collect_features(profile: &CommandProfile, assessment: &mut CommandAssessment) {
    add_feature_if(assessment, CommandFeature::DevTcp, has_dev_tcp(profile));
    add_feature_if(
        assessment,
        CommandFeature::NetworkChannel,
        has_network_channel(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::ExecBridge,
        has_exec_bridge(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::SystemBridge,
        has_system_bridge(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::ShellTarget,
        has_shell_target(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::InteractiveShell,
        has_interactive_shell(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::FdDuplication,
        has_fd_duplication(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::InlineInterpreter,
        has_inline_interpreter(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::SocketApi,
        has_socket_api(profile),
    );
    add_feature_if(
        assessment,
        CommandFeature::TtyAllocation,
        has_tty_allocation(profile),
    );
}

fn add_feature_if(assessment: &mut CommandAssessment, feature: CommandFeature, present: bool) {
    if present {
        assessment.features.insert(feature);
    }
}

fn is_dev_tcp_shell_bridge(assessment: &CommandAssessment) -> bool {
    has_features(
        assessment,
        &[
            CommandFeature::DevTcp,
            CommandFeature::InteractiveShell,
            CommandFeature::FdDuplication,
        ],
    )
}

fn is_socket_dup_shell(assessment: &CommandAssessment) -> bool {
    has_features(
        assessment,
        &[
            CommandFeature::InlineInterpreter,
            CommandFeature::SocketApi,
            CommandFeature::FdDuplication,
            CommandFeature::ShellTarget,
        ],
    )
}

fn is_network_shell_exec_bridge(assessment: &CommandAssessment) -> bool {
    has_features(
        assessment,
        &[
            CommandFeature::NetworkChannel,
            CommandFeature::ExecBridge,
            CommandFeature::ShellTarget,
        ],
    )
}

fn is_network_system_bridge(assessment: &CommandAssessment) -> bool {
    has_features(
        assessment,
        &[CommandFeature::NetworkChannel, CommandFeature::SystemBridge],
    )
}

fn is_tty_shell_bridge(assessment: &CommandAssessment) -> bool {
    has_features(
        assessment,
        &[
            CommandFeature::NetworkChannel,
            CommandFeature::ShellTarget,
            CommandFeature::TtyAllocation,
        ],
    )
}

fn has_features(assessment: &CommandAssessment, features: &[CommandFeature]) -> bool {
    features
        .iter()
        .all(|feature| assessment.features.contains(feature))
}

fn has_dev_tcp(profile: &CommandProfile) -> bool {
    profile.contains_text("/dev/tcp/")
}

fn has_network_channel(profile: &CommandProfile) -> bool {
    has_dev_tcp(profile)
        || profile.any_arg_contains(NETWORK_CHANNEL_MARKERS)
        || contains_ipv4_literal(&profile.lowered)
}

fn has_exec_bridge(profile: &CommandProfile) -> bool {
    profile.has_arg("-e")
        || profile.has_arg("--exec")
        || profile.any_arg_contains(EXEC_BRIDGE_MARKERS)
}

fn has_system_bridge(profile: &CommandProfile) -> bool {
    profile.any_arg_contains(SYSTEM_BRIDGE_MARKERS)
}

fn has_shell_target(profile: &CommandProfile) -> bool {
    profile.any_arg_contains(SHELL_TARGET_MARKERS)
        || SHELL_TARGET_NAMES.iter().any(|name| profile.has_arg(name))
}

fn has_interactive_shell(profile: &CommandProfile) -> bool {
    profile.contains_text("bash -i")
        || profile.contains_text("sh -i")
        || profile.contains_text("zsh -i")
        || profile.contains_text("ash -i")
}

fn has_fd_duplication(profile: &CommandProfile) -> bool {
    profile.contains_text("dup2")
        || profile.contains_text("0>&1")
        || profile.contains_text("1>&2")
        || profile.contains_text(">&")
}

fn has_inline_interpreter(profile: &CommandProfile) -> bool {
    matches!(
        profile.args.first().map(String::as_str),
        Some("python" | "python3" | "perl" | "ruby" | "php")
    ) && (profile.has_arg("-c") || profile.has_arg("-e") || profile.has_arg("-r"))
}

fn has_socket_api(profile: &CommandProfile) -> bool {
    profile.contains_text("socket")
        || profile.contains_text("socket.socket")
        || profile.contains_text("socket_create")
}

fn has_tty_allocation(profile: &CommandProfile) -> bool {
    profile
        .args
        .iter()
        .any(|arg| arg.split(',').any(|part| part == "pty"))
}

#[cfg(test)]
mod tests;
