use sentinel_core::{evidence_schema::keys, Category, Severity};
use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOwner {
    Ssh,
    Web,
    Process,
    Network,
    FileIntegrity,
    Persistence,
    User,
    Privilege,
    Tamper,
    Rootkit,
    Docker,
    ConfigRisk,
    ServiceProfile,
    ActiveResponse,
    Report,
}

impl RuleOwner {
    pub fn from_rule(rule_id: &str, category: &Category) -> Self {
        let prefix = rule_id
            .split_once('-')
            .map(|(prefix, _)| prefix)
            .unwrap_or("");
        match prefix {
            "SSH" => Self::Ssh,
            "WEB" => Self::Web,
            "PROC" => Self::Process,
            "NET" => Self::Network,
            "FILE" => Self::FileIntegrity,
            "PERSIST" => Self::Persistence,
            "USER" => Self::User,
            "PRIV" => Self::Privilege,
            "TAMPER" => Self::Tamper,
            "ROOTKIT" => Self::Rootkit,
            "DOCKER" => Self::Docker,
            "CONFIG" => Self::ConfigRisk,
            "SERVICE" => Self::ServiceProfile,
            "ACTIVE" => Self::ActiveResponse,
            "REPORT" => Self::Report,
            _ => Self::from_category(category),
        }
    }

    pub fn from_category(category: &Category) -> Self {
        match category {
            Category::Ssh => Self::Ssh,
            Category::User => Self::User,
            Category::Privilege => Self::Privilege,
            Category::Persistence => Self::Persistence,
            Category::Process => Self::Process,
            Category::Network => Self::Network,
            Category::FileIntegrity => Self::FileIntegrity,
            Category::Web => Self::Web,
            Category::Docker => Self::Docker,
            Category::Rootkit => Self::Rootkit,
            Category::ConfigRisk => Self::ConfigRisk,
            Category::System => Self::Report,
        }
    }

    pub fn compatible_category(self, category: &Category) -> bool {
        matches!(
            (self, category),
            (Self::Ssh, Category::Ssh)
                | (Self::Web, Category::Web)
                | (Self::Process, Category::Process)
                | (Self::Network | Self::ServiceProfile, Category::Network)
                | (Self::FileIntegrity, Category::FileIntegrity)
                | (Self::Persistence, Category::Persistence)
                | (Self::User, Category::User | Category::Privilege)
                | (Self::Privilege, Category::Privilege)
                | (Self::Tamper, Category::System)
                | (Self::Rootkit, Category::Rootkit)
                | (Self::Docker, Category::Docker)
                | (Self::ConfigRisk, Category::ConfigRisk)
                | (Self::ActiveResponse | Self::Report, Category::System)
        )
    }
}

impl Display for RuleOwner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Ssh => "ssh",
            Self::Web => "web",
            Self::Process => "process",
            Self::Network => "network",
            Self::FileIntegrity => "file_integrity",
            Self::Persistence => "persistence",
            Self::User => "user",
            Self::Privilege => "privilege",
            Self::Tamper => "tamper",
            Self::Rootkit => "rootkit",
            Self::Docker => "docker",
            Self::ConfigRisk => "config_risk",
            Self::ServiceProfile => "service_profile",
            Self::ActiveResponse => "active_response",
            Self::Report => "report",
        };
        f.write_str(text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleResponseScope {
    FindingOnly,
    ActiveResponseCandidate,
    SystemSummary,
    Report,
}

impl Display for RuleResponseScope {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::FindingOnly => "finding_only",
            Self::ActiveResponseCandidate => "active_response_candidate",
            Self::SystemSummary => "system_summary",
            Self::Report => "report",
        };
        f.write_str(text)
    }
}

/// Static metadata for one built-in detection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub title: &'static str,
    pub category: Category,
    pub default_severity: Severity,
    pub description: &'static str,
    pub owner: RuleOwner,
    pub response_scope: RuleResponseScope,
    pub evidence_keys: &'static [&'static str],
}

impl RuleMetadata {
    pub fn new(
        id: &'static str,
        title: &'static str,
        category: Category,
        default_severity: Severity,
        description: &'static str,
    ) -> Self {
        let owner = RuleOwner::from_rule(id, &category);
        Self {
            id,
            title,
            category,
            default_severity,
            description,
            owner,
            response_scope: default_response_scope(id),
            evidence_keys: default_evidence_keys(owner),
        }
    }

    pub fn with_evidence_keys(mut self, evidence_keys: &'static [&'static str]) -> Self {
        self.evidence_keys = evidence_keys;
        self
    }

    pub fn with_response_scope(mut self, response_scope: RuleResponseScope) -> Self {
        self.response_scope = response_scope;
        self
    }
}

fn default_response_scope(rule_id: &str) -> RuleResponseScope {
    match rule_id {
        "WEB-001" | "WEB-002" | "SSH-003" | "SSH-007" => RuleResponseScope::ActiveResponseCandidate,
        "ACTIVE-001" => RuleResponseScope::SystemSummary,
        "REPORT-001" => RuleResponseScope::Report,
        _ => RuleResponseScope::FindingOnly,
    }
}

fn default_evidence_keys(owner: RuleOwner) -> &'static [&'static str] {
    match owner {
        RuleOwner::Ssh => &[keys::SOURCE_IP, keys::USER, keys::FAILURE_COUNT],
        RuleOwner::Web => &[
            keys::SOURCE_IP,
            keys::PROBE_FAMILY,
            keys::RESPONSE_PROFILE,
            keys::REQUEST_COUNT,
            keys::SAMPLE_PATHS,
        ],
        RuleOwner::Process => &[
            keys::PROCESS_NAME,
            keys::EXE_PATH,
            keys::CMDLINE,
            keys::EXE_HASH_BLAKE3,
        ],
        RuleOwner::Network | RuleOwner::ServiceProfile => &[
            keys::PROCESS_NAME,
            keys::EXE_PATH,
            keys::PATH,
            keys::ACTIVE_RESPONSE_IP,
        ],
        RuleOwner::FileIntegrity | RuleOwner::Persistence | RuleOwner::Tamper => {
            &[keys::PATH, keys::PACKAGE_OWNER, keys::SYSTEMD_UNIT]
        }
        RuleOwner::User | RuleOwner::Privilege => &[keys::USER],
        RuleOwner::Rootkit | RuleOwner::Docker | RuleOwner::ConfigRisk => &[keys::PATH],
        RuleOwner::ActiveResponse => &[
            keys::ACTIVE_RESPONSE_STATUS,
            keys::ACTIVE_RESPONSE_IP,
            keys::SOURCE_IP,
        ],
        RuleOwner::Report => &[],
    }
}
