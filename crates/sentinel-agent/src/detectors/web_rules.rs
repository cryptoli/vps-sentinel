use crate::detectors::{evidence, field_is_allowlisted, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::BTreeMap;

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

        for event in events.iter().filter(|event| event.kind == "web_access") {
            let ip = string_field(event, "ip");
            if field_is_allowlisted(&ip, &ctx.config.allowlist.ips) {
                continue;
            }
            let path = string_field(event, "path");
            if is_probe_path(&path) || contains_attack_payload(&path) {
                findings.push(web_probe(event, ctx));
            }
            if matches!(event.field("status"), Some("403") | Some("404")) {
                *errors_by_ip.entry(ip).or_insert(0) += 1;
            }
        }

        for (ip, count) in errors_by_ip {
            if count >= 20 {
                findings.push(web_error_burst(&ip, count, ctx));
            }
        }
        findings
    }
}

fn web_probe(event: &RawEvent, ctx: &DetectContext) -> Finding {
    Finding::new(
        &ctx.host_id,
        "Web vulnerability probe detected",
        "A web request path matches common vulnerability scanning patterns.",
        Severity::Medium,
        Category::Web,
        "WEB-001",
        format!(
            "{} {}",
            string_field(event, "method"),
            string_field(event, "path")
        ),
    )
    .with_evidence(vec![
        evidence("ip", string_field(event, "ip")),
        evidence("method", string_field(event, "method")),
        evidence("path", string_field(event, "path")),
        evidence("status", string_field(event, "status")),
        evidence("log_source", string_field(event, "log_source")),
    ])
    .with_recommendations(vec![
        "Review whether any probe path returned a successful response.".to_string(),
        "Correlate with file changes and process anomalies around the same time.".to_string(),
    ])
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

fn is_probe_path(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    [
        ".env",
        "wp-admin",
        "phpmyadmin",
        "boaform",
        "cgi-bin",
        "actuator",
        "server-status",
        "vendor/phpunit",
        "/.git",
        "/etc/passwd",
        "../",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

fn contains_attack_payload(path: &str) -> bool {
    let lowered = path
        .to_ascii_lowercase()
        .replace("%20", " ")
        .replace('+', " ");
    [";wget", ";curl", "`curl", " or 1=1", "union select", "$("]
        .iter()
        .any(|marker| lowered.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{contains_attack_payload, is_probe_path};

    #[test]
    fn recognizes_common_web_probe_paths() {
        assert!(is_probe_path("/.env"));
        assert!(is_probe_path(
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        ));
        assert!(contains_attack_payload("/index.php?q=1%20union%20select"));
        assert!(!is_probe_path("/assets/app.css"));
    }
}
