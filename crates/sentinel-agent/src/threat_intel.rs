use sentinel_core::{Evidence, Finding, SentinelConfig};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;
use tracing::warn;

#[derive(Debug, Clone, Default)]
pub struct ThreatIntelSet {
    ips: BTreeSet<String>,
    paths: BTreeSet<String>,
    hashes: BTreeSet<String>,
    domains: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct JsonIndicator {
    #[serde(default)]
    r#type: String,
    value: String,
}

pub async fn load_threat_intel(config: &SentinelConfig) -> ThreatIntelSet {
    if !config.threat_intel.enabled {
        return ThreatIntelSet::default();
    }
    let mut set = ThreatIntelSet::default();
    for path in &config.threat_intel.indicator_paths {
        match fs::read_to_string(path) {
            Ok(text) => set.extend(parse_indicators(&text)),
            Err(err) => {
                warn!(path = %path.display(), error = %err, "failed to read threat intel indicator file")
            }
        }
    }
    if !config.threat_intel.url.trim().is_empty() {
        match fetch_remote_indicators(config).await {
            Some(text) => set.extend(parse_indicators(&text)),
            None => warn!("failed to fetch remote threat intel indicators"),
        }
    }
    set
}

pub fn enrich_findings(findings: &mut [Finding], intel: &ThreatIntelSet) {
    if intel.is_empty() {
        return;
    }
    for finding in findings {
        let matches = intel.matches_finding(finding);
        if matches.is_empty() {
            continue;
        }
        upsert_evidence(&mut finding.evidence, "threat_intel_match", "true");
        upsert_evidence(
            &mut finding.evidence,
            "threat_intel_matches",
            matches.join(", "),
        );
    }
}

impl ThreatIntelSet {
    fn extend(&mut self, other: ThreatIntelSet) {
        self.ips.extend(other.ips);
        self.paths.extend(other.paths);
        self.hashes.extend(other.hashes);
        self.domains.extend(other.domains);
    }

    fn is_empty(&self) -> bool {
        self.ips.is_empty()
            && self.paths.is_empty()
            && self.hashes.is_empty()
            && self.domains.is_empty()
    }

    fn matches_finding(&self, finding: &Finding) -> Vec<String> {
        let mut matches = BTreeSet::new();
        for evidence in &finding.evidence {
            let value = evidence.value.trim();
            if value.is_empty() {
                continue;
            }
            if self.ips.contains(value) {
                matches.insert(format!("ip:{value}"));
            }
            if self.paths.contains(value) {
                matches.insert(format!("path:{value}"));
            }
            if self.hashes.contains(value) {
                matches.insert(format!("hash:{value}"));
            }
            let lowered = value.to_ascii_lowercase();
            if self.hashes.contains(&lowered) {
                matches.insert(format!("hash:{value}"));
            }
            if self.domains.contains(&lowered) {
                matches.insert(format!("domain:{value}"));
            }
        }
        matches.into_iter().collect()
    }
}

fn parse_indicators(text: &str) -> ThreatIntelSet {
    let mut set = ThreatIntelSet::default();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(indicator) = serde_json::from_str::<JsonIndicator>(line) {
            insert_indicator(&mut set, &indicator.r#type, &indicator.value);
            continue;
        }
        insert_indicator(&mut set, "", line);
    }
    set
}

fn insert_indicator(set: &mut ThreatIntelSet, kind: &str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    match normalized_indicator_kind(kind, value) {
        "ip" => {
            set.ips.insert(value.to_string());
        }
        "path" => {
            set.paths.insert(value.to_string());
        }
        "hash" => {
            set.hashes.insert(value.to_ascii_lowercase());
        }
        "domain" => {
            set.domains.insert(value.to_ascii_lowercase());
        }
        _ => {}
    }
}

fn normalized_indicator_kind(kind: &str, value: &str) -> &'static str {
    let kind = kind.trim().to_ascii_lowercase();
    if kind == "ip" || kind == "path" || kind == "hash" || kind == "domain" {
        return match kind.as_str() {
            "ip" => "ip",
            "path" => "path",
            "hash" => "hash",
            "domain" => "domain",
            _ => "",
        };
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return "ip";
    }
    if value.starts_with('/') {
        return "path";
    }
    if value.len() >= 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return "hash";
    }
    if value.contains('.') && !value.contains('/') {
        return "domain";
    }
    ""
}

async fn fetch_remote_indicators(config: &SentinelConfig) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            config.threat_intel.request_timeout_seconds,
        ))
        .build()
        .ok()?;
    let mut request = client.get(config.threat_intel.url.trim());
    if !config.threat_intel.api_key_env.trim().is_empty() {
        if let Ok(token) = std::env::var(config.threat_intel.api_key_env.trim()) {
            request = request.bearer_auth(token);
        }
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}

fn upsert_evidence(evidence: &mut Vec<Evidence>, key: &str, value: impl Into<String>) {
    let value = value.into();
    if let Some(existing) = evidence.iter_mut().find(|item| item.key == key) {
        existing.value = value;
        return;
    }
    evidence.push(Evidence::new(key, value));
}

#[cfg(test)]
mod tests {
    use super::{enrich_findings, parse_indicators};
    use sentinel_core::{Category, Evidence, Finding, Severity};

    #[test]
    fn enriches_finding_when_indicator_matches_evidence() {
        let intel = parse_indicators("8.8.8.8\n{\"type\":\"path\",\"value\":\"/tmp/a\"}\n");
        let mut findings = vec![Finding::new(
            "host",
            "test",
            "test",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            "8.8.8.8",
        )
        .with_evidence(vec![Evidence::new("source_ip", "8.8.8.8")])];

        enrich_findings(&mut findings, &intel);

        assert!(findings[0]
            .evidence
            .iter()
            .any(|item| item.key == "threat_intel_match" && item.value == "true"));
    }
}
