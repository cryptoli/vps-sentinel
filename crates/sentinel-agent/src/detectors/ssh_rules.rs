use crate::detectors::{evidence, field_is_allowlisted, string_field, DetectContext, Detector};
use crate::rules::model::RuleMetadata;
use sentinel_core::{Category, Finding, RawEvent, Severity};
use std::collections::{BTreeMap, BTreeSet};

pub struct SshDetector;

impl Detector for SshDetector {
    fn name(&self) -> &'static str {
        "ssh_rules"
    }

    fn rules(&self) -> Vec<RuleMetadata> {
        vec![
            RuleMetadata::new(
                "SSH-001",
                "Root SSH login detected",
                Category::Ssh,
                Severity::High,
                "Root logged in through SSH.",
            ),
            RuleMetadata::new(
                "SSH-002",
                "Password-based SSH login detected",
                Category::Ssh,
                Severity::Medium,
                "A successful SSH login used password authentication.",
            ),
            RuleMetadata::new(
                "SSH-003",
                "Brute force login attempts",
                Category::Ssh,
                Severity::High,
                "Many failed SSH logins were observed from one source IP.",
            ),
        ]
    }

    fn detect(&self, events: &[RawEvent], ctx: &DetectContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut failures: BTreeMap<String, (usize, BTreeSet<String>)> = BTreeMap::new();

        for event in events.iter().filter(|event| event.kind == "ssh_auth") {
            let ip = string_field(event, "source_ip");
            let user = string_field(event, "user");
            if field_is_allowlisted(&ip, &ctx.config.allowlist.ips)
                || field_is_allowlisted(&user, &ctx.config.allowlist.users)
            {
                continue;
            }

            match event.field("outcome") {
                Some("success") => {
                    if ctx.config.ssh.alert_on_root_login && user == "root" {
                        findings.push(root_login_finding(event, ctx));
                    }
                    if ctx.config.ssh.alert_on_password_login
                        && event.field("method") == Some("password")
                    {
                        findings.push(password_login_finding(event, ctx));
                    }
                }
                Some("failure") => {
                    let entry = failures.entry(ip).or_insert_with(|| (0, BTreeSet::new()));
                    entry.0 += 1;
                    entry.1.insert(user);
                }
                _ => {}
            }
        }

        for (ip, (count, users)) in failures {
            if count >= ctx.config.ssh.failed_login_threshold {
                findings.push(bruteforce_finding(&ip, count, users, ctx));
            }
        }
        findings
    }
}

fn root_login_finding(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let ip = string_field(event, "source_ip");
    Finding::new(
        &ctx.host_id,
        "Root SSH login detected",
        "The root account successfully authenticated through SSH.",
        Severity::High,
        Category::Ssh,
        "SSH-001",
        format!("root@{ip}"),
    )
    .with_evidence(vec![
        evidence("user", "root"),
        evidence("source_ip", ip),
        evidence("method", string_field(event, "method")),
        evidence("log_source", string_field(event, "log_source")),
    ])
    .with_impact(vec![
        "Root SSH access bypasses per-user accountability and increases blast radius.".to_string(),
    ])
    .with_recommendations(vec![
        "Confirm the login source and time with the expected administrator.".to_string(),
        "Disable direct root SSH login if it is not required.".to_string(),
        "Rotate credentials if the login is unexpected.".to_string(),
    ])
}

fn password_login_finding(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let user = string_field(event, "user");
    let ip = string_field(event, "source_ip");
    Finding::new(
        &ctx.host_id,
        "Password-based SSH login detected",
        "A successful SSH login used password authentication.",
        Severity::Medium,
        Category::Ssh,
        "SSH-002",
        format!("{user}@{ip}"),
    )
    .with_evidence(vec![
        evidence("user", user),
        evidence("source_ip", ip),
        evidence("method", "password"),
        evidence("log_source", string_field(event, "log_source")),
    ])
    .with_impact(vec![
        "Password SSH login is more exposed to credential stuffing and brute force.".to_string(),
    ])
    .with_recommendations(vec![
        "Verify the login was expected.".to_string(),
        "Prefer key-based SSH authentication and disable password login when practical."
            .to_string(),
    ])
}

fn bruteforce_finding(
    ip: &str,
    count: usize,
    users: BTreeSet<String>,
    ctx: &DetectContext,
) -> Finding {
    Finding::new(
        &ctx.host_id,
        "SSH brute force pattern detected",
        "A single source IP generated many failed SSH login attempts in the scanned log window.",
        Severity::High,
        Category::Ssh,
        "SSH-003",
        ip,
    )
    .with_evidence(vec![
        evidence("source_ip", ip),
        evidence("failure_count", count.to_string()),
        evidence("users", users.into_iter().collect::<Vec<_>>().join(",")),
    ])
    .with_impact(vec![
        "Repeated failures may indicate active SSH password guessing.".to_string(),
    ])
    .with_recommendations(vec![
        "Review SSH exposure, fail2ban or firewall rules, and account lockout policy.".to_string(),
        "Check for any successful login from the same source.".to_string(),
    ])
}
