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
            RuleMetadata::new(
                "SSH-004",
                "SSH login detected",
                Category::Ssh,
                Severity::Info,
                "A user successfully authenticated through SSH.",
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
                    let root_alerted = ctx.config.ssh.alert_on_root_login && user == "root";
                    let password_alerted = ctx.config.ssh.alert_on_password_login
                        && event.field("method") == Some("password");
                    if root_alerted {
                        findings.push(root_login_finding(event, ctx));
                    } else if password_alerted {
                        findings.push(password_login_finding(event, ctx));
                    } else if ctx.config.ssh.alert_on_successful_login {
                        findings.push(successful_login_finding(event, ctx));
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

fn successful_login_finding(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let user = string_field(event, "user");
    let ip = string_field(event, "source_ip");
    Finding::new(
        &ctx.host_id,
        "SSH login detected",
        "A user successfully authenticated through SSH.",
        Severity::Info,
        Category::Ssh,
        "SSH-004",
        login_subject(&user, &ip, event),
    )
    .with_evidence_deduped_by(
        vec![
            evidence("user", user),
            evidence("source_ip", ip),
            evidence("port", string_field(event, "port")),
            evidence("method", string_field(event, "method")),
            evidence("log_source", string_field(event, "log_source")),
        ],
        &["user", "source_ip", "method"],
    )
    .with_recommendations(vec![
        "Confirm the login source, account, and time are expected.".to_string(),
        "Review recent commands and SSH key ownership if the login is unexpected.".to_string(),
    ])
}

fn root_login_finding(event: &RawEvent, ctx: &DetectContext) -> Finding {
    let ip = string_field(event, "source_ip");
    let password_login = event.field("method") == Some("password");
    let mut finding = Finding::new(
        &ctx.host_id,
        if password_login {
            "Root password SSH login detected"
        } else {
            "Root SSH login detected"
        },
        if password_login {
            "The root account successfully authenticated through SSH using password authentication."
        } else {
            "The root account successfully authenticated through SSH."
        },
        Severity::High,
        Category::Ssh,
        "SSH-001",
        login_subject("root", &ip, event),
    )
    .with_evidence_deduped_by(
        vec![
            evidence("user", "root"),
            evidence("source_ip", ip),
            evidence("port", string_field(event, "port")),
            evidence("method", string_field(event, "method")),
            evidence("log_source", string_field(event, "log_source")),
        ],
        &["user", "source_ip", "method"],
    )
    .with_impact(vec![
        "Root SSH access bypasses per-user accountability and increases blast radius.".to_string(),
    ])
    .with_recommendations(vec![
        "Confirm the login source and time with the expected administrator.".to_string(),
        "Disable direct root SSH login if it is not required.".to_string(),
        "Rotate credentials if the login is unexpected.".to_string(),
    ]);
    if password_login {
        finding.impact.push(
            "Password SSH login is more exposed to credential stuffing and brute force."
                .to_string(),
        );
        finding.recommendations.push(
            "Prefer key-based SSH authentication and disable password login when practical."
                .to_string(),
        );
    }
    finding
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
        login_subject(&user, &ip, event),
    )
    .with_evidence_deduped_by(
        vec![
            evidence("user", user),
            evidence("source_ip", ip),
            evidence("port", string_field(event, "port")),
            evidence("method", "password"),
            evidence("log_source", string_field(event, "log_source")),
        ],
        &["user", "source_ip", "method"],
    )
    .with_impact(vec![
        "Password SSH login is more exposed to credential stuffing and brute force.".to_string(),
    ])
    .with_recommendations(vec![
        "Verify the login was expected.".to_string(),
        "Prefer key-based SSH authentication and disable password login when practical."
            .to_string(),
    ])
}

fn login_subject(user: &str, ip: &str, _event: &RawEvent) -> String {
    format!("{user}@{ip}")
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
    .with_evidence_deduped_by(
        vec![
            evidence("source_ip", ip),
            evidence("failure_count", count.to_string()),
            evidence("users", users.into_iter().collect::<Vec<_>>().join(",")),
        ],
        &["source_ip"],
    )
    .with_impact(vec![
        "Repeated failures may indicate active SSH password guessing.".to_string(),
    ])
    .with_recommendations(vec![
        "Review SSH exposure, fail2ban or firewall rules, and account lockout policy.".to_string(),
        "Check for any successful login from the same source.".to_string(),
    ])
}

#[cfg(test)]
mod tests {
    use super::SshDetector;
    use crate::detectors::{DetectContext, Detector};
    use sentinel_core::{RawEvent, SentinelConfig};
    use std::sync::Arc;

    #[test]
    fn reports_non_root_key_successful_login() {
        let detector = SshDetector;
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let findings = detector.detect(&[success_event("deploy", "publickey")], &ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SSH-004");
        assert_eq!(findings[0].subject, "deploy@203.0.113.10");
    }

    #[test]
    fn does_not_duplicate_root_or_password_login() {
        let detector = SshDetector;
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let root_findings = detector.detect(&[success_event("root", "publickey")], &ctx);
        assert_eq!(root_findings.len(), 1);
        assert_eq!(root_findings[0].rule_id, "SSH-001");

        let root_password_findings = detector.detect(&[success_event("root", "password")], &ctx);
        assert_eq!(root_password_findings.len(), 1);
        assert_eq!(root_password_findings[0].rule_id, "SSH-001");
        assert!(root_password_findings[0]
            .recommendations
            .iter()
            .any(|item| item.contains("disable password login")));

        let password_findings = detector.detect(&[success_event("deploy", "password")], &ctx);
        assert_eq!(password_findings.len(), 1);
        assert_eq!(password_findings[0].rule_id, "SSH-002");
    }

    #[test]
    fn brute_force_dedup_ignores_volatile_failure_count() {
        let detector = SshDetector;
        let ctx = DetectContext::new(Arc::new(SentinelConfig::default()));
        let first = detector.detect(
            &(0..10)
                .map(|index| failure_event("203.0.113.20", &format!("user{index}")))
                .collect::<Vec<_>>(),
            &ctx,
        );
        let second = detector.detect(
            &(0..20)
                .map(|index| failure_event("203.0.113.20", &format!("user{index}")))
                .collect::<Vec<_>>(),
            &ctx,
        );

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].dedup_key, second[0].dedup_key);
    }

    fn success_event(user: &str, method: &str) -> RawEvent {
        RawEvent::new("ssh", "ssh_auth")
            .with_field("outcome", "success")
            .with_field("method", method)
            .with_field("user", user)
            .with_field("source_ip", "203.0.113.10")
            .with_field("port", "54122")
            .with_field("log_source", "/var/log/auth.log")
    }

    fn failure_event(ip: &str, user: &str) -> RawEvent {
        RawEvent::new("ssh", "ssh_auth")
            .with_field("outcome", "failure")
            .with_field("method", "password")
            .with_field("user", user)
            .with_field("source_ip", ip)
            .with_field("log_source", "/var/log/auth.log")
    }
}
