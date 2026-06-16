use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{path_string, read_tail};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};

const MAX_AUTH_LOG_BYTES: u64 = 1024 * 1024;

pub struct SshLogCollector;

#[async_trait]
impl Collector for SshLogCollector {
    fn name(&self) -> &'static str {
        "ssh_log"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.ssh.enabled {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        for configured_path in &ctx.config.ssh.auth_log_paths {
            let path = ctx.resolve(configured_path);
            if !path.exists() {
                continue;
            }
            let source = path_string(configured_path);
            let content = read_tail(&path, MAX_AUTH_LOG_BYTES)?;
            events.extend(
                content
                    .lines()
                    .filter_map(|line| parse_ssh_line(line, &source)),
            );
        }
        Ok(events)
    }
}

/// Parse one OpenSSH auth log line into a raw event.
pub fn parse_ssh_line(line: &str, source: &str) -> Option<RawEvent> {
    if let Some(rest) = line.split_once("Accepted ").map(|(_, rest)| rest) {
        return parse_accepted(rest, line, source);
    }
    if let Some(rest) = line.split_once("Failed ").map(|(_, rest)| rest) {
        return parse_failed(rest, line, source);
    }
    None
}

fn parse_accepted(rest: &str, raw: &str, source: &str) -> Option<RawEvent> {
    let (method, after_method) = rest.split_once(" for ")?;
    let (user, after_user) = after_method.split_once(" from ")?;
    let (ip, after_ip) = after_user.split_once(" port ")?;
    let port = after_ip.split_whitespace().next().unwrap_or("");
    Some(
        RawEvent::new("ssh", "ssh_auth")
            .with_field("outcome", "success")
            .with_field("method", method)
            .with_field("user", user)
            .with_field("source_ip", ip)
            .with_field("port", port)
            .with_field("log_source", source)
            .with_field("raw", raw),
    )
}

fn parse_failed(rest: &str, raw: &str, source: &str) -> Option<RawEvent> {
    let (method, after_method) = rest.split_once(" for ")?;
    let after_user_marker = after_method
        .strip_prefix("invalid user ")
        .unwrap_or(after_method);
    let (user, after_user) = after_user_marker.split_once(" from ")?;
    let (ip, after_ip) = after_user.split_once(" port ")?;
    let port = after_ip.split_whitespace().next().unwrap_or("");
    Some(
        RawEvent::new("ssh", "ssh_auth")
            .with_field("outcome", "failure")
            .with_field("method", method)
            .with_field("user", user)
            .with_field("source_ip", ip)
            .with_field("port", port)
            .with_field("log_source", source)
            .with_field("raw", raw),
    )
}

#[cfg(test)]
mod tests {
    use super::parse_ssh_line;

    #[test]
    fn parses_successful_password_login() -> Result<(), Box<dyn std::error::Error>> {
        let line = "Jun 16 10:00:01 host sshd[123]: Accepted password for root from 203.0.113.10 port 54122 ssh2";
        let event = parse_ssh_line(line, "/var/log/auth.log").ok_or("expected ssh event")?;
        assert_eq!(event.field("outcome"), Some("success"));
        assert_eq!(event.field("method"), Some("password"));
        assert_eq!(event.field("user"), Some("root"));
        assert_eq!(event.field("source_ip"), Some("203.0.113.10"));
        Ok(())
    }

    #[test]
    fn parses_failed_invalid_user_login() -> Result<(), Box<dyn std::error::Error>> {
        let line = "Jun 16 10:00:01 host sshd[123]: Failed password for invalid user admin from 198.51.100.8 port 52100 ssh2";
        let event = parse_ssh_line(line, "/var/log/auth.log").ok_or("expected ssh event")?;
        assert_eq!(event.field("outcome"), Some("failure"));
        assert_eq!(event.field("user"), Some("admin"));
        assert_eq!(event.field("source_ip"), Some("198.51.100.8"));
        Ok(())
    }
}
