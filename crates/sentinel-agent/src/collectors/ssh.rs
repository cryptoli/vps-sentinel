use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{path_string, read_tail};
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration, Local, TimeZone};
use sentinel_core::{RawEvent, SentinelResult};
use std::process::Command;

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
        let now = Local::now();
        let lookback = Duration::seconds(ctx.config.ssh.auth_log_lookback_seconds as i64);
        let mut existing_auth_logs = 0usize;
        for configured_path in &ctx.config.ssh.auth_log_paths {
            let path = ctx.resolve(configured_path);
            if !path.exists() {
                continue;
            }
            existing_auth_logs += 1;
            let source = path_string(configured_path);
            let content = read_tail(&path, MAX_AUTH_LOG_BYTES)?;
            events.extend(
                content
                    .lines()
                    .filter(|line| auth_line_is_recent(line, now, lookback))
                    .filter_map(|line| parse_ssh_line(line, &source)),
            );
        }
        if existing_auth_logs == 0 {
            events.extend(collect_journalctl_ssh(now, lookback));
        }
        Ok(events)
    }
}

fn collect_journalctl_ssh(now: DateTime<Local>, lookback: Duration) -> Vec<RawEvent> {
    let since_arg = format!("@{}", (now - lookback).timestamp());
    let Ok(output) = Command::new("journalctl")
        .args([
            "-u",
            "ssh.service",
            "-u",
            "sshd.service",
            "--since",
            &since_arg,
            "--no-pager",
            "-o",
            "short-iso",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| parse_ssh_line(line, "journalctl:ssh"))
        .collect()
}

fn auth_line_is_recent(line: &str, now: DateTime<Local>, lookback: Duration) -> bool {
    parse_syslog_timestamp(line, now)
        .map(|timestamp| timestamp >= now - lookback)
        .unwrap_or(true)
}

fn parse_syslog_timestamp(line: &str, now: DateTime<Local>) -> Option<DateTime<Local>> {
    if line.len() < 15 {
        return None;
    }
    let stamp = &line[..15];
    let month = month_number(stamp.get(0..3)?)?;
    let day = stamp.get(4..6)?.trim().parse::<u32>().ok()?;
    let hour = stamp.get(7..9)?.parse::<u32>().ok()?;
    let minute = stamp.get(10..12)?.parse::<u32>().ok()?;
    let second = stamp.get(13..15)?.parse::<u32>().ok()?;
    let candidate = Local
        .with_ymd_and_hms(now.year(), month, day, hour, minute, second)
        .single()?;
    if candidate > now + Duration::days(1) {
        Local
            .with_ymd_and_hms(now.year() - 1, month, day, hour, minute, second)
            .single()
    } else {
        Some(candidate)
    }
}

fn month_number(name: &str) -> Option<u32> {
    match name {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
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
    use super::{auth_line_is_recent, parse_ssh_line};
    use chrono::{Duration, Local, TimeZone};

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
    fn parses_journalctl_short_iso_login() -> Result<(), Box<dyn std::error::Error>> {
        let line = "2026-06-16T10:00:01+08:00 host sshd[123]: Accepted publickey for deploy from 203.0.113.10 port 54122 ssh2";
        let event = parse_ssh_line(line, "journalctl:ssh").ok_or("expected ssh event")?;
        assert_eq!(event.field("outcome"), Some("success"));
        assert_eq!(event.field("method"), Some("publickey"));
        assert_eq!(event.field("user"), Some("deploy"));
        assert_eq!(event.field("log_source"), Some("journalctl:ssh"));
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

    #[test]
    fn filters_auth_lines_by_recent_syslog_timestamp() -> Result<(), Box<dyn std::error::Error>> {
        let now = Local
            .with_ymd_and_hms(2026, 6, 16, 10, 5, 0)
            .single()
            .ok_or("valid local time")?;
        assert!(auth_line_is_recent(
            "Jun 16 10:04:30 host sshd[123]: Accepted publickey for deploy from 203.0.113.10 port 54122 ssh2",
            now,
            Duration::seconds(300),
        ));
        assert!(!auth_line_is_recent(
            "Jun 16 09:30:00 host sshd[123]: Accepted publickey for deploy from 203.0.113.10 port 54122 ssh2",
            now,
            Duration::seconds(300),
        ));
        assert!(auth_line_is_recent(
            "unrecognized timestamp Accepted publickey for deploy from 203.0.113.10 port 54122 ssh2",
            now,
            Duration::seconds(300),
        ));
        Ok(())
    }
}
