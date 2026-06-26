use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{path_string, read_tail};
use crate::utils::ip::ip_matches_patterns;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone, Utc};
use glob::glob;
use sentinel_core::{config::WebConfig, RawEvent, SentinelResult};
use serde_json::Value;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub struct WebLogCollector;

#[async_trait]
impl Collector for WebLogCollector {
    fn name(&self) -> &'static str {
        "web_logs"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.web.enabled {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        for (path, source) in web_log_paths(ctx) {
            if !path.exists() {
                continue;
            }
            let content = read_tail(&path, ctx.config.web.max_log_tail_bytes)?;
            for line in content.lines() {
                if !log_line_within_lookback(line, ctx.config.web.log_lookback_seconds) {
                    continue;
                }
                let Some(mut event) =
                    parse_web_log_line_with_config(line, &source, &ctx.config.web)
                else {
                    continue;
                };
                strip_raw_log_line_if_disabled(
                    &mut event,
                    ctx.config.performance.store_raw_log_lines,
                );
                events.push(event);
                if events.len() >= ctx.config.web.max_events_per_scan {
                    return Ok(events);
                }
            }
        }
        Ok(events)
    }
}

fn strip_raw_log_line_if_disabled(event: &mut RawEvent, keep_raw: bool) {
    if !keep_raw {
        event.fields.remove("raw");
    }
}

fn web_log_paths(ctx: &CollectContext) -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    for configured_path in &ctx.config.web.log_paths {
        let source = path_string(configured_path);
        let resolved = ctx.resolve(configured_path);
        if path_string(&resolved).contains('*') {
            if let Ok(matches) = glob(&path_string(&resolved)) {
                for path in matches.filter_map(Result::ok) {
                    paths.push((path, source.clone()));
                }
            }
        } else {
            paths.push((resolved.clone(), source.clone()));
            if ctx.config.web.include_rotated {
                let rotated = rotated_log_path(&resolved);
                paths.push((rotated, format!("{source}.1")));
            }
        }
    }
    paths
}

fn rotated_log_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.1", path_string(path)))
}

pub fn parse_web_log_line(line: &str, source: &str) -> Option<RawEvent> {
    parse_json_access_log_line(line, source)
        .or_else(|| parse_access_log_line(line, source))
        .or_else(|| parse_error_log_line(line, source))
}

fn parse_web_log_line_with_config(
    line: &str,
    source: &str,
    config: &WebConfig,
) -> Option<RawEvent> {
    let mut event =
        parse_json_access_log_line_with_fields(line, source, &config.real_client_ip_fields)
            .or_else(|| parse_access_log_line(line, source))
            .or_else(|| parse_error_log_line(line, source))?;
    normalize_web_client_ip(&mut event, config);
    Some(event)
}

/// Parse a common Nginx/Apache access log line.
pub fn parse_access_log_line(line: &str, source: &str) -> Option<RawEvent> {
    let ip = line.split_whitespace().next()?;
    let request_start = line.find('"')?;
    let request_rest = &line[request_start + 1..];
    let request_end = request_rest.find('"')?;
    let request = &request_rest[..request_end];
    let mut request_parts = request.split_whitespace();
    let method = request_parts.next().unwrap_or("");
    let path = request_parts.next().unwrap_or("");
    let after_request = request_rest[request_end + 1..].trim_start();
    let status = after_request.split_whitespace().next().unwrap_or("");

    if method.is_empty() || path.is_empty() || status.is_empty() {
        return None;
    }

    Some(
        RawEvent::new("web", "web_access")
            .with_field("ip", ip)
            .with_field("method", method)
            .with_field("path", path)
            .with_field("status", status)
            .with_field("log_source", source)
            .with_field("raw", line),
    )
}

pub fn parse_json_access_log_line(line: &str, source: &str) -> Option<RawEvent> {
    parse_json_access_log_line_with_fields(line, source, &[])
}

fn parse_json_access_log_line_with_fields(
    line: &str,
    source: &str,
    real_client_fields: &[String],
) -> Option<RawEvent> {
    let value: Value = serde_json::from_str(line).ok()?;
    let ip = json_string(&value, &["remote_addr"])
        .or_else(|| json_string(&value, &["remote_ip"]))
        .or_else(|| json_string(&value, &["client_ip"]))
        .or_else(|| json_string(&value, &["request", "remote_ip"]))
        .or_else(|| json_string(&value, &["request", "client_ip"]))?;
    let method = json_string(&value, &["method"])
        .or_else(|| json_string(&value, &["request_method"]))
        .or_else(|| json_string(&value, &["request", "method"]));
    let path = json_string(&value, &["path"])
        .or_else(|| json_string(&value, &["uri"]))
        .or_else(|| json_string(&value, &["request_uri"]))
        .or_else(|| json_string(&value, &["request", "uri"]));
    let request = json_string(&value, &["request"]);
    let (method, path) = method
        .zip(path)
        .or_else(|| request.as_deref().and_then(parse_request_target))?;
    let status = json_string(&value, &["status"])
        .or_else(|| json_string(&value, &["status_code"]))
        .unwrap_or_else(|| "000".to_string());

    let mut event = RawEvent::new("web", "web_access")
        .with_field("ip", ip)
        .with_field("method", method)
        .with_field("path", path)
        .with_field("status", status)
        .with_field("log_source", source)
        .with_field("raw", line);
    if let Some(real_client_ip) = real_client_ip_from_json(&value, real_client_fields) {
        event = event.with_field("real_client_ip", real_client_ip);
    }
    Some(event)
}

pub fn parse_error_log_line(line: &str, source: &str) -> Option<RawEvent> {
    let ip = value_after_marker(line, "client: ", ',')?;
    let request = value_after_marker(line, "request: \"", '"')?;
    let (method, path) = parse_request_target(&request)?;
    Some(
        RawEvent::new("web", "web_access")
            .with_field("ip", ip)
            .with_field("method", method)
            .with_field("path", path)
            .with_field("status", "000")
            .with_field("log_source", source)
            .with_field("raw", line),
    )
}

fn json_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    match cursor {
        Value::String(value) if !value.trim().is_empty() => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn real_client_ip_from_json(value: &Value, fields: &[String]) -> Option<String> {
    fields
        .iter()
        .filter_map(|field| json_string_by_dotted_path(value, field))
        .filter_map(|value| first_ip_from_header(&value))
        .find(|ip| ip.parse::<IpAddr>().is_ok())
}

fn json_string_by_dotted_path(value: &Value, path: &str) -> Option<String> {
    let parts = path
        .split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return None;
    }
    json_string(value, &parts)
}

fn first_ip_from_header(value: &str) -> Option<String> {
    value
        .split(',')
        .map(str::trim)
        .find(|candidate| candidate.parse::<IpAddr>().is_ok())
        .map(str::to_string)
}

fn normalize_web_client_ip(event: &mut RawEvent, config: &WebConfig) {
    let Some(original_ip) = event.field("ip").map(str::to_string) else {
        return;
    };
    if !ip_matches_patterns(&original_ip, &config.trusted_proxy_cidrs) {
        return;
    }

    event
        .fields
        .insert("source_is_trusted_proxy".to_string(), "true".to_string());
    event
        .fields
        .insert("proxy_ip".to_string(), original_ip.clone());

    let real_ip = event
        .field("real_client_ip")
        .and_then(first_ip_from_header)
        .filter(|ip| ip != &original_ip);
    if let Some(real_ip) = real_ip {
        event.fields.insert("ip".to_string(), real_ip);
        return;
    }

    if config.suppress_unresolved_trusted_proxy {
        event
            .fields
            .insert("proxy_source_unresolved".to_string(), "true".to_string());
    }
}

fn log_line_within_lookback(line: &str, lookback_seconds: u64) -> bool {
    log_line_within_lookback_at(line, lookback_seconds, Utc::now())
}

fn log_line_within_lookback_at(line: &str, lookback_seconds: u64, now: DateTime<Utc>) -> bool {
    let Some(timestamp) = parse_log_timestamp(line) else {
        return true;
    };
    let max_future_skew = Duration::minutes(5);
    timestamp >= now - Duration::seconds(lookback_seconds as i64)
        && timestamp <= now + max_future_skew
}

fn parse_log_timestamp(line: &str) -> Option<DateTime<Utc>> {
    parse_common_log_timestamp(line)
        .or_else(|| parse_nginx_error_timestamp(line))
        .or_else(|| parse_json_timestamp(line))
}

fn parse_common_log_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let start = line.find('[')?;
    let rest = &line[start + 1..];
    let end = rest.find(']')?;
    DateTime::parse_from_str(&rest[..end], "%d/%b/%Y:%H:%M:%S %z")
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn parse_nginx_error_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let value = line.get(..19)?;
    let timestamp = NaiveDateTime::parse_from_str(value, "%Y/%m/%d %H:%M:%S").ok()?;
    Local
        .from_local_datetime(&timestamp)
        .single()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn parse_json_timestamp(line: &str) -> Option<DateTime<Utc>> {
    let value: Value = serde_json::from_str(line).ok()?;
    for path in [
        &["time"][..],
        &["timestamp"][..],
        &["@timestamp"][..],
        &["datetime"][..],
        &["ts"][..],
        &["request", "time"][..],
    ] {
        let Some(value) = json_string(&value, path) else {
            continue;
        };
        if let Ok(timestamp) = DateTime::parse_from_rfc3339(&value) {
            return Some(timestamp.with_timezone(&Utc));
        }
    }
    None
}

fn parse_request_target(request: &str) -> Option<(String, String)> {
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    (!method.is_empty() && !path.is_empty()).then_some((method, path))
}

fn value_after_marker(line: &str, marker: &str, terminator: char) -> Option<String> {
    let (_, rest) = line.split_once(marker)?;
    let value = rest.split(terminator).next()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        log_line_within_lookback_at, parse_access_log_line, parse_error_log_line,
        parse_json_access_log_line, parse_web_log_line_with_config, strip_raw_log_line_if_disabled,
    };
    use chrono::{TimeZone, Utc};
    use sentinel_core::config::WebConfig;

    #[test]
    fn parses_common_access_log_line() -> Result<(), Box<dyn std::error::Error>> {
        let line = r#"203.0.113.9 - - [16/Jun/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;
        let event = parse_access_log_line(line, "/var/log/nginx/access.log").ok_or("event")?;
        assert_eq!(event.field("ip"), Some("203.0.113.9"));
        assert_eq!(event.field("path"), Some("/.env"));
        assert_eq!(event.field("status"), Some("404"));
        Ok(())
    }

    #[test]
    fn parses_json_access_log_line() -> Result<(), Box<dyn std::error::Error>> {
        let line = r#"{"remote_ip":"198.51.100.8","request":{"method":"POST","uri":"/cgi-bin/luci/;stok=/locale"},"status":403}"#;
        let event = parse_json_access_log_line(line, "/var/log/caddy/access.log").ok_or("event")?;

        assert_eq!(event.field("ip"), Some("198.51.100.8"));
        assert_eq!(event.field("method"), Some("POST"));
        assert_eq!(event.field("path"), Some("/cgi-bin/luci/;stok=/locale"));
        assert_eq!(event.field("status"), Some("403"));
        Ok(())
    }

    #[test]
    fn resolves_real_client_ip_from_trusted_proxy_json_logs(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = WebConfig::default();
        let line = r#"{"remote_ip":"172.70.12.9","request":{"method":"GET","uri":"/.env"},"status":404,"cf_connecting_ip":"198.51.100.8"}"#;
        let event = parse_web_log_line_with_config(line, "/var/log/caddy/access.log", &config)
            .ok_or("event")?;

        assert_eq!(event.field("ip"), Some("198.51.100.8"));
        assert_eq!(event.field("proxy_ip"), Some("172.70.12.9"));
        assert_eq!(event.field("source_is_trusted_proxy"), Some("true"));
        assert_eq!(event.field("proxy_source_unresolved"), None);
        Ok(())
    }

    #[test]
    fn marks_unresolved_trusted_proxy_common_log_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = WebConfig::default();
        let line = r#"172.70.12.9 - - [16/Jun/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;
        let event = parse_web_log_line_with_config(line, "/var/log/nginx/access.log", &config)
            .ok_or("event")?;

        assert_eq!(event.field("ip"), Some("172.70.12.9"));
        assert_eq!(event.field("proxy_ip"), Some("172.70.12.9"));
        assert_eq!(event.field("proxy_source_unresolved"), Some("true"));
        Ok(())
    }

    #[test]
    fn parses_nginx_error_log_request_context() -> Result<(), Box<dyn std::error::Error>> {
        let line = r#"2026/06/18 10:00:00 [error] 1#1: *1 open() "/var/www/.env" failed (2: No such file or directory), client: 203.0.113.7, server: _, request: "GET /.env HTTP/1.1", host: "example.com""#;
        let event = parse_error_log_line(line, "/var/log/nginx/error.log").ok_or("event")?;

        assert_eq!(event.field("ip"), Some("203.0.113.7"));
        assert_eq!(event.field("method"), Some("GET"));
        assert_eq!(event.field("path"), Some("/.env"));
        assert_eq!(event.field("status"), Some("000"));
        Ok(())
    }

    #[test]
    fn strips_raw_log_line_when_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let line = r#"203.0.113.9 - - [16/Jun/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;
        let mut event = parse_access_log_line(line, "/var/log/nginx/access.log").ok_or("event")?;
        assert!(event.field("raw").is_some());

        strip_raw_log_line_if_disabled(&mut event, false);

        assert!(event.field("raw").is_none());
        assert_eq!(event.field("path"), Some("/.env"));
        Ok(())
    }

    #[test]
    fn filters_rotated_log_lines_outside_lookback() {
        let now = Utc.with_ymd_and_hms(2026, 6, 19, 0, 10, 0).unwrap();
        let old = r#"203.0.113.9 - - [18/Jun/2026:23:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;
        let recent = r#"203.0.113.9 - - [19/Jun/2026:00:05:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;

        assert!(!log_line_within_lookback_at(old, 900, now));
        assert!(log_line_within_lookback_at(recent, 900, now));
    }
}
