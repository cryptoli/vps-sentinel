use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{path_string, read_tail};
use async_trait::async_trait;
use glob::glob;
use sentinel_core::{RawEvent, SentinelResult};
use serde_json::Value;
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
            events.extend(
                content
                    .lines()
                    .filter_map(|line| parse_web_log_line(line, &source)),
            );
        }
        Ok(events)
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
    use super::{parse_access_log_line, parse_error_log_line, parse_json_access_log_line};

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
    fn parses_nginx_error_log_request_context() -> Result<(), Box<dyn std::error::Error>> {
        let line = r#"2026/06/18 10:00:00 [error] 1#1: *1 open() "/var/www/.env" failed (2: No such file or directory), client: 203.0.113.7, server: _, request: "GET /.env HTTP/1.1", host: "example.com""#;
        let event = parse_error_log_line(line, "/var/log/nginx/error.log").ok_or("event")?;

        assert_eq!(event.field("ip"), Some("203.0.113.7"));
        assert_eq!(event.field("method"), Some("GET"));
        assert_eq!(event.field("path"), Some("/.env"));
        assert_eq!(event.field("status"), Some("000"));
        Ok(())
    }
}
