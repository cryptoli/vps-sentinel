use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::{path_string, read_tail};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};

const MAX_WEB_LOG_BYTES: u64 = 1024 * 1024;

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
        for configured_path in &ctx.config.web.log_paths {
            let path = ctx.resolve(configured_path);
            if !path.exists() {
                continue;
            }
            let source = path_string(configured_path);
            let content = read_tail(&path, MAX_WEB_LOG_BYTES)?;
            events.extend(
                content
                    .lines()
                    .filter_map(|line| parse_access_log_line(line, &source)),
            );
        }
        Ok(events)
    }
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

#[cfg(test)]
mod tests {
    use super::parse_access_log_line;

    #[test]
    fn parses_common_access_log_line() -> Result<(), Box<dyn std::error::Error>> {
        let line = r#"203.0.113.9 - - [16/Jun/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;
        let event = parse_access_log_line(line, "/var/log/nginx/access.log").ok_or("event")?;
        assert_eq!(event.field("ip"), Some("203.0.113.9"));
        assert_eq!(event.field("path"), Some("/.env"));
        assert_eq!(event.field("status"), Some("404"));
        Ok(())
    }
}
