use crate::collectors::{CollectContext, Collector};
use crate::utils::fs::read_tail;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::collections::BTreeMap;

pub struct AuditLogCollector;

#[async_trait]
impl Collector for AuditLogCollector {
    fn name(&self) -> &'static str {
        "auditd"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.advanced_collectors.auditd_enabled {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for path in &ctx.config.advanced_collectors.audit_log_paths {
            let resolved = ctx.resolve(path);
            if !resolved.exists() {
                continue;
            }
            let text = read_tail(
                &resolved,
                ctx.config.advanced_collectors.audit_max_tail_bytes,
            )?;
            events.extend(parse_audit_log(&text, &path.to_string_lossy()));
        }
        Ok(events)
    }
}

pub fn parse_audit_log(text: &str, path: &str) -> Vec<RawEvent> {
    text.lines()
        .filter_map(|line| parse_audit_line(line, path))
        .collect()
}

fn parse_audit_line(line: &str, path: &str) -> Option<RawEvent> {
    let fields = parse_audit_fields(line);
    let record_type = fields.get("type")?.to_string();
    let kind = match record_type.as_str() {
        "EXECVE" => "audit_exec",
        "SYSCALL" => "audit_syscall",
        "PATH" => "audit_path",
        "USER_AUTH" | "USER_LOGIN" | "USER_ACCT" => "audit_auth",
        _ => return None,
    };
    let mut event = RawEvent::new("auditd", kind)
        .with_field("audit_record_type", record_type)
        .with_field("path", path)
        .with_field("raw", line);
    for key in [
        "msg", "pid", "ppid", "uid", "auid", "ses", "comm", "exe", "name", "addr", "terminal",
        "res", "success", "syscall",
    ] {
        if let Some(value) = fields.get(key).filter(|value| !value.is_empty()) {
            event.fields.insert(key.to_string(), value.clone());
        }
    }
    if kind == "audit_exec" {
        let argv = audit_argv(&fields);
        event.fields.insert("argv".to_string(), argv.clone());
        event.fields.insert("cmdline".to_string(), argv);
        event
            .fields
            .insert("ephemeral_event".to_string(), "true".to_string());
        event.fields.insert(
            "event_source_detail".to_string(),
            "audit_execve".to_string(),
        );
        if let Some(value) = fields.get("exe").filter(|value| !value.is_empty()) {
            event.fields.insert("exe_path".to_string(), value.clone());
        }
        if let Some(value) = fields.get("comm").filter(|value| !value.is_empty()) {
            event
                .fields
                .insert("process_name".to_string(), value.clone());
            event.fields.insert("name".to_string(), value.clone());
        }
    }
    Some(event)
}

fn parse_audit_fields(line: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            fields.insert(key.to_string(), unquote(value));
        }
    }
    fields
}

fn audit_argv(fields: &BTreeMap<String, String>) -> String {
    let mut argv = fields
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix('a')
                .and_then(|index| index.parse::<usize>().ok())
                .map(|index| (index, value.clone()))
        })
        .collect::<Vec<_>>();
    argv.sort_by_key(|(index, _)| *index);
    argv.into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(" ")
}

fn unquote(value: &str) -> String {
    value
        .trim_matches('"')
        .trim_matches('\'')
        .replace("\\\"", "\"")
}

#[cfg(test)]
mod tests {
    use super::parse_audit_log;

    #[test]
    fn parses_execve_record() {
        let text = r#"type=EXECVE msg=audit(1710000000.1:99): argc=3 a0="sh" a1="-c" a2="id" comm="sh" exe="/usr/bin/sh""#;
        let events = parse_audit_log(text, "/var/log/audit/audit.log");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "audit_exec");
        assert_eq!(events[0].field("argv"), Some("sh -c id"));
        assert_eq!(events[0].field("cmdline"), Some("sh -c id"));
        assert_eq!(events[0].field("exe"), Some("/usr/bin/sh"));
        assert_eq!(events[0].field("exe_path"), Some("/usr/bin/sh"));
        assert_eq!(events[0].field("process_name"), Some("sh"));
        assert_eq!(events[0].field("ephemeral_event"), Some("true"));
        assert_eq!(events[0].field("event_source_detail"), Some("audit_execve"));
    }
}
