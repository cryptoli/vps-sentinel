use crate::collectors::{CollectContext, Collector};
use crate::utils::command::command_output;
use crate::utils::fs::read_tail;
use crate::utils::ip::is_public_remote_ip;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use serde_json::Value;
use std::time::Duration;

pub struct EbpfBridgeCollector;

#[async_trait]
impl Collector for EbpfBridgeCollector {
    fn name(&self) -> &'static str {
        "ebpf_bridge"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.advanced_collectors.ebpf_bridge_enabled {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for path in &ctx.config.advanced_collectors.ebpf_event_paths {
            let resolved = ctx.resolve(path);
            if !resolved.exists() {
                continue;
            }
            let text = read_tail(
                &resolved,
                ctx.config.advanced_collectors.audit_max_tail_bytes,
            )?;
            events.extend(parse_jsonl_events(&text, "file"));
        }
        if let Some((program, args)) = ctx.config.advanced_collectors.ebpf_command.split_first() {
            if !program.trim().is_empty() {
                let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
                if let Some(output) = command_output(
                    program,
                    &arg_refs,
                    Duration::from_secs(ctx.config.advanced_collectors.command_timeout_seconds),
                ) {
                    if output.status_success {
                        events.extend(parse_jsonl_events(&output.stdout, "command"));
                    }
                }
            }
        }
        Ok(events)
    }
}

pub fn parse_jsonl_events(text: &str, origin: &str) -> Vec<RawEvent> {
    text.lines()
        .filter_map(|line| parse_json_event(line, origin))
        .collect()
}

fn parse_json_event(line: &str, origin: &str) -> Option<RawEvent> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    let object = value.as_object()?;
    let source_kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("ebpf_event");
    let kind = canonical_kind(source_kind);
    let mut event = RawEvent::new("ebpf", kind)
        .with_field("origin", origin)
        .with_field("event_source_detail", source_kind)
        .with_field("ephemeral_event", "true")
        .with_field("raw", line);
    for (key, value) in object {
        if key == "kind" {
            continue;
        }
        let value = value
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| value.to_string());
        event.fields.insert(key.clone(), value);
    }
    normalize_fields(&mut event);
    Some(event)
}

fn canonical_kind(kind: &str) -> &str {
    match kind {
        "exec" | "execve" | "process_exec" => "process_exec",
        "connect" | "tcp_connect" | "udp_connect" | "network_connect" => "outbound_connection",
        "file_open" | "file_write" | "file_rename" | "file_unlink" => "file_activity",
        _ => kind,
    }
}

fn normalize_fields(event: &mut RawEvent) {
    if event.kind == "process_exec" {
        copy_first_field(event, "exe_path", &["exe", "executable", "path"]);
    } else {
        copy_first_field(event, "exe_path", &["exe", "executable"]);
    }
    if event.kind == "file_activity" {
        copy_first_field(event, "path", &["file_path", "filename", "name"]);
    }
    copy_first_field(event, "cmdline", &["argv", "args", "command", "comm"]);
    copy_first_field(event, "name", &["process_name", "comm"]);
    copy_first_field(event, "process_name", &["name", "comm"]);
    copy_first_field(
        event,
        "remote_addr",
        &["dst_addr", "daddr", "destination_ip", "ip"],
    );
    copy_first_field(
        event,
        "remote_port",
        &["dst_port", "dport", "destination_port", "port"],
    );
    copy_first_field(event, "operation", &["op", "action"]);
    if let Some(addr) = event.field("remote_addr").map(str::to_string) {
        let public = addr.parse().ok().is_some_and(is_public_remote_ip);
        event
            .fields
            .insert("remote_public".to_string(), public.to_string());
    }
}

fn copy_first_field(event: &mut RawEvent, target: &str, sources: &[&str]) {
    if event
        .field(target)
        .is_some_and(|value| !value.trim().is_empty())
    {
        return;
    }
    if let Some(value) = sources
        .iter()
        .find_map(|source| event.field(source).filter(|value| !value.trim().is_empty()))
        .map(str::to_string)
    {
        event.fields.insert(target.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_jsonl_events;

    #[test]
    fn parses_jsonl_bridge_events() {
        let events = parse_jsonl_events(
            r#"{"kind":"process_exec","pid":123,"exe":"/tmp/a","remote_addr":"8.8.8.8"}"#,
            "file",
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, "ebpf");
        assert_eq!(events[0].kind, "process_exec");
        assert_eq!(events[0].field("exe"), Some("/tmp/a"));
        assert_eq!(events[0].field("exe_path"), Some("/tmp/a"));
        assert_eq!(events[0].field("pid"), Some("123"));
        assert_eq!(events[0].field("ephemeral_event"), Some("true"));
        assert_eq!(events[0].field("event_source_detail"), Some("process_exec"));
    }

    #[test]
    fn normalizes_connect_events_for_outbound_profiles() {
        let events = parse_jsonl_events(
            r#"{"kind":"tcp_connect","pid":123,"dst_addr":"8.8.8.8","dst_port":3333}"#,
            "file",
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "outbound_connection");
        assert_eq!(events[0].field("remote_addr"), Some("8.8.8.8"));
        assert_eq!(events[0].field("remote_port"), Some("3333"));
        assert_eq!(events[0].field("remote_public"), Some("true"));
    }

    #[test]
    fn normalizes_file_activity_events() {
        let events = parse_jsonl_events(
            r#"{"kind":"file_write","pid":123,"path":"/etc/cron.d/a","op":"write"}"#,
            "file",
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "file_activity");
        assert_eq!(events[0].field("operation"), Some("write"));
    }
}
