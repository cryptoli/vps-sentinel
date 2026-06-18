use crate::collectors::{CollectContext, Collector};
use crate::utils::command::command_output;
use crate::utils::fs::read_tail;
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
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("ebpf_event");
    let mut event = RawEvent::new("ebpf", kind)
        .with_field("origin", origin)
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
    Some(event)
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
        assert_eq!(events[0].field("pid"), Some("123"));
    }
}
