use crate::collectors::{CollectContext, Collector};
use crate::utils::command::command_output;
use crate::utils::ip::is_public_remote_ip;
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelError, SentinelResult};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub struct EbpfBridgeCollector;

const FINGERPRINT_SAMPLE_BYTES: u64 = 512;

#[derive(Debug, Clone, Copy, Default)]
struct FileCursor {
    offset: u64,
    fingerprint: Option<blake3::Hash>,
}

static FILE_CURSORS: OnceLock<Mutex<BTreeMap<PathBuf, FileCursor>>> = OnceLock::new();

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
            let text = read_incremental_jsonl(
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

fn read_incremental_jsonl(path: &Path, max_bytes: u64) -> SentinelResult<String> {
    let mut file = File::open(path).map_err(|err| SentinelError::io(path, err))?;
    let metadata = file
        .metadata()
        .map_err(|err| SentinelError::io(path, err))?;
    let len = metadata.len();
    let fingerprint = file_fingerprint(&mut file, path, len)?;
    let start = next_file_offset(path, len, fingerprint)?;
    if start == len || max_bytes == 0 {
        update_file_offset(path, len, fingerprint)?;
        return Ok(String::new());
    }

    let available = len.saturating_sub(start);
    let capped = available > max_bytes;
    let read_start = if capped {
        len.saturating_sub(max_bytes)
    } else {
        start
    };
    file.seek(SeekFrom::Start(read_start))
        .map_err(|err| SentinelError::io(path, err))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| SentinelError::io(path, err))?;
    update_file_offset(path, len, fingerprint)?;

    let text = String::from_utf8_lossy(&bytes).into_owned();
    if capped {
        Ok(drop_partial_first_line(text))
    } else {
        Ok(text)
    }
}

fn next_file_offset(path: &Path, len: u64, fingerprint: blake3::Hash) -> SentinelResult<u64> {
    let cursors = FILE_CURSORS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cursors = cursors
        .lock()
        .map_err(|_| SentinelError::Config("eBPF bridge cursor state lock poisoned".to_string()))?;
    let cursor = cursors.entry(path.to_path_buf()).or_default();
    if cursor.offset > len || (cursor.offset == len && cursor.fingerprint != Some(fingerprint)) {
        cursor.offset = 0;
    }
    Ok(cursor.offset)
}

fn update_file_offset(path: &Path, offset: u64, fingerprint: blake3::Hash) -> SentinelResult<()> {
    let cursors = FILE_CURSORS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cursors = cursors
        .lock()
        .map_err(|_| SentinelError::Config("eBPF bridge cursor state lock poisoned".to_string()))?;
    cursors.insert(
        path.to_path_buf(),
        FileCursor {
            offset,
            fingerprint: Some(fingerprint),
        },
    );
    Ok(())
}

fn file_fingerprint(file: &mut File, path: &Path, len: u64) -> SentinelResult<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&len.to_le_bytes());
    if len == 0 {
        return Ok(hasher.finalize());
    }

    let head_len = len.min(FINGERPRINT_SAMPLE_BYTES);
    hash_file_slice(file, path, 0, head_len, &mut hasher)?;
    if len > head_len {
        let tail_len = (len - head_len).min(FINGERPRINT_SAMPLE_BYTES);
        hash_file_slice(file, path, len - tail_len, tail_len, &mut hasher)?;
    }
    Ok(hasher.finalize())
}

fn hash_file_slice(
    file: &mut File,
    path: &Path,
    offset: u64,
    len: u64,
    hasher: &mut blake3::Hasher,
) -> SentinelResult<()> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|err| SentinelError::io(path, err))?;
    let mut remaining = len as usize;
    let mut buffer = [0_u8; FINGERPRINT_SAMPLE_BYTES as usize];
    while remaining > 0 {
        let read_len = remaining.min(buffer.len());
        let read = file
            .read(&mut buffer[..read_len])
            .map_err(|err| SentinelError::io(path, err))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        remaining -= read;
    }
    Ok(())
}

fn drop_partial_first_line(text: String) -> String {
    text.split_once('\n')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_default()
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
    copy_first_field(event, "pid", &["tgid"]);
    copy_first_field(event, "uid", &["user_id"]);
    copy_first_field(event, "euid", &["effective_uid", "uid"]);
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
    use super::{parse_jsonl_events, read_incremental_jsonl};
    use std::fs;
    use std::io::Write;

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
    fn normalizes_runtime_probe_exec_fields() {
        let events = parse_jsonl_events(
            r#"{"kind":"process_exec","pid":123,"uid":0,"comm":"bash","exe":"/bin/bash"}"#,
            "file",
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].field("name"), Some("bash"));
        assert_eq!(events[0].field("process_name"), Some("bash"));
        assert_eq!(events[0].field("exe_path"), Some("/bin/bash"));
        assert_eq!(events[0].field("euid"), Some("0"));
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

    #[test]
    fn file_bridge_reads_only_new_jsonl_lines() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ebpf.jsonl");
        fs::write(&path, r#"{"kind":"process_exec","pid":1}"#)?;
        fs::write(&path, format!("{}\n", fs::read_to_string(&path)?))?;

        let first = read_incremental_jsonl(&path, 4096)?;
        let second = read_incremental_jsonl(&path, 4096)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(br#"{"kind":"process_exec","pid":2}"#)?;
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(b"\n")?;
        let third = read_incremental_jsonl(&path, 4096)?;

        assert!(first.contains(r#""pid":1"#));
        assert!(second.is_empty());
        assert!(!third.contains(r#""pid":1"#));
        assert!(third.contains(r#""pid":2"#));
        Ok(())
    }

    #[test]
    fn file_bridge_resets_cursor_after_truncation() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ebpf-rotated.jsonl");
        fs::write(&path, "{\"kind\":\"process_exec\",\"pid\":1}\n")?;
        assert!(read_incremental_jsonl(&path, 4096)?.contains(r#""pid":1"#));

        fs::write(&path, "{\"kind\":\"process_exec\",\"pid\":2}\n")?;
        let after_truncate = read_incremental_jsonl(&path, 4096)?;

        assert!(after_truncate.contains(r#""pid":2"#));
        Ok(())
    }
}
