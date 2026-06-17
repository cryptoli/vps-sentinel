use crate::collectors::{CollectContext, Collector};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv6Addr;
use std::path::Path;

pub struct NetworkCollector;

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.network.enabled {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        for (relative, protocol) in [
            ("/proc/net/tcp", "tcp"),
            ("/proc/net/tcp6", "tcp6"),
            ("/proc/net/udp", "udp"),
            ("/proc/net/udp6", "udp6"),
        ] {
            let path = ctx.resolve(Path::new(relative));
            if !path.exists() {
                continue;
            }
            let text = fs::read_to_string(&path)
                .map_err(|err| sentinel_core::SentinelError::io(&path, err))?;
            events.extend(parse_proc_net(&text, protocol));
        }
        enrich_socket_owners(&mut events, &ctx.scan_root);
        Ok(events)
    }
}

/// Parse `/proc/net/tcp*` or `/proc/net/udp*` lines into listening socket facts.
pub fn parse_proc_net(text: &str, protocol: &str) -> Vec<RawEvent> {
    text.lines()
        .skip(1)
        .filter_map(|line| parse_proc_net_line(line, protocol))
        .collect()
}

fn parse_proc_net_line(line: &str, protocol: &str) -> Option<RawEvent> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    let state = parts[3];
    let is_listening = state == "0A" || (protocol.starts_with("udp") && state == "07");
    if !is_listening {
        return None;
    }
    let (addr_hex, port_hex) = parts[1].split_once(':')?;
    let local_addr = parse_proc_address(addr_hex);
    let local_port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(
        RawEvent::new("network", "listening_socket")
            .with_field("protocol", protocol)
            .with_field("local_addr", local_addr)
            .with_field("local_port", local_port.to_string())
            .with_field("inode", parts[9]),
    )
}

fn enrich_socket_owners(events: &mut [RawEvent], scan_root: &Path) {
    let mut needed = events
        .iter()
        .filter_map(|event| event.field("inode").map(str::to_string))
        .collect::<Vec<_>>();
    needed.sort();
    needed.dedup();
    if needed.is_empty() {
        return;
    }
    let owners = socket_owner_map(scan_root, &needed);
    for event in events {
        let Some(inode) = event.field("inode") else {
            continue;
        };
        let Some(owner) = owners.get(inode) else {
            continue;
        };
        event.fields.insert("pid".to_string(), owner.pid.clone());
        event
            .fields
            .insert("process_name".to_string(), owner.name.clone());
        event
            .fields
            .insert("executable".to_string(), owner.executable.clone());
        event
            .fields
            .insert("cmdline".to_string(), owner.cmdline.clone());
        event
            .fields
            .insert("argv_json".to_string(), owner.argv_json.clone());
    }
}

fn socket_owner_map(scan_root: &Path, inodes: &[String]) -> BTreeMap<String, ProcessOwner> {
    let wanted = inodes.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let proc_path = scan_root.join("proc");
    let Ok(entries) = fs::read_dir(proc_path) else {
        return BTreeMap::new();
    };
    let mut owners = BTreeMap::new();
    for entry in entries.flatten() {
        let pid = entry.file_name().to_string_lossy().to_string();
        if !pid.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let fd_path = entry.path().join("fd");
        let Ok(fd_entries) = fs::read_dir(fd_path) else {
            continue;
        };
        let mut matched_inodes = Vec::new();
        for fd_entry in fd_entries.flatten() {
            let Ok(target) = fs::read_link(fd_entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = parse_socket_inode(&target) else {
                continue;
            };
            if wanted.contains(inode) {
                matched_inodes.push(inode.to_string());
            }
        }
        if matched_inodes.is_empty() {
            continue;
        }
        let owner = ProcessOwner::from_pid_path(&pid, &entry.path());
        for inode in matched_inodes {
            owners.entry(inode).or_insert_with(|| owner.clone());
        }
    }
    owners
}

fn parse_socket_inode(target: &str) -> Option<&str> {
    target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct ProcessOwner {
    pid: String,
    name: String,
    executable: String,
    cmdline: String,
    argv_json: String,
}

impl ProcessOwner {
    fn from_pid_path(pid: &str, pid_path: &Path) -> Self {
        let argv = read_argv(pid_path.join("cmdline"));
        Self {
            pid: pid.to_string(),
            name: read_trimmed(pid_path.join("comm")),
            executable: fs::read_link(pid_path.join("exe"))
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default(),
            cmdline: argv.join(" "),
            argv_json: serde_json::to_string(&argv).unwrap_or_else(|_| "[]".to_string()),
        }
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn read_argv(path: impl AsRef<Path>) -> Vec<String> {
    fs::read(path)
        .map(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_proc_address(hex: &str) -> String {
    if hex.len() == 8 {
        let bytes = (0..4)
            .filter_map(|index| {
                let offset = index * 2;
                u8::from_str_radix(&hex[offset..offset + 2], 16).ok()
            })
            .collect::<Vec<_>>();
        if bytes.len() == 4 {
            return format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
        }
    }
    if hex.len() == 32 {
        if let Some(addr) = parse_proc_ipv6_address(hex) {
            return addr.to_string();
        }
    }
    hex.to_string()
}

fn parse_proc_ipv6_address(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for chunk in 0..4 {
        for byte_index in 0..4 {
            let source_offset = chunk * 8 + byte_index * 2;
            let byte = u8::from_str_radix(&hex[source_offset..source_offset + 2], 16).ok()?;
            bytes[chunk * 4 + (3 - byte_index)] = byte;
        }
    }
    Some(Ipv6Addr::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::{parse_proc_ipv6_address, parse_proc_net, parse_socket_inode};

    #[test]
    fn parses_listening_tcp_socket() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1";
        let events = parse_proc_net(text, "tcp");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].field("local_addr"), Some("0.0.0.0"));
        assert_eq!(events[0].field("local_port"), Some("22"));
        assert_eq!(events[0].field("inode"), Some("1"));
    }

    #[test]
    fn parses_socket_inode_symlink() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some("12345"));
        assert_eq!(parse_socket_inode("pipe:[12345]"), None);
    }

    #[test]
    fn parses_proc_tcp6_loopback_address() {
        let address = parse_proc_ipv6_address("00000000000000000000000001000000");
        assert_eq!(
            address.map(|value| value.to_string()),
            Some("::1".to_string())
        );
    }
}
