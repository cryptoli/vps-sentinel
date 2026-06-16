use crate::collectors::{CollectContext, Collector};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::fs;
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
    if parts.len() < 4 {
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
            .with_field("local_port", local_port.to_string()),
    )
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
    if hex.chars().all(|ch| ch == '0') {
        return "::".to_string();
    }
    "ipv6".to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_proc_net;

    #[test]
    fn parses_listening_tcp_socket() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1";
        let events = parse_proc_net(text, "tcp");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].field("local_addr"), Some("0.0.0.0"));
        assert_eq!(events[0].field("local_port"), Some("22"));
    }
}
