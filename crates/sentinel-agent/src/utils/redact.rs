use std::net::IpAddr;

/// Mask an IP address while preserving enough shape for investigation.
pub fn mask_ip(value: &str) -> String {
    if value.contains(':') {
        return "ipv6:masked".to_string();
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 4 {
        return format!("{}.{}.x.x", parts[0], parts[1]);
    }
    "ip:masked".to_string()
}

/// Remove an IP address for telemetry that must not report raw network identities.
pub fn remove_ip(_value: &str) -> String {
    "redacted".to_string()
}

/// Mask IPv4 addresses embedded in larger strings while preserving context.
pub fn mask_ips_in_text(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index].is_ascii_digit() {
            if let Some((next, masked)) = parse_ipv4_at(&chars, index) {
                out.push_str(&masked);
                index = next;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

/// Remove IPv4 addresses embedded in larger strings for privacy-safe remote telemetry.
pub fn remove_ips_in_text(value: &str) -> String {
    redact_ip_tokens(&redact_ipv4_in_text(value, |_| "redacted".to_string()))
}

/// Keep the executable token and remove arguments from a command line.
pub fn mask_command_args(value: &str) -> String {
    value
        .split_whitespace()
        .next()
        .map(|binary| format!("{binary} [args masked]"))
        .unwrap_or_default()
}

fn redact_ipv4_in_text(value: &str, replacement: impl Fn([u16; 4]) -> String) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index].is_ascii_digit() {
            if let Some((next, parts)) = parse_ipv4_parts_at(&chars, index) {
                out.push_str(&replacement(parts));
                index = next;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    out
}

fn parse_ipv4_at(chars: &[char], start: usize) -> Option<(usize, String)> {
    let (offset, parts) = parse_ipv4_parts_at(chars, start)?;
    Some((offset, format!("{}.{}.x.x", parts[0], parts[1])))
}

fn parse_ipv4_parts_at(chars: &[char], start: usize) -> Option<(usize, [u16; 4])> {
    let mut offset = start;
    let mut parts = Vec::with_capacity(4);
    for part_index in 0..4 {
        let part_start = offset;
        while offset < chars.len() && chars[offset].is_ascii_digit() {
            offset += 1;
        }
        if part_start == offset || offset - part_start > 3 {
            return None;
        }
        let part = chars[part_start..offset]
            .iter()
            .collect::<String>()
            .parse::<u16>()
            .ok()?;
        if part > 255 {
            return None;
        }
        parts.push(part);
        if part_index < 3 {
            if chars.get(offset) != Some(&'.') {
                return None;
            }
            offset += 1;
        }
    }
    if matches!(chars.get(offset), Some(ch) if ch.is_ascii_digit() || *ch == '.') {
        return None;
    }
    Some((offset, [parts[0], parts[1], parts[2], parts[3]]))
}

fn redact_ip_tokens(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut token = String::new();
    for ch in value.chars() {
        if ch.is_whitespace() {
            out.push_str(&redact_ip_token(&token));
            token.clear();
            out.push(ch);
        } else {
            token.push(ch);
        }
    }
    if !token.is_empty() {
        out.push_str(&redact_ip_token(&token));
    }
    out
}

fn redact_ip_token(token: &str) -> String {
    if token_contains_ip_literal(token) {
        "redacted".to_string()
    } else {
        token.to_string()
    }
}

fn token_contains_ip_literal(token: &str) -> bool {
    if let Some(bracket_start) = token.find('[') {
        if let Some(bracket_end) = token[bracket_start + 1..].find(']') {
            let candidate = &token[bracket_start + 1..bracket_start + 1 + bracket_end];
            return ip_candidate(candidate);
        }
    }

    let candidate = token.trim_matches(|ch: char| {
        matches!(
            ch,
            ',' | ';' | '"' | '\'' | '(' | ')' | '{' | '}' | '<' | '>' | '[' | ']'
        )
    });
    ip_candidate(candidate)
}

fn ip_candidate(value: &str) -> bool {
    let candidate = value.split('%').next().unwrap_or(value);
    candidate.matches(':').count() >= 2 && candidate.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::{mask_command_args, mask_ip, mask_ips_in_text, remove_ip, remove_ips_in_text};

    #[test]
    fn redacts_ip_and_command_arguments() {
        assert_eq!(mask_ip("203.0.113.10"), "203.0.x.x");
        assert_eq!(
            mask_command_args("/bin/bash -c whoami"),
            "/bin/bash [args masked]"
        );
    }

    #[test]
    fn redacts_ipv4_inside_text() {
        assert_eq!(
            mask_ips_in_text("root@203.0.113.10 from 198.51.100.8:22"),
            "root@203.0.x.x from 198.51.x.x:22"
        );
    }

    #[test]
    fn removes_ipv4_for_remote_telemetry() {
        assert_eq!(remove_ip("203.0.113.10"), "redacted");
        assert_eq!(
            remove_ips_in_text("root@203.0.113.10 from 198.51.100.8:22"),
            "root@redacted from redacted:22"
        );
    }

    #[test]
    fn removes_ipv6_for_remote_telemetry() {
        assert_eq!(
            remove_ips_in_text("ssh from [2001:db8::1]:443 and fe80::1%eth0"),
            "ssh from redacted and redacted"
        );
    }
}
