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

/// Keep the executable token and remove arguments from a command line.
pub fn mask_command_args(value: &str) -> String {
    value
        .split_whitespace()
        .next()
        .map(|binary| format!("{binary} [args masked]"))
        .unwrap_or_default()
}

fn parse_ipv4_at(chars: &[char], start: usize) -> Option<(usize, String)> {
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
    Some((offset, format!("{}.{}.x.x", parts[0], parts[1])))
}

#[cfg(test)]
mod tests {
    use super::{mask_command_args, mask_ip, mask_ips_in_text};

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
}
