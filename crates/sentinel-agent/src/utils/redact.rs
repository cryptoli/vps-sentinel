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

/// Keep the executable token and remove arguments from a command line.
pub fn mask_command_args(value: &str) -> String {
    value
        .split_whitespace()
        .next()
        .map(|binary| format!("{binary} [args masked]"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{mask_command_args, mask_ip};

    #[test]
    fn redacts_ip_and_command_arguments() {
        assert_eq!(mask_ip("203.0.113.10"), "203.0.x.x");
        assert_eq!(
            mask_command_args("/bin/bash -c whoami"),
            "/bin/bash [args masked]"
        );
    }
}
