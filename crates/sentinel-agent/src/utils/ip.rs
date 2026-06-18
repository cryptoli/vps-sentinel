use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn is_public_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

pub(crate) fn is_public_remote_addr(addr: &str) -> bool {
    addr.trim().parse::<IpAddr>().is_ok_and(is_public_remote_ip)
}

pub(crate) fn is_public_listener_addr(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.eq_ignore_ascii_case("ipv6") {
        return true;
    }
    let addr = addr
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(addr);
    addr.parse::<IpAddr>().is_ok_and(is_public_listener_ip)
}

fn is_public_listener_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6_listener(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || is_this_network_ipv4(ip)
        || is_protocol_assignment_ipv4(ip)
        || is_documentation_ipv4(ip)
        || is_benchmark_ipv4(ip)
        || is_reserved_ipv4(ip)
        || is_shared_address_space_ipv4(ip))
}

fn is_this_network_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 0
}

fn is_protocol_assignment_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 192 && octets[1] == 0 && octets[2] == 0
}

fn is_documentation_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    )
}

fn is_benchmark_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && matches!(octets[1], 18 | 19)
}

fn is_shared_address_space_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_reserved_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] >= 240
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if is_ipv4_embedded_ipv6(segments) {
        return false;
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || is_unique_local_ipv6(segments)
        || is_unicast_link_local_ipv6(segments)
        || is_discard_only_ipv6(segments)
        || is_benchmark_ipv6(segments)
        || is_orchid_ipv6(segments)
        || is_documentation_ipv6(segments)
        || is_private_translation_ipv6(segments))
}

fn is_public_ipv6_listener(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    if let Some(ipv4) = embedded_ipv4(segments) {
        return ipv4.is_unspecified() || is_public_ipv4(ipv4);
    }
    !(ip.is_loopback()
        || ip.is_multicast()
        || is_unique_local_ipv6(segments)
        || is_unicast_link_local_ipv6(segments)
        || is_documentation_ipv6(segments)
        || is_discard_only_ipv6(segments)
        || is_benchmark_ipv6(segments)
        || is_orchid_ipv6(segments)
        || is_private_translation_ipv6(segments))
}

fn is_ipv4_embedded_ipv6(segments: [u16; 8]) -> bool {
    embedded_ipv4(segments).is_some()
}

fn embedded_ipv4(segments: [u16; 8]) -> Option<Ipv4Addr> {
    let prefix_zero = segments[0..5].iter().all(|segment| *segment == 0);
    let ipv4_mapped = prefix_zero && segments[5] == 0xffff;
    let ipv4_compatible = prefix_zero && segments[5] == 0;
    if !(ipv4_mapped || ipv4_compatible) {
        return None;
    }
    let [a, b] = segments[6].to_be_bytes();
    let [c, d] = segments[7].to_be_bytes();
    Some(Ipv4Addr::new(a, b, c, d))
}

fn is_unique_local_ipv6(segments: [u16; 8]) -> bool {
    segments[0] & 0xfe00 == 0xfc00
}

fn is_unicast_link_local_ipv6(segments: [u16; 8]) -> bool {
    segments[0] & 0xffc0 == 0xfe80
}

fn is_discard_only_ipv6(segments: [u16; 8]) -> bool {
    segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0)
}

fn is_benchmark_ipv6(segments: [u16; 8]) -> bool {
    segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0
}

fn is_orchid_ipv6(segments: [u16; 8]) -> bool {
    segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010
}

fn is_documentation_ipv6(segments: [u16; 8]) -> bool {
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_private_translation_ipv6(segments: [u16; 8]) -> bool {
    segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001
}

#[cfg(test)]
mod tests {
    use super::{is_public_listener_addr, is_public_remote_addr, is_public_remote_ip};

    #[test]
    fn public_ip_classifier_rejects_special_use_ranges() {
        assert!(is_public_remote_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_remote_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("172.16.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("0.1.2.3".parse().unwrap()));
        assert!(!is_public_remote_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("192.0.0.9".parse().unwrap()));
        assert!(!is_public_remote_ip("192.0.2.1".parse().unwrap()));
        assert!(!is_public_remote_ip("198.18.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("240.0.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("::1".parse().unwrap()));
        assert!(!is_public_remote_ip("fc00::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:db8::1".parse().unwrap()));
        assert!(!is_public_remote_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!is_public_remote_ip("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!is_public_remote_ip("100::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:2::1".parse().unwrap()));
        assert!(!is_public_remote_ip("2001:10::1".parse().unwrap()));
        assert!(!is_public_remote_ip("64:ff9b:1::1".parse().unwrap()));
    }

    #[test]
    fn remote_addr_classifier_rejects_non_ip_text() {
        assert!(is_public_remote_addr("8.8.8.8"));
        assert!(!is_public_remote_addr("10.0.0.1"));
        assert!(!is_public_remote_addr("not-an-ip"));
    }

    #[test]
    fn listener_classifier_uses_listener_exposure_semantics() {
        assert!(is_public_listener_addr("0.0.0.0"));
        assert!(is_public_listener_addr("::"));
        assert!(is_public_listener_addr("[::]"));
        assert!(is_public_listener_addr("ipv6"));
        assert!(is_public_listener_addr("8.8.8.8"));
        assert!(is_public_listener_addr("::ffff:8.8.8.8"));
        assert!(!is_public_listener_addr("127.0.0.1"));
        assert!(!is_public_listener_addr("10.0.0.5"));
        assert!(!is_public_listener_addr("100.64.0.1"));
        assert!(!is_public_listener_addr("192.0.2.1"));
        assert!(!is_public_listener_addr("fc00::1"));
        assert!(!is_public_listener_addr("fe80::1"));
        assert!(!is_public_listener_addr("2001:db8::1"));
        assert!(!is_public_listener_addr("::ffff:10.0.0.1"));
    }
}
