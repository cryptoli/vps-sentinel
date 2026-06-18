use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn is_public_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
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
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || is_discard_only_ipv6(segments)
        || is_benchmark_ipv6(segments)
        || is_orchid_ipv6(segments)
        || is_documentation_ipv6(segments)
        || is_private_translation_ipv6(segments))
}

fn is_ipv4_embedded_ipv6(segments: [u16; 8]) -> bool {
    let prefix_zero = segments[0..5].iter().all(|segment| *segment == 0);
    let ipv4_mapped = prefix_zero && segments[5] == 0xffff;
    let ipv4_compatible = prefix_zero && segments[5] == 0;
    ipv4_mapped || ipv4_compatible
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
    use super::is_public_remote_ip;

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
}
