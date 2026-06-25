use anyhow::{Context, Result};
use maxminddb::{geoip2, Reader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub(super) struct PanelGeoLocation {
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<String>,
    pub organization: Option<String>,
}

#[derive(Debug, Default)]
pub(super) struct PanelGeoIpResolver {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

impl PanelGeoIpResolver {
    pub(super) fn open(city_path: Option<&Path>, asn_path: Option<&Path>) -> Result<Self> {
        let city = match city_path.filter(|path| !path.as_os_str().is_empty()) {
            Some(path) => Some(
                Reader::open_readfile(path)
                    .with_context(|| format!("open GeoIP city database {}", path.display()))?,
            ),
            None => None,
        };
        let asn = match asn_path.filter(|path| !path.as_os_str().is_empty()) {
            Some(path) => Some(
                Reader::open_readfile(path)
                    .with_context(|| format!("open GeoIP ASN database {}", path.display()))?,
            ),
            None => None,
        };
        Ok(Self { city, asn })
    }

    pub(super) fn lookup(&self, ip: IpAddr) -> Option<PanelGeoLocation> {
        if !geoip_candidate(ip) {
            return None;
        }
        let mut location = PanelGeoLocation::default();
        if let Some(reader) = &self.city {
            if let Ok(result) = reader.lookup(ip) {
                if let Ok(Some(city)) = result.decode::<geoip2::City>() {
                    location.country_code = city
                        .country
                        .iso_code
                        .or(city.registered_country.iso_code)
                        .and_then(normalize_country_code);
                    location.country = city
                        .country
                        .names
                        .english
                        .or(city.registered_country.names.english)
                        .and_then(safe_geo_text);
                    location.region = city
                        .subdivisions
                        .first()
                        .and_then(|item| item.names.english)
                        .and_then(safe_geo_text);
                    location.city = city.city.names.english.and_then(safe_geo_text);
                }
            }
        }
        if let Some(reader) = &self.asn {
            if let Ok(result) = reader.lookup(ip) {
                if let Ok(Some(asn)) = result.decode::<geoip2::Asn>() {
                    location.asn = asn
                        .autonomous_system_number
                        .map(|number| format!("AS{number}"));
                    location.organization =
                        asn.autonomous_system_organization.and_then(safe_geo_text);
                }
            }
        }
        location.has_location().then_some(location)
    }
}

impl PanelGeoLocation {
    fn has_location(&self) -> bool {
        self.country_code.is_some()
            || self.country.is_some()
            || self.region.is_some()
            || self.city.is_some()
            || self.asn.is_some()
            || self.organization.is_some()
    }
}

fn normalize_country_code(value: &str) -> Option<String> {
    let code = value.trim().to_ascii_uppercase();
    if code.len() == 2 && code.chars().all(|ch| ch.is_ascii_alphabetic()) {
        Some(code)
    } else {
        None
    }
}

fn safe_geo_text(value: &str) -> Option<String> {
    let cleaned = value.trim();
    if cleaned.is_empty()
        || cleaned.len() > 96
        || cleaned.parse::<IpAddr>().is_ok()
        || cleaned
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | '"' | '\'' | '`'))
    {
        return None;
    }
    Some(cleaned.to_string())
}

fn geoip_candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_ipv4(ip),
        IpAddr::V6(ip) => public_ipv6(ip),
    }
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 224)
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ((segments[0] & 0xfe00) == 0xfc00)
        || ((segments[0] & 0xffc0) == 0xfe80)
        || ((segments[0] & 0xff00) == 0xff00)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geoip_skips_non_public_addresses() {
        assert!(!geoip_candidate(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!geoip_candidate(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!geoip_candidate(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(geoip_candidate(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn geo_text_rejects_ips_and_control_chars() {
        assert_eq!(safe_geo_text("Singapore").as_deref(), Some("Singapore"));
        assert!(safe_geo_text("203.0.113.10").is_none());
        assert!(safe_geo_text("bad\nvalue").is_none());
    }
}
