use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const PANEL_INGEST_METHOD: &str = "POST";
pub const PANEL_INGEST_PATH: &str = "/api/v1/ingest";

pub fn panel_header_nonce(node_id: &str, nonce: &str) -> String {
    format!("{node_id}:{nonce}")
}

pub fn panel_body_sha256_hex(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex_encode(&hasher.finalize())
}

pub fn panel_signing_string(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body_hash: &str,
) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        timestamp,
        nonce,
        body_hash
    )
}

pub fn panel_signature_hex(
    secret: &str,
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    body_hash: &str,
) -> String {
    let signing = panel_signing_string(method, path, timestamp, nonce, body_hash);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(signing.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

pub fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, panel_body_sha256_hex, panel_header_nonce, panel_signature_hex,
        panel_signing_string, PANEL_INGEST_METHOD, PANEL_INGEST_PATH,
    };

    #[test]
    fn panel_nonce_includes_node_prefix() {
        assert_eq!(panel_header_nonce("node-a", "nonce-1"), "node-a:nonce-1");
    }

    #[test]
    fn panel_signature_uses_transmitted_nonce() {
        let nonce = panel_header_nonce("node-a", "nonce-1");
        let body_hash = panel_body_sha256_hex(br#"{"ok":true}"#);
        let signing = panel_signing_string(
            PANEL_INGEST_METHOD,
            PANEL_INGEST_PATH,
            1_234_567,
            &nonce,
            &body_hash,
        );
        assert!(signing.contains("\nnode-a:nonce-1\n"));

        let signature = panel_signature_hex(
            "secret-secret-secret",
            PANEL_INGEST_METHOD,
            PANEL_INGEST_PATH,
            1_234_567,
            &nonce,
            &body_hash,
        );
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn constant_time_compare_checks_full_string() {
        assert!(constant_time_eq("abcdef", "abcdef"));
        assert!(!constant_time_eq("abcdef", "abcdeg"));
        assert!(!constant_time_eq("abcdef", "abc"));
    }
}
