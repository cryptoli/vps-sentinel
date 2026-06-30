use super::*;
use axum::body::Bytes;

pub(super) async fn ingest(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, PanelApiError> {
    if body.len() > state.max_body_bytes {
        return Err(PanelApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
        ));
    }
    let node_name = ingest_node_name(&headers)?;
    verify_signature(&state, &headers, &body, &node_name).await?;
    let payload_body = decode_ingest_body(&headers, &body)?;
    let mut payload: PanelEnvelope = serde_json::from_slice(&payload_body)
        .map_err(|err| PanelApiError::detail(StatusCode::BAD_REQUEST, "invalid_json", err))?;
    if !valid_panel_payload_identity(&payload, &node_name) {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
        ));
    }
    state.repo.insert_nonce(&headers, &node_name).await?;
    apply_node_location(&state, &headers, remote_addr.ip(), &mut payload);
    state.repo.persist_payload(&payload, &node_name).await?;
    invalidate_summary_cache(&state);
    let _ = state.events.send(PanelStreamEvent::refresh_datasets(
        PanelRole::Public,
        vec![
            "summary",
            "trends",
            "nodes",
            "findings",
            "incidents",
            "baseline_drifts",
            "active_blocks",
            "attack_fingerprints",
            "probe_sources",
        ],
    ));
    Ok(Json(json!({
        "ok": true,
        "message_id": payload.message_id,
    })))
}

pub(super) fn ingest_node_name(headers: &HeaderMap) -> Result<String, PanelApiError> {
    header(headers, "x-vps-sentinel-node-name").or_else(|_| header(headers, "x-vps-sentinel-node"))
}

fn decode_ingest_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, PanelApiError> {
    let encoding = optional_header(headers, "x-vps-sentinel-payload-encoding").unwrap_or_default();
    if encoding.is_empty() {
        return Ok(body.to_vec());
    }
    if encoding != PANEL_TRANSPORT_ENCODING {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_payload_encoding",
        ));
    }
    let wrapper: PanelTransportBody = serde_json::from_slice(body).map_err(|err| {
        PanelApiError::detail(StatusCode::BAD_REQUEST, "invalid_transport_json", err)
    })?;
    if wrapper.encoding != PANEL_TRANSPORT_ENCODING {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "payload_encoding_mismatch",
        ));
    }
    BASE64_STANDARD.decode(wrapper.payload).map_err(|err| {
        PanelApiError::detail(StatusCode::BAD_REQUEST, "invalid_payload_base64", err)
    })
}

fn valid_panel_payload_identity(payload: &PanelEnvelope, signed_node_name: &str) -> bool {
    match payload.schema_version {
        2 => payload.node.node_name == signed_node_name,
        1 => payload.node.node_id == signed_node_name || payload.node.node_name == signed_node_name,
        _ => false,
    }
}

fn apply_node_location(
    state: &AppState,
    headers: &HeaderMap,
    remote_ip: IpAddr,
    payload: &mut PanelEnvelope,
) {
    let metrics = payload.node.metrics.get_or_insert_with(|| json!({}));
    let Some(map) = metrics.as_object_mut() else {
        return;
    };
    if let Some(location) = detected_location_from_headers(headers) {
        apply_location_fields(map, location);
    }
    if let Some(location) = state.geoip.lookup(remote_ip) {
        let values = [
            ("country_code", location.country_code),
            ("country", location.country),
            ("region", location.region),
            ("city", location.city),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect::<Vec<_>>();
        apply_location_fields(map, values);
    }
}

fn apply_location_fields(map: &mut serde_json::Map<String, Value>, location: Vec<(&str, String)>) {
    for (key, value) in location {
        if !map.contains_key(key) {
            map.insert(key.to_string(), Value::String(value));
        }
    }
}

fn detected_location_from_headers(headers: &HeaderMap) -> Option<Vec<(&'static str, String)>> {
    let mut values = Vec::new();
    if let Some(country_code) = first_clean_header(headers, &COUNTRY_CODE_HEADERS)
        .and_then(|value| normalize_country_code(&value))
    {
        values.push(("country_code", country_code));
    }
    if let Some(country) = first_clean_header(headers, &COUNTRY_HEADERS) {
        values.push(("country", country));
    }
    if let Some(region) = first_clean_header(headers, &REGION_HEADERS) {
        values.push(("region", region));
    }
    if let Some(city) = first_clean_header(headers, &CITY_HEADERS) {
        values.push(("city", city));
    }
    (!values.is_empty()).then_some(values)
}

const COUNTRY_CODE_HEADERS: [&str; 5] = [
    "cf-ipcountry",
    "x-vercel-ip-country",
    "cloudfront-viewer-country",
    "x-appengine-country",
    "x-geoip-country-code",
];
const COUNTRY_HEADERS: [&str; 2] = ["x-geoip-country", "x-country"];
const REGION_HEADERS: [&str; 3] = ["x-vercel-ip-country-region", "x-geoip-region", "x-region"];
const CITY_HEADERS: [&str; 3] = ["x-vercel-ip-city", "x-geoip-city", "x-city"];

fn first_clean_header(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|name| optional_header(headers, name))
        .filter_map(|value| safe_location_value(&percent_decode_header(&value)))
        .next()
}

fn percent_decode_header(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hi = (bytes[index + 1] as char).to_digit(16);
            let lo = (bytes[index + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(((hi << 4) | lo) as u8);
                index += 3;
                continue;
            }
        }
        out.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn normalize_country_code(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() == 2 && trimmed.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Some(trimmed.to_ascii_uppercase());
    }
    None
}

fn safe_location_value(value: &str) -> Option<String> {
    let cleaned = value.trim();
    if cleaned.is_empty()
        || cleaned.len() > 96
        || cleaned.parse::<IpAddr>().is_ok()
        || cleaned
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '<' | '>' | '"' | '\''))
    {
        return None;
    }
    Some(cleaned.to_string())
}
