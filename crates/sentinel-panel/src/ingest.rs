use super::*;

pub(super) async fn ingest(
    State(state): State<AppState>,
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
    let payload: PanelEnvelope = serde_json::from_slice(&payload_body)
        .map_err(|err| PanelApiError::detail(StatusCode::BAD_REQUEST, "invalid_json", err))?;
    if !valid_panel_payload_identity(&payload, &node_name) {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
        ));
    }
    state.repo.insert_nonce(&headers, &node_name).await?;
    state.repo.persist_payload(&payload, &node_name).await?;
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
            "probe_sources",
        ],
    ));
    Ok(Json(
        json!({ "ok": true, "message_id": payload.message_id }),
    ))
}

fn ingest_node_name(headers: &HeaderMap) -> Result<String, PanelApiError> {
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
