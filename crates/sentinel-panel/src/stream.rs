use super::*;
use uuid::Uuid;

pub(super) async fn stream_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Public)?;
    let ticket = Uuid::new_v4().to_string();
    let expires_at = Utc::now().timestamp() + STREAM_TICKET_TTL_SECONDS;
    {
        let mut tickets = state.stream_tickets.lock().map_err(sqlite_lock_error)?;
        tickets.retain(|_, ticket| ticket.expires_at > Utc::now().timestamp());
        tickets.insert(ticket.clone(), StreamTicket { role, expires_at });
    }
    Ok(Json(json!({
        "ticket": ticket,
        "role": role,
        "expires_in_seconds": STREAM_TICKET_TTL_SECONDS
    })))
}

#[derive(Debug, Deserialize)]
pub(super) struct StreamQuery {
    ticket: String,
}

pub(super) async fn stream(
    websocket: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
) -> Result<Response, PanelApiError> {
    let role = consume_stream_ticket(&state, &query.ticket)?;
    Ok(websocket.on_upgrade(move |socket| stream_socket(socket, state, role)))
}

fn consume_stream_ticket(state: &AppState, ticket: &str) -> Result<PanelRole, PanelApiError> {
    let mut tickets = state.stream_tickets.lock().map_err(sqlite_lock_error)?;
    let now = Utc::now().timestamp();
    tickets.retain(|_, ticket| ticket.expires_at > now);
    let Some(ticket) = tickets.remove(ticket) else {
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_stream_ticket",
        ));
    };
    Ok(ticket.role)
}

async fn stream_socket(mut socket: WebSocket, state: AppState, role: PanelRole) {
    let mut receiver = state.events.subscribe();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(STREAM_HEARTBEAT_SECONDS));
    if send_stream_event(&mut socket, PanelStreamEvent::hello(role))
        .await
        .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            event = receiver.recv() => {
                match event {
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        if send_stream_event(&mut socket, PanelStreamEvent::refresh(role)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

async fn send_stream_event(
    socket: &mut WebSocket,
    event: PanelStreamEvent,
) -> Result<(), axum::Error> {
    let payload = serde_json::to_string(&event).unwrap_or_else(|_| {
        "{\"type\":\"refresh\",\"role\":\"public\",\"retry_after_seconds\":5}".to_string()
    });
    socket.send(Message::Text(payload)).await
}
