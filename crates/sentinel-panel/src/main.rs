use anyhow::{anyhow, Context, Result};
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, ValueEnum};
use rusqlite::{Connection, OptionalExtension};
use sentinel_core::panel_auth::{
    constant_time_eq, panel_body_sha256_hex, panel_signature_hex, PANEL_INGEST_METHOD,
    PANEL_INGEST_PATH,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx_core::column::Column;
use sqlx_core::query::query as sql_query;
use sqlx_core::row::Row;
use sqlx_mysql::MySqlPool;
use sqlx_postgres::PgPool;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use uuid::Uuid;

const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_WEB_DIR: &str = "panel/web";
const DEFAULT_PAGE_LIMIT: usize = 50;
const MAX_PAGE_LIMIT: usize = 200;
const DEFAULT_FRESHNESS_THRESHOLD_MINUTES: u64 = 30;
const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES: u64 = 720;
const STREAM_TICKET_TTL_SECONDS: i64 = 60;
const STREAM_HEARTBEAT_SECONDS: u64 = 30;
const STREAM_RETRY_SECONDS: u64 = 5;

#[derive(Debug, Parser)]
#[command(name = "vps-sentinel-panel", version)]
struct Args {
    #[arg(long, env = "PANEL_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    #[arg(long, env = "PANEL_DATABASE_URL", default_value = "sqlite://panel.db")]
    database_url: String,

    #[arg(long, env = "PANEL_DB_BACKEND", value_enum, default_value = "sqlite")]
    database_backend: DatabaseBackend,

    #[arg(long, env = "PANEL_SHARED_SECRET")]
    shared_secret: Option<String>,

    #[arg(long, env = "PANEL_NODE_SECRETS")]
    node_secrets_json: Option<String>,

    #[arg(long, env = "PANEL_VIEW_TOKEN")]
    view_token: Option<String>,

    #[arg(long, env = "PANEL_OPERATOR_TOKEN")]
    operator_token: Option<String>,

    #[arg(long, env = "PANEL_ADMIN_TOKEN")]
    admin_token: Option<String>,

    #[arg(long, env = "PANEL_PUBLIC_ENABLED", default_value_t = false)]
    public_enabled: bool,

    #[arg(long, env = "PANEL_WEB_DIR")]
    web_dir: Option<PathBuf>,

    #[arg(long, env = "PANEL_THEME", default_value = "default")]
    theme: String,

    #[arg(long, env = "PANEL_MAX_BODY_BYTES", default_value_t = DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DatabaseBackend {
    Sqlite,
    Postgres,
    Mysql,
}

#[derive(Clone)]
struct AppState {
    repo: Arc<Repository>,
    secrets: Arc<SecretResolver>,
    view_token: Option<String>,
    operator_token: Option<String>,
    admin_token: Option<String>,
    public_enabled: bool,
    theme: String,
    max_body_bytes: usize,
    events: broadcast::Sender<PanelStreamEvent>,
    stream_tickets: Arc<Mutex<BTreeMap<String, StreamTicket>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum PanelRole {
    Public = 0,
    Operator = 1,
    Admin = 2,
}

#[derive(Debug, Clone)]
struct StreamTicket {
    role: PanelRole,
    expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
struct PanelStreamEvent {
    #[serde(rename = "type")]
    kind: &'static str,
    role: PanelRole,
    server_time: DateTime<Utc>,
    retry_after_seconds: u64,
}

impl PanelStreamEvent {
    fn refresh(role: PanelRole) -> Self {
        Self {
            kind: "refresh",
            role,
            server_time: Utc::now(),
            retry_after_seconds: STREAM_RETRY_SECONDS,
        }
    }

    fn hello(role: PanelRole) -> Self {
        Self {
            kind: "hello",
            role,
            server_time: Utc::now(),
            retry_after_seconds: STREAM_RETRY_SECONDS,
        }
    }
}

#[derive(Clone)]
struct Repository {
    backend: DatabaseBackend,
    driver: RepositoryDriver,
}

#[derive(Clone)]
enum RepositoryDriver {
    Sqlite(Arc<Mutex<Connection>>),
    Postgres(PgPool),
    Mysql(MySqlPool),
}

enum DbValue {
    Text(String),
    Integer(i64),
    NullText,
    NullInteger,
}

#[derive(Debug, Clone, Copy)]
struct PanelDataset {
    table: &'static str,
    order_column: &'static str,
    active_filter: Option<&'static str>,
    columns: &'static [&'static str],
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct DetailQuery {
    id: String,
}

#[derive(Debug, Deserialize)]
struct FindingReviewRequest {
    finding_id: String,
    verdict: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    reviewer: String,
}

#[derive(Debug)]
struct PageRequest {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    limit: usize,
    offset: usize,
}

#[derive(Debug, Clone)]
struct SecretResolver {
    shared_secret: Option<String>,
    node_secrets: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PanelEnvelope {
    schema_version: u16,
    message_id: String,
    sent_at: DateTime<Utc>,
    node: PanelNode,
    scan: Value,
    #[serde(default)]
    findings: Vec<PanelFinding>,
    #[serde(default)]
    incidents: Vec<PanelIncident>,
    #[serde(default)]
    baseline_drifts: Vec<PanelBaselineDrift>,
    #[serde(default)]
    active_blocks: Vec<PanelActiveBlock>,
    #[serde(default)]
    probe_sources: Vec<PanelProbeSource>,
}

#[derive(Debug, Deserialize)]
struct PanelNode {
    #[serde(default)]
    node_id: String,
    node_name: String,
    agent_version: String,
    privacy_mode: String,
    #[serde(default)]
    enabled_features: Vec<String>,
    #[serde(default)]
    storage: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct PanelFinding {
    id: String,
    rule_id: String,
    title: String,
    severity: String,
    confidence: String,
    category: String,
    subject: String,
    timestamp: DateTime<Utc>,
    dedup_key: String,
    #[serde(default)]
    evidence: Vec<Value>,
    #[serde(default)]
    impact: Vec<String>,
    #[serde(default)]
    recommendations: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct PanelIncident {
    id: String,
    title: String,
    severity: String,
    score: u16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    summary: String,
}

#[derive(Debug, Deserialize)]
struct PanelBaselineDrift {
    finding_id: String,
    rule_id: String,
    severity: String,
    subject: String,
    timestamp: DateTime<Utc>,
    tier: String,
    score: Option<u16>,
    review_action: String,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PanelActiveBlock {
    #[serde(default)]
    ip: String,
    rule_id: String,
    finding_id: String,
    reason: String,
    backend: String,
    blocked_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    expired: bool,
    firewall_present: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PanelProbeSource {
    source_ip: String,
    ip_version: String,
    network_prefix: String,
    country: String,
    asn: String,
    organization: String,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    seen_count: usize,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    rule_ids: Vec<String>,
    latest_reason: String,
    block_status: String,
    block_reason: String,
}

#[derive(Debug, Clone)]
struct FindingReview {
    finding_id: String,
    verdict: String,
    note: String,
    reviewer: String,
    reviewed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    detail: String,
}

impl TryFrom<FindingReviewRequest> for FindingReview {
    type Error = PanelApiError;

    fn try_from(value: FindingReviewRequest) -> Result<Self, Self::Error> {
        let finding_id = value.finding_id.trim();
        if finding_id.is_empty() || finding_id.len() > 191 {
            return Err(PanelApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_finding_id",
            ));
        }
        let verdict = value.verdict.trim();
        if !matches!(verdict, "false_positive" | "confirmed" | "needs_review") {
            return Err(PanelApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_review_verdict",
            ));
        }
        Ok(Self {
            finding_id: finding_id.to_string(),
            verdict: verdict.to_string(),
            note: value.note.trim().chars().take(1000).collect(),
            reviewer: value.reviewer.trim().chars().take(128).collect::<String>(),
            reviewed_at: Utc::now(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt().with_target(false).init();
    if args.shared_secret.is_none() && args.node_secrets_json.is_none() {
        return Err(anyhow!(
            "set PANEL_SHARED_SECRET or PANEL_NODE_SECRETS before starting the panel"
        ));
    }
    let web_dir = args
        .web_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WEB_DIR));
    let repo = Repository::connect(args.database_backend, &args.database_url).await?;
    repo.init_schema().await?;
    let secrets = SecretResolver::new(args.shared_secret, args.node_secrets_json)?;
    let view_token = args
        .view_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    let operator_token = args
        .operator_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    let admin_token = args
        .admin_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    if view_token.is_none()
        && operator_token.is_none()
        && admin_token.is_none()
        && !args.public_enabled
    {
        warn!("PANEL_VIEW_TOKEN, PANEL_OPERATOR_TOKEN, PANEL_ADMIN_TOKEN, or PANEL_PUBLIC_ENABLED=true is not configured; panel read APIs will reject browser access");
    }
    let (events, _) = broadcast::channel(128);
    let state = AppState {
        repo: Arc::new(repo),
        secrets: Arc::new(secrets),
        view_token,
        operator_token,
        admin_token,
        public_enabled: args.public_enabled,
        theme: args.theme,
        max_body_bytes: args.max_body_bytes,
        events,
        stream_tickets: Arc::new(Mutex::new(BTreeMap::new())),
    };
    let app = Router::new()
        .route("/api/v1/settings", get(settings))
        .route("/api/v1/stream-ticket", get(stream_ticket))
        .route("/api/v1/stream", get(stream))
        .route("/api/v1/summary", get(summary))
        .route("/api/v1/trends", get(trends))
        .route("/api/v1/nodes", get(nodes))
        .route("/api/v1/findings", get(findings))
        .route("/api/v1/finding", get(finding_detail))
        .route("/api/v1/finding-review", post(finding_review))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/incident", get(incident_detail))
        .route("/api/v1/baseline-drifts", get(baseline_drifts))
        .route("/api/v1/active-blocks", get(active_blocks))
        .route("/api/v1/probe-sources", get(probe_sources))
        .route("/api/v1/audit-logs", get(audit_logs))
        .route("/api/v1/ingest", post(ingest))
        .fallback_service(ServeDir::new(web_dir))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);
    info!(bind = %args.bind, "vps-sentinel panel started");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn settings(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let role = resolve_panel_role(&state, &headers).ok();
    Json(json!({
        "theme": state.theme,
        "auth_required": !state.public_enabled,
        "auth_configured": state.view_token.is_some() || state.operator_token.is_some() || state.admin_token.is_some(),
        "public_enabled": state.public_enabled,
        "operator_configured": state.view_token.is_some() || state.operator_token.is_some(),
        "admin_configured": state.admin_token.is_some(),
        "role": role,
        "freshness_threshold_minutes": DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
        "node_retired_threshold_minutes": DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
        "server_time": Utc::now().to_rfc3339()
    }))
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response
}

async fn stream_ticket(
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
struct StreamQuery {
    ticket: String,
}

async fn stream(
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

fn verify_panel_role(
    state: &AppState,
    headers: &HeaderMap,
    minimum: PanelRole,
) -> Result<PanelRole, PanelApiError> {
    let role = resolve_panel_role(state, headers)?;
    if role < minimum {
        return Err(PanelApiError::new(
            StatusCode::FORBIDDEN,
            "insufficient_panel_role",
        ));
    }
    Ok(role)
}

#[cfg(test)]
fn verify_view_auth(state: &AppState, headers: &HeaderMap) -> Result<(), PanelApiError> {
    verify_panel_role(state, headers, PanelRole::Operator).map(|_| ())
}

fn resolve_panel_role(state: &AppState, headers: &HeaderMap) -> Result<PanelRole, PanelApiError> {
    if state.view_token.is_none()
        && state.operator_token.is_none()
        && state.admin_token.is_none()
        && !state.public_enabled
    {
        return Err(PanelApiError::new(
            StatusCode::FORBIDDEN,
            "panel_view_token_not_configured",
        ));
    };
    let Some(actual) = view_token_from_headers(headers) else {
        if state.public_enabled {
            return Ok(PanelRole::Public);
        }
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "missing_view_token",
        ));
    };
    let admin_match = state
        .admin_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected, actual));
    if admin_match {
        return Ok(PanelRole::Admin);
    }
    let operator_match = state
        .operator_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected, actual));
    let view_match = state
        .view_token
        .as_deref()
        .is_some_and(|expected| constant_time_eq(expected, actual));
    if operator_match || view_match {
        return Ok(PanelRole::Operator);
    }
    if state.public_enabled {
        return Ok(PanelRole::Public);
    }
    Err(PanelApiError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_view_token",
    ))
}

fn verify_admin_auth(state: &AppState, headers: &HeaderMap) -> Result<(), PanelApiError> {
    if state.admin_token.is_none() {
        return Err(PanelApiError::new(
            StatusCode::FORBIDDEN,
            "panel_admin_token_not_configured",
        ));
    }
    verify_panel_role(state, headers, PanelRole::Admin).map(|_| ())
}

fn view_token_from_headers(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(bearer_token)
    {
        return Some(value);
    }
    headers
        .get("x-vps-sentinel-view-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token);
        }
    }
    None
}

async fn ingest(
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
    let payload: PanelEnvelope = serde_json::from_slice(&body)
        .map_err(|err| PanelApiError::detail(StatusCode::BAD_REQUEST, "invalid_json", err))?;
    if !valid_panel_payload_identity(&payload, &node_name) {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
        ));
    }
    state.repo.insert_nonce(&headers, &node_name).await?;
    state.repo.persist_payload(&payload, &node_name).await?;
    let _ = state
        .events
        .send(PanelStreamEvent::refresh(PanelRole::Operator));
    Ok(Json(
        json!({ "ok": true, "message_id": payload.message_id }),
    ))
}

fn ingest_node_name(headers: &HeaderMap) -> Result<String, PanelApiError> {
    header(headers, "x-vps-sentinel-node-name").or_else(|_| header(headers, "x-vps-sentinel-node"))
}

fn valid_panel_payload_identity(payload: &PanelEnvelope, signed_node_name: &str) -> bool {
    match payload.schema_version {
        2 => payload.node.node_name == signed_node_name,
        1 => payload.node.node_id == signed_node_name || payload.node.node_name == signed_node_name,
        _ => false,
    }
}

async fn summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, PanelApiError> {
    verify_panel_role(&state, &headers, PanelRole::Public)?;
    let by_severity = state
        .repo
        .query_all("SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity")
        .await?;
    let by_category = state
        .repo
        .query_all("SELECT category, COUNT(*) AS count FROM findings GROUP BY category")
        .await?;
    let by_block_status = state
        .repo
        .query_all(
            "SELECT block_status, COUNT(*) AS count FROM probe_sources GROUP BY block_status",
        )
        .await?;
    let nodes = state
        .repo
        .query_all("SELECT node_name, last_seen_at, agent_version FROM nodes")
        .await?;
    Ok(Json(json!({
        "nodes": state.repo.count_distinct("nodes", "node_name", None).await?,
        "findings": state.repo.count("findings", None).await?,
        "incidents": state.repo.count("incidents", None).await?,
        "baseline_drifts": state.repo.count("baseline_drifts", None).await?,
        "active_blocks": state.repo.count("active_blocks", Some("expired = 0")).await?,
        "probe_sources": state.repo.count("probe_sources", None).await?,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_block_status": by_block_status,
        "node_status": node_status_counts(&nodes)
    })))
}

async fn trends(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    verify_panel_role(&state, &headers, PanelRole::Public)?;
    let request = PageRequest::try_from(query)?;
    let rows = state.repo.trend_points(&request).await?;
    Ok(Json(json!({ "items": rows })))
}

fn node_status_counts(nodes: &Value) -> Value {
    let mut counts = BTreeMap::from([
        ("fresh".to_string(), 0i64),
        ("stale".to_string(), 0i64),
        ("offline".to_string(), 0i64),
        ("retired".to_string(), 0i64),
    ]);
    let Value::Array(items) = nodes else {
        return json!(counts);
    };
    let now = Utc::now();
    for item in items {
        let name = item
            .get("node_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let version = item
            .get("agent_version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let status = panel_node_status(name, version, item.get("last_seen_at"), now);
        *counts.entry(status.to_string()).or_default() += 1;
    }
    json!(counts)
}

fn panel_node_status(
    node_name: &str,
    agent_version: &str,
    last_seen_at: Option<&Value>,
    now: DateTime<Utc>,
) -> &'static str {
    if node_name.trim().is_empty()
        || node_name.eq_ignore_ascii_case("local-host")
        || agent_version.to_ascii_lowercase().contains("smoke")
    {
        return "retired";
    }
    let Some(last_seen_at) = last_seen_at.and_then(Value::as_str) else {
        return "retired";
    };
    let Ok(last_seen_at) = DateTime::parse_from_rfc3339(last_seen_at) else {
        return "retired";
    };
    let age_minutes = now
        .signed_duration_since(last_seen_at.with_timezone(&Utc))
        .num_minutes();
    if age_minutes < 0 || age_minutes > DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES as i64 {
        "retired"
    } else if age_minutes > (DEFAULT_FRESHNESS_THRESHOLD_MINUTES * 6) as i64 {
        "offline"
    } else if age_minutes > DEFAULT_FRESHNESS_THRESHOLD_MINUTES as i64 {
        "stale"
    } else {
        "fresh"
    }
}

async fn nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Public)?;
    let columns = match role {
        PanelRole::Public | PanelRole::Operator => &["last_seen_at", "node_name"][..],
        PanelRole::Admin => &["last_seen_at", "node_name", "agent_version", "privacy_mode"][..],
    };
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "nodes",
            order_column: "last_seen_at",
            active_filter: None,
            columns,
        },
    )
    .await
}

async fn findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Operator)?;
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "findings",
            order_column: "timestamp",
            active_filter: None,
            columns: &[
                "id",
                "timestamp",
                "node_id AS node_name",
                "severity",
                "rule_id",
                "category",
                "subject",
                "title",
            ],
        },
    )
    .await
}

async fn finding_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DetailQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Operator)?;
    let detail = state.repo.finding_detail(&query.id, role).await?;
    Ok(Json(detail))
}

async fn finding_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FindingReviewRequest>,
) -> Result<Json<Value>, PanelApiError> {
    verify_admin_auth(&state, &headers)?;
    let review = FindingReview::try_from(request)?;
    state.repo.upsert_finding_review(&review).await?;
    let _ = state
        .events
        .send(PanelStreamEvent::refresh(PanelRole::Admin));
    Ok(Json(json!({ "ok": true, "finding_id": review.finding_id })))
}

async fn incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Operator)?;
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "incidents",
            order_column: "last_seen",
            active_filter: None,
            columns: &[
                "id",
                "last_seen",
                "node_id AS node_name",
                "severity",
                "score",
                "title",
                "summary",
            ],
        },
    )
    .await
}

async fn incident_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DetailQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Operator)?;
    let detail = state.repo.incident_detail(&query.id, role).await?;
    Ok(Json(detail))
}

async fn baseline_drifts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Operator)?;
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "baseline_drifts",
            order_column: "timestamp",
            active_filter: None,
            columns: &[
                "timestamp",
                "node_id AS node_name",
                "severity",
                "rule_id",
                "tier",
                "subject",
                "review_action",
            ],
        },
    )
    .await
}

async fn active_blocks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Operator)?;
    let columns = match role {
        PanelRole::Admin => &[
            "blocked_at",
            "node_id AS node_name",
            "ip",
            "rule_id",
            "backend",
            "reason",
            "expires_at",
        ][..],
        PanelRole::Operator => &[
            "blocked_at",
            "node_id AS node_name",
            "rule_id",
            "reason",
            "expires_at",
        ][..],
        PanelRole::Public => &["blocked_at", "node_id AS node_name"][..],
    };
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "active_blocks",
            order_column: "blocked_at",
            active_filter: Some("expired = 0"),
            columns,
        },
    )
    .await
}

async fn probe_sources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Admin)?;
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "probe_sources",
            order_column: "last_seen",
            active_filter: None,
            columns: &[
                "last_seen",
                "node_id AS node_name",
                "source_ip",
                "ip_version",
                "network_prefix",
                "seen_count",
                "block_status",
                "country",
                "asn",
                "organization",
                "categories_json",
                "rule_ids_json",
                "latest_reason",
                "block_reason",
            ],
        },
    )
    .await
}

async fn audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Admin)?;
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "panel_audit_logs",
            order_column: "created_at",
            active_filter: None,
            columns: &["created_at", "action", "actor", "target_type", "target_id"],
        },
    )
    .await
}

async fn paginated_dataset(
    state: &AppState,
    query: PageQuery,
    role: PanelRole,
    dataset: PanelDataset,
) -> Result<Json<Value>, PanelApiError> {
    let request = PageRequest::try_from(query)?;
    let (mut items, total) = state.repo.query_page(dataset, &request, role).await?;
    scope_panel_value(&mut items, role);
    Ok(Json(json!({
        "items": items,
        "total": total,
        "limit": request.limit,
        "offset": request.offset
    })))
}

impl TryFrom<PageQuery> for PageRequest {
    type Error = PanelApiError;

    fn try_from(value: PageQuery) -> Result<Self, Self::Error> {
        let from = value.from.as_deref().map(parse_panel_time).transpose()?;
        let to = value.to.as_deref().map(parse_panel_time).transpose()?;
        if let (Some(from), Some(to)) = (from, to) {
            if from > to {
                return Err(PanelApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_time_range",
                ));
            }
        }
        Ok(Self {
            from,
            to,
            limit: value
                .limit
                .unwrap_or(DEFAULT_PAGE_LIMIT)
                .clamp(1, MAX_PAGE_LIMIT),
            offset: value.offset.unwrap_or(0),
        })
    }
}

fn parse_panel_time(value: &str) -> Result<DateTime<Utc>, PanelApiError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d").map(|date| {
                date.and_hms_opt(0, 0, 0)
                    .expect("midnight is valid")
                    .and_utc()
            })
        })
        .map_err(|_| PanelApiError::new(StatusCode::BAD_REQUEST, "invalid_time"))
}

impl Repository {
    async fn connect(backend: DatabaseBackend, url: &str) -> Result<Self> {
        let driver = match backend {
            DatabaseBackend::Sqlite => {
                let path = sqlite_path_from_url(url);
                let connection = Connection::open(&path)
                    .with_context(|| format!("connect sqlite database: {path}"))?;
                RepositoryDriver::Sqlite(Arc::new(Mutex::new(connection)))
            }
            DatabaseBackend::Postgres => {
                let pool = PgPool::connect(url)
                    .await
                    .with_context(|| format!("connect postgres database: {url}"))?;
                RepositoryDriver::Postgres(pool)
            }
            DatabaseBackend::Mysql => {
                let pool = MySqlPool::connect(url)
                    .await
                    .with_context(|| format!("connect mysql database: {url}"))?;
                RepositoryDriver::Mysql(pool)
            }
        };
        Ok(Self { backend, driver })
    }

    async fn init_schema(&self) -> Result<()> {
        let schema = match self.backend {
            DatabaseBackend::Sqlite => include_str!("../../../panel/self-host/schema.sqlite.sql"),
            DatabaseBackend::Postgres => {
                include_str!("../../../panel/self-host/schema.postgres.sql")
            }
            DatabaseBackend::Mysql => include_str!("../../../panel/self-host/schema.mysql.sql"),
        };
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection
                    .lock()
                    .map_err(|err| anyhow!("sqlite connection lock poisoned: {err}"))?;
                connection.execute_batch(schema)?;
            }
            RepositoryDriver::Postgres(pool) => {
                for statement in schema
                    .split(';')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    if let Err(err) = sql_query(statement).execute(pool).await {
                        return Err(err.into());
                    }
                }
            }
            RepositoryDriver::Mysql(pool) => {
                for statement in schema
                    .split(';')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    if let Err(err) = sql_query(statement).execute(pool).await {
                        if !(self.backend == DatabaseBackend::Mysql
                            && is_mysql_duplicate_index(&err))
                        {
                            return Err(err.into());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn upsert_sql(
        &self,
        table: &str,
        columns: &[&str],
        conflict_columns: &[&str],
        update_columns: &[&str],
    ) -> String {
        let column_list = columns.join(", ");
        let placeholders = self.placeholders(columns.len());
        let updates = match self.backend {
            DatabaseBackend::Sqlite | DatabaseBackend::Postgres => update_columns
                .iter()
                .map(|column| format!("{column} = excluded.{column}"))
                .collect::<Vec<_>>()
                .join(", "),
            DatabaseBackend::Mysql => update_columns
                .iter()
                .map(|column| format!("{column} = VALUES({column})"))
                .collect::<Vec<_>>()
                .join(", "),
        };
        match self.backend {
            DatabaseBackend::Sqlite | DatabaseBackend::Postgres => format!(
                "INSERT INTO {table} ({column_list}) VALUES ({placeholders}) ON CONFLICT({}) DO UPDATE SET {updates}",
                conflict_columns.join(", ")
            ),
            DatabaseBackend::Mysql => format!(
                "INSERT INTO {table} ({column_list}) VALUES ({placeholders}) ON DUPLICATE KEY UPDATE {updates}"
            ),
        }
    }

    fn placeholders(&self, count: usize) -> String {
        match self.backend {
            DatabaseBackend::Postgres => (1..=count)
                .map(|index| format!("${index}"))
                .collect::<Vec<_>>()
                .join(", "),
            DatabaseBackend::Sqlite | DatabaseBackend::Mysql => std::iter::repeat("?")
                .take(count)
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    fn placeholder(&self, index: usize) -> String {
        match self.backend {
            DatabaseBackend::Postgres => format!("${index}"),
            DatabaseBackend::Sqlite | DatabaseBackend::Mysql => "?".to_string(),
        }
    }

    async fn execute_write(&self, sql: &str, values: &[DbValue]) -> Result<(), PanelApiError> {
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection.lock().map_err(sqlite_lock_error)?;
                let sqlite_values = values.iter().map(sqlite_value).collect::<Vec<_>>();
                connection.execute(sql, rusqlite::params_from_iter(sqlite_values))?;
            }
            RepositoryDriver::Postgres(pool) => {
                let mut query = sql_query(sql);
                for value in values {
                    query = match value {
                        DbValue::Text(value) => query.bind(value.as_str()),
                        DbValue::Integer(value) => query.bind(*value),
                        DbValue::NullText => query.bind(Option::<String>::None),
                        DbValue::NullInteger => query.bind(Option::<i64>::None),
                    };
                }
                query.execute(pool).await?;
            }
            RepositoryDriver::Mysql(pool) => {
                let mut query = sql_query(sql);
                for value in values {
                    query = match value {
                        DbValue::Text(value) => query.bind(value.as_str()),
                        DbValue::Integer(value) => query.bind(*value),
                        DbValue::NullText => query.bind(Option::<String>::None),
                        DbValue::NullInteger => query.bind(Option::<i64>::None),
                    };
                }
                query.execute(pool).await?;
            }
        }
        Ok(())
    }

    async fn query_all(&self, sql: &str) -> Result<Value, PanelApiError> {
        self.query_all_with_values(sql, &[]).await
    }

    async fn query_all_with_values(
        &self,
        sql: &str,
        values: &[DbValue],
    ) -> Result<Value, PanelApiError> {
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection.lock().map_err(sqlite_lock_error)?;
                let mut statement = connection.prepare(sql)?;
                let column_names = statement
                    .column_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let sqlite_values = values.iter().map(sqlite_value).collect::<Vec<_>>();
                let rows =
                    statement.query_map(rusqlite::params_from_iter(sqlite_values), |row| {
                        let mut map = serde_json::Map::new();
                        for (index, name) in column_names.iter().enumerate() {
                            map.insert(name.clone(), sqlite_ref_to_json(row.get_ref(index)?));
                        }
                        Ok(Value::Object(map))
                    })?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok(Value::Array(values))
            }
            RepositoryDriver::Postgres(pool) => {
                let mut query = sql_query(sql);
                for value in values {
                    query = match value {
                        DbValue::Text(value) => query.bind(value.as_str()),
                        DbValue::Integer(value) => query.bind(*value),
                        DbValue::NullText => query.bind(Option::<String>::None),
                        DbValue::NullInteger => query.bind(Option::<i64>::None),
                    };
                }
                let rows = query.fetch_all(pool).await?;
                let mut values = Vec::new();
                for row in rows {
                    let mut map = serde_json::Map::new();
                    for column in row.columns() {
                        let name = column.name();
                        let value = row
                            .try_get::<String, _>(name)
                            .map(Value::String)
                            .or_else(|_| row.try_get::<i64, _>(name).map(|value| json!(value)))
                            .or_else(|_| row.try_get::<f64, _>(name).map(|value| json!(value)))
                            .unwrap_or(Value::Null);
                        map.insert(name.to_string(), value);
                    }
                    values.push(Value::Object(map));
                }
                Ok(Value::Array(values))
            }
            RepositoryDriver::Mysql(pool) => {
                let mut query = sql_query(sql);
                for value in values {
                    query = match value {
                        DbValue::Text(value) => query.bind(value.as_str()),
                        DbValue::Integer(value) => query.bind(*value),
                        DbValue::NullText => query.bind(Option::<String>::None),
                        DbValue::NullInteger => query.bind(Option::<i64>::None),
                    };
                }
                let rows = query.fetch_all(pool).await?;
                let mut values = Vec::new();
                for row in rows {
                    let mut map = serde_json::Map::new();
                    for column in row.columns() {
                        let name = column.name();
                        let value = row
                            .try_get::<String, _>(name)
                            .map(Value::String)
                            .or_else(|_| row.try_get::<i64, _>(name).map(|value| json!(value)))
                            .or_else(|_| row.try_get::<f64, _>(name).map(|value| json!(value)))
                            .unwrap_or(Value::Null);
                        map.insert(name.to_string(), value);
                    }
                    values.push(Value::Object(map));
                }
                Ok(Value::Array(values))
            }
        }
    }

    async fn query_page(
        &self,
        dataset: PanelDataset,
        request: &PageRequest,
        role: PanelRole,
    ) -> Result<(Value, i64), PanelApiError> {
        let (where_sql, mut values) = self.page_where_clause(dataset, request);
        let count_sql = format!("SELECT COUNT(*) AS count FROM {}{where_sql}", dataset.table);
        let total = self.count_sql(&count_sql, &values).await?;

        let limit_placeholder = self.placeholder(values.len() + 1);
        let offset_placeholder = self.placeholder(values.len() + 2);
        values.push(DbValue::Integer(request.limit as i64));
        values.push(DbValue::Integer(request.offset as i64));
        let columns = dataset.columns.join(", ");
        let sql = format!(
            "SELECT {columns} FROM {}{where_sql} ORDER BY {} DESC LIMIT {limit_placeholder} OFFSET {offset_placeholder}",
            dataset.table, dataset.order_column
        );
        let mut items = self.query_all_with_values(&sql, &values).await?;
        expand_dataset_json_columns(dataset.table, &mut items);
        if should_redact_dataset(dataset.table, role) {
            redact_panel_value(&mut items);
        }
        Ok((items, total))
    }

    async fn finding_detail(&self, id: &str, role: PanelRole) -> Result<Value, PanelApiError> {
        let columns = [
            "id",
            "node_id AS node_name",
            "rule_id",
            "title",
            "severity",
            "confidence",
            "category",
            "subject",
            "timestamp",
            "dedup_key",
            "evidence_json",
            "impact_json",
            "recommendations_json",
            "received_at",
        ];
        let sql = format!(
            "SELECT {} FROM findings WHERE id = {}",
            columns.join(", "),
            self.placeholder(1)
        );
        let Some(mut detail) = self
            .query_one_with_values(&sql, &[DbValue::Text(id.to_string())])
            .await?
        else {
            return Err(PanelApiError::new(
                StatusCode::NOT_FOUND,
                "finding_not_found",
            ));
        };
        expand_json_column(&mut detail, "evidence_json", "evidence");
        expand_json_column(&mut detail, "impact_json", "impact");
        expand_json_column(&mut detail, "recommendations_json", "recommendations");
        if role == PanelRole::Admin {
            detail["review"] = self.finding_review_value(id).await?.unwrap_or(Value::Null);
        }
        redact_panel_value(&mut detail);
        scope_panel_value(&mut detail, role);
        Ok(detail)
    }

    async fn incident_detail(&self, id: &str, role: PanelRole) -> Result<Value, PanelApiError> {
        let columns = [
            "id",
            "node_id AS node_name",
            "title",
            "severity",
            "score",
            "first_seen",
            "last_seen",
            "summary",
            "payload_json",
            "received_at",
        ];
        let sql = format!(
            "SELECT {} FROM incidents WHERE id = {}",
            columns.join(", "),
            self.placeholder(1)
        );
        let Some(mut detail) = self
            .query_one_with_values(&sql, &[DbValue::Text(id.to_string())])
            .await?
        else {
            return Err(PanelApiError::new(
                StatusCode::NOT_FOUND,
                "incident_not_found",
            ));
        };
        expand_json_column(&mut detail, "payload_json", "payload");
        redact_panel_value(&mut detail);
        scope_panel_value(&mut detail, role);
        Ok(detail)
    }

    async fn trend_points(&self, request: &PageRequest) -> Result<Value, PanelApiError> {
        let mut values = Vec::new();
        let mut filters = Vec::new();
        if let Some(from) = request.from {
            filters.push(format!(
                "timestamp >= {}",
                self.placeholder(values.len() + 1)
            ));
            values.push(DbValue::Text(from.to_rfc3339()));
        }
        if let Some(to) = request.to {
            filters.push(format!(
                "timestamp <= {}",
                self.placeholder(values.len() + 1)
            ));
            values.push(DbValue::Text(to.to_rfc3339()));
        }
        let where_sql = if filters.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", filters.join(" AND "))
        };
        let limit_placeholder = self.placeholder(values.len() + 1);
        values.push(DbValue::Integer(5000));
        let sql = format!(
            "SELECT timestamp, severity FROM findings{where_sql} ORDER BY timestamp DESC LIMIT {limit_placeholder}"
        );
        let rows = self.query_all_with_values(&sql, &values).await?;
        let Value::Array(rows) = rows else {
            return Ok(Value::Array(Vec::new()));
        };
        let mut buckets: BTreeMap<String, BTreeMap<String, i64>> = BTreeMap::new();
        for row in rows {
            let timestamp = row
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let bucket = timestamp.chars().take(13).collect::<String>();
            if bucket.len() != 13 {
                continue;
            }
            let severity = row
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("Unknown")
                .to_string();
            *buckets
                .entry(bucket)
                .or_default()
                .entry(severity)
                .or_default() += 1;
        }
        let items = buckets
            .into_iter()
            .map(|(bucket, severities)| {
                let total = severities.values().sum::<i64>();
                json!({
                    "bucket": bucket,
                    "total": total,
                    "severity": severities
                })
            })
            .collect::<Vec<_>>();
        Ok(Value::Array(items))
    }

    async fn finding_review_value(&self, finding_id: &str) -> Result<Option<Value>, PanelApiError> {
        let columns = ["finding_id", "verdict", "note", "reviewer", "reviewed_at"];
        let sql = format!(
            "SELECT {} FROM finding_reviews WHERE finding_id = {}",
            columns.join(", "),
            self.placeholder(1)
        );
        self.query_one_with_values(&sql, &[DbValue::Text(finding_id.to_string())])
            .await
    }

    async fn query_one_with_values(
        &self,
        sql: &str,
        values: &[DbValue],
    ) -> Result<Option<Value>, PanelApiError> {
        let rows = self.query_all_with_values(sql, values).await?;
        let Value::Array(mut rows) = rows else {
            return Ok(None);
        };
        Ok(rows.pop())
    }

    async fn upsert_finding_review(&self, review: &FindingReview) -> Result<(), PanelApiError> {
        let exists_sql = format!(
            "SELECT COUNT(*) AS count FROM findings WHERE id = {}",
            self.placeholder(1)
        );
        if self
            .count_sql(&exists_sql, &[DbValue::Text(review.finding_id.clone())])
            .await?
            == 0
        {
            return Err(PanelApiError::new(
                StatusCode::NOT_FOUND,
                "finding_not_found",
            ));
        }
        let columns = ["finding_id", "verdict", "note", "reviewer", "reviewed_at"];
        let sql = self.upsert_sql(
            "finding_reviews",
            &columns,
            &["finding_id"],
            &["verdict", "note", "reviewer", "reviewed_at"],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(review.finding_id.clone()),
                DbValue::Text(review.verdict.clone()),
                DbValue::Text(review.note.clone()),
                DbValue::Text(review.reviewer.clone()),
                DbValue::Text(review.reviewed_at.to_rfc3339()),
            ],
        )
        .await?;
        self.insert_audit_log(
            "finding_review",
            &review.reviewer,
            "finding",
            &review.finding_id,
            json!({
                "verdict": review.verdict,
                "note_present": !review.note.is_empty()
            }),
            review.reviewed_at,
        )
        .await
    }

    async fn insert_audit_log(
        &self,
        action: &str,
        actor: &str,
        target_type: &str,
        target_id: &str,
        detail: Value,
        created_at: DateTime<Utc>,
    ) -> Result<(), PanelApiError> {
        let columns = [
            "id",
            "action",
            "actor",
            "target_type",
            "target_id",
            "detail_json",
            "created_at",
        ];
        let timestamp_key = created_at
            .timestamp_nanos_opt()
            .map(|value| value.to_string())
            .unwrap_or_else(|| created_at.timestamp_millis().to_string());
        let id = format!("{action}:{target_type}:{target_id}:{timestamp_key}");
        let sql = format!(
            "INSERT INTO panel_audit_logs ({}) VALUES ({})",
            columns.join(", "),
            self.placeholders(columns.len())
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(id),
                DbValue::Text(action.to_string()),
                DbValue::Text(if actor.trim().is_empty() {
                    "panel".to_string()
                } else {
                    actor.to_string()
                }),
                DbValue::Text(target_type.to_string()),
                DbValue::Text(target_id.to_string()),
                DbValue::Text(json_string(detail)?),
                DbValue::Text(created_at.to_rfc3339()),
            ],
        )
        .await
    }

    fn page_where_clause(
        &self,
        dataset: PanelDataset,
        request: &PageRequest,
    ) -> (String, Vec<DbValue>) {
        let mut parts = Vec::new();
        let mut values = Vec::new();
        if let Some(filter) = dataset.active_filter {
            parts.push(filter.to_string());
        }
        if let Some(from) = request.from {
            values.push(DbValue::Text(from.to_rfc3339()));
            parts.push(format!(
                "{} >= {}",
                dataset.order_column,
                self.placeholder(values.len())
            ));
        }
        if let Some(to) = request.to {
            values.push(DbValue::Text(to.to_rfc3339()));
            parts.push(format!(
                "{} <= {}",
                dataset.order_column,
                self.placeholder(values.len())
            ));
        }
        if parts.is_empty() {
            (String::new(), values)
        } else {
            (format!(" WHERE {}", parts.join(" AND ")), values)
        }
    }

    async fn count(&self, table: &str, where_clause: Option<&str>) -> Result<i64, PanelApiError> {
        let sql = match where_clause {
            Some(where_clause) => {
                format!("SELECT COUNT(*) AS count FROM {table} WHERE {where_clause}")
            }
            None => format!("SELECT COUNT(*) AS count FROM {table}"),
        };
        self.count_sql(&sql, &[]).await
    }

    async fn count_distinct(
        &self,
        table: &str,
        column: &str,
        where_clause: Option<&str>,
    ) -> Result<i64, PanelApiError> {
        let sql = match where_clause {
            Some(where_clause) => format!(
                "SELECT COUNT(DISTINCT {column}) AS count FROM {table} WHERE {where_clause}"
            ),
            None => format!("SELECT COUNT(DISTINCT {column}) AS count FROM {table}"),
        };
        self.count_sql(&sql, &[]).await
    }

    async fn count_sql(&self, sql: &str, values: &[DbValue]) -> Result<i64, PanelApiError> {
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection.lock().map_err(sqlite_lock_error)?;
                let sqlite_values = values.iter().map(sqlite_value).collect::<Vec<_>>();
                let count = connection.query_row(
                    sql,
                    rusqlite::params_from_iter(sqlite_values),
                    |row| row.get::<_, i64>(0),
                )?;
                Ok(count)
            }
            RepositoryDriver::Postgres(pool) => {
                let mut query = sql_query(sql);
                for value in values {
                    query = match value {
                        DbValue::Text(value) => query.bind(value.as_str()),
                        DbValue::Integer(value) => query.bind(*value),
                        DbValue::NullText => query.bind(Option::<String>::None),
                        DbValue::NullInteger => query.bind(Option::<i64>::None),
                    };
                }
                let row = query.fetch_one(pool).await?;
                Ok(row.try_get::<i64, _>("count").unwrap_or(0))
            }
            RepositoryDriver::Mysql(pool) => {
                let mut query = sql_query(sql);
                for value in values {
                    query = match value {
                        DbValue::Text(value) => query.bind(value.as_str()),
                        DbValue::Integer(value) => query.bind(*value),
                        DbValue::NullText => query.bind(Option::<String>::None),
                        DbValue::NullInteger => query.bind(Option::<i64>::None),
                    };
                }
                let row = query.fetch_one(pool).await?;
                Ok(row.try_get::<i64, _>("count").unwrap_or(0))
            }
        }
    }

    async fn insert_nonce(&self, headers: &HeaderMap, node_id: &str) -> Result<(), PanelApiError> {
        let now = Utc::now().timestamp();
        let nonce = header(headers, "x-vps-sentinel-nonce")?;
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection.lock().map_err(sqlite_lock_error)?;
                connection.execute(
                    "DELETE FROM ingest_nonces WHERE expires_at < ?",
                    rusqlite::params![now],
                )?;
                let existing = connection
                    .query_row(
                        "SELECT nonce FROM ingest_nonces WHERE nonce = ?",
                        rusqlite::params![&nonce],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                if existing.is_some() {
                    return Err(PanelApiError::new(StatusCode::CONFLICT, "nonce_replay"));
                }
                connection.execute(
                    "INSERT INTO ingest_nonces (nonce, node_id, expires_at) VALUES (?, ?, ?)",
                    rusqlite::params![&nonce, node_id, now + SIGNATURE_WINDOW_SECONDS],
                )?;
            }
            RepositoryDriver::Postgres(pool) => {
                let expires_placeholder = self.placeholders(1);
                sql_query(&format!(
                    "DELETE FROM ingest_nonces WHERE expires_at < {expires_placeholder}"
                ))
                .bind(now)
                .execute(pool)
                .await?;
                let existing = sql_query(&format!(
                    "SELECT nonce FROM ingest_nonces WHERE nonce = {}",
                    self.placeholders(1)
                ))
                .bind(&nonce)
                .fetch_optional(pool)
                .await?;
                if existing.is_some() {
                    return Err(PanelApiError::new(StatusCode::CONFLICT, "nonce_replay"));
                }
                sql_query(&format!(
                    "INSERT INTO ingest_nonces (nonce, node_id, expires_at) VALUES ({})",
                    self.placeholders(3)
                ))
                .bind(nonce)
                .bind(node_id)
                .bind(now + SIGNATURE_WINDOW_SECONDS)
                .execute(pool)
                .await?;
            }
            RepositoryDriver::Mysql(pool) => {
                let expires_placeholder = self.placeholders(1);
                sql_query(&format!(
                    "DELETE FROM ingest_nonces WHERE expires_at < {expires_placeholder}"
                ))
                .bind(now)
                .execute(pool)
                .await?;
                let existing = sql_query(&format!(
                    "SELECT nonce FROM ingest_nonces WHERE nonce = {}",
                    self.placeholders(1)
                ))
                .bind(&nonce)
                .fetch_optional(pool)
                .await?;
                if existing.is_some() {
                    return Err(PanelApiError::new(StatusCode::CONFLICT, "nonce_replay"));
                }
                sql_query(&format!(
                    "INSERT INTO ingest_nonces (nonce, node_id, expires_at) VALUES ({})",
                    self.placeholders(3)
                ))
                .bind(nonce)
                .bind(node_id)
                .bind(now + SIGNATURE_WINDOW_SECONDS)
                .execute(pool)
                .await?;
            }
        }
        Ok(())
    }

    async fn persist_payload(
        &self,
        payload: &PanelEnvelope,
        node_name: &str,
    ) -> Result<(), PanelApiError> {
        let received_at = Utc::now().to_rfc3339();
        let node = &payload.node;
        let node_name = redact_ip_text(node_name);
        self.upsert_node(&node_name, node, payload.sent_at, &received_at)
            .await?;
        self.upsert_heartbeat(&node_name, payload, &received_at)
            .await?;
        for finding in &payload.findings {
            self.upsert_finding(&node_name, finding, &received_at)
                .await?;
        }
        for incident in &payload.incidents {
            self.upsert_incident(&node_name, incident, &received_at)
                .await?;
        }
        for drift in &payload.baseline_drifts {
            self.upsert_drift(&node_name, drift, &received_at).await?;
        }
        for block in &payload.active_blocks {
            self.upsert_block(&node_name, block, &received_at).await?;
        }
        for source in &payload.probe_sources {
            self.upsert_probe_source(&node_name, source, &received_at)
                .await?;
        }
        Ok(())
    }

    async fn upsert_node(
        &self,
        node_name: &str,
        node: &PanelNode,
        sent_at: DateTime<Utc>,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let sql = self.upsert_sql(
            "nodes",
            &[
                "node_id",
                "node_name",
                "host_id",
                "hostname",
                "agent_version",
                "privacy_mode",
                "enabled_features_json",
                "storage_json",
                "last_seen_at",
                "updated_at",
            ],
            &["node_id"],
            &[
                "node_name",
                "host_id",
                "hostname",
                "agent_version",
                "privacy_mode",
                "enabled_features_json",
                "storage_json",
                "last_seen_at",
                "updated_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(node_name.to_string()),
                DbValue::Text(node_name.to_string()),
                DbValue::Text(String::new()),
                DbValue::Text(String::new()),
                DbValue::Text(node.agent_version.clone()),
                DbValue::Text(node.privacy_mode.clone()),
                DbValue::Text(json_string(&node.enabled_features)?),
                DbValue::Text(json_string(&node.storage)?),
                DbValue::Text(sent_at.to_rfc3339()),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn upsert_heartbeat(
        &self,
        node_name: &str,
        payload: &PanelEnvelope,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let mut scan = payload.scan.clone();
        redact_panel_value(&mut scan);
        let sql = self.upsert_sql(
            "heartbeats",
            &[
                "message_id",
                "node_id",
                "sent_at",
                "received_at",
                "scan_json",
            ],
            &["message_id"],
            &["sent_at", "received_at", "scan_json"],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(payload.message_id.clone()),
                DbValue::Text(node_name.to_string()),
                DbValue::Text(payload.sent_at.to_rfc3339()),
                DbValue::Text(received_at.to_string()),
                DbValue::Text(json_string(&scan)?),
            ],
        )
        .await?;
        Ok(())
    }

    async fn upsert_finding(
        &self,
        node_id: &str,
        finding: &PanelFinding,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let mut evidence = json!(finding.evidence);
        redact_panel_value(&mut evidence);
        let impact = redact_text_list(&finding.impact);
        let recommendations = redact_text_list(&finding.recommendations);
        let sql = self.upsert_sql(
            "findings",
            &[
                "id",
                "node_id",
                "rule_id",
                "title",
                "severity",
                "confidence",
                "category",
                "subject",
                "timestamp",
                "dedup_key",
                "evidence_json",
                "impact_json",
                "recommendations_json",
                "received_at",
            ],
            &["id"],
            &[
                "title",
                "severity",
                "confidence",
                "category",
                "subject",
                "timestamp",
                "dedup_key",
                "evidence_json",
                "impact_json",
                "recommendations_json",
                "received_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(finding.id.clone()),
                DbValue::Text(node_id.to_string()),
                DbValue::Text(finding.rule_id.clone()),
                DbValue::Text(redact_ip_text(&finding.title)),
                DbValue::Text(finding.severity.clone()),
                DbValue::Text(finding.confidence.clone()),
                DbValue::Text(finding.category.clone()),
                DbValue::Text(redact_ip_text(&finding.subject)),
                DbValue::Text(finding.timestamp.to_rfc3339()),
                DbValue::Text(redact_ip_text(&finding.dedup_key)),
                DbValue::Text(json_string(&evidence)?),
                DbValue::Text(json_string(&impact)?),
                DbValue::Text(json_string(&recommendations)?),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn upsert_incident(
        &self,
        node_id: &str,
        incident: &PanelIncident,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let mut payload = json!(incident);
        redact_panel_value(&mut payload);
        let sql = self.upsert_sql(
            "incidents",
            &[
                "id",
                "node_id",
                "title",
                "severity",
                "score",
                "first_seen",
                "last_seen",
                "summary",
                "payload_json",
                "received_at",
            ],
            &["id"],
            &[
                "title",
                "severity",
                "score",
                "first_seen",
                "last_seen",
                "summary",
                "payload_json",
                "received_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(incident.id.clone()),
                DbValue::Text(node_id.to_string()),
                DbValue::Text(redact_ip_text(&incident.title)),
                DbValue::Text(incident.severity.clone()),
                DbValue::Integer(i64::from(incident.score)),
                DbValue::Text(incident.first_seen.to_rfc3339()),
                DbValue::Text(incident.last_seen.to_rfc3339()),
                DbValue::Text(redact_ip_text(&incident.summary)),
                DbValue::Text(json_string(&payload)?),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn upsert_drift(
        &self,
        node_id: &str,
        drift: &PanelBaselineDrift,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let subject = redact_ip_text(&drift.subject);
        let reasons = redact_text_list(&drift.reasons);
        let id = format!(
            "{}:{}:{}:{}",
            node_id, drift.finding_id, subject, drift.timestamp
        );
        let sql = self.upsert_sql(
            "baseline_drifts",
            &[
                "id",
                "node_id",
                "finding_id",
                "rule_id",
                "severity",
                "subject",
                "timestamp",
                "tier",
                "score",
                "review_action",
                "reasons_json",
                "received_at",
            ],
            &["id"],
            &[
                "severity",
                "subject",
                "timestamp",
                "tier",
                "score",
                "review_action",
                "reasons_json",
                "received_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(id),
                DbValue::Text(node_id.to_string()),
                DbValue::Text(drift.finding_id.clone()),
                DbValue::Text(drift.rule_id.clone()),
                DbValue::Text(drift.severity.clone()),
                DbValue::Text(subject),
                DbValue::Text(drift.timestamp.to_rfc3339()),
                DbValue::Text(drift.tier.clone()),
                optional_i64(drift.score.map(i64::from)),
                DbValue::Text(drift.review_action.clone()),
                DbValue::Text(json_string(&reasons)?),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn upsert_block(
        &self,
        node_id: &str,
        block: &PanelActiveBlock,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let id = panel_block_storage_id(node_id, block);
        let sql = self.upsert_sql(
            "active_blocks",
            &[
                "id",
                "node_id",
                "ip",
                "rule_id",
                "finding_id",
                "reason",
                "backend",
                "blocked_at",
                "expires_at",
                "expired",
                "firewall_present",
                "received_at",
            ],
            &["id"],
            &[
                "rule_id",
                "finding_id",
                "reason",
                "backend",
                "blocked_at",
                "expires_at",
                "expired",
                "firewall_present",
                "received_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(id),
                DbValue::Text(node_id.to_string()),
                DbValue::Text(block.ip.clone()),
                DbValue::Text(block.rule_id.clone()),
                DbValue::Text(block.finding_id.clone()),
                DbValue::Text(redact_ip_text(&block.reason)),
                DbValue::Text(block.backend.clone()),
                DbValue::Text(block.blocked_at.to_rfc3339()),
                optional_string(block.expires_at.map(|value| value.to_rfc3339())),
                DbValue::Integer(if block.expired { 1 } else { 0 }),
                optional_i64(
                    block
                        .firewall_present
                        .map(|value| if value { 1 } else { 0 }),
                ),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn upsert_probe_source(
        &self,
        node_id: &str,
        source: &PanelProbeSource,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let id = panel_probe_source_id(node_id, &source.source_ip);
        let merged = self
            .merge_probe_source(&id, source)
            .await?
            .unwrap_or_else(|| MergedProbeSource::from(source));
        let columns = [
            "id",
            "node_id",
            "source_ip",
            "ip_version",
            "network_prefix",
            "country",
            "asn",
            "organization",
            "first_seen",
            "last_seen",
            "seen_count",
            "categories_json",
            "rule_ids_json",
            "latest_reason",
            "block_status",
            "block_reason",
            "updated_at",
        ];
        let sql = self.upsert_sql(
            "probe_sources",
            &columns,
            &["id"],
            &[
                "node_id",
                "source_ip",
                "ip_version",
                "network_prefix",
                "country",
                "asn",
                "organization",
                "first_seen",
                "last_seen",
                "seen_count",
                "categories_json",
                "rule_ids_json",
                "latest_reason",
                "block_status",
                "block_reason",
                "updated_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(id),
                DbValue::Text(node_id.to_string()),
                DbValue::Text(source.source_ip.clone()),
                DbValue::Text(source.ip_version.clone()),
                DbValue::Text(source.network_prefix.clone()),
                DbValue::Text(source.country.clone()),
                DbValue::Text(source.asn.clone()),
                DbValue::Text(source.organization.clone()),
                DbValue::Text(merged.first_seen),
                DbValue::Text(merged.last_seen),
                DbValue::Integer(merged.seen_count),
                DbValue::Text(json_string(&merged.categories)?),
                DbValue::Text(json_string(&merged.rule_ids)?),
                DbValue::Text(redact_ip_text(&source.latest_reason)),
                DbValue::Text(source.block_status.clone()),
                DbValue::Text(redact_ip_text(&source.block_reason)),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    async fn merge_probe_source(
        &self,
        id: &str,
        source: &PanelProbeSource,
    ) -> Result<Option<MergedProbeSource>, PanelApiError> {
        let sql = format!(
            "SELECT first_seen, last_seen, seen_count, categories_json, rule_ids_json FROM probe_sources WHERE id = {}",
            self.placeholder(1)
        );
        let Some(existing) = self
            .query_one_with_values(&sql, &[DbValue::Text(id.to_string())])
            .await?
        else {
            return Ok(None);
        };
        let first_seen = min_time_string(existing.get("first_seen"), source.first_seen);
        let last_seen = max_time_string(existing.get("last_seen"), source.last_seen);
        let seen_count = existing
            .get("seen_count")
            .and_then(Value::as_i64)
            .unwrap_or_default()
            .saturating_add(source.seen_count as i64);
        let categories = merge_string_sets(existing.get("categories_json"), &source.categories);
        let rule_ids = merge_string_sets(existing.get("rule_ids_json"), &source.rule_ids);
        Ok(Some(MergedProbeSource {
            first_seen,
            last_seen,
            seen_count,
            categories,
            rule_ids,
        }))
    }
}

struct MergedProbeSource {
    first_seen: String,
    last_seen: String,
    seen_count: i64,
    categories: Vec<String>,
    rule_ids: Vec<String>,
}

impl From<&PanelProbeSource> for MergedProbeSource {
    fn from(value: &PanelProbeSource) -> Self {
        Self {
            first_seen: value.first_seen.to_rfc3339(),
            last_seen: value.last_seen.to_rfc3339(),
            seen_count: value.seen_count as i64,
            categories: sorted_unique(&value.categories),
            rule_ids: sorted_unique(&value.rule_ids),
        }
    }
}

impl SecretResolver {
    fn new(shared_secret: Option<String>, node_secrets_json: Option<String>) -> Result<Self> {
        let node_secrets = match node_secrets_json {
            Some(value) if !value.trim().is_empty() => serde_json::from_str(&value)?,
            _ => BTreeMap::new(),
        };
        Ok(Self {
            shared_secret,
            node_secrets,
        })
    }

    fn secret_for(&self, node_id: &str) -> Option<&str> {
        self.node_secrets
            .get(node_id)
            .map(String::as_str)
            .or(self.shared_secret.as_deref())
    }
}

fn panel_block_storage_id(node_id: &str, block: &PanelActiveBlock) -> String {
    let source = if block.finding_id.trim().is_empty() {
        format!(
            "{}:{}:{}",
            block.rule_id,
            block.blocked_at.timestamp_millis(),
            block.backend
        )
    } else {
        block.finding_id.clone()
    };
    format!("{node_id}:{source}")
}

fn panel_probe_source_id(node_id: &str, source_ip: &str) -> String {
    format!("{node_id}:{}", source_ip.trim())
}

fn min_time_string(existing: Option<&Value>, candidate: DateTime<Utc>) -> String {
    let candidate_text = candidate.to_rfc3339();
    let Some(existing_text) = existing.and_then(Value::as_str) else {
        return candidate_text;
    };
    let Ok(existing_time) = DateTime::parse_from_rfc3339(existing_text) else {
        return candidate_text;
    };
    if existing_time.with_timezone(&Utc) <= candidate {
        existing_text.to_string()
    } else {
        candidate_text
    }
}

fn max_time_string(existing: Option<&Value>, candidate: DateTime<Utc>) -> String {
    let candidate_text = candidate.to_rfc3339();
    let Some(existing_text) = existing.and_then(Value::as_str) else {
        return candidate_text;
    };
    let Ok(existing_time) = DateTime::parse_from_rfc3339(existing_text) else {
        return candidate_text;
    };
    if existing_time.with_timezone(&Utc) >= candidate {
        existing_text.to_string()
    } else {
        candidate_text
    }
}

fn merge_string_sets(existing_json: Option<&Value>, incoming: &[String]) -> Vec<String> {
    let mut values = existing_json
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Vec<String>>(text).ok())
        .unwrap_or_default()
        .into_iter()
        .chain(incoming.iter().cloned())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut values = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn panel_redacted_ip_value() -> String {
    "redacted".to_string()
}

fn redact_text_list(items: &[String]) -> Vec<String> {
    items.iter().map(|item| redact_ip_text(item)).collect()
}

fn redact_panel_value(value: &mut Value) {
    match value {
        Value::String(text) => *text = redact_ip_text(text),
        Value::Array(items) => {
            for item in items {
                redact_panel_value(item);
            }
        }
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                let normalized_key = key.to_ascii_lowercase();
                if normalized_key == "ip"
                    || normalized_key.contains("_ip")
                    || normalized_key.contains("addr")
                {
                    *value = Value::String(panel_redacted_ip_value());
                } else if normalized_key == "node_name" {
                    if let Some(text) = value.as_str() {
                        *value = Value::String(public_node_name(text));
                    } else {
                        redact_panel_value(value);
                    }
                } else {
                    redact_panel_value(value);
                }
            }
        }
        _ => {}
    }
}

fn scope_panel_value(value: &mut Value, role: PanelRole) {
    match value {
        Value::Array(items) => {
            for item in items {
                scope_panel_value(item, role);
            }
        }
        Value::Object(map) => {
            let hidden = hidden_panel_keys(role);
            map.retain(|key, _| {
                let normalized = key.to_ascii_lowercase();
                !(hidden.iter().any(|candidate| *candidate == normalized)
                    || role != PanelRole::Admin && normalized.ends_with("_backend"))
            });
            if role != PanelRole::Admin {
                if let Some(reason) = map.get_mut("reason") {
                    *reason =
                        Value::String(panel_block_reason_summary(reason.as_str().unwrap_or("")));
                }
            }
            for value in map.values_mut() {
                scope_panel_value(value, role);
            }
        }
        _ => {}
    }
}

fn hidden_panel_keys(role: PanelRole) -> &'static [&'static str] {
    match role {
        PanelRole::Public => &[
            "active_response_backend",
            "backend",
            "dedup_key",
            "evidence",
            "evidence_json",
            "finding_id",
            "firewall_backend",
            "firewall_present",
            "host_id",
            "hostname",
            "id",
            "impact",
            "ip",
            "payload",
            "payload_json",
            "raw_log",
            "recommendations",
            "review",
            "reviewer",
            "storage",
            "storage_json",
        ],
        PanelRole::Operator => &[
            "active_response_backend",
            "backend",
            "dedup_key",
            "evidence",
            "evidence_json",
            "firewall_backend",
            "firewall_present",
            "host_id",
            "hostname",
            "payload",
            "payload_json",
            "raw_log",
            "received_at",
            "review",
            "reviewer",
            "storage",
            "storage_json",
        ],
        PanelRole::Admin => &[],
    }
}

fn panel_block_reason_summary(value: &str) -> String {
    let reason = value.to_ascii_lowercase();
    if reason.contains("web") || reason.contains("http") {
        "web_attack".to_string()
    } else if reason.contains("ssh") {
        "ssh_bruteforce".to_string()
    } else if reason.contains("repeated") || reason.contains("permanent") {
        "repeated_risk".to_string()
    } else if reason.trim().is_empty() {
        "policy_match".to_string()
    } else {
        "active_response".to_string()
    }
}

fn public_node_name(value: &str) -> String {
    let redacted = redact_ip_text(value).trim().to_string();
    if redacted.is_empty() || redacted == "redacted" {
        return "unnamed-node".to_string();
    }
    if generated_panel_identity(&redacted) {
        return "legacy-node".to_string();
    }
    redacted
}

fn generated_panel_identity(value: &str) -> bool {
    let Some((prefix, suffix)) = value.split_once('-') else {
        return false;
    };
    matches!(prefix, "node" | "host")
        && suffix.len() == 16
        && suffix.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn redact_ip_text(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index].is_ascii_digit() {
            if let Some(next) = ipv4_end_at(&chars, index) {
                out.push_str("redacted");
                index = next;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    redact_ip_tokens(&out)
}

fn ipv4_end_at(chars: &[char], start: usize) -> Option<usize> {
    let mut offset = start;
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
    Some(offset)
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
        panel_redacted_ip_value()
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

fn sqlite_path_from_url(url: &str) -> String {
    let trimmed = url.trim();
    let path = trimmed
        .strip_prefix("sqlite://")
        .or_else(|| trimmed.strip_prefix("sqlite:"))
        .unwrap_or(trimmed);
    if path.is_empty() {
        "panel.db".to_string()
    } else {
        path.to_string()
    }
}

fn sqlite_value(value: &DbValue) -> rusqlite::types::Value {
    match value {
        DbValue::Text(value) => rusqlite::types::Value::Text(value.clone()),
        DbValue::Integer(value) => rusqlite::types::Value::Integer(*value),
        DbValue::NullText | DbValue::NullInteger => rusqlite::types::Value::Null,
    }
}

fn sqlite_ref_to_json(value: rusqlite::types::ValueRef<'_>) -> Value {
    match value {
        rusqlite::types::ValueRef::Null => Value::Null,
        rusqlite::types::ValueRef::Integer(value) => json!(value),
        rusqlite::types::ValueRef::Real(value) => json!(value),
        rusqlite::types::ValueRef::Text(value) => {
            Value::String(String::from_utf8_lossy(value).to_string())
        }
        rusqlite::types::ValueRef::Blob(value) => {
            Value::String(format!("<{} bytes blob>", value.len()))
        }
    }
}

fn expand_json_column(row: &mut Value, json_column: &str, output_column: &str) {
    let Some(object) = row.as_object_mut() else {
        return;
    };
    let parsed = object
        .remove(json_column)
        .and_then(|value| value.as_str().map(str::to_string))
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or(Value::Null);
    object.insert(output_column.to_string(), parsed);
}

fn expand_dataset_json_columns(table: &str, rows: &mut Value) {
    let Value::Array(items) = rows else {
        return;
    };
    for row in items {
        if table == "probe_sources" {
            expand_json_column(row, "categories_json", "categories");
            expand_json_column(row, "rule_ids_json", "rule_ids");
        }
    }
}

fn should_redact_dataset(table: &str, role: PanelRole) -> bool {
    if role == PanelRole::Admin && matches!(table, "active_blocks" | "probe_sources") {
        return false;
    }
    true
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::Text).unwrap_or(DbValue::NullText)
}

fn optional_i64(value: Option<i64>) -> DbValue {
    value.map(DbValue::Integer).unwrap_or(DbValue::NullInteger)
}

fn sqlite_lock_error<T>(err: std::sync::PoisonError<T>) -> PanelApiError {
    PanelApiError::detail(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database_lock_error",
        err,
    )
}

async fn verify_signature(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    node_id: &str,
) -> Result<(), PanelApiError> {
    let timestamp = header(headers, "x-vps-sentinel-timestamp")?
        .parse::<i64>()
        .map_err(|_| PanelApiError::new(StatusCode::UNAUTHORIZED, "invalid_timestamp"))?;
    let nonce = header(headers, "x-vps-sentinel-nonce")?;
    let body_hash = header(headers, "x-vps-sentinel-body-sha256")?;
    let signature = header(headers, "x-vps-sentinel-signature")?;
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > SIGNATURE_WINDOW_SECONDS {
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "signature_timestamp_out_of_window",
        ));
    }
    if !nonce.starts_with(&format!("{node_id}:")) {
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "nonce_node_mismatch",
        ));
    }
    let actual_hash = panel_body_sha256_hex(body);
    if !constant_time_eq(&actual_hash, &body_hash) {
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "body_hash_mismatch",
        ));
    }
    let Some(secret) = state.secrets.secret_for(node_id) else {
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "unknown_node_secret",
        ));
    };
    let expected = panel_signature_hex(
        secret,
        PANEL_INGEST_METHOD,
        PANEL_INGEST_PATH,
        timestamp,
        &nonce,
        &body_hash,
    );
    if !constant_time_eq(&expected, &signature) {
        return Err(PanelApiError::new(
            StatusCode::UNAUTHORIZED,
            "signature_mismatch",
        ));
    }
    Ok(())
}

fn header(headers: &HeaderMap, name: &str) -> Result<String, PanelApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            PanelApiError::new(StatusCode::UNAUTHORIZED, format!("missing_header:{name}"))
        })
}

fn json_string(value: impl Serialize) -> Result<String, PanelApiError> {
    serde_json::to_string(&value)
        .map_err(|err| PanelApiError::detail(StatusCode::INTERNAL_SERVER_ERROR, "json_error", err))
}

fn is_mysql_duplicate_index(error: &sqlx_core::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db_error| db_error.code())
        .is_some_and(|code| code == "1061")
        || error.to_string().contains("Duplicate key name")
}

#[derive(Debug)]
struct PanelApiError {
    status: StatusCode,
    code: String,
    detail: String,
}

impl PanelApiError {
    fn new(status: StatusCode, code: impl Into<String>) -> Self {
        let code = code.into();
        Self {
            status,
            detail: code.clone(),
            code,
        }
    }

    fn detail(status: StatusCode, code: impl Into<String>, err: impl std::fmt::Display) -> Self {
        Self {
            status,
            code: code.into(),
            detail: err.to_string(),
        }
    }
}

impl IntoResponse for PanelApiError {
    fn into_response(self) -> Response {
        warn!(
            error = self.code,
            detail = self.detail,
            "panel request failed"
        );
        let public_detail = if self.status.is_server_error() {
            self.code.clone()
        } else {
            self.detail
        };
        (
            self.status,
            Json(ApiError {
                error: self.code,
                detail: public_detail,
            }),
        )
            .into_response()
    }
}

impl From<sqlx_core::Error> for PanelApiError {
    fn from(value: sqlx_core::Error) -> Self {
        Self::detail(StatusCode::INTERNAL_SERVER_ERROR, "database_error", value)
    }
}

impl From<rusqlite::Error> for PanelApiError {
    fn from(value: rusqlite::Error) -> Self {
        Self::detail(StatusCode::INTERNAL_SERVER_ERROR, "database_error", value)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        redact_ip_text, redact_panel_value, resolve_panel_role, scope_panel_value,
        verify_admin_auth, verify_view_auth, view_token_from_headers, AppState, DbValue,
        FindingReview, FindingReviewRequest, PageQuery, PageRequest, PanelDataset, PanelRole,
        PanelStreamEvent, Repository, RepositoryDriver, SecretResolver, MAX_PAGE_LIMIT,
    };
    use axum::http::{header, HeaderMap, HeaderValue};
    use chrono::Utc;
    use rusqlite::Connection;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::broadcast;

    #[test]
    fn page_request_clamps_limit_and_parses_dates() {
        let request = PageRequest::try_from(PageQuery {
            from: Some("2026-06-01".to_string()),
            to: Some("2026-06-20T10:00:00Z".to_string()),
            limit: Some(MAX_PAGE_LIMIT + 50),
            offset: Some(40),
        })
        .expect("valid page query");

        assert!(request.from.is_some());
        assert!(request.to.is_some());
        assert_eq!(request.limit, MAX_PAGE_LIMIT);
        assert_eq!(request.offset, 40);
    }

    #[test]
    fn page_request_rejects_inverted_time_range() {
        let err = PageRequest::try_from(PageQuery {
            from: Some("2026-06-20T10:00:00Z".to_string()),
            to: Some("2026-06-01T10:00:00Z".to_string()),
            limit: None,
            offset: None,
        })
        .expect_err("inverted time range should fail");

        assert_eq!(err.code, "invalid_time_range");
    }

    #[test]
    fn redacts_ipv4_and_ipv6_from_panel_values() {
        let mut value = serde_json::json!({
            "source_ip": "203.0.113.44",
            "node_name": "node-0123456789abcdef",
            "subject": "root@198.51.100.8 and [2001:db8::1]:443",
            "items": ["fe80::1%eth0", "no network identity"]
        });

        redact_panel_value(&mut value);
        let text = serde_json::to_string(&value).expect("json");

        assert!(!text.contains("203.0.113"));
        assert!(!text.contains("198.51.100"));
        assert!(!text.contains("2001:db8"));
        assert!(!text.contains("fe80::1"));
        assert!(!text.contains("0123456789abcdef"));
        assert_eq!(value["node_name"], "legacy-node");
        assert!(text.contains("redacted"));
    }

    #[test]
    fn redacts_ip_text_without_touching_normal_text() {
        assert_eq!(
            redact_ip_text("attempt from 203.0.113.44 and [2001:db8::5]:22"),
            "attempt from redacted and redacted"
        );
        assert_eq!(
            redact_ip_text("normal service event"),
            "normal service event"
        );
    }

    #[tokio::test]
    async fn repository_read_paths_redact_legacy_raw_ip_rows() {
        let repo = test_repo();
        repo.init_schema().await.expect("schema");
        let now = Utc::now().to_rfc3339();
        repo.execute_write(
            "INSERT INTO findings
             (id, node_id, rule_id, title, severity, confidence, category, subject, timestamp,
              dedup_key, evidence_json, impact_json, recommendations_json, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &[
                DbValue::Text("finding-raw".to_string()),
                DbValue::Text("node-a".to_string()),
                DbValue::Text("SSH-001".to_string()),
                DbValue::Text("source 203.0.113.44".to_string()),
                DbValue::Text("High".to_string()),
                DbValue::Text("high".to_string()),
                DbValue::Text("ssh".to_string()),
                DbValue::Text("root@203.0.113.44".to_string()),
                DbValue::Text(now.clone()),
                DbValue::Text("ssh:203.0.113.44".to_string()),
                DbValue::Text(r#"[{"key":"source_ip","value":"203.0.113.44"}]"#.to_string()),
                DbValue::Text(r#"["203.0.113.44 attempted login"]"#.to_string()),
                DbValue::Text(r#"["review 203.0.113.44"]"#.to_string()),
                DbValue::Text(now.clone()),
            ],
        )
        .await
        .expect("insert finding");
        repo.execute_write(
            "INSERT INTO finding_reviews (finding_id, verdict, note, reviewer, reviewed_at)
             VALUES (?, ?, ?, ?, ?)",
            &[
                DbValue::Text("finding-raw".to_string()),
                DbValue::Text("needs_review".to_string()),
                DbValue::Text("note with 203.0.113.44".to_string()),
                DbValue::Text("panel".to_string()),
                DbValue::Text(now.clone()),
            ],
        )
        .await
        .expect("insert review");
        repo.execute_write(
            "INSERT INTO incidents
             (id, node_id, title, severity, score, first_seen, last_seen, summary, payload_json, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &[
                DbValue::Text("incident-raw".to_string()),
                DbValue::Text("node-a".to_string()),
                DbValue::Text("incident 198.51.100.8".to_string()),
                DbValue::Text("High".to_string()),
                DbValue::Integer(90),
                DbValue::Text(now.clone()),
                DbValue::Text(now.clone()),
                DbValue::Text("summary 198.51.100.8".to_string()),
                DbValue::Text(r#"{"source_ip":"198.51.100.8"}"#.to_string()),
                DbValue::Text(now),
            ],
        )
        .await
        .expect("insert incident");

        let (page, total) = repo
            .query_page(
                PanelDataset {
                    table: "findings",
                    order_column: "timestamp",
                    active_filter: None,
                    columns: &[
                        "id",
                        "timestamp",
                        "node_id",
                        "severity",
                        "rule_id",
                        "category",
                        "subject",
                        "title",
                    ],
                },
                &PageRequest {
                    from: None,
                    to: None,
                    limit: 10,
                    offset: 0,
                },
                PanelRole::Operator,
            )
            .await
            .expect("page query");
        let finding_detail = repo
            .finding_detail("finding-raw", PanelRole::Admin)
            .await
            .expect("finding detail");
        let incident_detail = repo
            .incident_detail("incident-raw", PanelRole::Admin)
            .await
            .expect("incident detail");
        let output = serde_json::to_string(&(page, finding_detail, incident_detail)).expect("json");

        assert_eq!(total, 1);
        assert!(!output.contains("203.0.113"));
        assert!(!output.contains("198.51.100"));
        assert!(output.contains("redacted"));
    }

    #[tokio::test]
    async fn probe_source_page_preserves_admin_ip_and_redacts_lower_roles() {
        let repo = test_repo();
        repo.init_schema().await.expect("schema");
        let now = Utc::now().to_rfc3339();
        repo.execute_write(
            "INSERT INTO probe_sources
             (id, node_id, source_ip, ip_version, network_prefix, country, asn, organization,
              first_seen, last_seen, seen_count, categories_json, rule_ids_json, latest_reason,
              block_status, block_reason, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &[
                DbValue::Text("node-a:8.8.8.8".to_string()),
                DbValue::Text("node-a".to_string()),
                DbValue::Text("8.8.8.8".to_string()),
                DbValue::Text("ipv4".to_string()),
                DbValue::Text("8.8.8.0/24".to_string()),
                DbValue::Text("unknown".to_string()),
                DbValue::Text("unknown".to_string()),
                DbValue::Text("unknown".to_string()),
                DbValue::Text(now.clone()),
                DbValue::Text(now.clone()),
                DbValue::Integer(3),
                DbValue::Text(r#"["web"]"#.to_string()),
                DbValue::Text(r#"["WEB-001"]"#.to_string()),
                DbValue::Text("web_probe family=env_file count=3".to_string()),
                DbValue::Text("blocked".to_string()),
                DbValue::Text("web probe request_count=3".to_string()),
                DbValue::Text(now),
            ],
        )
        .await
        .expect("insert probe source");
        let dataset = PanelDataset {
            table: "probe_sources",
            order_column: "last_seen",
            active_filter: None,
            columns: &[
                "last_seen",
                "node_id AS node_name",
                "source_ip",
                "categories_json",
                "rule_ids_json",
                "latest_reason",
            ],
        };
        let request = PageRequest {
            from: None,
            to: None,
            limit: 10,
            offset: 0,
        };
        let (admin_page, _) = repo
            .query_page(dataset, &request, PanelRole::Admin)
            .await
            .expect("admin query");
        let (mut operator_page, _) = repo
            .query_page(dataset, &request, PanelRole::Operator)
            .await
            .expect("operator query");
        scope_panel_value(&mut operator_page, PanelRole::Operator);
        let admin_text = serde_json::to_string(&admin_page).expect("json");
        let operator_text = serde_json::to_string(&operator_page).expect("json");

        assert!(admin_text.contains("8.8.8.8"));
        assert!(admin_text.contains(r#""categories":["web"]"#));
        assert!(!operator_text.contains("8.8.8.8"));
        assert!(operator_text.contains("redacted"));
    }

    #[test]
    fn view_token_accepts_bearer_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer panel-token"),
        );

        assert_eq!(view_token_from_headers(&headers), Some("panel-token"));
    }

    #[test]
    fn view_token_accepts_legacy_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-vps-sentinel-view-token",
            HeaderValue::from_static("panel-token"),
        );

        assert_eq!(view_token_from_headers(&headers), Some("panel-token"));
    }

    #[test]
    fn view_token_rejects_missing_or_malformed_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(view_token_from_headers(&headers), None);

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic panel-token"),
        );
        assert_eq!(view_token_from_headers(&headers), None);
    }

    #[test]
    fn per_node_secret_overrides_shared_secret() {
        let mut nodes = BTreeMap::new();
        nodes.insert("node-a".to_string(), "node-secret".to_string());
        let resolver = SecretResolver {
            shared_secret: Some("shared".to_string()),
            node_secrets: nodes,
        };

        assert_eq!(resolver.secret_for("node-a"), Some("node-secret"));
        assert_eq!(resolver.secret_for("node-b"), Some("shared"));
    }

    #[test]
    fn admin_token_can_read_but_view_token_cannot_write() {
        let state = test_state(Some("view-token"), Some("admin-token"));
        let mut admin_headers = HeaderMap::new();
        admin_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer admin-token"),
        );
        let mut view_headers = HeaderMap::new();
        view_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer view-token"),
        );

        assert!(verify_view_auth(&state, &admin_headers).is_ok());
        assert!(verify_view_auth(&state, &view_headers).is_ok());
        assert!(verify_admin_auth(&state, &admin_headers).is_ok());
        assert_eq!(
            verify_admin_auth(&state, &view_headers)
                .expect_err("view token cannot administer")
                .code,
            "insufficient_panel_role"
        );
    }

    #[test]
    fn public_role_requires_enabled_public_access() {
        let state = test_state(Some("view-token"), Some("admin-token"));
        let headers = HeaderMap::new();

        assert_eq!(
            resolve_panel_role(&state, &headers)
                .expect_err("public access is disabled by default")
                .code,
            "missing_view_token"
        );

        let mut public_state = test_state(Some("view-token"), Some("admin-token"));
        public_state.public_enabled = true;
        assert_eq!(
            resolve_panel_role(&public_state, &headers).expect("public role"),
            PanelRole::Public
        );
    }

    #[test]
    fn scope_removes_sensitive_fields_for_operator() {
        let mut value = serde_json::json!({
            "id": "finding-1",
            "node_name": "node-a",
            "rule_id": "SSH-001",
            "reason": "web probe family=cgi request_count=10 backend=nft",
            "backend": "nftables",
            "evidence": [{"key": "cmdline", "value": "secret"}],
            "payload": {"token": "secret"},
            "recommendations": ["review service"]
        });

        scope_panel_value(&mut value, PanelRole::Operator);
        let text = serde_json::to_string(&value).expect("json");

        assert!(text.contains("SSH-001"));
        assert!(text.contains("web_attack"));
        assert!(!text.contains("nftables"));
        assert!(!text.contains("cmdline"));
        assert!(!text.contains("payload"));
        assert!(text.contains("recommendations"));
    }

    #[test]
    fn finding_review_rejects_unknown_verdict() {
        let err = FindingReview::try_from(FindingReviewRequest {
            finding_id: "finding-1".to_string(),
            verdict: "ignore_forever".to_string(),
            note: String::new(),
            reviewer: String::new(),
        })
        .expect_err("unknown verdict should fail");

        assert_eq!(err.code, "invalid_review_verdict");
    }

    fn test_state(view_token: Option<&str>, admin_token: Option<&str>) -> AppState {
        AppState {
            repo: Arc::new(test_repo()),
            secrets: Arc::new(SecretResolver {
                shared_secret: Some("shared".to_string()),
                node_secrets: BTreeMap::new(),
            }),
            view_token: view_token.map(str::to_string),
            operator_token: None,
            admin_token: admin_token.map(str::to_string),
            public_enabled: false,
            theme: "default".to_string(),
            max_body_bytes: 1024,
            events: broadcast::channel::<PanelStreamEvent>(8).0,
            stream_tickets: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn test_repo() -> Repository {
        Repository {
            backend: super::DatabaseBackend::Sqlite,
            driver: RepositoryDriver::Sqlite(Arc::new(Mutex::new(
                Connection::open_in_memory().expect("memory sqlite"),
            ))),
        }
    }
}
