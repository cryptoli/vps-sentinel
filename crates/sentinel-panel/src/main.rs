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
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use clap::{Parser, ValueEnum};
use rusqlite::{Connection, OptionalExtension};
use sentinel_core::panel_auth::{
    constant_time_eq, panel_body_sha256_hex, panel_signature_hex, PANEL_INGEST_METHOD,
    PANEL_INGEST_PATH,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx_core::column::Column;
use sqlx_core::query::query as sql_query;
use sqlx_core::row::Row;
use sqlx_mysql::MySqlPool;
use sqlx_postgres::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};
use uuid::Uuid;

mod auth;
mod http_security;
mod ingest;
mod repository;
mod stream;

use auth::*;
use http_security::{panel_csp_header, security_headers};
use ingest::ingest;
use stream::{stream, stream_ticket};
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
const PANEL_TRANSPORT_ENCODING: &str = "json-base64";
const DEFAULT_PUBLIC_PAGES: &str = "overview,probe_sources,nodes";
const DEFAULT_ADMIN_PATH: &str = "/panel-admin";
const DEFAULT_THEMES: &str = "default:Default";

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

    #[arg(long, env = "PANEL_TOKEN")]
    panel_token: Option<String>,

    #[arg(long, env = "PANEL_PUBLIC_ENABLED", default_value_t = false)]
    public_enabled: bool,

    #[arg(long, env = "PANEL_PUBLIC_PAGES", default_value = DEFAULT_PUBLIC_PAGES)]
    public_pages: String,

    #[arg(long, env = "PANEL_ADMIN_PATH")]
    admin_path: Option<String>,

    #[arg(long, env = "PANEL_WEB_DIR")]
    web_dir: Option<PathBuf>,

    #[arg(long, env = "PANEL_THEME", default_value = "default")]
    theme: String,

    #[arg(long, env = "PANEL_THEMES", default_value = DEFAULT_THEMES)]
    themes: String,

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
    panel_token: Option<String>,
    public_enabled: bool,
    public_pages: BTreeSet<String>,
    admin_path: String,
    theme: String,
    themes: Vec<PanelThemeOption>,
    max_body_bytes: usize,
    events: broadcast::Sender<PanelStreamEvent>,
    stream_tickets: Arc<Mutex<BTreeMap<String, StreamTicket>>>,
    csp_header: HeaderValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
enum PanelRole {
    Public = 0,
    Private = 1,
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
    datasets: Vec<&'static str>,
    server_time: DateTime<Utc>,
    retry_after_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
struct PanelThemeOption {
    id: String,
    label: String,
}

impl PanelStreamEvent {
    fn refresh(role: PanelRole) -> Self {
        Self::refresh_datasets(
            role,
            vec![
                "summary",
                "trends",
                "nodes",
                "findings",
                "incidents",
                "baseline_drifts",
                "active_blocks",
                "probe_sources",
                "audit_logs",
            ],
        )
    }

    fn refresh_datasets(role: PanelRole, datasets: Vec<&'static str>) -> Self {
        Self {
            kind: "refresh",
            role,
            datasets,
            server_time: Utc::now(),
            retry_after_seconds: STREAM_RETRY_SECONDS,
        }
    }

    fn hello(role: PanelRole) -> Self {
        Self {
            kind: "hello",
            role,
            datasets: Vec::new(),
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

#[derive(Debug, Deserialize)]
struct PanelReviewRequest {
    target_type: String,
    target_id: String,
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
struct PanelTransportBody {
    encoding: String,
    payload: String,
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
    #[serde(default)]
    metrics: Option<Value>,
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
    #[serde(default)]
    category: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewTargetType {
    Finding,
    Incident,
    BaselineDrift,
}

#[derive(Debug, Clone)]
struct PanelReview {
    target_type: ReviewTargetType,
    target_id: String,
    review_signature: String,
    verdict: String,
    note: String,
    reviewer: String,
    reviewed_at: DateTime<Utc>,
}

impl PanelReview {
    fn response_review(&self) -> Value {
        json!({
            "target_type": self.target_type.as_str(),
            "target_id": &self.target_id,
            "review_signature": &self.review_signature,
            "verdict": &self.verdict,
            "note": &self.note,
            "reviewer": &self.reviewer,
            "reviewed_at": self.reviewed_at.to_rfc3339(),
        })
    }
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
        let verdict = normalize_review_verdict(&value.verdict)?;
        Ok(Self {
            finding_id: finding_id.to_string(),
            verdict,
            note: value.note.trim().chars().take(1000).collect(),
            reviewer: value.reviewer.trim().chars().take(128).collect::<String>(),
            reviewed_at: Utc::now(),
        })
    }
}

impl TryFrom<PanelReviewRequest> for PanelReview {
    type Error = PanelApiError;

    fn try_from(value: PanelReviewRequest) -> Result<Self, Self::Error> {
        let target_type = ReviewTargetType::try_from(value.target_type.as_str())?;
        let target_id = value.target_id.trim();
        if target_id.is_empty() || target_id.len() > 191 {
            return Err(PanelApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_review_target_id",
            ));
        }
        let verdict = normalize_review_verdict(&value.verdict)?;
        Ok(Self {
            target_type,
            target_id: target_id.to_string(),
            review_signature: String::new(),
            verdict,
            note: value.note.trim().chars().take(1000).collect(),
            reviewer: value.reviewer.trim().chars().take(128).collect::<String>(),
            reviewed_at: Utc::now(),
        })
    }
}

impl TryFrom<&str> for ReviewTargetType {
    type Error = PanelApiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "finding" | "findings" => Ok(Self::Finding),
            "incident" | "incidents" => Ok(Self::Incident),
            "baseline_drift" | "baseline_drifts" | "baseline" | "drift" => Ok(Self::BaselineDrift),
            _ => Err(PanelApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_review_target_type",
            )),
        }
    }
}

impl ReviewTargetType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::Incident => "incident",
            Self::BaselineDrift => "baseline_drift",
        }
    }

    fn table(self) -> &'static str {
        match self {
            Self::Finding => "findings",
            Self::Incident => "incidents",
            Self::BaselineDrift => "baseline_drifts",
        }
    }

    fn id_column(self) -> &'static str {
        "id"
    }

    fn not_found_error(self) -> &'static str {
        match self {
            Self::Finding => "finding_not_found",
            Self::Incident => "incident_not_found",
            Self::BaselineDrift => "baseline_drift_not_found",
        }
    }
}

fn normalize_review_verdict(value: &str) -> Result<String, PanelApiError> {
    let verdict = value.trim();
    if !matches!(verdict, "false_positive" | "confirmed" | "needs_review") {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_review_verdict",
        ));
    }
    Ok(verdict.to_string())
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
    let panel_token = args
        .panel_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    let public_pages = parse_public_pages(&args.public_pages);
    if panel_token.is_none() && !args.public_enabled && public_pages.is_empty() {
        warn!("PANEL_TOKEN, PANEL_PUBLIC_ENABLED=true, or PANEL_PUBLIC_PAGES is not configured; panel browser APIs will reject access");
    }
    let (events, _) = broadcast::channel(128);
    let csp_header = panel_csp_header(&web_dir);
    let admin_path = match args
        .admin_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(path) => normalize_panel_path(path),
        None => {
            let generated = random_panel_admin_path();
            warn!(
                "PANEL_ADMIN_PATH is not set; generated a temporary management path: {}",
                generated
            );
            generated
        }
    };
    let themes = parse_panel_themes(&args.themes);
    let state = AppState {
        repo: Arc::new(repo),
        secrets: Arc::new(secrets),
        panel_token,
        public_enabled: args.public_enabled,
        public_pages,
        admin_path,
        theme: args.theme,
        themes,
        max_body_bytes: args.max_body_bytes,
        events,
        stream_tickets: Arc::new(Mutex::new(BTreeMap::new())),
        csp_header,
    };
    let index_file = web_dir.join("index.html");
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
        .route("/api/v1/review", post(panel_review))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/incident", get(incident_detail))
        .route("/api/v1/baseline-drifts", get(baseline_drifts))
        .route("/api/v1/active-blocks", get(active_blocks))
        .route("/api/v1/probe-sources", get(probe_sources))
        .route("/api/v1/audit-logs", get(audit_logs))
        .route("/api/v1/ingest", post(ingest))
        .fallback_service(ServeDir::new(&web_dir).fallback(ServeFile::new(index_file)))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state);
    info!(bind = %args.bind, "vps-sentinel panel started");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn settings(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let role = resolve_panel_role(&state, &headers).ok();
    let public_pages = state.public_pages.iter().cloned().collect::<Vec<_>>();
    Json(json!({
        "admin_path": state.admin_path,
        "theme": state.theme,
        "themes": state.themes,
        "auth_required": !panel_public_access_enabled(&state),
        "auth_configured": state.panel_token.is_some(),
        "stream_supported": true,
        "public_enabled": panel_public_access_enabled(&state),
        "public_pages": public_pages,
        "role": role,
        "freshness_threshold_minutes": DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
        "node_retired_threshold_minutes": DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
        "server_time": Utc::now().to_rfc3339()
    }))
}

async fn summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, PanelApiError> {
    verify_panel_role(&state, &headers, PanelRole::Public)?;
    let active_findings_filter =
        review_not_false_positive_filter("findings", ReviewTargetType::Finding);
    let active_incidents_filter =
        review_not_false_positive_filter("incidents", ReviewTargetType::Incident);
    let active_drifts_filter =
        review_not_false_positive_filter("baseline_drifts", ReviewTargetType::BaselineDrift);
    let by_severity = state
        .repo
        .query_all(&format!(
            "SELECT severity, COUNT(*) AS count FROM findings WHERE {active_findings_filter} GROUP BY severity"
        ))
        .await?;
    let by_category = state
        .repo
        .query_all(&format!(
            "SELECT category, COUNT(*) AS count FROM findings WHERE {active_findings_filter} GROUP BY category"
        ))
        .await?;
    let by_block_status = state
        .repo
        .query_all(
            &format!(
                "SELECT block_status, COUNT(DISTINCT source_ip) AS count FROM probe_sources WHERE {} GROUP BY block_status",
                blocked_probe_source_filter()
            ),
        )
        .await?;
    let nodes = state
        .repo
        .latest_node_rows(&["node_name", "last_seen_at", "agent_version"], None)
        .await?;
    let node_count = nodes.len();
    Ok(Json(json!({
        "nodes": node_count,
        "findings": state.repo.count("findings", Some(&active_findings_filter)).await?,
        "incidents": state.repo.count("incidents", Some(&active_incidents_filter)).await?,
        "baseline_drifts": state.repo.count("baseline_drifts", Some(&active_drifts_filter)).await?,
        "active_blocks": state.repo.count("active_blocks", Some("expired = 0")).await?,
        "probe_sources": state.repo.count_distinct("probe_sources", "source_ip", Some(blocked_probe_source_filter())).await?,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_block_status": by_block_status,
        "node_status": node_status_counts(&Value::Array(nodes))
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
    if is_panel_placeholder_node(node_name, agent_version) {
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

fn is_panel_placeholder_node(node_name: &str, agent_version: &str) -> bool {
    node_name.trim().is_empty()
        || node_name.eq_ignore_ascii_case("local-host")
        || agent_version.to_ascii_lowercase().contains("smoke")
}

fn panel_row_is_newer(candidate: &Value, existing: &Value, time_key: &str) -> bool {
    panel_row_time(candidate, time_key) > panel_row_time(existing, time_key)
}

fn panel_row_time(row: &Value, key: &str) -> Option<DateTime<Utc>> {
    row.get(key)
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn panel_row_name(row: &Value) -> &str {
    row.get("node_name")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn panel_node_sort_key(row: &Value) -> String {
    panel_row_name(row).trim().to_ascii_lowercase()
}

async fn nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_role(&state, &headers, PanelRole::Public)?;
    let columns = match role {
        PanelRole::Public => &["last_seen_at", "node_name", "agent_version", "metrics_json"][..],
        PanelRole::Private => &[
            "last_seen_at",
            "node_name",
            "agent_version",
            "privacy_mode",
            "storage_json",
            "metrics_json",
        ][..],
    };
    let request = PageRequest::try_from(query)?;
    let (mut items, total) = state
        .repo
        .latest_nodes_page(columns, &request, role)
        .await?;
    scope_panel_value(&mut items, role);
    Ok(Json(json!({
        "items": items,
        "total": total,
        "limit": request.limit,
        "offset": request.offset
    })))
}

async fn findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_page_role(&state, &headers, "findings", PanelRole::Private)?;
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
                "review_signature",
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
    let role = verify_panel_role(&state, &headers, PanelRole::Private)?;
    let detail = state.repo.finding_detail(&query.id, role).await?;
    Ok(Json(detail))
}

async fn finding_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FindingReviewRequest>,
) -> Result<Json<Value>, PanelApiError> {
    verify_private_write_auth(&state, &headers)?;
    let review = FindingReview::try_from(request)?;
    let panel_review = state.repo.upsert_finding_review(&review).await?;
    let _ = state.events.send(PanelStreamEvent::refresh_datasets(
        PanelRole::Public,
        vec!["summary", "trends", "findings", "audit_logs"],
    ));
    Ok(Json(json!({
        "ok": true,
        "finding_id": &review.finding_id,
        "review": panel_review.response_review(),
    })))
}

async fn panel_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PanelReviewRequest>,
) -> Result<Json<Value>, PanelApiError> {
    verify_private_write_auth(&state, &headers)?;
    let review = PanelReview::try_from(request)?;
    let review = state.repo.upsert_panel_review(&review).await?;
    let datasets = match review.target_type {
        ReviewTargetType::Finding => vec!["summary", "trends", "findings", "audit_logs"],
        ReviewTargetType::Incident => vec!["summary", "trends", "incidents", "audit_logs"],
        ReviewTargetType::BaselineDrift => {
            vec!["summary", "trends", "baseline_drifts", "audit_logs"]
        }
    };
    let _ = state.events.send(PanelStreamEvent::refresh_datasets(
        PanelRole::Public,
        datasets,
    ));
    Ok(Json(json!({
        "ok": true,
        "target_type": review.target_type.as_str(),
        "target_id": &review.target_id,
        "review": review.response_review(),
    })))
}

async fn incidents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_page_role(&state, &headers, "incidents", PanelRole::Private)?;
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
                "review_signature",
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
    let role = verify_panel_role(&state, &headers, PanelRole::Private)?;
    let detail = state.repo.incident_detail(&query.id, role).await?;
    Ok(Json(detail))
}

async fn baseline_drifts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_page_role(&state, &headers, "baseline_drifts", PanelRole::Private)?;
    paginated_dataset(
        &state,
        query,
        role,
        PanelDataset {
            table: "baseline_drifts",
            order_column: "timestamp",
            active_filter: None,
            columns: &[
                "id",
                "finding_id",
                "timestamp",
                "node_id AS node_name",
                "severity",
                "rule_id",
                "category",
                "tier",
                "subject",
                "review_signature",
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
    let role = verify_panel_page_role(&state, &headers, "active_blocks", PanelRole::Private)?;
    let columns = match role {
        PanelRole::Private => &[
            "blocked_at",
            "node_id AS node_name",
            "ip",
            "(
                SELECT network_prefix FROM probe_sources
                WHERE probe_sources.source_ip = active_blocks.ip
                  AND network_prefix IS NOT NULL
                  AND network_prefix <> ''
                  AND LOWER(network_prefix) <> 'unknown'
                ORDER BY probe_sources.last_seen DESC
                LIMIT 1
             ) AS network_prefix",
            "(
                SELECT country FROM probe_sources
                WHERE probe_sources.source_ip = active_blocks.ip
                  AND country IS NOT NULL
                  AND country <> ''
                  AND LOWER(country) <> 'unknown'
                ORDER BY probe_sources.last_seen DESC
                LIMIT 1
             ) AS country",
            "(
                SELECT asn FROM probe_sources
                WHERE probe_sources.source_ip = active_blocks.ip
                  AND asn IS NOT NULL
                  AND asn <> ''
                  AND LOWER(asn) <> 'unknown'
                ORDER BY probe_sources.last_seen DESC
                LIMIT 1
             ) AS asn",
            "(
                SELECT organization FROM probe_sources
                WHERE probe_sources.source_ip = active_blocks.ip
                  AND organization IS NOT NULL
                  AND organization <> ''
                  AND LOWER(organization) <> 'unknown'
                ORDER BY probe_sources.last_seen DESC
                LIMIT 1
             ) AS organization",
            "rule_id",
            "backend",
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
    let role = verify_panel_page_role(&state, &headers, "probe_sources", PanelRole::Private)?;
    let request = PageRequest::try_from(query)?;
    let (mut items, total) = state.repo.probe_sources_page(&request, role).await?;
    scope_panel_value(&mut items, role);
    scope_probe_source_rows(&mut items, role);
    Ok(Json(json!({
        "items": items,
        "total": total,
        "limit": request.limit,
        "offset": request.offset
    })))
}

async fn audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Result<Json<Value>, PanelApiError> {
    let role = verify_panel_page_role(&state, &headers, "audit_logs", PanelRole::Private)?;
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
    if let Some(target_type) = review_target_for_table(dataset.table) {
        state
            .repo
            .attach_panel_reviews(target_type, &mut items, role)
            .await?;
    }
    scope_panel_value(&mut items, role);
    Ok(Json(json!({
        "items": items,
        "total": total,
        "limit": request.limit,
        "offset": request.offset
    })))
}

fn review_target_for_table(table: &str) -> Option<ReviewTargetType> {
    match table {
        "findings" => Some(ReviewTargetType::Finding),
        "incidents" => Some(ReviewTargetType::Incident),
        "baseline_drifts" => Some(ReviewTargetType::BaselineDrift),
        _ => None,
    }
}

fn review_not_false_positive_filter(table: &str, target_type: ReviewTargetType) -> String {
    format!(
        "NOT EXISTS (
            SELECT 1 FROM panel_reviews review
            WHERE review.target_type = '{}'
              AND (
                review.target_id = {table}.id
                OR (
                    review.review_signature <> ''
                    AND review.review_signature = {table}.review_signature
                )
              )
              AND review.verdict = 'false_positive'
        )",
        target_type.as_str()
    )
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
            NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M")
                .or_else(|_| NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M"))
                .map(|timestamp| timestamp.and_utc())
        })
        .or_else(|_| {
            NaiveDate::parse_from_str(value, "%Y-%m-%d").map(|date| {
                date.and_hms_opt(0, 0, 0)
                    .expect("midnight is valid")
                    .and_utc()
            })
        })
        .map_err(|_| PanelApiError::new(StatusCode::BAD_REQUEST, "invalid_time"))
}

fn baseline_category_from_rule(rule_id: &str) -> &'static str {
    match rule_id
        .split('-')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase()
        .as_str()
    {
        "AUTH" | "SSH" => "ssh",
        "USER" => "user",
        "PRIV" => "privilege",
        "PERSIST" => "persistence",
        "PROC" => "process",
        "NET" | "SERVICE" => "network",
        "FILE" => "file_integrity",
        "WEB" => "web",
        "DOCKER" => "docker",
        "ROOTKIT" => "rootkit",
        "CONFIG" => "config_risk",
        "SYS" | "SYSTEM" => "system",
        _ => "system",
    }
}

fn finding_review_signature(
    node_id: &str,
    rule_id: &str,
    category: &str,
    subject: &str,
    title: &str,
) -> String {
    review_signature(&[
        ReviewSignaturePart::stable("finding"),
        ReviewSignaturePart::stable(node_id),
        ReviewSignaturePart::stable(rule_id),
        ReviewSignaturePart::stable(category),
        ReviewSignaturePart::dynamic(subject),
        ReviewSignaturePart::dynamic(title),
    ])
}

fn incident_review_signature(node_id: &str, severity: &str, title: &str, summary: &str) -> String {
    review_signature(&[
        ReviewSignaturePart::stable("incident"),
        ReviewSignaturePart::stable(node_id),
        ReviewSignaturePart::stable(severity),
        ReviewSignaturePart::dynamic(title),
        ReviewSignaturePart::dynamic(summary),
    ])
}

fn drift_review_signature(
    node_id: &str,
    rule_id: &str,
    category: &str,
    subject: &str,
    tier: &str,
) -> String {
    review_signature(&[
        ReviewSignaturePart::stable("baseline_drift"),
        ReviewSignaturePart::stable(node_id),
        ReviewSignaturePart::stable(rule_id),
        ReviewSignaturePart::stable(category),
        ReviewSignaturePart::dynamic(subject),
        ReviewSignaturePart::stable(tier),
    ])
}

struct ReviewSignaturePart<'a> {
    value: &'a str,
    dynamic: bool,
}

impl<'a> ReviewSignaturePart<'a> {
    fn stable(value: &'a str) -> Self {
        Self {
            value,
            dynamic: false,
        }
    }

    fn dynamic(value: &'a str) -> Self {
        Self {
            value,
            dynamic: true,
        }
    }
}

fn review_signature(parts: &[ReviewSignaturePart<'_>]) -> String {
    let mut source = String::new();
    for part in parts {
        source.push('|');
        source.push_str(&normalize_review_signature_part(part.value, part.dynamic));
    }
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    format!("v1:{:x}", hasher.finalize())
}

fn normalize_review_signature_part(value: &str, dynamic: bool) -> String {
    let redacted = redact_ip_text(value);
    let mut out = String::new();
    let mut previous_space = false;
    let mut number_open = false;
    for ch in redacted.trim().to_ascii_lowercase().chars() {
        if dynamic && ch.is_ascii_digit() {
            if !number_open {
                out.push('#');
                number_open = true;
            }
            previous_space = false;
            continue;
        }
        number_open = false;
        if ch.is_whitespace() {
            if !previous_space {
                out.push(' ');
                previous_space = true;
            }
            continue;
        }
        previous_space = false;
        if dynamic && matches!(ch, '"' | '\'' | '`') {
            continue;
        }
        out.push(ch);
    }
    out.trim().chars().take(256).collect()
}

fn review_signature_from_row(target_type: ReviewTargetType, row: &Value) -> String {
    let text = |key: &str| row.get(key).and_then(Value::as_str).unwrap_or_default();
    match target_type {
        ReviewTargetType::Finding => finding_review_signature(
            text("node_id"),
            text("rule_id"),
            text("category"),
            text("subject"),
            text("title"),
        ),
        ReviewTargetType::Incident => incident_review_signature(
            text("node_id"),
            text("severity"),
            text("title"),
            text("summary"),
        ),
        ReviewTargetType::BaselineDrift => drift_review_signature(
            text("node_id"),
            text("rule_id"),
            text("category"),
            text("subject"),
            text("tier"),
        ),
    }
}

struct MergedProbeSource {
    first_seen: String,
    last_seen: String,
    seen_count: i64,
    categories: Vec<String>,
    rule_ids: Vec<String>,
    network_prefix: String,
    country: String,
    asn: String,
    organization: String,
    block_status: String,
}

impl From<&PanelProbeSource> for MergedProbeSource {
    fn from(value: &PanelProbeSource) -> Self {
        Self {
            first_seen: value.first_seen.to_rfc3339(),
            last_seen: value.last_seen.to_rfc3339(),
            seen_count: value.seen_count as i64,
            categories: sorted_unique(&value.categories),
            rule_ids: sorted_unique(&value.rule_ids),
            network_prefix: value.network_prefix.clone(),
            country: value.country.clone(),
            asn: value.asn.clone(),
            organization: value.organization.clone(),
            block_status: value.block_status.clone(),
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

fn blocked_probe_source_filter() -> &'static str {
    "(LOWER(COALESCE(block_status, '')) LIKE '%block%' OR LOWER(COALESCE(block_status, '')) IN ('temporary', 'permanent', 'blocked'))"
}

fn prefer_meaningful_text(existing: Option<&Value>, candidate: &str) -> String {
    let candidate = candidate.trim();
    if meaningful_probe_text(candidate) {
        return candidate.to_string();
    }
    let existing = existing.and_then(Value::as_str).unwrap_or_default().trim();
    if meaningful_probe_text(existing) {
        existing.to_string()
    } else if candidate.is_empty() {
        "unknown".to_string()
    } else {
        candidate.to_string()
    }
}

fn meaningful_probe_text(value: &str) -> bool {
    let normalized = value.trim();
    !normalized.is_empty() && !normalized.eq_ignore_ascii_case("unknown")
}

fn strongest_probe_source_status(existing: &str, candidate: &str) -> String {
    match (
        probe_source_status_rank(existing),
        probe_source_status_rank(candidate),
    ) {
        (left, right) if right >= left => candidate.trim().to_string(),
        _ => existing.trim().to_string(),
    }
}

fn probe_source_status_rank(value: &str) -> u8 {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.contains("permanent") {
        3
    } else if normalized.contains("block") || matches!(normalized.as_str(), "temporary" | "blocked")
    {
        2
    } else if normalized == "observed" {
        1
    } else {
        0
    }
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
                    || role != PanelRole::Private && normalized.ends_with("_backend"))
            });
            if role != PanelRole::Private {
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

fn scope_probe_source_rows(value: &mut Value, role: PanelRole) {
    if role != PanelRole::Public {
        return;
    }
    let Value::Array(rows) = value else {
        return;
    };
    for row in rows {
        let Some(object) = row.as_object_mut() else {
            continue;
        };
        for key in [
            "network_prefix",
            "latest_reason",
            "block_reason",
            "first_seen",
        ] {
            object.remove(key);
        }
        if let Some(Value::String(node_name)) = object.get_mut("node_name") {
            *node_name = public_node_name(node_name);
        }
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
            "review_signature",
            "reviewer",
            "storage",
            "storage_json",
        ],
        PanelRole::Private => &["review_signature"],
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
        if table == "nodes" {
            expand_json_column(row, "storage_json", "storage");
            expand_json_column(row, "metrics_json", "metrics");
        }
    }
}

fn attach_node_statuses(rows: &mut Value) {
    let Value::Array(items) = rows else {
        return;
    };
    let now = Utc::now();
    for item in items {
        let node_name = item
            .get("node_name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let version = item
            .get("agent_version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let status = panel_node_status(node_name, version, item.get("last_seen_at"), now);
        item["status"] = Value::String(status.to_string());
    }
}

fn should_redact_dataset(table: &str, role: PanelRole) -> bool {
    if role == PanelRole::Private && matches!(table, "active_blocks" | "probe_sources") {
        return false;
    }
    if table == "probe_sources" {
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

fn optional_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
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

fn is_sqlite_missing_compat_index(error: &rusqlite::Error, statement: &str) -> bool {
    is_compat_review_signature_index(statement)
        && error
            .to_string()
            .to_ascii_lowercase()
            .contains("no such column: review_signature")
}

fn is_sqlx_missing_compat_index(error: &sqlx_core::Error, statement: &str) -> bool {
    if !is_compat_review_signature_index(statement) {
        return false;
    }
    let message = error.to_string().to_ascii_lowercase();
    message.contains("review_signature") && message.contains("column")
}

fn is_compat_review_signature_index(statement: &str) -> bool {
    let normalized = statement.to_ascii_lowercase();
    normalized.contains("create index") && normalized.contains("review_signature")
}

fn is_mysql_duplicate_column(error: &sqlx_core::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db_error| db_error.code())
        .is_some_and(|code| code == "1060")
        || error.to_string().contains("Duplicate column name")
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
mod tests;
