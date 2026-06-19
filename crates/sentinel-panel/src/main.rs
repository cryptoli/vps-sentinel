use anyhow::{anyhow, Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
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
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{info, warn};

const SIGNATURE_WINDOW_SECONDS: i64 = 300;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_WEB_DIR: &str = "panel/web";

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
    theme: String,
    max_body_bytes: usize,
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
}

#[derive(Debug, Deserialize)]
struct PanelNode {
    node_id: String,
    node_name: String,
    host_id: String,
    hostname: String,
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

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
    detail: String,
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
    let state = AppState {
        repo: Arc::new(repo),
        secrets: Arc::new(secrets),
        theme: args.theme,
        max_body_bytes: args.max_body_bytes,
    };
    let app = Router::new()
        .route("/api/v1/settings", get(settings))
        .route("/api/v1/summary", get(summary))
        .route("/api/v1/nodes", get(nodes))
        .route("/api/v1/findings", get(findings))
        .route("/api/v1/incidents", get(incidents))
        .route("/api/v1/baseline-drifts", get(baseline_drifts))
        .route("/api/v1/active-blocks", get(active_blocks))
        .route("/api/v1/ingest", post(ingest))
        .fallback_service(ServeDir::new(web_dir))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);
    info!(bind = %args.bind, "vps-sentinel panel started");
    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn settings(State(state): State<AppState>) -> Json<Value> {
    Json(json!({ "theme": state.theme }))
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
    let node_id = header(&headers, "x-vps-sentinel-node")?;
    verify_signature(&state, &headers, &body, &node_id).await?;
    let payload: PanelEnvelope = serde_json::from_slice(&body)
        .map_err(|err| PanelApiError::detail(StatusCode::BAD_REQUEST, "invalid_json", err))?;
    if payload.schema_version != 1 || payload.node.node_id != node_id {
        return Err(PanelApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
        ));
    }
    state.repo.insert_nonce(&headers, &node_id).await?;
    state.repo.persist_payload(&payload).await?;
    Ok(Json(
        json!({ "ok": true, "message_id": payload.message_id }),
    ))
}

async fn summary(State(state): State<AppState>) -> Result<Json<Value>, PanelApiError> {
    let by_severity = state
        .repo
        .query_all("SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity")
        .await?;
    Ok(Json(json!({
        "nodes": state.repo.count("nodes", None).await?,
        "findings": state.repo.count("findings", None).await?,
        "incidents": state.repo.count("incidents", None).await?,
        "baseline_drifts": state.repo.count("baseline_drifts", None).await?,
        "active_blocks": state.repo.count("active_blocks", Some("expired = 0")).await?,
        "by_severity": by_severity
    })))
}

async fn nodes(State(state): State<AppState>) -> Result<Json<Value>, PanelApiError> {
    Ok(Json(
        state
            .repo
            .query_all("SELECT * FROM nodes ORDER BY last_seen_at DESC LIMIT 200")
            .await?,
    ))
}

async fn findings(State(state): State<AppState>) -> Result<Json<Value>, PanelApiError> {
    Ok(Json(
        state
            .repo
            .query_all("SELECT * FROM findings ORDER BY timestamp DESC LIMIT 300")
            .await?,
    ))
}

async fn incidents(State(state): State<AppState>) -> Result<Json<Value>, PanelApiError> {
    Ok(Json(
        state
            .repo
            .query_all("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 200")
            .await?,
    ))
}

async fn baseline_drifts(State(state): State<AppState>) -> Result<Json<Value>, PanelApiError> {
    Ok(Json(
        state
            .repo
            .query_all("SELECT * FROM baseline_drifts ORDER BY timestamp DESC LIMIT 300")
            .await?,
    ))
}

async fn active_blocks(State(state): State<AppState>) -> Result<Json<Value>, PanelApiError> {
    Ok(Json(
        state
            .repo
            .query_all(
                "SELECT * FROM active_blocks WHERE expired = 0 ORDER BY blocked_at DESC LIMIT 300",
            )
            .await?,
    ))
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
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection.lock().map_err(sqlite_lock_error)?;
                let mut statement = connection.prepare(sql)?;
                let column_names = statement
                    .column_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let rows = statement.query_map([], |row| {
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
                let rows = sql_query(sql).fetch_all(pool).await?;
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
                let rows = sql_query(sql).fetch_all(pool).await?;
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

    async fn count(&self, table: &str, where_clause: Option<&str>) -> Result<i64, PanelApiError> {
        let sql = match where_clause {
            Some(where_clause) => {
                format!("SELECT COUNT(*) AS count FROM {table} WHERE {where_clause}")
            }
            None => format!("SELECT COUNT(*) AS count FROM {table}"),
        };
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection.lock().map_err(sqlite_lock_error)?;
                let count = connection.query_row(&sql, [], |row| row.get::<_, i64>(0))?;
                Ok(count)
            }
            RepositoryDriver::Postgres(pool) => {
                let row = sql_query(&sql).fetch_one(pool).await?;
                Ok(row.try_get::<i64, _>("count").unwrap_or(0))
            }
            RepositoryDriver::Mysql(pool) => {
                let row = sql_query(&sql).fetch_one(pool).await?;
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

    async fn persist_payload(&self, payload: &PanelEnvelope) -> Result<(), PanelApiError> {
        let received_at = Utc::now().to_rfc3339();
        let node = &payload.node;
        self.upsert_node(node, payload.sent_at, &received_at)
            .await?;
        self.upsert_heartbeat(payload, &received_at).await?;
        for finding in &payload.findings {
            self.upsert_finding(&node.node_id, finding, &received_at)
                .await?;
        }
        for incident in &payload.incidents {
            self.upsert_incident(&node.node_id, incident, &received_at)
                .await?;
        }
        for drift in &payload.baseline_drifts {
            self.upsert_drift(&node.node_id, drift, &received_at)
                .await?;
        }
        for block in &payload.active_blocks {
            self.upsert_block(&node.node_id, block, &received_at)
                .await?;
        }
        Ok(())
    }

    async fn upsert_node(
        &self,
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
                DbValue::Text(node.node_id.clone()),
                DbValue::Text(node.node_name.clone()),
                DbValue::Text(node.host_id.clone()),
                DbValue::Text(node.hostname.clone()),
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
        payload: &PanelEnvelope,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
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
                DbValue::Text(payload.node.node_id.clone()),
                DbValue::Text(payload.sent_at.to_rfc3339()),
                DbValue::Text(received_at.to_string()),
                DbValue::Text(json_string(&payload.scan)?),
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
                DbValue::Text(finding.title.clone()),
                DbValue::Text(finding.severity.clone()),
                DbValue::Text(finding.confidence.clone()),
                DbValue::Text(finding.category.clone()),
                DbValue::Text(finding.subject.clone()),
                DbValue::Text(finding.timestamp.to_rfc3339()),
                DbValue::Text(finding.dedup_key.clone()),
                DbValue::Text(json_string(&finding.evidence)?),
                DbValue::Text(json_string(&finding.impact)?),
                DbValue::Text(json_string(&finding.recommendations)?),
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
                DbValue::Text(incident.title.clone()),
                DbValue::Text(incident.severity.clone()),
                DbValue::Integer(i64::from(incident.score)),
                DbValue::Text(incident.first_seen.to_rfc3339()),
                DbValue::Text(incident.last_seen.to_rfc3339()),
                DbValue::Text(incident.summary.clone()),
                DbValue::Text(json_string(incident)?),
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
        let id = format!(
            "{}:{}:{}:{}",
            node_id, drift.finding_id, drift.subject, drift.timestamp
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
                DbValue::Text(drift.subject.clone()),
                DbValue::Text(drift.timestamp.to_rfc3339()),
                DbValue::Text(drift.tier.clone()),
                optional_i64(drift.score.map(i64::from)),
                DbValue::Text(drift.review_action.clone()),
                DbValue::Text(json_string(&drift.reasons)?),
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
        let id = format!("{}:{}", node_id, block.ip);
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
                DbValue::Text(block.reason.clone()),
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
        (
            self.status,
            Json(ApiError {
                error: self.code,
                detail: self.detail,
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
    use super::SecretResolver;
    use std::collections::BTreeMap;

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
}
