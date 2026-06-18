use crate::baseline::BaselineSnapshot;
use blake3::Hasher;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use sentinel_core::{Finding, RawEvent, SentinelError, SentinelResult};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const SIZE_LIMIT_TARGET_PERCENT: u64 = 80;
const SIZE_LIMIT_MAX_PASSES: usize = 6;
const MIN_SIZE_PRUNE_BATCH: usize = 1_000;
const KEEP_LATEST_FINDINGS: usize = 5_000;
const KEEP_LATEST_NOTIFICATION_LOGS: usize = 5_000;
const KEEP_LATEST_SCAN_RUNS: usize = 1_000;

#[derive(Debug, Clone, Copy)]
struct SizePrunePolicy {
    table: &'static str,
    order_column: &'static str,
    divisor: usize,
    min_pass: usize,
    keep_latest: usize,
}

const SIZE_PRUNE_POLICIES: &[SizePrunePolicy] = &[
    SizePrunePolicy {
        table: "raw_events",
        order_column: "timestamp",
        divisor: 4,
        min_pass: 0,
        keep_latest: 0,
    },
    SizePrunePolicy {
        table: "notification_logs",
        order_column: "attempted_at",
        divisor: 3,
        min_pass: 0,
        keep_latest: KEEP_LATEST_NOTIFICATION_LOGS,
    },
    SizePrunePolicy {
        table: "scan_runs",
        order_column: "finished_at",
        divisor: 3,
        min_pass: 0,
        keep_latest: KEEP_LATEST_SCAN_RUNS,
    },
    SizePrunePolicy {
        table: "findings",
        order_column: "timestamp",
        divisor: 5,
        min_pass: 1,
        keep_latest: KEEP_LATEST_FINDINGS,
    },
    SizePrunePolicy {
        table: "baseline_snapshots",
        order_column: "created_at",
        divisor: 2,
        min_pass: 2,
        keep_latest: 1,
    },
];

/// SQLite-backed local event store.
pub struct SqliteStore {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLimitReport {
    pub size_before_bytes: u64,
    pub size_after_bytes: u64,
    pub deleted_rows: usize,
    pub vacuumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageStats {
    pub database_bytes: u64,
    pub raw_events: usize,
    pub findings: usize,
    pub notification_logs: usize,
    pub finding_dedup_states: usize,
    pub scan_runs: usize,
    pub baseline_snapshots: usize,
    pub rule_states: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRunSummary {
    pub total: usize,
    pub failed: usize,
    pub last_finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClearTarget {
    RawEvents,
    Findings,
    NotificationLogs,
    ScanRuns,
    BaselineSnapshots,
    AllHistory,
}

impl SqliteStore {
    /// Open or create the database and run idempotent migrations.
    pub fn open(path: impl Into<PathBuf>) -> SentinelResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| SentinelError::io(parent, err))?;
        }
        let store = Self { path };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stats(&self) -> SentinelResult<StorageStats> {
        let conn = self.connection()?;
        Ok(StorageStats {
            database_bytes: self.database_footprint_bytes()?,
            raw_events: table_row_count(&conn, "raw_events")?,
            findings: table_row_count(&conn, "findings")?,
            notification_logs: table_row_count(&conn, "notification_logs")?,
            finding_dedup_states: table_row_count(&conn, "finding_dedup_state")?,
            scan_runs: table_row_count(&conn, "scan_runs")?,
            baseline_snapshots: table_row_count(&conn, "baseline_snapshots")?,
            rule_states: table_row_count(&conn, "rule_states")?,
        })
    }

    pub fn save_raw_events(&self, events: &[RawEvent]) -> SentinelResult<()> {
        let mut conn = self.connection()?;
        let tx = conn
            .transaction()
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        for event in events {
            let mut stored_event = event.clone();
            stored_event.id = raw_event_storage_id(event);
            let payload = serde_json::to_string(&stored_event)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            tx.execute(
                "INSERT OR REPLACE INTO raw_events (id, source, kind, timestamp, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    stored_event.id,
                    stored_event.source,
                    stored_event.kind,
                    stored_event.timestamp.to_rfc3339(),
                    payload
                ],
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        }
        tx.commit()
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }

    pub fn save_findings(&self, findings: &[Finding]) -> SentinelResult<()> {
        let mut conn = self.connection()?;
        let tx = conn
            .transaction()
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        for finding in findings {
            let payload = serde_json::to_string(finding)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            tx.execute(
                "INSERT OR REPLACE INTO findings
                 (id, host_id, title, severity, category, rule_id, timestamp, subject, dedup_key, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    finding.id,
                    finding.host_id,
                    finding.title,
                    finding.severity.to_string(),
                    finding.category.to_string(),
                    finding.rule_id,
                    finding.timestamp.to_rfc3339(),
                    finding.subject,
                    finding.dedup_key,
                    payload
                ],
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
            tx.execute(
                "INSERT INTO finding_dedup_state (dedup_key, last_seen_at)
                 VALUES (?1, ?2)
                 ON CONFLICT(dedup_key) DO UPDATE SET
                   last_seen_at = CASE
                     WHEN excluded.last_seen_at > finding_dedup_state.last_seen_at
                     THEN excluded.last_seen_at
                     ELSE finding_dedup_state.last_seen_at
                   END",
                params![finding.dedup_key, finding.timestamp.to_rfc3339()],
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        }
        tx.commit()
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }

    pub fn list_findings(&self, limit: usize) -> SentinelResult<Vec<Finding>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT payload_json FROM findings ORDER BY timestamp DESC LIMIT ?1")
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let rows = stmt
            .query_map([limit as i64], |row| row.get::<_, String>(0))
            .map_err(|err| SentinelError::Storage(err.to_string()))?;

        let mut findings = Vec::new();
        for row in rows {
            let payload = row.map_err(|err| SentinelError::Storage(err.to_string()))?;
            let finding = serde_json::from_str(&payload)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            findings.push(finding);
        }
        Ok(findings)
    }

    pub fn list_findings_between(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> SentinelResult<Vec<Finding>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM findings
                 WHERE timestamp >= ?1 AND timestamp < ?2
                 ORDER BY timestamp DESC",
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let rows = stmt
            .query_map(params![since.to_rfc3339(), until.to_rfc3339()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|err| SentinelError::Storage(err.to_string()))?;

        let mut findings = Vec::new();
        for row in rows {
            let payload = row.map_err(|err| SentinelError::Storage(err.to_string()))?;
            let finding = serde_json::from_str(&payload)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            findings.push(finding);
        }
        Ok(findings)
    }

    pub fn get_finding(&self, id: &str) -> SentinelResult<Option<Finding>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT payload_json FROM findings WHERE id = ?1")
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let mut rows = stmt
            .query([id])
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|err| SentinelError::Storage(err.to_string()))?
        {
            let payload: String = row
                .get(0)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            let finding = serde_json::from_str(&payload)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            return Ok(Some(finding));
        }
        Ok(None)
    }

    pub fn finding_seen_since(
        &self,
        dedup_key: &str,
        since: DateTime<Utc>,
    ) -> SentinelResult<bool> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT 1 FROM finding_dedup_state
                 WHERE dedup_key = ?1 AND last_seen_at >= ?2
                 LIMIT 1",
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let mut rows = stmt
            .query(params![dedup_key, since.to_rfc3339()])
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        rows.next()
            .map(|row| row.is_some())
            .map_err(|err| SentinelError::Storage(err.to_string()))
    }

    pub fn save_baseline_snapshot(&self, snapshot: &BaselineSnapshot) -> SentinelResult<()> {
        let conn = self.connection()?;
        let payload = serde_json::to_string(snapshot)
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        conn.execute(
            "INSERT INTO baseline_snapshots (id, created_at, payload_json) VALUES (?1, ?2, ?3)",
            params![snapshot.id, snapshot.created_at.to_rfc3339(), payload],
        )
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }

    pub fn latest_baseline_snapshot(&self) -> SentinelResult<Option<BaselineSnapshot>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT payload_json FROM baseline_snapshots ORDER BY created_at DESC LIMIT 1")
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let mut rows = stmt
            .query([])
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|err| SentinelError::Storage(err.to_string()))?
        {
            let payload: String = row
                .get(0)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            let snapshot = serde_json::from_str(&payload)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            return Ok(Some(snapshot));
        }
        Ok(None)
    }

    pub fn clear_baselines(&self) -> SentinelResult<()> {
        self.clear_storage(StorageClearTarget::BaselineSnapshots)
            .map(|_| ())
    }

    pub fn load_rule_state<T>(&self, rule_id: &str) -> SentinelResult<Option<T>>
    where
        T: DeserializeOwned,
    {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare("SELECT state_json FROM rule_states WHERE rule_id = ?1")
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let mut rows = stmt
            .query([rule_id])
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        if let Some(row) = rows
            .next()
            .map_err(|err| SentinelError::Storage(err.to_string()))?
        {
            let payload: String = row
                .get(0)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            let state = serde_json::from_str(&payload)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            return Ok(Some(state));
        }
        Ok(None)
    }

    pub fn save_rule_state<T>(&self, rule_id: &str, state: &T) -> SentinelResult<()>
    where
        T: Serialize,
    {
        let conn = self.connection()?;
        let payload =
            serde_json::to_string(state).map_err(|err| SentinelError::Storage(err.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO rule_states (rule_id, state_json) VALUES (?1, ?2)",
            params![rule_id, payload],
        )
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }

    pub fn record_scan_run(
        &self,
        raw_count: usize,
        finding_count: usize,
        status: &str,
    ) -> SentinelResult<()> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO scan_runs (id, started_at, finished_at, raw_count, finding_count, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                uuid::Uuid::new_v4().to_string(),
                Utc::now().to_rfc3339(),
                Utc::now().to_rfc3339(),
                raw_count as i64,
                finding_count as i64,
                status
            ],
        )
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }

    pub fn scan_run_summary_between(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> SentinelResult<ScanRunSummary> {
        let conn = self.connection()?;
        let (total, failed, last_finished_at): (i64, i64, Option<String>) = conn
            .query_row(
                "SELECT
                   COUNT(*),
                   COALESCE(SUM(CASE WHEN status = 'ok' THEN 0 ELSE 1 END), 0),
                   MAX(finished_at)
                 FROM scan_runs
                 WHERE finished_at >= ?1 AND finished_at < ?2",
                params![since.to_rfc3339(), until.to_rfc3339()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        let last_finished_at = match last_finished_at {
            Some(value) => Some(
                DateTime::parse_from_rfc3339(&value)
                    .map_err(|err| SentinelError::Storage(err.to_string()))?
                    .with_timezone(&Utc),
            ),
            None => None,
        };
        Ok(ScanRunSummary {
            total: total.max(0) as usize,
            failed: failed.max(0) as usize,
            last_finished_at,
        })
    }

    pub fn record_notification_log(
        &self,
        finding_id: &str,
        channel: &str,
        status: &str,
        error: &str,
    ) -> SentinelResult<()> {
        let conn = self.connection()?;
        conn.execute(
            "INSERT INTO notification_logs (id, finding_id, channel, status, attempted_at, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                uuid::Uuid::new_v4().to_string(),
                finding_id,
                channel,
                status,
                Utc::now().to_rfc3339(),
                error
            ],
        )
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }

    pub fn notification_attempt_count_since(&self, since: DateTime<Utc>) -> SentinelResult<usize> {
        let conn = self.connection()?;
        let count = conn
            .query_row(
                "SELECT COUNT(*) FROM notification_logs WHERE attempted_at >= ?1",
                [since.to_rfc3339()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(count.max(0) as usize)
    }

    pub fn prune_older_than(&self, retention_days: u32) -> SentinelResult<usize> {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff = cutoff.to_rfc3339();
        let conn = self.connection()?;
        let mut deleted = 0;
        for (table, column) in [
            ("raw_events", "timestamp"),
            ("findings", "timestamp"),
            ("finding_dedup_state", "last_seen_at"),
            ("notification_logs", "attempted_at"),
            ("scan_runs", "finished_at"),
        ] {
            let sql = format!("DELETE FROM {table} WHERE {column} < ?1");
            deleted += conn
                .execute(&sql, [&cutoff])
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
        }
        Ok(deleted)
    }

    pub fn clear_storage(&self, target: StorageClearTarget) -> SentinelResult<usize> {
        let conn = self.connection()?;
        let mut deleted = 0usize;
        for table in target.tables() {
            let sql = format!("DELETE FROM {table}");
            deleted += conn
                .execute(&sql, [])
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
        }
        checkpoint_and_vacuum(&conn)?;
        Ok(deleted)
    }

    pub fn vacuum(&self) -> SentinelResult<()> {
        let conn = self.connection()?;
        checkpoint_and_vacuum(&conn)
    }

    pub fn enforce_size_limit(
        &self,
        max_database_size_mb: u64,
    ) -> SentinelResult<Option<StorageLimitReport>> {
        let limit_bytes = max_database_size_mb.saturating_mul(1024 * 1024);
        let size_before = self.database_footprint_bytes()?;
        if size_before <= limit_bytes {
            return Ok(None);
        }

        let target_bytes = limit_bytes.saturating_mul(SIZE_LIMIT_TARGET_PERCENT) / 100;
        let conn = self.connection()?;
        let mut deleted_rows = 0;
        let mut vacuumed = false;

        for pass in 0..SIZE_LIMIT_MAX_PASSES {
            let deleted_this_pass = prune_size_pressure_batch(&conn, pass)?;
            deleted_rows += deleted_this_pass;
            checkpoint_and_vacuum(&conn)?;
            vacuumed = true;

            let current_size = self.database_footprint_bytes()?;
            if current_size <= target_bytes {
                break;
            }
            if deleted_this_pass == 0 && !has_future_size_prune_candidates(&conn, pass)? {
                break;
            }
        }

        Ok(Some(StorageLimitReport {
            size_before_bytes: size_before,
            size_after_bytes: self.database_footprint_bytes()?,
            deleted_rows,
            vacuumed,
        }))
    }

    fn database_footprint_bytes(&self) -> SentinelResult<u64> {
        database_footprint_bytes(&self.path)
    }

    fn connection(&self) -> SentinelResult<Connection> {
        Connection::open(&self.path).map_err(|err| SentinelError::Storage(err.to_string()))
    }

    fn migrate(&self) -> SentinelResult<()> {
        let conn = self.connection()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS host_info (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS baseline_snapshots (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                subject TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
            CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(dedup_key);
            CREATE TABLE IF NOT EXISTS finding_dedup_state (
                dedup_key TEXT PRIMARY KEY,
                last_seen_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_finding_dedup_state_seen
              ON finding_dedup_state(last_seen_at);
            CREATE TABLE IF NOT EXISTS raw_events (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_logs (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                status TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                error TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_notification_logs_attempted
              ON notification_logs(attempted_at);
            CREATE TABLE IF NOT EXISTS rule_states (
                rule_id TEXT PRIMARY KEY,
                state_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS allowlist (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS scan_runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                raw_count INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            "#,
        )
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO finding_dedup_state (dedup_key, last_seen_at)
             SELECT dedup_key, MAX(timestamp)
             FROM findings
             GROUP BY dedup_key",
            [],
        )
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
    }
}

impl StorageClearTarget {
    fn tables(self) -> &'static [&'static str] {
        match self {
            Self::RawEvents => &["raw_events"],
            Self::Findings => &["findings", "finding_dedup_state"],
            Self::NotificationLogs => &["notification_logs"],
            Self::ScanRuns => &["scan_runs"],
            Self::BaselineSnapshots => &["baseline_snapshots"],
            Self::AllHistory => &[
                "raw_events",
                "findings",
                "finding_dedup_state",
                "notification_logs",
                "scan_runs",
            ],
        }
    }
}

fn prune_size_pressure_batch(conn: &Connection, pass: usize) -> SentinelResult<usize> {
    let mut deleted = 0;
    for policy in SIZE_PRUNE_POLICIES {
        if pass < policy.min_pass {
            continue;
        }
        let batch = policy.prune_batch_size(conn)?;
        if batch == 0 {
            continue;
        }
        deleted += if policy.keep_latest > 0 {
            delete_oldest_rows_keep_latest(
                conn,
                policy.table,
                policy.order_column,
                batch,
                policy.keep_latest,
            )?
        } else {
            delete_oldest_rows(conn, policy.table, policy.order_column, batch)?
        };
    }
    Ok(deleted)
}

fn has_future_size_prune_candidates(conn: &Connection, pass: usize) -> SentinelResult<bool> {
    for policy in SIZE_PRUNE_POLICIES
        .iter()
        .filter(|policy| policy.min_pass > pass && policy.min_pass < SIZE_LIMIT_MAX_PASSES)
    {
        if policy.deletable_count(conn)? > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

impl SizePrunePolicy {
    fn prune_batch_size(&self, conn: &Connection) -> SentinelResult<usize> {
        let deletable = self.deletable_count(conn)?;
        if deletable == 0 {
            return Ok(0);
        }
        Ok((deletable / self.divisor)
            .max(MIN_SIZE_PRUNE_BATCH)
            .min(deletable))
    }

    fn deletable_count(&self, conn: &Connection) -> SentinelResult<usize> {
        let count = table_row_count(conn, self.table)?;
        Ok(count.saturating_sub(self.keep_latest))
    }
}

fn table_row_count(conn: &Connection, table: &str) -> SentinelResult<usize> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count = conn
        .query_row(&sql, [], |row| row.get::<_, i64>(0))
        .map_err(|err| SentinelError::Storage(err.to_string()))?;
    Ok(count.max(0) as usize)
}

fn delete_oldest_rows(
    conn: &Connection,
    table: &str,
    order_column: &str,
    limit: usize,
) -> SentinelResult<usize> {
    let sql = format!(
        "DELETE FROM {table}
         WHERE rowid IN (
             SELECT rowid FROM {table}
             ORDER BY {order_column} ASC
             LIMIT ?1
         )"
    );
    conn.execute(&sql, [limit as i64])
        .map_err(|err| SentinelError::Storage(err.to_string()))
}

fn delete_oldest_rows_keep_latest(
    conn: &Connection,
    table: &str,
    order_column: &str,
    limit: usize,
    keep_latest: usize,
) -> SentinelResult<usize> {
    let count = table_row_count(conn, table)?;
    let max_delete = count.saturating_sub(keep_latest).min(limit);
    if max_delete == 0 {
        return Ok(0);
    }
    delete_oldest_rows(conn, table, order_column, max_delete)
}

fn checkpoint_and_vacuum(conn: &Connection) -> SentinelResult<()> {
    conn.execute_batch(
        r#"
        PRAGMA wal_checkpoint(TRUNCATE);
        VACUUM;
        PRAGMA optimize;
        "#,
    )
    .map_err(|err| SentinelError::Storage(err.to_string()))
}

fn database_footprint_bytes(path: &Path) -> SentinelResult<u64> {
    let mut total = file_len(path)?;
    total = total.saturating_add(file_len(&sidecar_path(path, "wal"))?);
    total = total.saturating_add(file_len(&sidecar_path(path, "shm"))?);
    Ok(total)
}

fn file_len(path: &Path) -> SentinelResult<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(SentinelError::io(path, err)),
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}-{suffix}", path.display()))
}

fn raw_event_storage_id(event: &RawEvent) -> String {
    let mut hasher = Hasher::new();
    hasher.update(event.source.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.kind.as_bytes());
    hasher.update(b"\n");
    for (key, value) in stable_raw_event_fields(event) {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.as_bytes());
        hasher.update(b"\n");
    }
    format!("raw-{}", hasher.finalize().to_hex())
}

fn stable_raw_event_fields(event: &RawEvent) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    match event.kind.as_str() {
        "web_access" => {
            if let Some(raw) = event.field("raw").filter(|value| !value.trim().is_empty()) {
                insert_field(&mut fields, "log_source", event);
                fields.insert("raw".to_string(), raw.to_string());
            } else {
                insert_fields(
                    &mut fields,
                    event,
                    &["ip", "method", "path", "status", "log_source"],
                );
            }
        }
        "process_snapshot" => {
            insert_fields(
                &mut fields,
                event,
                &["pid", "process_start_ticks", "exe_path", "cmdline", "name"],
            );
        }
        _ => {
            for (key, value) in &event.fields {
                if !is_volatile_raw_event_field(key) {
                    fields.insert(key.clone(), value.clone());
                }
            }
        }
    }
    if fields.is_empty() {
        for (key, value) in &event.fields {
            fields.insert(key.clone(), value.clone());
        }
    }
    fields
}

fn insert_fields(fields: &mut BTreeMap<String, String>, event: &RawEvent, keys: &[&str]) {
    for key in keys {
        insert_field(fields, key, event);
    }
}

fn insert_field(fields: &mut BTreeMap<String, String>, key: &str, event: &RawEvent) {
    if let Some(value) = event.field(key).filter(|value| !value.trim().is_empty()) {
        fields.insert(key.to_string(), value.to_string());
    }
}

fn is_volatile_raw_event_field(key: &str) -> bool {
    matches!(
        key,
        "cpu_percent"
            | "cpu_total_seconds"
            | "process_age_seconds"
            | "socket_fd_count"
            | "outbound_connection_count"
            | "public_outbound_count"
            | "process_start_changed"
            | "process_start_drift"
            | "previous_process_start_ticks"
            | "current_process_start_ticks"
            | "package_activity_recent"
    )
}

#[cfg(test)]
mod tests {
    use super::{SqliteStore, StorageClearTarget};
    use crate::baseline::{snapshot::FileBaseline, BaselineSnapshot};
    use chrono::{Duration, Utc};
    use sentinel_core::{Category, Finding, RawEvent, Severity};
    use serde::{Deserialize, Serialize};

    #[test]
    fn stores_and_reads_findings() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let finding = Finding::new(
            "host",
            "title",
            "description",
            Severity::High,
            Category::Ssh,
            "SSH-001",
            "root",
        );
        store.save_findings(std::slice::from_ref(&finding))?;
        let listed = store.list_findings(10)?;
        assert_eq!(listed.len(), 1);
        assert_eq!(
            store.get_finding(&finding.id)?.map(|item| item.id),
            Some(finding.id)
        );
        assert!(store.finding_seen_since(&finding.dedup_key, Utc::now() - Duration::minutes(1))?);
        Ok(())
    }

    #[test]
    fn finding_dedup_state_survives_finding_row_cleanup() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let finding = Finding::new(
            "host",
            "SSH password authentication enabled",
            "Password login is enabled.",
            Severity::Medium,
            Category::ConfigRisk,
            "CONFIG-001",
            "/etc/ssh/sshd_config",
        );
        store.save_findings(std::slice::from_ref(&finding))?;
        store.connection()?.execute("DELETE FROM findings", [])?;

        assert!(store.finding_seen_since(&finding.dedup_key, Utc::now() - Duration::minutes(1))?);
        Ok(())
    }

    #[test]
    fn counts_notification_attempts() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        store.record_notification_log("finding", "telegram", "ok", "")?;
        assert_eq!(
            store.notification_attempt_count_since(Utc::now() - chrono::Duration::minutes(1))?,
            1
        );
        Ok(())
    }

    #[test]
    fn lists_findings_between_time_bounds() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let now = Utc::now();
        let mut old = Finding::new(
            "host",
            "old",
            "description",
            Severity::Low,
            Category::System,
            "TEST-001",
            "old",
        );
        old.timestamp = now - Duration::days(2);
        let mut current = Finding::new(
            "host",
            "current",
            "description",
            Severity::High,
            Category::Ssh,
            "SSH-003",
            "8.8.8.8",
        );
        current.timestamp = now - Duration::minutes(5);
        store.save_findings(&[old, current.clone()])?;

        let listed = store.list_findings_between(now - Duration::hours(1), now)?;

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, current.id);
        Ok(())
    }

    #[test]
    fn summarizes_scan_runs_between_time_bounds() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        store.record_scan_run(10, 2, "ok")?;
        store.record_scan_run(5, 0, "failed")?;

        let summary =
            store.scan_run_summary_between(Utc::now() - Duration::minutes(1), Utc::now())?;

        assert_eq!(summary.total, 2);
        assert_eq!(summary.failed, 1);
        assert!(summary.last_finished_at.is_some());
        Ok(())
    }

    #[test]
    fn raw_event_storage_replaces_duplicate_web_log_lines() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let raw = r#"203.0.113.9 - - [17/Jun/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "curl/8""#;
        let first = RawEvent::new("web", "web_access")
            .with_field("ip", "203.0.113.9")
            .with_field("method", "GET")
            .with_field("path", "/.env")
            .with_field("status", "404")
            .with_field("log_source", "/var/log/nginx/access.log")
            .with_field("raw", raw);
        let second = RawEvent::new("web", "web_access")
            .with_field("ip", "203.0.113.9")
            .with_field("method", "GET")
            .with_field("path", "/.env")
            .with_field("status", "404")
            .with_field("log_source", "/var/log/nginx/access.log")
            .with_field("raw", raw);

        store.save_raw_events(&[first, second])?;
        let count: i64 =
            store
                .connection()?
                .query_row("SELECT COUNT(*) FROM raw_events", [], |row| row.get(0))?;

        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn enforce_size_limit_prunes_old_raw_events() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let events = (0..400)
            .map(|index| {
                RawEvent::new("web", "web_access")
                    .with_field("ip", format!("198.51.100.{}", index % 200))
                    .with_field("method", "GET")
                    .with_field("path", format!("/probe-{index}"))
                    .with_field("status", "404")
                    .with_field("log_source", "/var/log/nginx/access.log")
                    .with_field("raw", format!("{} {}", index, "x".repeat(10_000)))
            })
            .collect::<Vec<_>>();
        store.save_raw_events(&events)?;
        let before: i64 =
            store
                .connection()?
                .query_row("SELECT COUNT(*) FROM raw_events", [], |row| row.get(0))?;

        let report = store.enforce_size_limit(1)?.ok_or("expected cleanup")?;
        let after: i64 =
            store
                .connection()?
                .query_row("SELECT COUNT(*) FROM raw_events", [], |row| row.get(0))?;

        assert!(report.deleted_rows > 0);
        assert!(after < before);
        assert!(report.size_after_bytes <= report.size_before_bytes);
        Ok(())
    }

    #[test]
    fn enforce_size_limit_keeps_latest_baseline_snapshot() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        for index in 0..3 {
            let mut snapshot = BaselineSnapshot {
                id: format!("baseline-{index}"),
                created_at: Utc::now() - chrono::Duration::days(3 - index),
                ..BaselineSnapshot::default()
            };
            snapshot.files.insert(
                format!("sentinel-test-{index}"),
                FileBaseline {
                    hash: "x".repeat(700_000),
                    size: "700000".to_string(),
                    executable: "false".to_string(),
                    is_web_path: "false".to_string(),
                },
            );
            store.save_baseline_snapshot(&snapshot)?;
        }

        let report = store.enforce_size_limit(1)?.ok_or("expected cleanup")?;
        let latest = store
            .latest_baseline_snapshot()?
            .ok_or("expected latest baseline")?;
        let count: i64 = store.connection()?.query_row(
            "SELECT COUNT(*) FROM baseline_snapshots",
            [],
            |row| row.get(0),
        )?;

        assert!(report.deleted_rows > 0);
        assert_eq!(latest.id, "baseline-2");
        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn clear_all_history_keeps_baseline_and_rule_state() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let raw = RawEvent::new("web", "web_access")
            .with_field("ip", "8.8.8.8")
            .with_field("method", "GET")
            .with_field("path", "/.env")
            .with_field("status", "404");
        let finding = Finding::new(
            "host",
            "title",
            "description",
            Severity::High,
            Category::Web,
            "WEB-001",
            "8.8.8.8",
        );
        let snapshot = BaselineSnapshot::default();
        let state = TestRuleState {
            value: "blocked".to_string(),
            count: 1,
        };
        store.save_raw_events(&[raw])?;
        store.save_findings(&[finding])?;
        store.record_notification_log("finding", "telegram", "ok", "")?;
        store.record_scan_run(1, 1, "ok")?;
        store.save_baseline_snapshot(&snapshot)?;
        store.save_rule_state("active_response_blocks", &state)?;

        let deleted = store.clear_storage(StorageClearTarget::AllHistory)?;
        let stats = store.stats()?;

        assert_eq!(deleted, 5);
        assert_eq!(stats.raw_events, 0);
        assert_eq!(stats.findings, 0);
        assert_eq!(stats.finding_dedup_states, 0);
        assert_eq!(stats.notification_logs, 0);
        assert_eq!(stats.scan_runs, 0);
        assert_eq!(stats.baseline_snapshots, 1);
        assert_eq!(stats.rule_states, 1);
        Ok(())
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestRuleState {
        value: String,
        count: usize,
    }

    #[test]
    fn stores_and_reads_rule_state() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SqliteStore::open(temp.path().join("sentinel.db"))?;
        let state = TestRuleState {
            value: "process-start".to_string(),
            count: 2,
        };

        store.save_rule_state("process_start_times", &state)?;
        let loaded = store.load_rule_state::<TestRuleState>("process_start_times")?;

        assert_eq!(loaded, Some(state));
        assert_eq!(
            store.load_rule_state::<TestRuleState>("missing-rule")?,
            None
        );
        Ok(())
    }
}
