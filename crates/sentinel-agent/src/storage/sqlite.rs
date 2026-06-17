use crate::baseline::BaselineSnapshot;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use sentinel_core::{Finding, RawEvent, SentinelError, SentinelResult};
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// SQLite-backed local event store.
pub struct SqliteStore {
    path: PathBuf,
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

    pub fn save_raw_events(&self, events: &[RawEvent]) -> SentinelResult<()> {
        let mut conn = self.connection()?;
        let tx = conn
            .transaction()
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        for event in events {
            let payload = serde_json::to_string(event)
                .map_err(|err| SentinelError::Storage(err.to_string()))?;
            tx.execute(
                "INSERT OR REPLACE INTO raw_events (id, source, kind, timestamp, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.id,
                    event.source,
                    event.kind,
                    event.timestamp.to_rfc3339(),
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
                "SELECT 1 FROM findings
                 WHERE dedup_key = ?1 AND timestamp >= ?2
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
        let conn = self.connection()?;
        conn.execute("DELETE FROM baseline_snapshots", [])
            .map_err(|err| SentinelError::Storage(err.to_string()))?;
        Ok(())
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SqliteStore;
    use chrono::Utc;
    use sentinel_core::{Category, Finding, Severity};
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
