use super::*;

impl Repository {
    pub(super) async fn connect(backend: DatabaseBackend, url: &str) -> Result<Self> {
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

    pub(super) async fn init_schema(&self) -> Result<()> {
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
                for statement in schema
                    .split(';')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    if let Err(err) = connection.execute_batch(&format!("{statement};")) {
                        if !is_sqlite_missing_compat_index(&err, statement) {
                            return Err(err.into());
                        }
                    }
                }
            }
            RepositoryDriver::Postgres(pool) => {
                for statement in schema
                    .split(';')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    if let Err(err) = sql_query(statement).execute(pool).await {
                        if !is_sqlx_missing_compat_index(&err, statement) {
                            return Err(err.into());
                        }
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
                        if !(is_sqlx_missing_compat_index(&err, statement)
                            || self.backend == DatabaseBackend::Mysql
                                && is_mysql_duplicate_index(&err))
                        {
                            return Err(err.into());
                        }
                    }
                }
            }
        }
        self.ensure_compat_schema().await?;
        Ok(())
    }

    pub(super) async fn ensure_compat_schema(&self) -> Result<()> {
        for (table, column, sqlite_definition, sql_definition) in [
            (
                "nodes",
                "metrics_json",
                "TEXT NOT NULL DEFAULT '{}'",
                "TEXT NOT NULL DEFAULT '{}'",
            ),
            (
                "baseline_drifts",
                "category",
                "TEXT NOT NULL DEFAULT 'system'",
                "VARCHAR(64) NOT NULL DEFAULT 'system'",
            ),
            (
                "findings",
                "review_signature",
                "TEXT NOT NULL DEFAULT ''",
                "VARCHAR(96) NOT NULL DEFAULT ''",
            ),
            (
                "incidents",
                "review_signature",
                "TEXT NOT NULL DEFAULT ''",
                "VARCHAR(96) NOT NULL DEFAULT ''",
            ),
            (
                "baseline_drifts",
                "review_signature",
                "TEXT NOT NULL DEFAULT ''",
                "VARCHAR(96) NOT NULL DEFAULT ''",
            ),
            (
                "panel_reviews",
                "review_signature",
                "TEXT NOT NULL DEFAULT ''",
                "VARCHAR(96) NOT NULL DEFAULT ''",
            ),
        ] {
            self.ensure_column(table, column, sqlite_definition, sql_definition)
                .await?;
        }
        for (name, table, columns) in [
            (
                "idx_findings_review_signature",
                "findings",
                "review_signature",
            ),
            (
                "idx_incidents_review_signature",
                "incidents",
                "review_signature",
            ),
            (
                "idx_baseline_review_signature",
                "baseline_drifts",
                "review_signature",
            ),
            (
                "idx_panel_reviews_signature",
                "panel_reviews",
                "target_type, review_signature, verdict, reviewed_at",
            ),
        ] {
            self.ensure_index(name, table, columns).await?;
        }
        Ok(())
    }

    pub(super) async fn ensure_column(
        &self,
        table: &str,
        column: &str,
        sqlite_definition: &str,
        sql_definition: &str,
    ) -> Result<()> {
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection
                    .lock()
                    .map_err(|err| anyhow!("sqlite connection lock poisoned: {err}"))?;
                let mut stmt = connection.prepare(&format!("PRAGMA table_info({table})"))?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let name: String = row.get(1)?;
                    if name == column {
                        return Ok(());
                    }
                }
                connection.execute(
                    &format!("ALTER TABLE {table} ADD COLUMN {column} {sqlite_definition}"),
                    [],
                )?;
            }
            RepositoryDriver::Postgres(pool) => {
                sql_query(&format!(
                    "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {sql_definition}"
                ))
                .execute(pool)
                .await?;
            }
            RepositoryDriver::Mysql(pool) => {
                if let Err(err) = sql_query(&format!(
                    "ALTER TABLE {table} ADD COLUMN {column} {sql_definition}"
                ))
                .execute(pool)
                .await
                {
                    if !is_mysql_duplicate_column(&err) {
                        return Err(err.into());
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) async fn ensure_index(&self, name: &str, table: &str, columns: &str) -> Result<()> {
        match &self.driver {
            RepositoryDriver::Sqlite(connection) => {
                let connection = connection
                    .lock()
                    .map_err(|err| anyhow!("sqlite connection lock poisoned: {err}"))?;
                connection.execute(
                    &format!("CREATE INDEX IF NOT EXISTS {name} ON {table}({columns})"),
                    [],
                )?;
            }
            RepositoryDriver::Postgres(pool) => {
                sql_query(&format!(
                    "CREATE INDEX IF NOT EXISTS {name} ON {table}({columns})"
                ))
                .execute(pool)
                .await?;
            }
            RepositoryDriver::Mysql(pool) => {
                if let Err(err) = sql_query(&format!("CREATE INDEX {name} ON {table}({columns})"))
                    .execute(pool)
                    .await
                {
                    if !is_mysql_duplicate_index(&err) {
                        return Err(err.into());
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn upsert_sql(
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

    pub(super) fn placeholders(&self, count: usize) -> String {
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

    pub(super) fn placeholder(&self, index: usize) -> String {
        match self.backend {
            DatabaseBackend::Postgres => format!("${index}"),
            DatabaseBackend::Sqlite | DatabaseBackend::Mysql => "?".to_string(),
        }
    }

    pub(super) async fn execute_write(
        &self,
        sql: &str,
        values: &[DbValue],
    ) -> Result<(), PanelApiError> {
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

    pub(super) async fn query_all(&self, sql: &str) -> Result<Value, PanelApiError> {
        self.query_all_with_values(sql, &[]).await
    }

    pub(super) async fn query_all_with_values(
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

    pub(super) async fn query_page(
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

    pub(super) async fn probe_sources_page(
        &self,
        request: &PageRequest,
        role: PanelRole,
    ) -> Result<(Value, i64), PanelApiError> {
        let (where_sql, mut values) = self.probe_sources_where_clause(request);
        let count_sql = format!(
            "SELECT COUNT(*) AS count FROM (SELECT source_ip FROM probe_sources{where_sql} GROUP BY source_ip) grouped_sources"
        );
        let total = self.count_sql(&count_sql, &values).await?;

        let limit_placeholder = self.placeholder(values.len() + 1);
        let offset_placeholder = self.placeholder(values.len() + 2);
        values.push(DbValue::Integer(request.limit as i64));
        values.push(DbValue::Integer(request.offset as i64));

        let columns = [
            "MAX(last_seen) AS last_seen",
            "MIN(first_seen) AS first_seen",
            "MAX(node_id) AS node_name",
            "source_ip",
            "MAX(ip_version) AS ip_version",
            "MAX(CASE WHEN network_prefix IS NOT NULL AND network_prefix <> '' AND LOWER(network_prefix) <> 'unknown' THEN network_prefix ELSE '' END) AS network_prefix",
            "SUM(seen_count) AS seen_count",
            "CASE
                WHEN SUM(CASE WHEN LOWER(COALESCE(block_status, '')) LIKE '%permanent%' THEN 1 ELSE 0 END) > 0 THEN 'permanent_block'
                WHEN SUM(CASE WHEN LOWER(COALESCE(block_status, '')) LIKE '%block%' OR LOWER(COALESCE(block_status, '')) IN ('temporary', 'blocked') THEN 1 ELSE 0 END) > 0 THEN 'temporary_block'
                ELSE MAX(block_status)
             END AS block_status",
            "COALESCE(NULLIF(MAX(CASE WHEN country IS NOT NULL AND country <> '' AND LOWER(country) <> 'unknown' THEN country ELSE '' END), ''), 'unknown') AS country",
            "COALESCE(NULLIF(MAX(CASE WHEN asn IS NOT NULL AND asn <> '' AND LOWER(asn) <> 'unknown' THEN asn ELSE '' END), ''), 'unknown') AS asn",
            "COALESCE(NULLIF(MAX(CASE WHEN organization IS NOT NULL AND organization <> '' AND LOWER(organization) <> 'unknown' THEN organization ELSE '' END), ''), 'unknown') AS organization",
            "MAX(categories_json) AS categories_json",
            "MAX(rule_ids_json) AS rule_ids_json",
            "MAX(CASE WHEN latest_reason IS NOT NULL AND latest_reason <> '' THEN latest_reason ELSE '' END) AS latest_reason",
            "MAX(CASE WHEN block_reason IS NOT NULL AND block_reason <> '' THEN block_reason ELSE '' END) AS block_reason",
        ];
        let sql = format!(
            "SELECT {} FROM probe_sources{where_sql} GROUP BY source_ip ORDER BY last_seen DESC LIMIT {limit_placeholder} OFFSET {offset_placeholder}",
            columns.join(", ")
        );
        let mut items = self.query_all_with_values(&sql, &values).await?;
        expand_dataset_json_columns("probe_sources", &mut items);
        if should_redact_dataset("probe_sources", role) {
            redact_panel_value(&mut items);
        }
        Ok((items, total))
    }

    pub(super) async fn latest_nodes_page(
        &self,
        columns: &'static [&'static str],
        request: &PageRequest,
        role: PanelRole,
    ) -> Result<(Value, i64), PanelApiError> {
        let rows = self.latest_node_rows(columns, Some(request)).await?;
        let total = rows.len() as i64;
        let start = request.offset.min(rows.len());
        let end = (start + request.limit).min(rows.len());
        let mut items = Value::Array(rows[start..end].to_vec());
        expand_dataset_json_columns("nodes", &mut items);
        attach_node_statuses(&mut items);
        if should_redact_dataset("nodes", role) {
            redact_panel_value(&mut items);
        }
        Ok((items, total))
    }

    pub(super) async fn latest_node_rows(
        &self,
        columns: &'static [&'static str],
        request: Option<&PageRequest>,
    ) -> Result<Vec<Value>, PanelApiError> {
        let (where_sql, values) = request
            .map(|request| {
                self.page_where_clause(
                    PanelDataset {
                        table: "nodes",
                        order_column: "last_seen_at",
                        active_filter: None,
                        columns,
                    },
                    request,
                )
            })
            .unwrap_or_else(|| (String::new(), Vec::new()));
        let sql = format!(
            "SELECT {} FROM nodes{where_sql} ORDER BY last_seen_at DESC",
            columns.join(", ")
        );
        let rows = self.query_all_with_values(&sql, &values).await?;
        let Value::Array(rows) = rows else {
            return Ok(Vec::new());
        };
        let mut latest = BTreeMap::<String, Value>::new();
        for row in rows {
            let node_name = row
                .get("node_name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("unnamed-node")
                .to_string();
            let agent_version = row
                .get("agent_version")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if is_panel_placeholder_node(&node_name, agent_version) {
                continue;
            }
            let replace = latest
                .get(&node_name)
                .map(|existing| panel_row_is_newer(&row, existing, "last_seen_at"))
                .unwrap_or(true);
            if replace {
                latest.insert(node_name, row);
            }
        }
        let mut rows = latest.into_values().collect::<Vec<_>>();
        rows.sort_by_key(panel_node_sort_key);
        Ok(rows)
    }

    pub(super) async fn finding_detail(
        &self,
        id: &str,
        role: PanelRole,
    ) -> Result<Value, PanelApiError> {
        let columns = [
            "id",
            "node_id AS node_name",
            "rule_id",
            "title",
            "severity",
            "confidence",
            "category",
            "subject",
            "review_signature",
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
            let signature = detail
                .get("review_signature")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            detail["review"] = self
                .panel_review_value(ReviewTargetType::Finding, id)
                .await?
                .or(self
                    .panel_review_by_signature(ReviewTargetType::Finding, &signature)
                    .await?)
                .or(self.finding_review_value(id).await?)
                .unwrap_or(Value::Null);
        }
        redact_panel_value(&mut detail);
        scope_panel_value(&mut detail, role);
        Ok(detail)
    }

    pub(super) async fn incident_detail(
        &self,
        id: &str,
        role: PanelRole,
    ) -> Result<Value, PanelApiError> {
        let columns = [
            "id",
            "node_id AS node_name",
            "title",
            "severity",
            "score",
            "first_seen",
            "last_seen",
            "summary",
            "review_signature",
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
        if role == PanelRole::Admin {
            let signature = detail
                .get("review_signature")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            detail["review"] = self
                .panel_review_value(ReviewTargetType::Incident, id)
                .await?
                .or(self
                    .panel_review_by_signature(ReviewTargetType::Incident, &signature)
                    .await?)
                .unwrap_or(Value::Null);
        }
        redact_panel_value(&mut detail);
        scope_panel_value(&mut detail, role);
        Ok(detail)
    }

    pub(super) async fn trend_points(&self, request: &PageRequest) -> Result<Value, PanelApiError> {
        let mut values = Vec::new();
        let mut filters = vec![review_not_false_positive_filter(
            "findings",
            ReviewTargetType::Finding,
        )];
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
        let where_sql = format!(" WHERE {}", filters.join(" AND "));
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

    pub(super) async fn finding_review_value(
        &self,
        finding_id: &str,
    ) -> Result<Option<Value>, PanelApiError> {
        let columns = ["finding_id", "verdict", "note", "reviewer", "reviewed_at"];
        let sql = format!(
            "SELECT {} FROM finding_reviews WHERE finding_id = {}",
            columns.join(", "),
            self.placeholder(1)
        );
        self.query_one_with_values(&sql, &[DbValue::Text(finding_id.to_string())])
            .await
    }

    pub(super) async fn panel_review_value(
        &self,
        target_type: ReviewTargetType,
        target_id: &str,
    ) -> Result<Option<Value>, PanelApiError> {
        let columns = [
            "target_type",
            "target_id",
            "review_signature",
            "verdict",
            "note",
            "reviewer",
            "reviewed_at",
        ];
        let sql = format!(
            "SELECT {} FROM panel_reviews WHERE target_type = {} AND target_id = {}",
            columns.join(", "),
            self.placeholder(1),
            self.placeholder(2)
        );
        self.query_one_with_values(
            &sql,
            &[
                DbValue::Text(target_type.as_str().to_string()),
                DbValue::Text(target_id.to_string()),
            ],
        )
        .await
    }

    pub(super) async fn attach_panel_reviews(
        &self,
        target_type: ReviewTargetType,
        rows: &mut Value,
        role: PanelRole,
    ) -> Result<(), PanelApiError> {
        let Value::Array(items) = rows else {
            return Ok(());
        };
        for item in items {
            let Some(target_id) = item.get("id").and_then(Value::as_str).map(str::to_string) else {
                continue;
            };
            let signature = item
                .get("review_signature")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if let Some(review) = self
                .panel_review_value(target_type, &target_id)
                .await?
                .or(self
                    .panel_review_by_signature(target_type, &signature)
                    .await?)
            {
                let verdict = review
                    .get("verdict")
                    .and_then(Value::as_str)
                    .unwrap_or("needs_review")
                    .to_string();
                item["review_verdict"] = Value::String(verdict);
                item["status"] = item["review_verdict"].clone();
                if role == PanelRole::Admin {
                    item["review"] = review;
                }
            } else {
                item["review_verdict"] = Value::String("needs_review".to_string());
                item["status"] = Value::String("needs_review".to_string());
            }
        }
        Ok(())
    }

    pub(super) async fn query_one_with_values(
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

    pub(super) async fn upsert_finding_review(
        &self,
        review: &FindingReview,
    ) -> Result<PanelReview, PanelApiError> {
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
        self.write_finding_review_row(review).await?;
        let panel_review = PanelReview {
            target_type: ReviewTargetType::Finding,
            target_id: review.finding_id.clone(),
            review_signature: self
                .target_review_signature(ReviewTargetType::Finding, &review.finding_id)
                .await?,
            verdict: review.verdict.clone(),
            note: review.note.clone(),
            reviewer: review.reviewer.clone(),
            reviewed_at: review.reviewed_at,
        };
        self.write_panel_review_row(&panel_review).await?;
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
        .await?;
        Ok(panel_review)
    }

    pub(super) async fn upsert_panel_review(
        &self,
        review: &PanelReview,
    ) -> Result<PanelReview, PanelApiError> {
        let exists_sql = format!(
            "SELECT COUNT(*) AS count FROM {} WHERE {} = {}",
            review.target_type.table(),
            review.target_type.id_column(),
            self.placeholder(1)
        );
        if self
            .count_sql(&exists_sql, &[DbValue::Text(review.target_id.clone())])
            .await?
            == 0
        {
            return Err(PanelApiError::new(
                StatusCode::NOT_FOUND,
                review.target_type.not_found_error(),
            ));
        }
        let scoped_review = PanelReview {
            review_signature: self
                .target_review_signature(review.target_type, &review.target_id)
                .await?,
            ..review.clone()
        };
        self.write_panel_review_row(&scoped_review).await?;
        if scoped_review.target_type == ReviewTargetType::Finding {
            let legacy_review = FindingReview {
                finding_id: scoped_review.target_id.clone(),
                verdict: scoped_review.verdict.clone(),
                note: scoped_review.note.clone(),
                reviewer: scoped_review.reviewer.clone(),
                reviewed_at: scoped_review.reviewed_at,
            };
            self.write_finding_review_row(&legacy_review).await?;
        }
        self.insert_audit_log(
            "panel_review",
            &scoped_review.reviewer,
            scoped_review.target_type.as_str(),
            &scoped_review.target_id,
            json!({
                "verdict": scoped_review.verdict,
                "note_present": !scoped_review.note.is_empty(),
                "similar_scope": !scoped_review.review_signature.is_empty()
            }),
            scoped_review.reviewed_at,
        )
        .await?;
        Ok(scoped_review)
    }

    pub(super) async fn write_finding_review_row(
        &self,
        review: &FindingReview,
    ) -> Result<(), PanelApiError> {
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
        .await
    }

    pub(super) async fn write_panel_review_row(
        &self,
        review: &PanelReview,
    ) -> Result<(), PanelApiError> {
        let columns = [
            "target_type",
            "target_id",
            "review_signature",
            "verdict",
            "note",
            "reviewer",
            "reviewed_at",
        ];
        let sql = self.upsert_sql(
            "panel_reviews",
            &columns,
            &["target_type", "target_id"],
            &[
                "review_signature",
                "verdict",
                "note",
                "reviewer",
                "reviewed_at",
            ],
        );
        self.execute_write(
            &sql,
            &[
                DbValue::Text(review.target_type.as_str().to_string()),
                DbValue::Text(review.target_id.clone()),
                DbValue::Text(review.review_signature.clone()),
                DbValue::Text(review.verdict.clone()),
                DbValue::Text(review.note.clone()),
                DbValue::Text(review.reviewer.clone()),
                DbValue::Text(review.reviewed_at.to_rfc3339()),
            ],
        )
        .await
    }

    pub(super) async fn target_review_signature(
        &self,
        target_type: ReviewTargetType,
        target_id: &str,
    ) -> Result<String, PanelApiError> {
        let columns = match target_type {
            ReviewTargetType::Finding => {
                "node_id, rule_id, category, subject, title, review_signature"
            }
            ReviewTargetType::Incident => "node_id, severity, title, summary, review_signature",
            ReviewTargetType::BaselineDrift => {
                "node_id, rule_id, category, subject, tier, review_signature"
            }
        };
        let sql = format!(
            "SELECT {columns} FROM {} WHERE {} = {}",
            target_type.table(),
            target_type.id_column(),
            self.placeholder(1)
        );
        let Some(row) = self
            .query_one_with_values(&sql, &[DbValue::Text(target_id.to_string())])
            .await?
        else {
            return Err(PanelApiError::new(
                StatusCode::NOT_FOUND,
                target_type.not_found_error(),
            ));
        };
        let existing = row
            .get("review_signature")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if !existing.is_empty() {
            return Ok(existing);
        }
        let signature = review_signature_from_row(target_type, &row);
        self.execute_write(
            &format!(
                "UPDATE {} SET review_signature = {} WHERE {} = {}",
                target_type.table(),
                self.placeholder(1),
                target_type.id_column(),
                self.placeholder(2)
            ),
            &[
                DbValue::Text(signature.clone()),
                DbValue::Text(target_id.to_string()),
            ],
        )
        .await?;
        Ok(signature)
    }

    pub(super) async fn panel_review_by_signature(
        &self,
        target_type: ReviewTargetType,
        signature: &str,
    ) -> Result<Option<Value>, PanelApiError> {
        if signature.trim().is_empty() {
            return Ok(None);
        }
        let columns = [
            "target_type",
            "target_id",
            "review_signature",
            "verdict",
            "note",
            "reviewer",
            "reviewed_at",
        ];
        let sql = format!(
            "SELECT {} FROM panel_reviews
             WHERE target_type = {} AND review_signature = {}
             ORDER BY reviewed_at DESC LIMIT 1",
            columns.join(", "),
            self.placeholder(1),
            self.placeholder(2)
        );
        self.query_one_with_values(
            &sql,
            &[
                DbValue::Text(target_type.as_str().to_string()),
                DbValue::Text(signature.to_string()),
            ],
        )
        .await
    }

    pub(super) async fn insert_audit_log(
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

    pub(super) fn page_where_clause(
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

    pub(super) fn probe_sources_where_clause(
        &self,
        request: &PageRequest,
    ) -> (String, Vec<DbValue>) {
        let mut parts = vec![blocked_probe_source_filter().to_string()];
        let mut values = Vec::new();
        if let Some(from) = request.from {
            values.push(DbValue::Text(from.to_rfc3339()));
            parts.push(format!("last_seen >= {}", self.placeholder(values.len())));
        }
        if let Some(to) = request.to {
            values.push(DbValue::Text(to.to_rfc3339()));
            parts.push(format!("last_seen <= {}", self.placeholder(values.len())));
        }
        (format!(" WHERE {}", parts.join(" AND ")), values)
    }

    pub(super) async fn count(
        &self,
        table: &str,
        where_clause: Option<&str>,
    ) -> Result<i64, PanelApiError> {
        let sql = match where_clause {
            Some(where_clause) => {
                format!("SELECT COUNT(*) AS count FROM {table} WHERE {where_clause}")
            }
            None => format!("SELECT COUNT(*) AS count FROM {table}"),
        };
        self.count_sql(&sql, &[]).await
    }

    pub(super) async fn count_distinct(
        &self,
        table: &str,
        column: &str,
        where_clause: Option<&str>,
    ) -> Result<i64, PanelApiError> {
        let sql = match where_clause {
            Some(where_clause) => {
                format!(
                    "SELECT COUNT(DISTINCT {column}) AS count FROM {table} WHERE {where_clause}"
                )
            }
            None => format!("SELECT COUNT(DISTINCT {column}) AS count FROM {table}"),
        };
        self.count_sql(&sql, &[]).await
    }

    pub(super) async fn count_sql(
        &self,
        sql: &str,
        values: &[DbValue],
    ) -> Result<i64, PanelApiError> {
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

    pub(super) async fn insert_nonce(
        &self,
        headers: &HeaderMap,
        node_id: &str,
    ) -> Result<(), PanelApiError> {
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

    pub(super) async fn persist_payload(
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

    pub(super) async fn upsert_node(
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
                "metrics_json",
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
                "metrics_json",
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
                DbValue::Text(json_string(
                    node.metrics.clone().unwrap_or_else(|| json!({})),
                )?),
                DbValue::Text(sent_at.to_rfc3339()),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    pub(super) async fn upsert_heartbeat(
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

    pub(super) async fn upsert_finding(
        &self,
        node_id: &str,
        finding: &PanelFinding,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let mut evidence = json!(finding.evidence);
        redact_panel_value(&mut evidence);
        let impact = redact_text_list(&finding.impact);
        let recommendations = redact_text_list(&finding.recommendations);
        let title = redact_ip_text(&finding.title);
        let subject = redact_ip_text(&finding.subject);
        let dedup_key = redact_ip_text(&finding.dedup_key);
        let review_signature = finding_review_signature(
            node_id,
            &finding.rule_id,
            &finding.category,
            &subject,
            &title,
        );
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
                "review_signature",
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
                "review_signature",
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
                DbValue::Text(title),
                DbValue::Text(finding.severity.clone()),
                DbValue::Text(finding.confidence.clone()),
                DbValue::Text(finding.category.clone()),
                DbValue::Text(subject),
                DbValue::Text(review_signature),
                DbValue::Text(finding.timestamp.to_rfc3339()),
                DbValue::Text(dedup_key),
                DbValue::Text(json_string(&evidence)?),
                DbValue::Text(json_string(&impact)?),
                DbValue::Text(json_string(&recommendations)?),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    pub(super) async fn upsert_incident(
        &self,
        node_id: &str,
        incident: &PanelIncident,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let mut payload = json!(incident);
        redact_panel_value(&mut payload);
        let title = redact_ip_text(&incident.title);
        let summary = redact_ip_text(&incident.summary);
        let review_signature =
            incident_review_signature(node_id, &incident.severity, &title, &summary);
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
                "review_signature",
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
                "review_signature",
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
                DbValue::Text(summary),
                DbValue::Text(review_signature),
                DbValue::Text(json_string(&payload)?),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    pub(super) async fn upsert_drift(
        &self,
        node_id: &str,
        drift: &PanelBaselineDrift,
        received_at: &str,
    ) -> Result<(), PanelApiError> {
        let subject = redact_ip_text(&drift.subject);
        let reasons = redact_text_list(&drift.reasons);
        let category = if drift.category.trim().is_empty() {
            baseline_category_from_rule(&drift.rule_id).to_string()
        } else {
            drift.category.trim().to_string()
        };
        let review_signature =
            drift_review_signature(node_id, &drift.rule_id, &category, &subject, &drift.tier);
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
                "category",
                "severity",
                "subject",
                "review_signature",
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
                "category",
                "subject",
                "review_signature",
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
                DbValue::Text(category),
                DbValue::Text(drift.severity.clone()),
                DbValue::Text(subject),
                DbValue::Text(review_signature),
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

    pub(super) async fn upsert_block(
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

    pub(super) async fn upsert_probe_source(
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
                DbValue::Text(merged.network_prefix),
                DbValue::Text(merged.country),
                DbValue::Text(merged.asn),
                DbValue::Text(merged.organization),
                DbValue::Text(merged.first_seen),
                DbValue::Text(merged.last_seen),
                DbValue::Integer(merged.seen_count),
                DbValue::Text(json_string(&merged.categories)?),
                DbValue::Text(json_string(&merged.rule_ids)?),
                DbValue::Text(redact_ip_text(&source.latest_reason)),
                DbValue::Text(merged.block_status),
                DbValue::Text(redact_ip_text(&source.block_reason)),
                DbValue::Text(received_at.to_string()),
            ],
        )
        .await?;
        Ok(())
    }

    pub(super) async fn merge_probe_source(
        &self,
        id: &str,
        source: &PanelProbeSource,
    ) -> Result<Option<MergedProbeSource>, PanelApiError> {
        let sql = format!(
            "SELECT first_seen, last_seen, seen_count, categories_json, rule_ids_json, network_prefix, country, asn, organization, block_status FROM probe_sources WHERE id = {}",
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
        let network_prefix =
            prefer_meaningful_text(existing.get("network_prefix"), &source.network_prefix);
        let country = prefer_meaningful_text(existing.get("country"), &source.country);
        let asn = prefer_meaningful_text(existing.get("asn"), &source.asn);
        let organization =
            prefer_meaningful_text(existing.get("organization"), &source.organization);
        let block_status = strongest_probe_source_status(
            existing
                .get("block_status")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            &source.block_status,
        );
        Ok(Some(MergedProbeSource {
            first_seen,
            last_seen,
            seen_count,
            categories,
            rule_ids,
            network_prefix,
            country,
            asn,
            organization,
            block_status,
        }))
    }
}
