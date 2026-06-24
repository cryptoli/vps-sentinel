use super::{
    normalize_panel_path, parse_panel_themes, redact_ip_text, redact_panel_value,
    resolve_panel_role, scope_panel_value, scope_probe_source_rows, verify_admin_auth,
    verify_view_auth, view_token_from_headers, AppState, DbValue, FindingReview,
    FindingReviewRequest, PageQuery, PageRequest, PanelDataset, PanelReview, PanelReviewRequest,
    PanelRole, PanelStreamEvent, Repository, RepositoryDriver, ReviewTargetType, SecretResolver,
    DEFAULT_ADMIN_PATH, DEFAULT_THEMES, MAX_PAGE_LIMIT,
};
use axum::http::{header, HeaderMap, HeaderValue};
use chrono::Utc;
use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
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
async fn probe_source_page_preserves_public_block_source_ip() {
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
    let (mut public_page, _) = repo
        .query_page(dataset, &request, PanelRole::Public)
        .await
        .expect("public query");
    scope_panel_value(&mut public_page, PanelRole::Public);
    scope_probe_source_rows(&mut public_page, PanelRole::Public);
    let admin_text = serde_json::to_string(&admin_page).expect("json");
    let public_text = serde_json::to_string(&public_page).expect("json");

    assert!(admin_text.contains("8.8.8.8"));
    assert!(admin_text.contains(r#""categories":["web"]"#));
    assert!(public_text.contains("8.8.8.8"));
    assert!(!public_text.contains("8.8.8.0/24"));
    assert!(!public_text.contains("web probe request_count=3"));
}

#[test]
fn panel_admin_path_and_theme_config_are_normalized() {
    assert_eq!(normalize_panel_path("secure-admin/"), "/secure-admin");
    assert_eq!(normalize_panel_path(""), DEFAULT_ADMIN_PATH);

    let themes = parse_panel_themes("default:Default, ocean:Ocean Theme, ../bad:Bad");
    assert_eq!(themes[0].id, "default");
    assert_eq!(themes[1].id, "ocean");
    assert_eq!(themes[2].id, "bad");
}

#[tokio::test]
async fn node_page_expands_probe_metrics_without_sensitive_identity() {
    let repo = test_repo();
    repo.init_schema().await.expect("schema");
    let now = Utc::now().to_rfc3339();
    let old = Utc::now()
        .checked_sub_signed(chrono::Duration::minutes(10))
        .expect("old timestamp")
        .to_rfc3339();
    repo.execute_write(
        "INSERT INTO nodes
             (node_id, node_name, host_id, hostname, agent_version, privacy_mode,
              enabled_features_json, storage_json, metrics_json, last_seen_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &[
            DbValue::Text("legacy-node-a".to_string()),
            DbValue::Text("node-a".to_string()),
            DbValue::Text(String::new()),
            DbValue::Text(String::new()),
            DbValue::Text("0.1.0".to_string()),
            DbValue::Text("strict".to_string()),
            DbValue::Text(r#"["ssh","panel"]"#.to_string()),
            DbValue::Text("{}".to_string()),
            DbValue::Text(r#"{"cpu_percent":99.0,"memory_used_percent":99.0}"#.to_string()),
            DbValue::Text(old.clone()),
            DbValue::Text(old),
        ],
    )
    .await
    .expect("insert legacy node");
    repo.execute_write(
        "INSERT INTO nodes
             (node_id, node_name, host_id, hostname, agent_version, privacy_mode,
              enabled_features_json, storage_json, metrics_json, last_seen_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &[
            DbValue::Text("local-host".to_string()),
            DbValue::Text("local-host".to_string()),
            DbValue::Text(String::new()),
            DbValue::Text(String::new()),
            DbValue::Text("smoke-test".to_string()),
            DbValue::Text("strict".to_string()),
            DbValue::Text(r#"["panel"]"#.to_string()),
            DbValue::Text("{}".to_string()),
            DbValue::Text(r#"{"cpu_percent":1.0}"#.to_string()),
            DbValue::Text(now.clone()),
            DbValue::Text(now.clone()),
        ],
    )
    .await
    .expect("insert placeholder node");
    repo.execute_write(
        "INSERT INTO nodes
             (node_id, node_name, host_id, hostname, agent_version, privacy_mode,
              enabled_features_json, storage_json, metrics_json, last_seen_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &[
            DbValue::Text("node-a".to_string()),
            DbValue::Text("node-a".to_string()),
            DbValue::Text(String::new()),
            DbValue::Text(String::new()),
            DbValue::Text("0.2.0".to_string()),
            DbValue::Text("strict".to_string()),
            DbValue::Text(r#"["ssh","panel"]"#.to_string()),
            DbValue::Text("{}".to_string()),
            DbValue::Text(r#"{"cpu_percent":12.5,"memory_used_percent":44.0}"#.to_string()),
            DbValue::Text(now.clone()),
            DbValue::Text(now),
        ],
    )
    .await
    .expect("insert node");
    let request = PageRequest {
        from: None,
        to: None,
        limit: 10,
        offset: 0,
    };

    let (mut page, total) = repo
        .latest_nodes_page(
            &["last_seen_at", "node_name", "agent_version", "metrics_json"],
            &request,
            PanelRole::Public,
        )
        .await
        .expect("node query");
    scope_panel_value(&mut page, PanelRole::Public);
    let text = serde_json::to_string(&page).expect("json");

    assert_eq!(total, 1);
    assert_eq!(page[0]["agent_version"], "0.2.0");
    assert_eq!(page[0]["metrics"]["cpu_percent"], 12.5);
    assert_eq!(page[0]["metrics"]["memory_used_percent"], 44.0);
    assert!(!text.contains("node_id"));
    assert!(!text.contains("host_id"));
    assert!(!text.contains("hostname"));
    assert!(!text.contains("metrics_json"));
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

#[test]
fn panel_review_accepts_baseline_drift_target() {
    let review = PanelReview::try_from(PanelReviewRequest {
        target_type: "baseline_drifts".to_string(),
        target_id: "drift-1".to_string(),
        verdict: "confirmed".to_string(),
        note: "checked".to_string(),
        reviewer: "panel".to_string(),
    })
    .expect("baseline drift review should be valid");

    assert_eq!(review.target_type, ReviewTargetType::BaselineDrift);
    assert_eq!(review.target_id, "drift-1");
    assert_eq!(review.verdict, "confirmed");
}

#[test]
fn panel_review_rejects_unknown_target_type() {
    let err = PanelReview::try_from(PanelReviewRequest {
        target_type: "node".to_string(),
        target_id: "node-1".to_string(),
        verdict: "confirmed".to_string(),
        note: String::new(),
        reviewer: String::new(),
    })
    .expect_err("unknown target type should fail");

    assert_eq!(err.code, "invalid_review_target_type");
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
        public_pages: BTreeSet::new(),
        admin_path: DEFAULT_ADMIN_PATH.to_string(),
        theme: "default".to_string(),
        themes: parse_panel_themes(DEFAULT_THEMES),
        max_body_bytes: 1024,
        events: broadcast::channel::<PanelStreamEvent>(8).0,
        stream_tickets: Arc::new(Mutex::new(BTreeMap::new())),
        csp_header: HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
        ),
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
