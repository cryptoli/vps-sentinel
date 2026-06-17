use sentinel_core::{NotificationLanguage, Severity};

pub struct MessageCatalog {
    pub heading: &'static str,
    pub vps: &'static str,
    pub severity: &'static str,
    pub host_id: &'static str,
    pub time: &'static str,
    pub category: &'static str,
    pub rule: &'static str,
    pub subject: &'static str,
    pub description: &'static str,
    pub evidence: &'static str,
    pub impact: &'static str,
    pub recommendations: &'static str,
    pub event_id: &'static str,
    pub dedup_key: &'static str,
    pub technical_details: &'static str,
}

pub fn catalog(language: NotificationLanguage) -> MessageCatalog {
    match language {
        NotificationLanguage::En => MessageCatalog {
            heading: "VPS Sentinel Alert",
            vps: "VPS",
            severity: "Severity",
            host_id: "Host ID",
            time: "Time",
            category: "Category",
            rule: "Rule",
            subject: "Subject",
            description: "Description",
            evidence: "Evidence",
            impact: "Impact",
            recommendations: "Recommendations",
            event_id: "Event ID",
            dedup_key: "Dedup Key",
            technical_details: "Technical Details",
        },
        NotificationLanguage::ZhCn => MessageCatalog {
            heading: "VPS Sentinel 告警",
            vps: "VPS 名称",
            severity: "风险等级",
            host_id: "主机 ID",
            time: "时间",
            category: "分类",
            rule: "规则",
            subject: "对象",
            description: "说明",
            evidence: "证据",
            impact: "影响",
            recommendations: "建议",
            event_id: "事件 ID",
            dedup_key: "去重 Key",
            technical_details: "技术详情",
        },
    }
}

pub fn severity_label(severity: Severity, language: NotificationLanguage) -> &'static str {
    match language {
        NotificationLanguage::En => match severity {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        },
        NotificationLanguage::ZhCn => match severity {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "信息",
        },
    }
}

pub fn evidence_label(key: &str, language: NotificationLanguage) -> String {
    let text = match language {
        NotificationLanguage::En => match key {
            "protocol" => "protocol",
            "local_addr" => "local address",
            "local_port" => "local port",
            "port" => "port",
            "process_name" => "process",
            "previous_process_name" => "previous process",
            "previous_executable" => "previous executable",
            "pid" => "process ID",
            "ppid" => "parent process ID",
            "source_ip" | "ip" => "source IP",
            "cmdline" => "command line",
            "container_context" => "container context",
            "cpu_percent" => "CPU %",
            "cpu_total_seconds" => "CPU seconds",
            "cwd" => "working directory",
            "euid" => "effective UID",
            "exe_gid" => "executable GID",
            "exe_hash_blake3" => "executable hash",
            "exe_path" | "executable" => "executable",
            "exe_size" => "executable size bytes",
            "exe_uid" => "executable UID",
            "firewall_sources" => "firewall sources",
            "firewall_status" => "firewall status",
            "matched_tool" => "matched tool",
            "match_source" => "match source",
            "matched_value" => "matched value",
            "outbound_connection_count" => "outbound connections",
            "outbound_remote_ports" => "outbound remote ports",
            "package_activity_recent" => "recent package activity",
            "package_activity_sources" => "package logs",
            "package_owner" => "package owner",
            "parent_name" => "parent process",
            "process_age_seconds" => "process age seconds",
            "process_start_drift" => "process start drift",
            "public_outbound_count" => "public outbound connections",
            "risk_score" => "risk score",
            "risk_reasons" => "risk reasons",
            "risk_features" => "risk features",
            "socket_fd_count" => "socket FDs",
            "signals" => "signals",
            "systemd_execstart" => "systemd ExecStart",
            "systemd_unit" => "systemd unit",
            "path" => "path",
            "user" => "user",
            "method" => "method",
            "status" => "status",
            "log_source" => "log source",
            "log_sources" => "log sources",
            "methods" => "methods",
            "probe_family" => "probe family",
            "request_count" => "request count",
            "response_profile" => "response profile",
            "sample_paths" => "sample paths",
            "failure_count" => "failure count",
            other => other,
        },
        NotificationLanguage::ZhCn => match key {
            "protocol" => "协议",
            "local_addr" => "监听地址",
            "local_port" => "监听端口",
            "port" => "端口",
            "process_name" => "进程",
            "previous_process_name" => "原进程",
            "previous_executable" => "原可执行文件",
            "pid" => "进程 ID",
            "ppid" => "父进程 ID",
            "source_ip" | "ip" => "来源 IP",
            "cmdline" => "命令行",
            "container_context" => "容器上下文",
            "cpu_percent" => "CPU 占用",
            "cpu_total_seconds" => "累计 CPU 秒数",
            "cwd" => "工作目录",
            "euid" => "有效 UID",
            "exe_gid" => "可执行文件 GID",
            "exe_hash_blake3" => "可执行文件哈希",
            "exe_path" | "executable" => "可执行文件",
            "exe_size" => "可执行文件字节数",
            "exe_uid" => "可执行文件 UID",
            "firewall_sources" => "防火墙来源",
            "firewall_status" => "防火墙状态",
            "matched_tool" => "命中的工具",
            "match_source" => "命中来源",
            "matched_value" => "命中值",
            "outbound_connection_count" => "出站连接数",
            "outbound_remote_ports" => "出站远端端口",
            "package_activity_recent" => "近期软件包活动",
            "package_activity_sources" => "软件包日志",
            "package_owner" => "软件包归属",
            "parent_name" => "父进程",
            "process_age_seconds" => "进程运行秒数",
            "process_start_drift" => "进程启动变化",
            "public_outbound_count" => "公网出站连接数",
            "risk_score" => "风险评分",
            "risk_reasons" => "风险原因",
            "risk_features" => "风险特征",
            "socket_fd_count" => "Socket FD 数",
            "signals" => "关联信号",
            "systemd_execstart" => "systemd ExecStart",
            "systemd_unit" => "systemd 单元",
            "path" => "路径",
            "user" => "用户",
            "method" => "认证方式",
            "status" => "状态码",
            "log_source" => "日志来源",
            "log_sources" => "日志来源",
            "methods" => "请求方法",
            "probe_family" => "探测类型",
            "request_count" => "请求次数",
            "response_profile" => "响应画像",
            "sample_paths" => "样例路径",
            "failure_count" => "失败次数",
            other => other,
        },
    };
    text.to_string()
}

pub fn evidence_value_label(key: &str, value: &str, language: NotificationLanguage) -> String {
    if key == "probe_family" {
        return probe_family_value_label(value, language)
            .unwrap_or(value)
            .to_string();
    }

    match (key, value, language) {
        ("process_start_drift", "changed", NotificationLanguage::En) => {
            "changed since previous scan".to_string()
        }
        ("process_start_drift", "changed", NotificationLanguage::ZhCn) => {
            "较上一轮扫描发生变化".to_string()
        }
        ("response_profile", "successful_response", NotificationLanguage::En) => {
            "successful response".to_string()
        }
        ("response_profile", "protected_response", NotificationLanguage::En) => {
            "protected response".to_string()
        }
        ("response_profile", "redirected_response", NotificationLanguage::En) => {
            "redirected response".to_string()
        }
        ("response_profile", "missing_or_rejected", NotificationLanguage::En) => {
            "missing or rejected".to_string()
        }
        ("response_profile", "server_error", NotificationLanguage::En) => {
            "server error".to_string()
        }
        ("response_profile", "unknown_response", NotificationLanguage::En) => {
            "unknown response".to_string()
        }
        ("response_profile", "successful_response", NotificationLanguage::ZhCn) => {
            "成功响应".to_string()
        }
        ("response_profile", "protected_response", NotificationLanguage::ZhCn) => {
            "受保护响应".to_string()
        }
        ("response_profile", "redirected_response", NotificationLanguage::ZhCn) => {
            "重定向响应".to_string()
        }
        ("response_profile", "missing_or_rejected", NotificationLanguage::ZhCn) => {
            "不存在或被拒绝".to_string()
        }
        ("response_profile", "server_error", NotificationLanguage::ZhCn) => {
            "服务端错误".to_string()
        }
        ("response_profile", "unknown_response", NotificationLanguage::ZhCn) => {
            "未知响应".to_string()
        }
        _ => value.to_string(),
    }
}

fn probe_family_value_label(value: &str, language: NotificationLanguage) -> Option<&'static str> {
    match language {
        NotificationLanguage::En => match value {
            "env_file" => Some(".env exposure probe"),
            "git_exposure" => Some(".git exposure probe"),
            "phpunit_eval_stdin" => Some("PHPUnit eval-stdin probe"),
            "cgi_shell_traversal" => Some("CGI shell traversal attempt"),
            "command_injection" => Some("command-injection payload"),
            "sql_injection" => Some("SQL-injection payload"),
            "path_traversal" => Some("path-traversal probe"),
            "phpmyadmin" => Some("phpMyAdmin probe"),
            "wordpress_admin" => Some("WordPress admin probe"),
            "boaform" => Some("Boa router form probe"),
            "actuator" => Some("Spring actuator probe"),
            "server_status" => Some("server-status probe"),
            "generic_cgi" => Some("generic CGI probe"),
            _ => None,
        },
        NotificationLanguage::ZhCn => match value {
            "env_file" => Some(".env 暴露探测"),
            "git_exposure" => Some(".git 暴露探测"),
            "phpunit_eval_stdin" => Some("PHPUnit eval-stdin 探测"),
            "cgi_shell_traversal" => Some("CGI shell 路径穿越尝试"),
            "command_injection" => Some("命令注入 payload"),
            "sql_injection" => Some("SQL 注入 payload"),
            "path_traversal" => Some("路径穿越探测"),
            "phpmyadmin" => Some("phpMyAdmin 探测"),
            "wordpress_admin" => Some("WordPress admin 探测"),
            "boaform" => Some("Boa 路由器表单探测"),
            "actuator" => Some("Spring actuator 探测"),
            "server_status" => Some("server-status 探测"),
            "generic_cgi" => Some("通用 CGI 探测"),
            _ => None,
        },
    }
}
