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
            technical_details: "技术细节",
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
    if let Some(label) = gpu_evidence_label(key, language) {
        return label.to_string();
    }
    if let Some(label) = intrusion_evidence_label(key, language) {
        return label.to_string();
    }
    let text = match language {
        NotificationLanguage::En => match key {
            "account_subjects" => "account subjects",
            "argv_json" => "argv JSON",
            "active_response_backend" => "active response backend",
            "active_response_block_count" => "active response block count",
            "active_response_command" => "review command",
            "active_response_detail" => "active response detail",
            "active_response_detail_limit" => "active response detail limit",
            "active_response_expires_at" => "active response expires at",
            "active_response_failed_count" => "active response failed count",
            "active_response_ip" => "active response IP",
            "active_response_permanent_count" => "permanent block count",
            "active_response_reason" => "active response reason",
            "active_response_reason_summary" => "active response reason summary",
            "active_response_status" => "active response status",
            "active_response_window" => "active response window",
            "attack_fingerprint_action_hint" => "attack fingerprint action",
            "attack_fingerprint_id" => "attack fingerprint",
            "attack_fingerprint_kind" => "attack fingerprint kind",
            "attack_fingerprint_score" => "attack fingerprint score",
            "attack_fingerprint_seen_count" => "attack fingerprint observations",
            "attack_fingerprint_source_ip_count" => "attack fingerprint source IPs",
            "attack_fingerprint_verdict" => "attack fingerprint verdict",
            "baseline_drift_downgrades" => "baseline drift downgrades",
            "baseline_drift_reasons" => "baseline drift reasons",
            "baseline_drift_score" => "baseline drift score",
            "baseline_drift_tier" => "baseline drift tier",
            "baseline_review_action" => "baseline review action",
            "change" => "change",
            "cmdline" => "command line",
            "command" => "command",
            "container_context" => "container context",
            "content_markers" => "content markers",
            "cpu_percent" => "CPU %",
            "cpu_total_seconds" => "CPU seconds",
            "current_hash" => "current hash",
            "current_process_start_ticks" => "current process start ticks",
            "cwd" => "working directory",
            "entries" => "entries",
            "error_count" => "error count",
            "euid" => "effective UID",
            "executable" | "exe_path" => "executable",
            "executable_changed" => "executable changed",
            "exe_gid" => "executable GID",
            "exe_hash_blake3" => "executable hash",
            "exe_size" => "executable size bytes",
            "exe_uid" => "executable UID",
            "exists" => "exists",
            "extension" => "extension",
            "failure_count" => "failure count",
            "firewall_sources" => "firewall sources",
            "firewall_status" => "firewall status",
            "gid" => "GID",
            "hidden" => "hidden",
            "home" => "home directory",
            "identity_files" => "identity files",
            "ip" | "source_ip" => "source IP",
            "is_web_path" => "web path",
            "key" => "key",
            "local_addr" => "local address",
            "local_port" => "local port",
            "log_source" => "log source",
            "log_sources" => "log sources",
            "match_source" => "match source",
            "matched_tool" => "matched tool",
            "matched_value" => "matched value",
            "method" => "method",
            "methods" => "methods",
            "name" => "process name",
            "outbound_connection_count" => "outbound connections",
            "outbound_remote_ports" => "outbound remote ports",
            "outcome" => "outcome",
            "notification_grouped_findings" => "grouped findings",
            "notification_grouped_probe_families" => "grouped probe families",
            "notification_grouped_rule_ids" => "grouped rule IDs",
            "package_activity_recent" => "recent package activity",
            "package_activity_sources" => "package logs",
            "package_managed_system_user" => "package-managed system user",
            "package_owner" => "package owner",
            "parent_name" => "parent process",
            "path" => "path",
            "pid" => "process ID",
            "port" => "port",
            "ppid" => "parent process ID",
            "previous_executable" => "previous executable",
            "previous_hash" => "previous hash",
            "previous_process_name" => "previous process",
            "previous_process_start_ticks" => "previous process start ticks",
            "previous_uid" => "previous UID",
            "probe_family" => "probe family",
            "process_age_seconds" => "process age seconds",
            "process_name" => "process",
            "process_start_changed" => "process start changed",
            "process_start_drift" => "process start drift",
            "protocol" => "protocol",
            "public_exposure" => "public exposure",
            "public_outbound_count" => "public outbound connections",
            "raw" => "raw record",
            "remote_addr" => "remote address",
            "remote_port" => "remote port",
            "remote_public" => "remote is public",
            "report_active_response" => "active response summary",
            "report_category_summary" => "category summary",
            "report_database_size" => "database size",
            "report_end" => "report end",
            "report_failed_scan_runs" => "failed scans",
            "report_findings_total" => "findings total",
            "report_important_events" => "important events",
            "report_last_scan_at" => "last scan at",
            "report_notification_attempts" => "notification attempts",
            "report_period" => "report period",
            "report_scan_runs" => "scan runs",
            "report_severity_summary" => "severity summary",
            "report_start" => "report start",
            "report_top_rules" => "top rules",
            "request_count" => "request count",
            "response_profile" => "response profile",
            "risk_features" => "risk features",
            "risk_reasons" => "risk reasons",
            "risk_score" => "risk score",
            "sample_paths" => "sample paths",
            "service_profile" => "service profile",
            "service_profile_identity" => "service identity",
            "shell" => "shell",
            "signals" => "signals",
            "size" => "size bytes",
            "socket_fd_count" => "socket FDs",
            "status" => "status",
            "statuses" => "statuses",
            "suspicious_lines" => "suspicious lines",
            "systemd_execstart" => "systemd ExecStart",
            "systemd_unit" => "systemd unit",
            "type" => "type",
            "uid" => "UID",
            "user" => "user",
            "users" => "users",
            "value" => "value",
            other => other,
        },
        NotificationLanguage::ZhCn => match key {
            "account_subjects" => "账号对象",
            "argv_json" => "参数 JSON",
            "active_response_backend" => "主动响应后端",
            "active_response_block_count" => "封禁 IP 数量",
            "active_response_command" => "查看命令",
            "active_response_detail" => "主动响应详情",
            "active_response_detail_limit" => "明细展示上限",
            "active_response_expires_at" => "封禁到期时间",
            "active_response_failed_count" => "封禁失败数量",
            "active_response_ip" => "封禁 IP",
            "active_response_permanent_count" => "永久封禁数量",
            "active_response_reason" => "封禁原因",
            "active_response_reason_summary" => "封禁原因摘要",
            "active_response_status" => "主动响应状态",
            "active_response_window" => "主动响应窗口",
            "attack_fingerprint_action_hint" => "攻击指纹动作",
            "attack_fingerprint_id" => "攻击指纹",
            "attack_fingerprint_kind" => "攻击指纹类型",
            "attack_fingerprint_score" => "攻击指纹评分",
            "attack_fingerprint_seen_count" => "攻击指纹观察次数",
            "attack_fingerprint_source_ip_count" => "攻击指纹来源 IP 数",
            "attack_fingerprint_verdict" => "攻击指纹判定",
            "baseline_drift_downgrades" => "基线漂移降噪因素",
            "baseline_drift_reasons" => "基线漂移原因",
            "baseline_drift_score" => "基线漂移评分",
            "baseline_drift_tier" => "基线漂移层级",
            "baseline_review_action" => "基线复核动作",
            "change" => "变化类型",
            "cmdline" => "命令行",
            "command" => "命令",
            "container_context" => "容器上下文",
            "content_markers" => "内容特征",
            "cpu_percent" => "CPU 占用",
            "cpu_total_seconds" => "累计 CPU 秒数",
            "current_hash" => "当前哈希",
            "current_process_start_ticks" => "当前启动计数",
            "cwd" => "工作目录",
            "entries" => "条目",
            "error_count" => "错误次数",
            "euid" => "有效 UID",
            "executable" | "exe_path" => "可执行文件",
            "executable_changed" => "可执行文件变化",
            "exe_gid" => "可执行文件 GID",
            "exe_hash_blake3" => "可执行文件哈希",
            "exe_size" => "可执行文件字节数",
            "exe_uid" => "可执行文件 UID",
            "exists" => "是否存在",
            "extension" => "扩展名",
            "failure_count" => "失败次数",
            "firewall_sources" => "防火墙来源",
            "firewall_status" => "防火墙状态",
            "gid" => "GID",
            "hidden" => "隐藏文件",
            "home" => "Home 目录",
            "identity_files" => "身份文件",
            "ip" | "source_ip" => "来源 IP",
            "is_web_path" => "Web 路径",
            "key" => "键",
            "local_addr" => "监听地址",
            "local_port" => "监听端口",
            "log_source" => "日志来源",
            "log_sources" => "日志来源",
            "match_source" => "命中来源",
            "matched_tool" => "命中的工具",
            "matched_value" => "命中值",
            "method" => "方式",
            "methods" => "请求方法",
            "name" => "进程名",
            "outbound_connection_count" => "出站连接数",
            "outbound_remote_ports" => "出站远端端口",
            "outcome" => "结果",
            "notification_grouped_findings" => "合并告警数",
            "notification_grouped_probe_families" => "合并探测类型",
            "notification_grouped_rule_ids" => "合并规则",
            "package_activity_recent" => "近期软件包活动",
            "package_activity_sources" => "软件包日志",
            "package_managed_system_user" => "软件包创建的系统用户",
            "package_owner" => "软件包归属",
            "parent_name" => "父进程",
            "path" => "路径",
            "pid" => "进程 ID",
            "port" => "端口",
            "ppid" => "父进程 ID",
            "previous_executable" => "原可执行文件",
            "previous_hash" => "原哈希",
            "previous_process_name" => "原进程",
            "previous_process_start_ticks" => "原启动计数",
            "previous_uid" => "原 UID",
            "probe_family" => "探测类型",
            "process_age_seconds" => "进程运行秒数",
            "process_name" => "进程",
            "process_start_changed" => "进程启动是否变化",
            "process_start_drift" => "进程启动变化",
            "protocol" => "协议",
            "public_exposure" => "公网暴露",
            "public_outbound_count" => "公网出站连接数",
            "raw" => "原始记录",
            "remote_addr" => "远端地址",
            "remote_port" => "远端端口",
            "remote_public" => "远端公网",
            "report_active_response" => "主动响应摘要",
            "report_category_summary" => "分类汇总",
            "report_database_size" => "数据库大小",
            "report_end" => "报告结束时间",
            "report_failed_scan_runs" => "失败扫描次数",
            "report_findings_total" => "告警总数",
            "report_important_events" => "重点事件",
            "report_last_scan_at" => "最近扫描时间",
            "report_notification_attempts" => "通知发送次数",
            "report_period" => "报告周期",
            "report_scan_runs" => "扫描次数",
            "report_severity_summary" => "风险等级汇总",
            "report_start" => "报告开始时间",
            "report_top_rules" => "Top 规则",
            "request_count" => "请求次数",
            "response_profile" => "响应画像",
            "risk_features" => "风险特征",
            "risk_reasons" => "风险原因",
            "risk_score" => "风险评分",
            "sample_paths" => "样例路径",
            "service_profile" => "服务画像",
            "service_profile_identity" => "服务身份",
            "shell" => "Shell",
            "signals" => "关联信号",
            "size" => "字节数",
            "socket_fd_count" => "Socket FD 数",
            "status" => "状态码",
            "statuses" => "状态码",
            "suspicious_lines" => "可疑行",
            "systemd_execstart" => "systemd ExecStart",
            "systemd_unit" => "systemd 单元",
            "type" => "类型",
            "uid" => "UID",
            "user" => "用户",
            "users" => "用户",
            "value" => "值",
            other => other,
        },
    };
    text.to_string()
}

fn gpu_evidence_label(key: &str, language: NotificationLanguage) -> Option<&'static str> {
    match language {
        NotificationLanguage::En => match key {
            "gpu_memory_mb" => Some("GPU memory MB"),
            "gpu_process_names" => Some("GPU process names"),
            "gpu_uuids" => Some("GPU UUIDs"),
            "mining_pool_remote_ports" => Some("mining-pool remote ports"),
            _ => None,
        },
        NotificationLanguage::ZhCn => match key {
            "gpu_memory_mb" => Some("GPU 显存 MB"),
            "gpu_process_names" => Some("GPU 进程名"),
            "gpu_uuids" => Some("GPU UUID"),
            "mining_pool_remote_ports" => Some("矿池远端端口"),
            _ => None,
        },
    }
}

fn intrusion_evidence_label(key: &str, language: NotificationLanguage) -> Option<&'static str> {
    match language {
        NotificationLanguage::En => match key {
            "current_size" => Some("current size bytes"),
            "drop_percent" => Some("drop percent"),
            "dropped_bytes" => Some("dropped bytes"),
            "file_type" => Some("file type"),
            "log_file_missing" => Some("log file missing"),
            "log_size_drop" => Some("log size dropped"),
            "mode_octal" => Some("mode"),
            "modified_time_utc" => Some("modified time"),
            "previous_file_type" => Some("previous file type"),
            "previous_modified_unix" => Some("previous modified time"),
            "previous_modified_time_utc" => Some("previous modified time"),
            "previous_size" => Some("previous size bytes"),
            "previous_symlink_target" => Some("previous symlink target"),
            "recent_rotated_sibling" => Some("recent rotated sibling"),
            "rotated_sibling" => Some("rotated sibling"),
            "symlink_target" => Some("symlink target"),
            _ => None,
        },
        NotificationLanguage::ZhCn => match key {
            "current_size" => Some("当前字节数"),
            "drop_percent" => Some("下降比例"),
            "dropped_bytes" => Some("减少字节数"),
            "file_type" => Some("文件类型"),
            "log_file_missing" => Some("日志文件缺失"),
            "log_size_drop" => Some("日志大小下降"),
            "mode_octal" => Some("权限模式"),
            "modified_time_utc" => Some("修改时间"),
            "previous_file_type" => Some("原文件类型"),
            "previous_modified_unix" => Some("原修改时间"),
            "previous_modified_time_utc" => Some("原修改时间"),
            "previous_size" => Some("原字节数"),
            "previous_symlink_target" => Some("原软链目标"),
            "recent_rotated_sibling" => Some("近期轮转文件"),
            "rotated_sibling" => Some("轮转文件"),
            "symlink_target" => Some("软链目标"),
            _ => None,
        },
    }
}

pub fn evidence_value_label(key: &str, value: &str, language: NotificationLanguage) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    if let Some(label) = direct_value_label(key, value, language) {
        return label.to_string();
    }
    if let Some(label) = dynamic_value_label(key, value, language) {
        return label;
    }
    if is_localized_list_key(key) {
        return localize_list_value(value, language);
    }
    value.to_string()
}

fn direct_value_label(
    key: &str,
    value: &str,
    language: NotificationLanguage,
) -> Option<&'static str> {
    match (key, value, language) {
        ("active_response_status", "already_blocked", NotificationLanguage::En) => {
            Some("already blocked")
        }
        ("active_response_status", "already_blocked", NotificationLanguage::ZhCn) => {
            Some("此前已封禁")
        }
        ("active_response_status", "already_permanently_blocked", NotificationLanguage::En) => {
            Some("already permanently blocked")
        }
        ("active_response_status", "already_permanently_blocked", NotificationLanguage::ZhCn) => {
            Some("此前已永久封禁")
        }
        ("active_response_status", "blocked", NotificationLanguage::En) => {
            Some("temporary block applied")
        }
        ("active_response_status", "blocked", NotificationLanguage::ZhCn) => Some("已临时封禁"),
        ("active_response_status", "permanently_blocked", NotificationLanguage::En) => {
            Some("permanent block applied")
        }
        ("active_response_status", "permanently_blocked", NotificationLanguage::ZhCn) => {
            Some("已永久封禁")
        }
        ("active_response_status", "blocked_many", NotificationLanguage::En) => {
            Some("multiple blocks applied")
        }
        ("active_response_status", "blocked_many", NotificationLanguage::ZhCn) => {
            Some("已封禁多个 IP")
        }
        ("active_response_status", "failed", NotificationLanguage::En) => Some("block failed"),
        ("active_response_status", "failed", NotificationLanguage::ZhCn) => Some("封禁失败"),
        ("active_response_status", "skipped_limit", NotificationLanguage::En) => {
            Some("skipped because block limit was reached")
        }
        ("active_response_status", "skipped_limit", NotificationLanguage::ZhCn) => {
            Some("达到单轮封禁上限，已跳过")
        }
        ("attack_fingerprint_action_hint", "block", NotificationLanguage::En) => {
            Some("block current source")
        }
        ("attack_fingerprint_action_hint", "block", NotificationLanguage::ZhCn) => {
            Some("封禁当前来源")
        }
        ("attack_fingerprint_kind", "web_probe", NotificationLanguage::En) => {
            Some("Web probing pattern")
        }
        ("attack_fingerprint_kind", "web_probe", NotificationLanguage::ZhCn) => {
            Some("Web 探测模式")
        }
        ("attack_fingerprint_kind", "ssh_bruteforce", NotificationLanguage::En) => {
            Some("SSH brute-force pattern")
        }
        ("attack_fingerprint_kind", "ssh_bruteforce", NotificationLanguage::ZhCn) => {
            Some("SSH 爆破模式")
        }
        ("attack_fingerprint_kind", "host_process", NotificationLanguage::En) => {
            Some("host process behavior")
        }
        ("attack_fingerprint_kind", "host_process", NotificationLanguage::ZhCn) => {
            Some("主机进程行为")
        }
        ("attack_fingerprint_kind", "host_persistence", NotificationLanguage::En) => {
            Some("host persistence behavior")
        }
        ("attack_fingerprint_kind", "host_persistence", NotificationLanguage::ZhCn) => {
            Some("主机持久化行为")
        }
        ("attack_fingerprint_verdict", "unknown", NotificationLanguage::En) => Some("unknown"),
        ("attack_fingerprint_verdict", "unknown", NotificationLanguage::ZhCn) => Some("未确认"),
        ("attack_fingerprint_verdict", "benign", NotificationLanguage::En) => Some("benign"),
        ("attack_fingerprint_verdict", "benign", NotificationLanguage::ZhCn) => {
            Some("已标记为正常")
        }
        ("attack_fingerprint_verdict", "malicious", NotificationLanguage::En) => {
            Some("confirmed malicious")
        }
        ("attack_fingerprint_verdict", "malicious", NotificationLanguage::ZhCn) => {
            Some("已确认恶意")
        }
        ("baseline_drift_tier", "routine", NotificationLanguage::En) => Some("routine"),
        ("baseline_drift_tier", "routine", NotificationLanguage::ZhCn) => Some("常规变更"),
        ("baseline_drift_tier", "review", NotificationLanguage::En) => Some("needs review"),
        ("baseline_drift_tier", "review", NotificationLanguage::ZhCn) => Some("需要复核"),
        ("baseline_drift_tier", "suspicious", NotificationLanguage::En) => Some("suspicious"),
        ("baseline_drift_tier", "suspicious", NotificationLanguage::ZhCn) => Some("可疑"),
        ("baseline_drift_tier", "critical", NotificationLanguage::En) => Some("critical"),
        ("baseline_drift_tier", "critical", NotificationLanguage::ZhCn) => Some("严重"),
        ("baseline_review_action", "confirm_context_then_refresh", NotificationLanguage::En) => {
            Some("confirm context before refreshing baseline")
        }
        ("baseline_review_action", "confirm_context_then_refresh", NotificationLanguage::ZhCn) => {
            Some("确认变更上下文后再刷新基线")
        }
        ("baseline_review_action", "review_change_before_refresh", NotificationLanguage::En) => {
            Some("review change before refreshing baseline")
        }
        ("baseline_review_action", "review_change_before_refresh", NotificationLanguage::ZhCn) => {
            Some("复核变更后再刷新基线")
        }
        ("baseline_review_action", "investigate_before_refresh", NotificationLanguage::En) => {
            Some("investigate before refreshing baseline")
        }
        ("baseline_review_action", "investigate_before_refresh", NotificationLanguage::ZhCn) => {
            Some("调查清楚后再刷新基线")
        }
        (
            "baseline_review_action",
            "treat_as_incident_before_refresh",
            NotificationLanguage::En,
        ) => Some("treat as incident before refreshing baseline"),
        (
            "baseline_review_action",
            "treat_as_incident_before_refresh",
            NotificationLanguage::ZhCn,
        ) => Some("按安全事件处置后再考虑刷新基线"),
        ("probe_family", value, language) => probe_family_value_label(value, language),
        ("process_start_drift", "changed", NotificationLanguage::En) => {
            Some("changed since previous scan")
        }
        ("process_start_drift", "changed", NotificationLanguage::ZhCn) => {
            Some("较上一轮扫描发生变化")
        }
        ("response_profile", "successful_response", NotificationLanguage::En) => {
            Some("successful response")
        }
        ("response_profile", "protected_response", NotificationLanguage::En) => {
            Some("protected response")
        }
        ("response_profile", "redirected_response", NotificationLanguage::En) => {
            Some("redirected response")
        }
        ("response_profile", "missing_or_rejected", NotificationLanguage::En) => {
            Some("missing or rejected")
        }
        ("response_profile", "server_error", NotificationLanguage::En) => Some("server error"),
        ("response_profile", "unknown_response", NotificationLanguage::En) => {
            Some("unknown response")
        }
        ("response_profile", "successful_response", NotificationLanguage::ZhCn) => Some("成功响应"),
        ("response_profile", "protected_response", NotificationLanguage::ZhCn) => {
            Some("受保护响应")
        }
        ("response_profile", "redirected_response", NotificationLanguage::ZhCn) => {
            Some("重定向响应")
        }
        ("response_profile", "missing_or_rejected", NotificationLanguage::ZhCn) => {
            Some("不存在或被拒绝")
        }
        ("response_profile", "server_error", NotificationLanguage::ZhCn) => Some("服务端错误"),
        ("response_profile", "unknown_response", NotificationLanguage::ZhCn) => Some("未知响应"),
        ("active_response_window", "current_scan", NotificationLanguage::En) => {
            Some("current scan")
        }
        ("active_response_window", "current_scan", NotificationLanguage::ZhCn) => {
            Some("当前扫描窗口")
        }
        ("report_period", "today", NotificationLanguage::En) => Some("today"),
        ("report_period", "today", NotificationLanguage::ZhCn) => Some("今日"),
        ("report_period", "last24h", NotificationLanguage::En) => Some("last 24 hours"),
        ("report_period", "last24h", NotificationLanguage::ZhCn) => Some("过去 24 小时"),
        (
            "report_category_summary" | "report_severity_summary" | "report_top_rules",
            "none",
            NotificationLanguage::ZhCn,
        ) => Some("无"),
        (
            "package_activity_recent"
            | "process_start_changed"
            | "remote_public"
            | "public_exposure"
            | "exists"
            | "executable"
            | "hidden"
            | "is_web_path"
            | "package_managed_system_user"
            | "executable_changed",
            "true",
            NotificationLanguage::ZhCn,
        ) => Some("是"),
        (
            "package_activity_recent"
            | "process_start_changed"
            | "remote_public"
            | "public_exposure"
            | "exists"
            | "executable"
            | "hidden"
            | "is_web_path"
            | "package_managed_system_user"
            | "executable_changed",
            "false",
            NotificationLanguage::ZhCn,
        ) => Some("否"),
        ("method", "password", NotificationLanguage::En) => Some("password authentication"),
        ("method", "publickey", NotificationLanguage::En) => Some("public key authentication"),
        ("method", "password", NotificationLanguage::ZhCn) => Some("密码认证"),
        ("method", "publickey", NotificationLanguage::ZhCn) => Some("公钥认证"),
        ("outcome", "success", NotificationLanguage::ZhCn) => Some("成功"),
        ("outcome", "failure", NotificationLanguage::ZhCn) => Some("失败"),
        ("change", value, NotificationLanguage::ZhCn) => change_value_label(value),
        ("type", value, NotificationLanguage::ZhCn) => type_value_label(value),
        ("match_source", value, NotificationLanguage::ZhCn) => match_source_label(value),
        ("service_profile", "configured high-risk service", NotificationLanguage::ZhCn) => {
            Some("配置中的高风险服务")
        }
        ("firewall_status", "active", NotificationLanguage::ZhCn) => Some("已启用"),
        ("firewall_status", "inactive", NotificationLanguage::ZhCn) => Some("未启用"),
        ("firewall_status", "unknown", NotificationLanguage::ZhCn) => Some("未知"),
        _ => None,
    }
}

fn is_localized_list_key(key: &str) -> bool {
    matches!(
        key,
        "signals"
            | "risk_features"
            | "risk_reasons"
            | "content_markers"
            | "baseline_drift_reasons"
            | "baseline_drift_downgrades"
    )
}

fn localize_list_value(value: &str, language: NotificationLanguage) -> String {
    let parts = value
        .split([',', ';'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            technical_token_label(part, language)
                .unwrap_or(part)
                .to_string()
        })
        .collect::<Vec<_>>();

    if parts.is_empty() {
        return value.to_string();
    }
    match language {
        NotificationLanguage::En => parts.join(", "),
        NotificationLanguage::ZhCn => parts.join("，"),
    }
}

fn dynamic_value_label(key: &str, value: &str, language: NotificationLanguage) -> Option<String> {
    if key == "report_active_response" {
        return localize_report_active_response(value, language);
    }
    if key == "report_severity_summary" {
        return localize_report_count_summary(value, language, report_severity_token_label);
    }
    if key == "report_category_summary" {
        return localize_report_count_summary(value, language, report_category_token_label);
    }
    if key == "notification_grouped_probe_families" {
        return Some(localize_probe_family_list(value, language));
    }
    if key == "active_response_detail" && value.starts_with("permanent_escalation ") {
        let parts = value
            .split_whitespace()
            .filter_map(|part| part.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();
        let trigger_count = parts.get("trigger_count").copied().unwrap_or("0");
        let window_seconds = parts.get("window_seconds").copied().unwrap_or("0");
        return Some(match language {
            NotificationLanguage::En => format!(
                "escalated after {trigger_count} repeated block-candidate scans within {window_seconds}s"
            ),
            NotificationLanguage::ZhCn => {
                format!("{window_seconds} 秒窗口内第 {trigger_count} 次触发封禁候选，已升级为永久封禁")
            }
        });
    }
    if language != NotificationLanguage::ZhCn {
        return None;
    }
    if key == "active_response_reason" {
        return localize_active_response_reason(value);
    }
    if key == "active_response_reason_summary" {
        return localize_active_response_reason_summary(value);
    }
    let lowered = value.to_ascii_lowercase();
    if lowered.starts_with("process identity ") && lowered.contains(" matches configured tool ") {
        return Some("进程身份匹配配置中的高风险工具".to_string());
    }
    None
}

fn localize_probe_family_list(value: &str, language: NotificationLanguage) -> String {
    let labels = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            probe_family_value_label(part, language)
                .unwrap_or(part)
                .to_string()
        })
        .collect::<Vec<_>>();
    match language {
        NotificationLanguage::En => labels.join(", "),
        NotificationLanguage::ZhCn => labels.join("，"),
    }
}

fn localize_report_active_response(value: &str, language: NotificationLanguage) -> Option<String> {
    let parts = value
        .split(',')
        .filter_map(|part| {
            let (key, count) = part.trim().split_once('=')?;
            let label = match (key, language) {
                ("temporary_blocks", NotificationLanguage::En) => "temporary blocks",
                ("temporary_blocks", NotificationLanguage::ZhCn) => "临时封禁",
                ("permanent_blocks", NotificationLanguage::En) => "permanent blocks",
                ("permanent_blocks", NotificationLanguage::ZhCn) => "永久封禁",
                ("failed_blocks", NotificationLanguage::En) => "failed blocks",
                ("failed_blocks", NotificationLanguage::ZhCn) => "封禁失败",
                ("source_ips", NotificationLanguage::En) => "source IPs",
                ("source_ips", NotificationLanguage::ZhCn) => "来源 IP",
                _ => return None,
            };
            let value = if key == "source_ips" {
                count.replace('|', ", ")
            } else {
                count.to_string()
            };
            Some(format!("{label}={value}"))
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(match language {
            NotificationLanguage::En => parts.join(", "),
            NotificationLanguage::ZhCn => parts.join("，"),
        })
    }
}

fn localize_report_count_summary<F>(
    value: &str,
    language: NotificationLanguage,
    label_fn: F,
) -> Option<String>
where
    F: Fn(&str, NotificationLanguage) -> Option<&'static str>,
{
    let parts = value
        .split(',')
        .filter_map(|part| {
            let (key, count) = part.trim().split_once('=')?;
            let label = label_fn(key, language)
                .map(str::to_string)
                .unwrap_or_else(|| key.to_string());
            Some(format!("{label}={count}"))
        })
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(match language {
            NotificationLanguage::En => parts.join(", "),
            NotificationLanguage::ZhCn => parts.join("，"),
        })
    }
}

fn report_severity_token_label(
    value: &str,
    language: NotificationLanguage,
) -> Option<&'static str> {
    match (value, language) {
        ("Critical", NotificationLanguage::ZhCn) => Some("严重"),
        ("High", NotificationLanguage::ZhCn) => Some("高危"),
        ("Medium", NotificationLanguage::ZhCn) => Some("中危"),
        ("Low", NotificationLanguage::ZhCn) => Some("低危"),
        ("Info", NotificationLanguage::ZhCn) => Some("信息"),
        _ => None,
    }
}

fn report_category_token_label(
    value: &str,
    language: NotificationLanguage,
) -> Option<&'static str> {
    match (value, language) {
        ("ssh", NotificationLanguage::ZhCn) => Some("SSH"),
        ("user", NotificationLanguage::ZhCn) => Some("用户"),
        ("privilege", NotificationLanguage::ZhCn) => Some("权限"),
        ("persistence", NotificationLanguage::ZhCn) => Some("持久化"),
        ("process", NotificationLanguage::ZhCn) => Some("进程"),
        ("network", NotificationLanguage::ZhCn) => Some("网络"),
        ("file_integrity", NotificationLanguage::ZhCn) => Some("文件完整性"),
        ("web", NotificationLanguage::ZhCn) => Some("Web"),
        ("docker", NotificationLanguage::ZhCn) => Some("Docker"),
        ("rootkit", NotificationLanguage::ZhCn) => Some("Rootkit"),
        ("config_risk", NotificationLanguage::ZhCn) => Some("配置风险"),
        ("system", NotificationLanguage::ZhCn) => Some("系统"),
        _ => None,
    }
}

fn localize_active_response_reason_summary(value: &str) -> Option<String> {
    let items = value
        .split(',')
        .filter_map(|item| {
            let (reason, count) = item.trim().split_once('=')?;
            let label = match reason {
                "web_probe" => "Web 探测",
                "web_error_burst" => "Web 错误爆发",
                "ssh_brute_force" => "SSH 暴力尝试",
                "other" => "其他",
                _ => return None,
            };
            Some(format!("{label}={count}"))
        })
        .collect::<Vec<_>>();
    if items.is_empty() {
        None
    } else {
        Some(items.join("，"))
    }
}

fn localize_active_response_reason(value: &str) -> Option<String> {
    let parts = value
        .split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    if value.starts_with("web probe ") {
        let family = parts
            .get("family")
            .map(|value| evidence_value_label("probe_family", value, NotificationLanguage::ZhCn))
            .unwrap_or_else(|| "未知".to_string());
        let response = parts
            .get("response")
            .map(|value| {
                evidence_value_label("response_profile", value, NotificationLanguage::ZhCn)
            })
            .unwrap_or_else(|| "未知".to_string());
        let request_count = parts.get("request_count").copied().unwrap_or("0");
        return Some(format!(
            "Web 探测：类型={family}，响应={response}，请求次数={request_count}"
        ));
    }
    if value.starts_with("web error burst ") {
        let error_count = parts.get("error_count").copied().unwrap_or("0");
        return Some(format!("Web 错误爆发：错误次数={error_count}"));
    }
    if value.starts_with("ssh brute force ") {
        let failure_count = parts.get("failure_count").copied().unwrap_or("0");
        return Some(format!("SSH 暴力尝试：失败次数={failure_count}"));
    }
    None
}

fn change_value_label(value: &str) -> Option<&'static str> {
    match value {
        "file_created" => Some("文件新增"),
        "file_modified" => Some("文件修改"),
        "file_deleted" => Some("文件删除"),
        "persistence_created" => Some("持久化项新增"),
        "persistence_modified" => Some("持久化项修改"),
        "user_created" => Some("用户新增"),
        "user_modified" => Some("用户修改"),
        "user_uid_changed_to_zero" => Some("用户 UID 改为 0"),
        "listening_socket" => Some("新增监听端口"),
        "listening_socket_owner_changed" => Some("监听进程变化"),
        _ => None,
    }
}

fn type_value_label(value: &str) -> Option<&'static str> {
    match value {
        "cron" => Some("cron"),
        "systemd" => Some("systemd"),
        "shell_profile" => Some("Shell 启动脚本"),
        "ld_preload" => Some("动态链接器 preload"),
        "ipv4" => Some("IPv4"),
        "ipv6" => Some("IPv6"),
        _ => None,
    }
}

fn match_source_label(value: &str) -> Option<&'static str> {
    match value {
        "argv_json" => Some("进程参数"),
        "cmdline" => Some("命令行"),
        "exe_path" => Some("可执行文件路径"),
        "name" => Some("进程名"),
        _ => None,
    }
}

fn technical_token_label(value: &str, language: NotificationLanguage) -> Option<&'static str> {
    if let Some(label) = gpu_technical_token_label(value, language) {
        return Some(label);
    }
    if let Some(label) = intrusion_technical_token_label(value, language) {
        return Some(label);
    }
    match language {
        NotificationLanguage::En => match value {
            "account file drift" => Some("account file drift"),
            "baseline change detected" => Some("baseline change detected"),
            "baseline drift finding" => Some("baseline drift finding"),
            "dev_tcp" => Some("/dev/tcp"),
            "dynamic linker preload changed" => Some("dynamic linker preload changed"),
            "dynamic UDP listener" => Some("dynamic UDP listener"),
            "executable state changed" => Some("executable state changed"),
            "exec_bridge" => Some("exec bridge"),
            "large file size delta" => Some("large file size delta"),
            "fd_bridge" | "fd_duplication" => Some("file descriptor bridge"),
            "inline_interpreter" => Some("inline interpreter"),
            "interactive_shell" => Some("interactive shell"),
            "listener owner changed" => Some("listener owner changed"),
            "network_channel" => Some("network channel"),
            "network_execution_bridge" => Some("network execution bridge"),
            "not publicly exposed" => Some("not publicly exposed"),
            "local user account" => Some("local user account"),
            "local firewall context is present" => Some("local firewall context is present"),
            "privileged account state changed" => Some("privileged account state changed"),
            "privilege account change" => Some("privilege account change"),
            "public listener exposure" => Some("public listener exposure"),
            "recent package manager activity" => Some("recent package manager activity"),
            "risk evidence attached" => Some("risk evidence attached"),
            "risk-scored suspicious traits present" => {
                Some("risk-scored suspicious traits present")
            }
            "security-sensitive drift" => Some("security-sensitive drift"),
            "service owner changed" => Some("service owner changed"),
            "shell_target" => Some("shell target"),
            "socket_api" => Some("socket API"),
            "suspicious executable path" => Some("suspicious executable path"),
            "system_bridge" => Some("system command bridge"),
            "tty_allocation" => Some("TTY allocation"),
            "temporary_path" => Some("temporary path"),
            "runtime_executable_path" => Some("runtime-path executable"),
            "temporary_executable_path" => Some("temporary-path executable"),
            "configured_suspicious_executable_path" => {
                Some("configured suspicious-path executable")
            }
            "deleted_runtime_executable_path" => Some("deleted runtime-path executable"),
            "deleted_temporary_executable_path" | "temporary_deleted_executable" => {
                Some("deleted temporary-path executable")
            }
            "deleted_configured_suspicious_executable_path" => {
                Some("deleted configured suspicious-path executable")
            }
            "privileged_runtime_process" => Some("privileged runtime-path process"),
            "executable is under a runtime state path" => {
                Some("executable is under a runtime state path")
            }
            "executable is under a common temporary staging directory" => {
                Some("executable is under a common temporary staging directory")
            }
            "executable is under a configured suspicious directory" => {
                Some("executable is under a configured suspicious directory")
            }
            "deleted executable is under a runtime state path" => {
                Some("deleted executable is under a runtime state path")
            }
            "deleted executable is under a common temporary staging directory" => {
                Some("deleted executable is under a common temporary staging directory")
            }
            "deleted executable is under a configured suspicious directory" => {
                Some("deleted executable is under a configured suspicious directory")
            }
            "runtime path process is running with effective root privileges" => {
                Some("runtime-path process is running with effective root privileges")
            }
            _ => None,
        },
        NotificationLanguage::ZhCn => match value {
            "account file drift" => Some("账号文件漂移"),
            "baseline change detected" => Some("检测到基线变更"),
            "baseline drift finding" => Some("基线漂移告警"),
            "dynamic linker preload changed" => Some("动态链接器 preload 发生变化"),
            "dynamic UDP listener" => Some("动态 UDP 监听端口"),
            "executable state changed" => Some("可执行状态发生变化"),
            "large file size delta" => Some("文件大小变化较大"),
            "listener owner changed" => Some("监听端口所属进程发生变化"),
            "local firewall context is present" => Some("存在本机防火墙上下文"),
            "not publicly exposed" => Some("未暴露到公网"),
            "privileged account state changed" => Some("特权账号状态发生变化"),
            "public listener exposure" => Some("存在公网监听暴露"),
            "recent package manager activity" => Some("近期存在软件包管理器活动"),
            "risk evidence attached" => Some("已附加风险证据"),
            "risk-scored suspicious traits present" => Some("存在达到风险评分的可疑特征"),
            "security-sensitive drift" => Some("安全敏感对象发生漂移"),
            "service owner changed" => Some("服务所属进程发生变化"),
            "anonymous_deleted_executable" => Some("匿名或 memfd 删除态可执行文件"),
            "command_execution_marker" => Some("命令执行特征"),
            "configured miner/scanner identity matched" => Some("命中配置中的挖矿或扫描工具身份"),
            "deleted executable has a hidden basename outside standard runtime paths" => {
                Some("删除态可执行文件在非常规路径中使用隐藏文件名")
            }
            "deleted executable is backed by memfd or an anonymous file" => {
                Some("删除态可执行文件来自 memfd 或匿名文件")
            }
            "deleted executable is running from a suspicious temporary directory" => {
                Some("删除态可执行文件从可疑临时目录运行")
            }
            "deleted executable process name is a shell" => Some("删除态进程名是 Shell"),
            "dev_tcp" => Some("/dev/tcp"),
            "download_to_shell" => Some("下载内容直接送入 Shell"),
            "downloaded payload piped to shell" => Some("下载的载荷被管道传入 Shell"),
            "dynamic_code_marker" => Some("动态代码执行特征"),
            "encoded_command_execution" => Some("编码载荷结合命令执行"),
            "encoded_dynamic_execution" => Some("编码载荷结合动态执行"),
            "encoded_payload_marker" => Some("编码载荷特征"),
            "encoded_shell_payload" => Some("编码 Shell 载荷"),
            "exec_bridge" => Some("exec 桥接"),
            "local user account" => Some("本地用户账号"),
            "privilege account change" => Some("权限账号变更"),
            "executable appears deleted while still running" => {
                Some("可执行文件已删除但进程仍在运行")
            }
            "executable is under a suspicious temporary directory" => {
                Some("可执行文件位于可疑临时目录")
            }
            "fd_bridge" | "fd_duplication" => Some("文件描述符桥接"),
            "file integrity" => Some("文件完整性"),
            "file contains command-execution style markers" => Some("文件包含命令执行类特征"),
            "file contains dynamic code execution markers" => Some("文件包含动态代码执行特征"),
            "file contains encoded-payload markers" => Some("文件包含编码载荷特征"),
            "hidden_executable_name" => Some("隐藏可执行文件名"),
            "hidden_nonstandard_executable" => Some("非常规路径隐藏可执行文件"),
            "hidden_suspicious_script" => Some("隐藏可疑脚本"),
            "inline script uses socket APIs, fd duplication, and a shell target" => {
                Some("内联脚本同时使用 socket API、文件描述符重定向和 Shell 目标")
            }
            "inline_interpreter" => Some("内联解释器"),
            "interactive_shell" => Some("交互式 Shell"),
            "kernel_thread_masquerade" => Some("伪装成内核线程名"),
            "known_bad_tool" => Some("已知高风险工具"),
            "large_encoded_web_script" => Some("Web 脚本中的大段编码内容"),
            "listener owner changed from baseline" => Some("监听进程相对基线发生变化"),
            "many_socket_fds" => Some("大量 Socket 文件描述符"),
            "marker appears in a script-like file under a web path" => {
                Some("特征出现在 Web 路径下的脚本类文件中")
            }
            "miner or scanner indicator" => Some("挖矿或扫描器指标"),
            "network channel is bridged directly into a shell execution target" => {
                Some("网络通道被直接桥接到 Shell 执行目标")
            }
            "network channel is bridged into a system command runner" => {
                Some("网络通道被桥接到系统命令执行器")
            }
            "network command allocates a TTY for an interactive shell" => {
                Some("网络命令为交互式 Shell 分配 TTY")
            }
            "network execution bridge" | "network_execution_bridge" => Some("网络命令执行桥接"),
            "network shell bridge" => Some("网络 Shell 桥接"),
            "network_channel" => Some("网络通道"),
            "persistence" => Some("持久化"),
            "plain shell wrapper" => Some("普通 Shell 包装器"),
            "privileged_suspicious_process" => Some("高权限可疑进程"),
            "process current working directory is under a suspicious temporary path" => {
                Some("进程工作目录位于可疑临时路径")
            }
            "process executable has a hidden basename" => Some("进程可执行文件名为隐藏文件"),
            "process executable is under a configured web root" => {
                Some("进程可执行文件位于 Web 根目录")
            }
            "process has established outbound connections to public addresses" => {
                Some("进程存在到公网地址的已建立连接")
            }
            "process identity matches a configured miner or scanner tool" => {
                Some("进程身份匹配配置中的挖矿或扫描工具")
            }
            "process owns many socket file descriptors" => Some("进程持有大量 Socket 文件描述符"),
            "process owns socket file descriptors" => Some("进程持有 Socket 文件描述符"),
            "process_start_drift" => Some("进程启动变化"),
            "public_outbound_connections" => Some("公网出站连接"),
            "shell_process" => Some("Shell 进程"),
            "shell_target" => Some("Shell 目标"),
            "shell_wrapper" => Some("Shell 包装器"),
            "socket_activity" => Some("Socket 活动"),
            "socket_api" => Some("Socket API"),
            "startup command decodes payload data before shell execution" => {
                Some("启动命令在 Shell 执行前解码载荷")
            }
            "startup command downloads data and pipes it to a shell" => {
                Some("启动命令下载数据并通过管道送入 Shell")
            }
            "startup command references a temporary executable path" => {
                Some("启动命令引用临时目录中的可执行文件")
            }
            "suspicious markers appear in a hidden file" => Some("可疑特征出现在隐藏文件中"),
            "suspicious_cwd" => Some("可疑工作目录"),
            "suspicious executable path" => Some("可疑可执行路径"),
            "sustained_high_cpu" => Some("持续高 CPU"),
            "system_bridge" => Some("系统命令桥接"),
            "systemd ExecStart does not appear to match the listener executable" => {
                Some("systemd ExecStart 与监听进程可执行文件不一致")
            }
            "systemd_execstart_mismatch" => Some("systemd ExecStart 不一致"),
            "temporary executable path" => Some("临时目录可执行文件"),
            "temporary path" | "temporary_path" => Some("临时路径"),
            "temporary_deleted_executable" => Some("临时目录删除态可执行文件"),
            "runtime_executable_path" => Some("运行时路径可执行文件"),
            "temporary_executable_path" => Some("临时路径可执行文件"),
            "configured_suspicious_executable_path" => Some("配置的可疑路径可执行文件"),
            "deleted_runtime_executable_path" => Some("运行时路径删除态可执行文件"),
            "deleted_temporary_executable_path" => Some("临时路径删除态可执行文件"),
            "deleted_configured_suspicious_executable_path" => {
                Some("配置的可疑路径删除态可执行文件")
            }
            "privileged_runtime_process" => Some("高权限运行时路径进程"),
            "executable is under a runtime state path" => Some("可执行文件位于运行时状态路径"),
            "executable is under a common temporary staging directory" => {
                Some("可执行文件位于常见临时落地目录")
            }
            "executable is under a configured suspicious directory" => {
                Some("可执行文件位于配置的可疑目录")
            }
            "deleted executable is under a runtime state path" => {
                Some("删除态可执行文件位于运行时状态路径")
            }
            "deleted executable is under a common temporary staging directory" => {
                Some("删除态可执行文件位于常见临时落地目录")
            }
            "deleted executable is under a configured suspicious directory" => {
                Some("删除态可执行文件位于配置的可疑目录")
            }
            "runtime path process is running with effective root privileges" => {
                Some("运行时路径进程正在以有效 root 权限运行")
            }
            "tty_allocation" => Some("TTY 分配"),
            "userland process name resembles a kernel thread" => Some("用户态进程名伪装成内核线程"),
            "web_command_execution" => Some("Web 命令执行"),
            "web_path_executable" => Some("Web 路径可执行文件"),
            "web_script_context" => Some("Web 脚本上下文"),
            "/dev/tcp is combined with an interactive shell and fd redirection" => {
                Some("/dev/tcp 与交互式 Shell 和文件描述符重定向组合")
            }
            _ => content_marker_label(value),
        },
    }
}

fn intrusion_technical_token_label(
    value: &str,
    language: NotificationLanguage,
) -> Option<&'static str> {
    match language {
        NotificationLanguage::En => match value {
            "authorized_keys is writable by group or other users" => {
                Some("authorized_keys is writable by group or other users")
            }
            "authorized_keys symlink points to a risky target" => {
                Some("authorized_keys symlink points to a risky target")
            }
            "risky_authorized_keys_symlink" => Some("risky authorized_keys symlink"),
            "unsafe_authorized_keys_permissions" => Some("unsafe authorized_keys permissions"),
            _ => None,
        },
        NotificationLanguage::ZhCn => match value {
            "authorized_keys is writable by group or other users" => {
                Some("authorized_keys 可被同组或其他用户写入")
            }
            "authorized_keys symlink points to a risky target" => {
                Some("authorized_keys 软链指向高风险目标")
            }
            "risky_authorized_keys_symlink" => Some("高风险 authorized_keys 软链"),
            "unsafe_authorized_keys_permissions" => Some("authorized_keys 权限过宽"),
            _ => None,
        },
    }
}

fn gpu_technical_token_label(value: &str, language: NotificationLanguage) -> Option<&'static str> {
    match language {
        NotificationLanguage::En => match value {
            "gpu_compute_process" => Some("GPU compute process"),
            "gpu_deleted_executable" => Some("deleted GPU executable"),
            "gpu_anonymous_executable" => Some("anonymous GPU executable"),
            "gpu_temporary_executable" => Some("temporary-path GPU executable"),
            "gpu_runtime_executable_path" => Some("runtime-path GPU executable"),
            "gpu_temporary_executable_path" => Some("temporary-path GPU executable"),
            "gpu_configured_suspicious_executable_path" => {
                Some("configured suspicious-path GPU executable")
            }
            "GPU compute executable is under a runtime state path" => {
                Some("GPU compute executable is under a runtime state path")
            }
            "GPU compute executable is under a common temporary staging directory" => {
                Some("GPU compute executable is under a common temporary staging directory")
            }
            "GPU compute executable is under a configured suspicious directory" => {
                Some("GPU compute executable is under a configured suspicious directory")
            }
            "known_gpu_miner_identity" => Some("known GPU miner identity"),
            "mining_pool_remote_port" => Some("mining-pool remote port"),
            "gpu_network_execution_bridge" => Some("GPU network execution bridge"),
            "gpu_hidden_executable_name" => Some("hidden GPU executable"),
            "gpu_public_outbound_connections" => Some("GPU public outbound connections"),
            "gpu_sustained_high_cpu" => Some("GPU process sustained high CPU"),
            "hidden_gpu_process_with_public_outbound" => {
                Some("hidden GPU process with public outbound activity")
            }
            "gpu mining indicator" => Some("GPU mining indicator"),
            _ => None,
        },
        NotificationLanguage::ZhCn => match value {
            "gpu_compute_process" => Some("GPU 计算进程"),
            "gpu_deleted_executable" => Some("已删除的 GPU 可执行文件"),
            "gpu_anonymous_executable" => Some("匿名 GPU 可执行文件"),
            "gpu_temporary_executable" => Some("临时路径 GPU 可执行文件"),
            "gpu_runtime_executable_path" => Some("运行时路径 GPU 可执行文件"),
            "gpu_temporary_executable_path" => Some("临时路径 GPU 可执行文件"),
            "gpu_configured_suspicious_executable_path" => Some("配置的可疑路径 GPU 可执行文件"),
            "GPU compute executable is under a runtime state path" => {
                Some("GPU 计算进程可执行文件位于运行时状态路径")
            }
            "GPU compute executable is under a common temporary staging directory" => {
                Some("GPU 计算进程可执行文件位于常见临时落地目录")
            }
            "GPU compute executable is under a configured suspicious directory" => {
                Some("GPU 计算进程可执行文件位于配置的可疑目录")
            }
            "known_gpu_miner_identity" => Some("已知 GPU 挖矿器身份"),
            "mining_pool_remote_port" => Some("矿池远端端口"),
            "gpu_network_execution_bridge" => Some("GPU 网络命令执行桥接"),
            "gpu_hidden_executable_name" => Some("隐藏 GPU 可执行文件"),
            "gpu_public_outbound_connections" => Some("GPU 进程公网出站连接"),
            "gpu_sustained_high_cpu" => Some("GPU 进程持续高 CPU"),
            "hidden_gpu_process_with_public_outbound" => Some("隐藏 GPU 进程伴随公网出站连接"),
            "gpu mining indicator" => Some("GPU 挖矿指标"),
            _ => None,
        },
    }
}

fn content_marker_label(value: &str) -> Option<&'static str> {
    match value {
        "assert_call" => Some("assert 调用"),
        "base64_decode" => Some("base64 解码"),
        "cmd_exe" => Some("cmd.exe 调用"),
        "dev_tcp" => Some("/dev/tcp"),
        "eval_call" => Some("eval 调用"),
        "long_base64" => Some("长 base64 字符串"),
        "passthru" => Some("passthru 调用"),
        "shell_exec" => Some("shell_exec 调用"),
        "system_call" => Some("system 调用"),
        _ => None,
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
            "php_config_injection" => Some("PHP config injection payload"),
            "lfi_file_read" => Some("LFI file-read payload"),
            "php_stream_wrapper" => Some("PHP stream-wrapper payload"),
            "java_jndi_injection" => Some("JNDI injection payload"),
            "ssrf_metadata" => Some("cloud metadata SSRF probe"),
            "template_injection" => Some("template-injection payload"),
            "deserialization_probe" => Some("deserialization probe"),
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
            "php_config_injection" => Some("PHP 配置写入 payload"),
            "lfi_file_read" => Some("LFI 文件读取 payload"),
            "php_stream_wrapper" => Some("PHP stream wrapper payload"),
            "java_jndi_injection" => Some("JNDI 注入 payload"),
            "ssrf_metadata" => Some("云元数据 SSRF 探测"),
            "template_injection" => Some("模板注入 payload"),
            "deserialization_probe" => Some("反序列化探测"),
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
