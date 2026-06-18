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
            "argv_json" => "argv JSON",
            "active_response_backend" => "active response backend",
            "active_response_detail" => "active response detail",
            "active_response_expires_at" => "active response expires at",
            "active_response_ip" => "active response IP",
            "active_response_reason" => "active response reason",
            "active_response_status" => "active response status",
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
            "package_activity_recent" => "recent package activity",
            "package_activity_sources" => "package logs",
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
            "public_outbound_count" => "public outbound connections",
            "raw" => "raw record",
            "remote_addr" => "remote address",
            "remote_port" => "remote port",
            "remote_public" => "remote is public",
            "request_count" => "request count",
            "response_profile" => "response profile",
            "risk_features" => "risk features",
            "risk_reasons" => "risk reasons",
            "risk_score" => "risk score",
            "sample_paths" => "sample paths",
            "service_profile" => "service profile",
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
            "argv_json" => "参数 JSON",
            "active_response_backend" => "主动响应后端",
            "active_response_detail" => "主动响应详情",
            "active_response_expires_at" => "封禁到期时间",
            "active_response_ip" => "封禁 IP",
            "active_response_reason" => "封禁原因",
            "active_response_status" => "主动响应状态",
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
            "package_activity_recent" => "近期软件包活动",
            "package_activity_sources" => "软件包日志",
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
            "public_outbound_count" => "公网出站连接数",
            "raw" => "原始记录",
            "remote_addr" => "远端地址",
            "remote_port" => "远端端口",
            "remote_public" => "远端公网",
            "request_count" => "请求次数",
            "response_profile" => "响应画像",
            "risk_features" => "风险特征",
            "risk_reasons" => "风险原因",
            "risk_score" => "风险评分",
            "sample_paths" => "样例路径",
            "service_profile" => "服务画像",
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
    if let Some(label) = dynamic_value_label(value, language) {
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
        ("active_response_status", "blocked", NotificationLanguage::En) => {
            Some("temporary block applied")
        }
        ("active_response_status", "blocked", NotificationLanguage::ZhCn) => Some("已临时封禁"),
        ("active_response_status", "failed", NotificationLanguage::En) => Some("block failed"),
        ("active_response_status", "failed", NotificationLanguage::ZhCn) => Some("封禁失败"),
        ("active_response_status", "skipped_limit", NotificationLanguage::En) => {
            Some("skipped because block limit was reached")
        }
        ("active_response_status", "skipped_limit", NotificationLanguage::ZhCn) => {
            Some("达到单轮封禁上限，已跳过")
        }
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
        (
            "package_activity_recent"
            | "process_start_changed"
            | "remote_public"
            | "exists"
            | "executable"
            | "hidden"
            | "is_web_path"
            | "executable_changed",
            "true",
            NotificationLanguage::ZhCn,
        ) => Some("是"),
        (
            "package_activity_recent"
            | "process_start_changed"
            | "remote_public"
            | "exists"
            | "executable"
            | "hidden"
            | "is_web_path"
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
        "signals" | "risk_features" | "risk_reasons" | "content_markers"
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

fn dynamic_value_label(value: &str, language: NotificationLanguage) -> Option<String> {
    if language != NotificationLanguage::ZhCn {
        return None;
    }
    let lowered = value.to_ascii_lowercase();
    if lowered.starts_with("process identity ") && lowered.contains(" matches configured tool ") {
        return Some("进程身份匹配配置中的高风险工具".to_string());
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
            "dev_tcp" => Some("/dev/tcp"),
            "exec_bridge" => Some("exec bridge"),
            "fd_bridge" | "fd_duplication" => Some("file descriptor bridge"),
            "inline_interpreter" => Some("inline interpreter"),
            "interactive_shell" => Some("interactive shell"),
            "network_channel" => Some("network channel"),
            "network_execution_bridge" => Some("network execution bridge"),
            "shell_target" => Some("shell target"),
            "socket_api" => Some("socket API"),
            "system_bridge" => Some("system command bridge"),
            "tty_allocation" => Some("TTY allocation"),
            "temporary_path" => Some("temporary path"),
            _ => None,
        },
        NotificationLanguage::ZhCn => match value {
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
            "sustained_high_cpu" => Some("持续高 CPU"),
            "system_bridge" => Some("系统命令桥接"),
            "systemd ExecStart does not appear to match the listener executable" => {
                Some("systemd ExecStart 与监听进程可执行文件不一致")
            }
            "systemd_execstart_mismatch" => Some("systemd ExecStart 不一致"),
            "temporary executable path" => Some("临时目录可执行文件"),
            "temporary path" | "temporary_path" => Some("临时路径"),
            "temporary_deleted_executable" => Some("临时目录删除态可执行文件"),
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
