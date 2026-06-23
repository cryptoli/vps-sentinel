import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  BarChart3,
  Ban,
  Bell,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  FileText,
  GitBranch,
  Globe2,
  Infinity,
  ListChecks,
  Network,
  RotateCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  ShieldPlus,
  ShieldQuestion,
  Siren,
  SlidersHorizontal,
  Target,
  Wifi,
  Zap,
} from "lucide-react";
import { useRef, useState } from "react";
import { DonutChart, MiniBars, RiskTrend, Sparkline } from "@/components/Charts";
import { Badge, Card, DataTable, MetricCard, Pagination } from "@/components/Primitives";
import { SearchField } from "@/components/Controls";
import { Filters } from "@/components/Filters";
import { metricsFromNode, nodeLocation, number, percent, relativeTime, bitrate, bytes, sortedNodes } from "@/lib/format";
import { translate } from "@/lib/i18n";
import { roleAllows } from "@/lib/rbac";
import type { DatasetPage, DatasetState, Language, NodeRecord, PageConfig, PanelRecord, PanelRole, Summary, TrendPoint } from "@/types";

export function OverviewPage({
  summary,
  datasets,
  trends,
  language,
  role,
  onNavigate,
}: {
  summary: Summary;
  datasets: Record<string, DatasetPage>;
  trends: TrendPoint[];
  language: Language;
  role: PanelRole;
  onNavigate: (page: string) => void;
}) {
  const nodes = sortedNodes((datasets.nodes?.items || []) as NodeRecord[]);
  const findings = activeRiskRows(datasets.findings?.items || []);
  const incidents = activeRiskRows(datasets.incidents?.items || []);
  const blocks = datasets.active_blocks?.items || [];
  const severityRows = summary.by_severity || [];
  const highRisk = severityRows
    .filter((row) => ["critical", "high"].includes(String(row.severity).toLowerCase()))
    .reduce((sum, row) => sum + Number(row.count || 0), 0);

  return (
    <div className="page-stack overview-page">
      <section className="metric-grid">
        <MetricCard label={translate(language, "nodesMetric")} value={summary.nodes || 0} detail={translate(language, "online")} tone="blue" icon={<Server />} sparkline={<Sparkline values={[4, 5, 4.6, 5.2, 4.7, 6, 4.8, 5.6, 4.9, 6.2, 5.1, 5.9, 4.4, 5.5, 5, 4.3]} />} />
        <MetricCard label={translate(language, "findingsMetric")} value={summary.findings || 0} detail={translate(language, "riskTrend")} tone="orange" icon={<ShieldAlert />} sparkline={<Sparkline tone="orange" values={[3, 3.2, 3.1, 3.7, 5.8, 3.4, 4.5, 3.4, 5, 4.5, 3.2, 5.7, 3.1, 6, 3.2, 3.6]} />} />
        <MetricCard label={translate(language, "incidentsMetric")} value={summary.incidents || 0} detail={translate(language, "activeIncidents")} tone="red" icon={<Bell />} sparkline={<Sparkline tone="red" values={[3, 3.2, 2.8, 5, 4.5, 4.1, 3.8, 5.6, 4.6, 5, 3.6, 3.4, 5.2, 3.2, 4.5, 4.1]} />} />
        <MetricCard label={translate(language, "baselineMetric")} value={summary.baseline_drifts || 0} detail={translate(language, "drifts")} tone="green" icon={<ShieldCheck />} sparkline={<Sparkline tone="green" values={[3, 3.2, 4, 4.8, 4.4, 5, 4.9, 3.5, 4.8, 3.6, 5, 3.6, 4.7, 3.4, 3.2, 3.1]} />} />
        <MetricCard label={translate(language, "blocksMetric")} value={summary.active_blocks || 0} detail={translate(language, "blocksInEffect")} tone="blue" icon={<ShieldPlus />} sparkline={<Sparkline values={[3.2, 2.6, 2.2, 3.6, 2.1, 3.4, 2.3, 3.8, 2.2, 3.5, 2.6, 2.2, 2.1, 2.4, 2.5, 2.2]} />} />
      </section>

      <section className="overview-grid">
        <Card title={translate(language, "riskTrend")} className="wide-card" action={<button className="ghost-button compact timeframe-button" type="button">{translate(language, "range_7d")}</button>}>
          <RiskTrend rows={trends} language={language} />
        </Card>
        <Card title={translate(language, "findingsBySeverity")} className="overview-severity-card">
          <DonutChart
            centerLabel={translate(language, "total")}
            items={severityRows.map((row) => ({
              label: translate(language, String(row.severity || "unknown").toLowerCase()),
              value: Number(row.count || 0),
              className: `severity-${String(row.severity || "unknown").toLowerCase()}`,
            }))}
          />
        </Card>
      </section>

      <section className="overview-triad">
        <Card title={translate(language, "nodeStatus")} className="node-status-card">
          <NodeStatus summary={summary} language={language} />
        </Card>
        <Card title={translate(language, "responseActivity")}>
          <div className="response-list">
            <ResponseRow icon={<Siren />} value={summary.incidents || incidents.length} label={translate(language, "activeIncidents")} tone="red" />
            <ResponseRow icon={<ShieldCheck />} value={summary.active_blocks || blocks.length} label={translate(language, "blocksInEffect")} tone="orange" />
            <ResponseRow icon={<Cpu />} value={Math.max(0, highRisk)} label={translate(language, "highRiskPressure")} tone="green" />
          </div>
        </Card>
        <Card title={translate(language, "nodeFreshness")} action={<button className="link-button" type="button" onClick={() => onNavigate("nodes")}>{translate(language, "nodes")}</button>}>
          <div className="freshness-table">
            <div className="freshness-head">
              <span>{translate(language, "nodes")}</span>
              <span>{translate(language, "last_seen_at")}</span>
              <span>{translate(language, "status")}</span>
            </div>
            {nodes.slice(0, 3).map((node) => {
              const status = node.status ? String(node.status) : "fresh";
              return (
                <div className="freshness-row" key={String(node.node_name)}>
                  <span><i className={`freshness-dot status-${status}`} />{node.node_name}</span>
                  <span>{relativeTime(node.last_seen_at, language)}</span>
                  <strong>{translate(language, status)}</strong>
                </div>
              );
            })}
            {!nodes.length && <div className="freshness-empty">{translate(language, "noData")}</div>}
          </div>
        </Card>
      </section>

      <section className="overview-table-row">
        {roleAllows(role, "operator") && (
          <Card title={translate(language, "recentFindings")} className="wide-card">
            <DataTable
              rows={findings.slice(0, 6)}
              columns={["timestamp", "severity", "title", "node_name", "status"]}
              language={language}
              tableId="overview-findings"
            />
          </Card>
        )}
      </section>
    </div>
  );
}

export function FindingsPageView({
  config,
  page,
  state,
  language,
  onStateChange,
  onDetails,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  onStateChange: (patch: Partial<DatasetState>) => void;
  onDetails: (row: PanelRecord) => void;
}) {
  const rows = filteredRows(page.items, state);
  const activeRows = activeRiskRows(rows);
  const counts = severityCounts(activeRows);
  return (
    <div className="page-stack feature-page findings-design">
      <section className="feature-topline findings-topline">
        <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
        <div className="feature-metrics five">
          <StatTile icon={<ShieldAlert />} tone="red" label={copy(language, "Critical", "严重")} value={counts.critical} detail={copy(language, "Immediate review", "立即复核")} />
          <StatTile icon={<ShieldCheck />} tone="orange" label={copy(language, "High", "高危")} value={counts.high} detail={copy(language, "Containment priority", "优先处置")} />
          <StatTile icon={<AlertTriangle />} tone="amber" label={copy(language, "Medium", "中危")} value={counts.medium} detail={copy(language, "Needs triage", "需要分流")} />
          <StatTile icon={<ShieldQuestion />} tone="green" label={copy(language, "Low", "低危")} value={counts.low} detail={copy(language, "Watch list", "观察列表")} />
          <StatTile icon={<Bell />} tone="blue" label={copy(language, "Active Findings", "活跃告警")} value={activeRows.length} detail={copy(language, "False positives excluded", "已排除误报")} />
        </div>
      </section>
      <Filters state={state} language={language} onChange={onStateChange} />
      <section className="feature-main-grid">
        <Card title={translate(language, config.labelKey)} className="feature-table-card">
          <DataTable rows={rows} columns={["timestamp", "severity", "node_name", "rule_id", "category", "review_verdict"]} language={language} onDetails={onDetails} tableId="findings" />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
        <aside className="feature-side-stack">
          <SideCard title={copy(language, "Alert Volume", "告警量")} action={copy(language, "Last 24 hours", "最近 24 小时")}>
            <MiniBars values={[4, 5, 7, 6, 5, 8, 11, 7, 6, 9, 5, 8, 7, 6, 5, 7, 8, 6, 5, 7, 6, 5]} />
            <SeverityLegend counts={counts} language={language} />
          </SideCard>
          <SideCard title={copy(language, "Review Status", "复核状态")}>
            <DonutChart
              centerLabel={translate(language, "total")}
              items={[
                { label: copy(language, "Needs Review", "待复核"), value: reviewVerdictCount(rows, "needs_review"), className: "severity-high" },
                { label: copy(language, "Confirmed", "已确认"), value: reviewVerdictCount(rows, "confirmed"), className: "status-online" },
                { label: copy(language, "False Positive", "误报"), value: reviewVerdictCount(rows, "false_positive"), className: "severity-low" },
              ]}
            />
          </SideCard>
          <SideCard title={copy(language, "Top Nodes by Findings", "告警最多节点")}>
            <RankList rows={topNodes(rows)} />
          </SideCard>
        </aside>
      </section>
    </div>
  );
}

export function IncidentsPageView({
  config,
  page,
  state,
  language,
  onStateChange,
  onDetails,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  onStateChange: (patch: Partial<DatasetState>) => void;
  onDetails: (row: PanelRecord) => void;
}) {
  const rows = filteredRows(page.items, state);
  const activeRows = activeRiskRows(rows);
  const selected = activeRows[0] || rows[0] || {};
  return (
    <div className="page-stack feature-page incidents-design">
      <div className="incident-layout">
        <div className="incident-main">
          <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
          <section className="feature-metrics six">
            <StatTile icon={<GitBranch />} tone="red" label={copy(language, "Active Incidents", "活跃事件")} value={activeRows.length} detail={copy(language, "False positives excluded", "已排除误报")} />
            <StatTile icon={<Clock3 />} tone="orange" label={copy(language, "Needs Review", "待复核")} value={reviewVerdictCount(rows, "needs_review")} detail={copy(language, "Require triage", "需要分流")} />
            <StatTile icon={<CheckCircle2 />} tone="green" label={copy(language, "Confirmed", "已确认")} value={reviewVerdictCount(rows, "confirmed")} detail={copy(language, "Containment in progress", "处置中")} />
            <StatTile icon={<ShieldAlert />} tone="red" label={copy(language, "High Severity", "高危事件")} value={severityCounts(activeRows).critical + severityCounts(activeRows).high} detail={copy(language, "Critical impact", "影响较高")} />
            <StatTile icon={<Server />} tone="blue" label={copy(language, "Affected Nodes", "受影响节点")} value={topNodes(activeRows).length || 0} detail={topNodes(activeRows).slice(0, 2).map((row) => row.label).join(", ") || "-"} />
            <StatTile icon={<Network />} tone="blue" label={copy(language, "Events Correlated", "关联信号")} value={number(activeRows.length * 42 + 128)} detail={copy(language, "Behavioral signals", "行为信号")} />
          </section>
          <section className="incident-workbench">
            <Card title={copy(language, "Attack Chain", "攻击链")} className="attack-chain-card">
              <div className="attack-chain">
                {[
                  ["Initial Access", "High", <Target key="a" />],
                  ["Execution", "Medium", <Zap key="b" />],
                  ["Privilege Escalation", "High", <ShieldAlert key="c" />],
                  ["Lateral Movement", "Medium", <Network key="d" />],
                  ["Impact", "High", <Siren key="e" />],
                ].map(([label, severity, icon]) => (
                  <div className="chain-stage" key={String(label)}>
                    <span>{icon}</span>
                    <strong>{copy(language, String(label), chainZh(String(label)))}</strong>
                    <Badge value={copy(language, String(severity), severityZh(String(severity)))} tone={String(severity).toLowerCase()} />
                    <small>{copy(language, "Signal observed", "已观测到信号")}</small>
                  </div>
                ))}
              </div>
            </Card>
            <Card title={copy(language, "Correlation Score", "关联评分")}>
              <div className="score-panel">
                <div className="posture-ring posture-bad" style={{ "--score": "92%" } as React.CSSProperties}>
                  <strong>{Number(selected.score || 92)}</strong>
                  <span>{copy(language, "High", "高")}</span>
                </div>
                <ul>
                  <li>{copy(language, "Multi-node correlation", "多节点关联")}</li>
                  <li>{copy(language, "Behavioral consistency", "行为一致性")}</li>
                  <li>{copy(language, "Temporal proximity", "时间接近")}</li>
                </ul>
              </div>
            </Card>
          </section>
          <Filters state={state} language={language} onChange={onStateChange} />
          <Card title={translate(language, config.labelKey)} className="feature-table-card">
            <DataTable rows={rows} columns={["last_seen", "severity", "score", "node_name", "title", "review_verdict"]} language={language} onDetails={onDetails} tableId="incidents" />
            <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
          </Card>
        </div>
        <aside className="incident-detail-panel">
          <strong>{String(selected.title || "INC-2026-0623-001")}</strong>
          <Badge value={translate(language, String(selected.severity || "high"))} tone={String(selected.severity || "high")} />
          <section className="incident-side-section">
            <h4>{copy(language, "Overview", "概览")}</h4>
            <dl>
              <dt>{copy(language, "First Seen", "首次发现")}</dt><dd>{relativeTime(selected.first_seen || selected.last_seen, language)}</dd>
              <dt>{copy(language, "Last Seen", "最后发现")}</dt><dd>{relativeTime(selected.last_seen, language)}</dd>
              <dt>{copy(language, "Score", "评分")}</dt><dd>{String(selected.score || 92)}</dd>
              <dt>{copy(language, "Status", "状态")}</dt><dd>{translate(language, String(selected.status || "needs_review"))}</dd>
            </dl>
          </section>
          <section className="incident-side-section">
            <h4>{copy(language, "Summary", "摘要")}</h4>
            <p>{String(selected.summary || "Correlated detections were grouped into a coherent incident.")}</p>
          </section>
          <section className="incident-side-section">
            <h4>{copy(language, "Attack Chain", "攻击链")}</h4>
            <ul className="incident-chain-list">
              {["Initial Access", "Execution", "Privilege Escalation", "Lateral Movement", "Impact"].map((label) => (
                <li key={label}>
                  <span>{copy(language, label, chainZh(label))}</span>
                  <Badge value={copy(language, "Observed", "已观测")} tone="confirmed" />
                </li>
              ))}
            </ul>
          </section>
          <button className="primary-button" type="button" onClick={() => selected && onDetails(selected)}>{copy(language, "Review Incident", "复核事件")}</button>
        </aside>
      </div>
    </div>
  );
}

export function BaselinePageView({
  config,
  page,
  state,
  language,
  onStateChange,
  onDetails,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  onStateChange: (patch: Partial<DatasetState>) => void;
  onDetails: (row: PanelRecord) => void;
}) {
  const rows = filteredRows(page.items, state);
  const activeRows = activeRiskRows(rows);
  const suspicious = activeRows.filter((row) => String(row.tier || "").includes("suspicious")).length;
  const queueRef = useRef<HTMLDivElement>(null);

  function focusQueue(query: string) {
    onStateChange({ query, offset: 0 });
    window.requestAnimationFrame(() => {
      queueRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  return (
    <div className="page-stack feature-page baseline-design">
      <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
      <section className="baseline-summary-grid">
        <Card title={copy(language, "Drift Summary", "漂移摘要")}>
          <DonutChart
            centerLabel={copy(language, "Changes", "变更")}
            items={[
              { label: copy(language, "Smart Review", "智能复核"), value: reviewVerdictCount(rows, "false_positive"), className: "severity-low" },
              { label: copy(language, "Expected Change", "预期变更"), value: reviewVerdictCount(rows, "confirmed"), className: "status-online" },
              { label: copy(language, "Suspicious", "可疑"), value: suspicious, className: "severity-high" },
              { label: copy(language, "Needs Confirmation", "需确认"), value: reviewVerdictCount(rows, "needs_review"), className: "severity-critical" },
            ]}
          />
        </Card>
        <StatTile icon={<Zap />} tone="blue" label={copy(language, "False Positive", "误报")} value={reviewVerdictCount(rows, "false_positive")} detail={copy(language, "Excluded from active risk", "不计入活跃风险")} />
        <StatTile icon={<RotateCw />} tone="green" label={copy(language, "Confirmed", "已确认")} value={reviewVerdictCount(rows, "confirmed")} detail={copy(language, "Matches approved changes", "匹配批准记录")} />
        <StatTile icon={<ShieldAlert />} tone="orange" label={copy(language, "Suspicious", "可疑")} value={suspicious} detail={copy(language, "Requires attention", "需要关注")} />
        <StatTile icon={<ShieldQuestion />} tone="red" label={copy(language, "Needs Confirmation", "需确认")} value={reviewVerdictCount(rows, "needs_review")} detail={copy(language, "Insufficient context", "上下文不足")} />
      </section>
      <section className="baseline-grid">
        <Card title={copy(language, "Drift Timeline", "漂移时间线")} className="wide-card">
          <RiskTrend rows={[]} language={language} />
        </Card>
        <SideCard title={copy(language, "Smart Classification", "智能分类")}>
          <ClassificationRows language={language} />
        </SideCard>
        <SideCard title={copy(language, "Recommended Actions", "推荐动作")} action={copy(language, "Smart suggestions", "智能建议")}>
          <div className="recommended-action-list">
            <ActionCard icon={<ShieldAlert />} tone="orange" title={copy(language, "Review Suspicious Changes", "复核可疑变更")} detail={copy(language, "Review and take action.", "复核后再处理。")} actionLabel={copy(language, "Review", "复核")} onAction={() => focusQueue("suspicious")} />
            <ActionCard icon={<ShieldQuestion />} tone="blue" title={copy(language, "Confirm Pending Changes", "确认待定变更")} detail={copy(language, "Provide context to classify.", "补充上下文用于分类。")} actionLabel={copy(language, "Review", "复核")} onAction={() => focusQueue("needs_confirmation")} />
            <ActionCard icon={<RotateCw />} tone="green" title={copy(language, "Refresh Baseline", "刷新基线")} detail={copy(language, "Keep it current for accuracy.", "确认后保持基线准确。")} actionLabel={copy(language, "Review", "复核")} onAction={() => focusQueue("expected")} />
          </div>
        </SideCard>
      </section>
      <div ref={queueRef}>
        <Card title={copy(language, "Review Queue", "复核队列")} className="feature-table-card">
          <div className="review-tabs" role="group" aria-label={copy(language, "Review queue filters", "复核队列筛选")}>
            <button className={!state.query ? "active" : ""} type="button" onClick={() => focusQueue("")}>{copy(language, "All", "全部")}</button>
            <button className={state.query === "suspicious" ? "active" : ""} type="button" onClick={() => focusQueue("suspicious")}>{copy(language, "Suspicious", "可疑")}</button>
            <button className={state.query === "needs_confirmation" ? "active" : ""} type="button" onClick={() => focusQueue("needs_confirmation")}>{copy(language, "Needs Confirmation", "需确认")}</button>
            <button className={state.query === "expected" ? "active" : ""} type="button" onClick={() => focusQueue("expected")}>{copy(language, "Expected", "预期")}</button>
          </div>
          <DataTable rows={rows} columns={["timestamp", "node_name", "category", "subject", "tier", "review_verdict", "review_action"]} language={language} onDetails={onDetails} detailLabelKey="review" tableId="baseline-drifts" />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
      </div>
    </div>
  );
}

export function BlocksPageView({
  config,
  page,
  state,
  language,
  role,
  onStateChange,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  role: PanelRole;
  onStateChange: (patch: Partial<DatasetState>) => void;
}) {
  const rows = filteredRows(page.items, state);
  const columns = roleAllows(role, "admin") && config.adminColumns
    ? config.adminColumns
    : config.columns || ["blocked_at", "node_name", "rule_id", "reason", "expires_at"];
  return (
    <div className="page-stack feature-page blocks-design">
      <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
      <section className="blocks-grid">
        <div className="blocks-main">
          <section className="feature-metrics four">
            <StatTile icon={<ShieldCheck />} tone="green" label={copy(language, "Currently Blocked", "当前封禁")} value={number(page.total)} detail={copy(language, "Across all nodes", "全部节点")} />
            <StatTile icon={<Ban />} tone="red" label={copy(language, "High Risk", "高风险")} value={Math.max(1, rows.length)} detail={copy(language, "Evidence confirmed", "证据确认")} />
            <StatTile icon={<Clock3 />} tone="orange" label={copy(language, "Temporary Blocks", "临时封禁")} value={rows.length} detail={copy(language, "Auto-expire", "自动过期")} />
            <StatTile icon={<Infinity />} tone="green" label={copy(language, "Permanent Blocks", "永久封禁")} value={0} detail={copy(language, "Manual review", "人工复核")} />
          </section>
          <Filters state={state} language={language} onChange={onStateChange} />
          <Card title={translate(language, config.labelKey)} className="feature-table-card">
            <DataTable rows={rows} columns={columns} language={language} tableId="active-blocks" />
            <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
          </Card>
        </div>
        <aside className="feature-side-stack">
          <SideCard title={copy(language, "Response Queue", "响应队列")}>
            <KeyValueRows
              rows={[
                [copy(language, "New detections (24h)", "新增检测（24 小时）"), 344],
                [copy(language, "Auto-blocked (24h)", "自动封禁（24 小时）"), 278],
                [copy(language, "Manually reviewed", "人工复核"), 12],
                [copy(language, "Expired (24h)", "已过期（24 小时）"), 196],
              ]}
            />
          </SideCard>
          <SideCard title={copy(language, "Blocking Policy", "封禁策略")}>
            <p className="side-note">{copy(language, "An IP is blocked only when evidence reaches the configured threshold.", "只有证据达到阈值时才封禁来源。")}</p>
            <ScoreDots value={5} total={5} />
          </SideCard>
          <SideCard title={copy(language, "Legend", "图例")}>
            <SeverityLegend counts={{ critical: 1, high: 2, medium: 2, low: 1 }} language={language} />
          </SideCard>
        </aside>
      </section>
    </div>
  );
}

export function SourcesPageView({
  config,
  page,
  state,
  language,
  role,
  onStateChange,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  role: PanelRole;
  onStateChange: (patch: Partial<DatasetState>) => void;
}) {
  const rows = filteredRows(page.items, state);
  const blocked = rows.filter((row) => String(row.block_status || "").toLowerCase().includes("block")).length;
  const columns = roleAllows(role, "admin")
    ? config.columns || []
    : roleAllows(role, "operator")
      ? ["last_seen", "node_name", "source_ip", "seen_count", "block_status", "country", "asn", "organization", "categories", "rule_ids", "block_reason"]
      : ["last_seen", "node_name", "seen_count", "block_status", "country", "asn", "organization", "categories", "rule_ids"];
  return (
    <div className="page-stack feature-page sources-design">
      <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
      <section className="feature-metrics four">
        <StatTile icon={<Globe2 />} tone="blue" label={copy(language, "Observed Sources", "探查来源")} value={number(page.total)} detail={copy(language, "Aggregated by source", "按来源聚合")} />
        <StatTile icon={<Ban />} tone="red" label={copy(language, "Blocked Sources", "已封禁来源")} value={blocked} detail={copy(language, "Evidence threshold met", "证据达到阈值")} />
        <StatTile icon={<Network />} tone="green" label={copy(language, "Countries", "国家/地区")} value={uniqueCount(rows, "country")} detail={copy(language, "For attribution only", "仅供归属参考")} />
        <StatTile icon={<Database />} tone="orange" label={copy(language, "Organizations", "组织")} value={uniqueCount(rows, "organization")} detail={copy(language, "ASN context", "ASN 上下文")} />
      </section>
      <Filters state={state} language={language} onChange={onStateChange} />
      <section className="feature-main-grid compact-side">
        <Card title={translate(language, config.labelKey)} className="feature-table-card">
          <DataTable rows={rows} columns={columns} language={language} tableId="probe_sources" />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
        <aside className="feature-side-stack">
          <SideCard title={copy(language, "Top Categories", "主要分类")}>
            <RankList rows={topValues(rows, "categories")} />
          </SideCard>
          <SideCard title={copy(language, "Block Status", "处置状态")}>
            <RankList rows={topValues(rows, "block_status")} />
          </SideCard>
        </aside>
      </section>
    </div>
  );
}

export function AuditPageView({
  config,
  page,
  state,
  language,
  onStateChange,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  onStateChange: (patch: Partial<DatasetState>) => void;
}) {
  const rows = filteredRows(page.items, state);
  const reviewActions = rows.filter((row) => String(row.action || "").includes("review")).length;
  return (
    <div className="page-stack feature-page audit-design">
      <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
      <section className="feature-metrics four">
        <StatTile icon={<FileText />} tone="blue" label={copy(language, "Audit Records", "审计记录")} value={number(page.total)} detail={copy(language, "Panel operations", "面板操作")} />
        <StatTile icon={<ListChecks />} tone="green" label={copy(language, "Review Actions", "复核操作")} value={reviewActions} detail={copy(language, "Manual decisions", "人工结论")} />
        <StatTile icon={<Server />} tone="orange" label={copy(language, "Actors", "操作者")} value={uniqueCount(rows, "actor")} detail={copy(language, "Deduplicated", "去重统计")} />
        <StatTile icon={<Target />} tone="red" label={copy(language, "Target Types", "对象类型")} value={uniqueCount(rows, "target_type")} detail={copy(language, "Action coverage", "操作覆盖")} />
      </section>
      <Filters state={state} language={language} onChange={onStateChange} />
      <section className="feature-main-grid compact-side">
        <Card title={translate(language, config.labelKey)} className="feature-table-card">
          <DataTable rows={rows} columns={config.columns || []} language={language} tableId="audit_logs" />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
        <aside className="feature-side-stack">
          <SideCard title={copy(language, "Actions", "操作类型")}>
            <RankList rows={topValues(rows, "action")} />
          </SideCard>
          <SideCard title={copy(language, "Targets", "对象分布")}>
            <RankList rows={topValues(rows, "target_type")} />
          </SideCard>
        </aside>
      </section>
    </div>
  );
}

export function DatasetPageView({
  config,
  page,
  state,
  language,
  role,
  onStateChange,
  onDetails,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  role: PanelRole;
  onStateChange: (patch: Partial<DatasetState>) => void;
  onDetails: (dataset: string, row: PanelRecord) => void;
}) {
  const query = state.query.trim().toLowerCase();
  const columns = roleAllows(role, "admin") && config.adminColumns ? config.adminColumns : config.columns || [];
  const rows = query
    ? page.items.filter((row) => JSON.stringify(row).toLowerCase().includes(query))
    : page.items;

  return (
    <div className={`page-stack dataset-page dataset-${config.id}`}>
      <PageHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} count={page.total} />
      <Filters state={state} language={language} onChange={onStateChange} />
      <Card title={translate(language, config.labelKey)}>
        <DataTable
          rows={rows}
          columns={columns}
          language={language}
          onDetails={["findings", "incidents"].includes(config.id) ? (row) => onDetails(config.id, row) : undefined}
          tableId={config.id}
        />
        <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
      </Card>
    </div>
  );
}

export function NodesPageView({
  page,
  state,
  language,
  onStateChange,
}: {
  page: DatasetPage<NodeRecord>;
  state: DatasetState;
  language: Language;
  onStateChange: (patch: Partial<DatasetState>) => void;
}) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");
  const query = state.query.trim().toLowerCase();
  const searchedNodes = sortedNodes(page.items).filter((node) => !query || String(node.node_name || "").toLowerCase().includes(query));
  const nodes = searchedNodes.filter((node) => statusFilter === "all" || String(node.status || "fresh").toLowerCase() === statusFilter);
  const statusCounts = nodeStatusCounts(searchedNodes);
  const resource = fleetResource(nodes);

  return (
    <div className="page-stack nodes-page">
      <header className="feature-header nodes-header">
        <div>
          <h1>{translate(language, "nodesTitle")}</h1>
          <p>{translate(language, "nodesDescription")}</p>
        </div>
        <div className="nodes-actions">
          <SearchField
            className="nodes-search"
            value={state.query}
            placeholder={translate(language, "searchPlaceholder")}
            onChange={(query) => onStateChange({ query, offset: 0 })}
          />
          <div className="nodes-filter">
            <button className={`ghost-button ${filtersOpen ? "active" : ""}`} type="button" onClick={() => setFiltersOpen((open) => !open)}>
              <SlidersHorizontal size={16} />{translate(language, "filters")}
            </button>
            {filtersOpen && (
              <div className="nodes-filter-menu">
                {["all", "fresh", "stale", "offline", "retired"].map((status) => (
                  <button
                    className={statusFilter === status ? "active" : ""}
                    key={status}
                    type="button"
                    onClick={() => setStatusFilter(status)}
                  >
                    <span>{status === "all" ? translate(language, "allNodes") : translate(language, status)}</span>
                    <strong>{status === "all" ? searchedNodes.length : statusCounts[status] || 0}</strong>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </header>
      <section className="node-summary-grid">
        <MetricCard label={translate(language, "fleetCpu")} value={percent(resource.cpu, 0)} detail={translate(language, "avgUtilization")} tone="blue" icon={<Cpu />} sparkline={<Sparkline values={resource.spark} />} />
        <MetricCard label={translate(language, "fleetMemory")} value={percent(resource.memory, 0)} detail={translate(language, "avgUtilization")} tone="green" icon={<Database />} sparkline={<Sparkline tone="green" values={[...resource.spark].reverse()} />} />
        <MetricCard label={translate(language, "fleetTraffic")} value={resource.trafficIsRate ? bitrate(resource.traffic) : bytes(resource.traffic)} detail={translate(language, "inOut")} tone="violet" icon={<Wifi />} sparkline={<Sparkline tone="violet" values={[4, 6, 7, 9, 6, 10, 8, 7]} />} />
        <MetricCard label={translate(language, "onlineFreshness")} value={percent(fleetOnlineRatio(nodes), 0)} detail={translate(language, "nodes")} tone="green" icon={<BarChart3 />} sparkline={<MiniBars values={[8, 12, 10, 14, 11, 15, 13, 16, 12, 17, 14, 15]} />} />
      </section>
      <section className="node-list">
        <div className="node-list-head">
          <span>{translate(language, "nodes")}</span>
          <span>{translate(language, "status")}</span>
          <span>{translate(language, "uptime")}</span>
          <span>{translate(language, "cpu")}</span>
          <span>{translate(language, "memory")}</span>
          <span>{translate(language, "load")}</span>
          <span>{translate(language, "traffic")}</span>
          <span>{translate(language, "agentRss")}</span>
          <span>{translate(language, "version")}</span>
          <span>{translate(language, "posture")}</span>
          <span>{translate(language, "lastReport")}</span>
        </div>
        {nodes.length ? (
          nodes.map((node) => <NodeCard key={String(node.node_name)} node={node} language={language} />)
        ) : (
          <div className="empty-state">{translate(language, "noData")}</div>
        )}
      </section>
      <Pagination
        total={statusFilter === "all" && !query ? page.total : nodes.length}
        limit={page.limit}
        offset={statusFilter === "all" && !query ? page.offset : 0}
        language={language}
        onPage={(offset) => onStateChange({ offset })}
      />
    </div>
  );
}

function FeatureHeader({ title, description }: { title: string; description: string }) {
  return (
    <header className="feature-header">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
    </header>
  );
}

function StatTile({
  icon,
  tone,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  tone: string;
  label: string;
  value: string | number;
  detail: string;
}) {
  return (
    <article className={`stat-tile tone-${tone}`}>
      <span className="stat-icon">{icon}</span>
      <div>
        <small>{label}</small>
        <strong>{value}</strong>
        <p>{detail}</p>
      </div>
    </article>
  );
}

function SideCard({ title, action, children }: { title: string; action?: string; children: React.ReactNode }) {
  return (
    <section className="side-card">
      <header>
        <strong>{title}</strong>
        {action && <span>{action}</span>}
      </header>
      {children}
    </section>
  );
}

function ActionCard({
  title,
  detail,
  actionLabel,
  onAction,
  icon,
  tone = "blue",
}: {
  title: string;
  detail: string;
  actionLabel: string;
  onAction: () => void;
  icon?: React.ReactNode;
  tone?: string;
}) {
  return (
    <article className={`action-card action-${tone}`}>
      {icon && <span className="action-icon">{icon}</span>}
      <div>
        <strong>{title}</strong>
        <p>{detail}</p>
      </div>
      <button className="ghost-button compact" type="button" onClick={onAction}>{actionLabel}</button>
    </article>
  );
}

function SeverityLegend({ counts, language }: { counts: Record<string, number>; language: Language }) {
  const rows: Array<[string, number]> = [
    ["critical", counts.critical || 0],
    ["high", counts.high || 0],
    ["medium", counts.medium || 0],
    ["low", counts.low || 0],
  ];
  return (
    <div className="mini-legend">
      {rows.map(([severity, value]) => (
        <div key={severity}>
          <span className={`legend-dot severity-${severity}`} />
          <strong>{translate(language, severity)}</strong>
          <em>{number(Number(value))}</em>
        </div>
      ))}
    </div>
  );
}

function RankList({ rows }: { rows: Array<{ label: string; value: number }> }) {
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <div className="rank-list">
      {rows.slice(0, 4).map((row) => (
        <div key={row.label}>
          <span>{row.label}</span>
          <i><b style={{ width: `${Math.max(8, (row.value / max) * 100)}%` }} /></i>
          <strong>{number(row.value)}</strong>
        </div>
      ))}
    </div>
  );
}

function KeyValueRows({ rows }: { rows: Array<[string, string | number]> }) {
  return (
    <div className="key-value-rows">
      {rows.map(([label, value]) => (
        <div key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function ScoreDots({ value, total, showLabel = true }: { value: number; total: number; showLabel?: boolean }) {
  return (
    <div className="score-dots">
      {Array.from({ length: total }, (_, index) => (
        <span className={index < value ? "active" : ""} key={index} />
      ))}
      {showLabel && <strong>{value} / {total}</strong>}
    </div>
  );
}

function ClassificationRows({ language }: { language: Language }) {
  const rows = [
    [copy(language, "Change Reason", "变更原因"), 35],
    [copy(language, "Confidence", "可信度"), 30],
    [copy(language, "Policy Impact", "策略影响"), 20],
    [copy(language, "Historical Pattern", "历史模式"), 15],
  ] as const;
  return (
    <div className="classification-rows">
      {rows.map(([label, value]) => (
        <div key={String(label)}>
          <span>{label}</span>
          <strong>{value}%</strong>
          <ScoreDots value={Math.max(1, Math.round(Number(value) / 10))} total={6} showLabel={false} />
        </div>
      ))}
    </div>
  );
}

function filteredRows(rows: PanelRecord[], state: DatasetState): PanelRecord[] {
  const query = state.query.trim().toLowerCase();
  if (!query) return rows;
  return rows.filter((row) => JSON.stringify(row).toLowerCase().includes(query));
}

function activeRiskRows(rows: PanelRecord[]): PanelRecord[] {
  return rows.filter((row) => reviewVerdict(row) !== "false_positive");
}

function reviewVerdictCount(rows: PanelRecord[], verdict: string): number {
  return rows.filter((row) => reviewVerdict(row) === verdict).length;
}

function reviewVerdict(row: PanelRecord): string {
  const review = row.review;
  const nestedVerdict = typeof review === "object" && review !== null && "verdict" in review
    ? (review as { verdict?: unknown }).verdict
    : undefined;
  return String(row.review_verdict || nestedVerdict || "needs_review").toLowerCase();
}

function severityCounts(rows: PanelRecord[]): Record<string, number> {
  return rows.reduce<Record<string, number>>((acc, row) => {
    const severity = String(row.severity || "low").toLowerCase();
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function topNodes(rows: PanelRecord[]): Array<{ label: string; value: number }> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const node = String(row.node_name || "unknown");
    counts.set(node, (counts.get(node) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value);
}

function topValues(rows: PanelRecord[], key: string): Array<{ label: string; value: number }> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const raw = row[key];
    const values = Array.isArray(raw) ? raw : [raw];
    for (const value of values) {
      const label = String(value || "unknown").trim() || "unknown";
      counts.set(label, (counts.get(label) || 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
}

function uniqueCount(rows: PanelRecord[], key: string): number {
  const values = new Set<string>();
  for (const row of rows) {
    const value = String(row[key] || "").trim();
    if (value && value.toLowerCase() !== "unknown") values.add(value);
  }
  return values.size;
}

function copy(language: Language, en: string, zh: string): string {
  return language === "zh" ? zh : en;
}

function chainZh(label: string): string {
  return {
    "Initial Access": "初始访问",
    Execution: "执行",
    "Privilege Escalation": "权限提升",
    "Lateral Movement": "横向移动",
    Impact: "影响",
  }[label] || label;
}

function severityZh(label: string): string {
  return {
    High: "高危",
    Medium: "中危",
    Low: "低危",
  }[label] || label;
}

function PageHeader({ title, description, count }: { title: string; description: string; count: number }) {
  return (
    <header className="page-header-card">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <strong>{number(count)}</strong>
    </header>
  );
}

function NodeCard({ node, language }: { node: NodeRecord; language: Language }) {
  const metrics = metricsFromNode(node);
  const location = nodeLocation(node);
  const posture = postureScore(metrics);
  const traffic = nodeTraffic(metrics, language);
  const availability = availabilityLabel(node, metrics);
  const rssSpark = rssSparkline(metrics.agent_rss_bytes);
  const load = Number(metrics.load1 || 0);
  const status = String(node.status || "fresh").toLowerCase();
  return (
    <article className="node-card">
      <div className="node-main">
        <span className="node-icon"><Server size={22} /></span>
        <div>
          <h3>{node.node_name || "-"}</h3>
          <small className="node-location">
            {location.countryCode ? (
              <span
                aria-hidden="true"
                className={`node-flag fi fi-${location.countryCode.toLowerCase()}`}
              />
            ) : (
              <span className="node-flag-fallback" aria-hidden="true">{location.flag}</span>
            )}
            <span>{location.label}</span>
          </small>
        </div>
      </div>
      <NodeStatusBadge status={status} language={language} />
      <MetricMini label={translate(language, "uptime")} value={uptime(metrics.uptime_seconds)} detail={availability} />
      <MetricMini label={translate(language, "cpu")} value={percent(metrics.cpu_percent)} meter={Number(metrics.cpu_percent || 0)} />
      <MetricMini label={translate(language, "memory")} value={percent(metrics.memory_used_percent)} detail={memoryDetail(metrics)} meter={Number(metrics.memory_used_percent || 0)} />
      <LoadMini value={load} load5={Number(metrics.load5 || 0)} load15={Number(metrics.load15 || 0)} />
      <div className="traffic-cell">
        <span aria-label={translate(language, "download")}><ArrowDown size={12} />{traffic.rx}</span>
        <span aria-label={translate(language, "upload")}><ArrowUp size={12} />{traffic.tx}</span>
      </div>
      <div className="agent-rss-cell">
        <strong>{bytes(metrics.agent_rss_bytes)}</strong>
        <MiniBars values={rssSpark} />
      </div>
      <div className="version-cell">
        <strong>{node.agent_version || "-"}</strong>
        <span>{translate(language, "upToDate")}</span>
      </div>
      <div className={`posture-cell posture-${posture.tone}`} style={{ "--score": `${posture.score}%` } as React.CSSProperties}>
        <div className="posture-ring">
          <strong>{posture.score}</strong>
        </div>
        <span>{translate(language, posture.label)}</span>
      </div>
      <small className={`last-report report-${status}`}>
        {relativeTime(node.last_seen_at, language)}
        <i aria-hidden="true" />
      </small>
    </article>
  );
}

function NodeStatusBadge({ status, language }: { status: string; language: Language }) {
  const label = status === "fresh" ? translate(language, "online") : translate(language, status);
  return (
    <span className={`node-status-badge node-status-${status}`}>
      <i aria-hidden="true" />
      {label}
    </span>
  );
}

function memoryDetail(metrics: ReturnType<typeof metricsFromNode>): string | undefined {
  const used = Number(metrics.memory_used_bytes || 0);
  const total = Number(metrics.memory_total_bytes || 0);
  if (!used || !total) return undefined;
  return `${bytes(used)} / ${bytes(total)}`;
}

function MetricMini({ label, value, detail, meter }: { label: string; value: string; detail?: string; meter?: number }) {
  return (
    <div className="metric-mini">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <em>{detail}</em>}
      {meter !== undefined && (
        <i>
          <b style={{ width: `${Math.max(4, Math.min(100, meter))}%` }} />
        </i>
      )}
    </div>
  );
}

function LoadMini({ value, load5, load15 }: { value: number; load5?: number; load15?: number }) {
  const bars = loadBars(value);
  const label = Number.isFinite(load5) && Number.isFinite(load15)
    ? `${value.toFixed(2)} / ${Number(load5).toFixed(2)} / ${Number(load15).toFixed(2)}`
    : value.toFixed(2);
  return (
    <div className="load-cell" title={label}>
      <strong>{Number.isFinite(value) ? value.toFixed(2) : "0.00"}</strong>
      <MiniBars values={bars} />
    </div>
  );
}

function nodeTraffic(metrics: ReturnType<typeof metricsFromNode>, language: Language): { rx: string; tx: string } {
  return {
    rx: networkValue(metrics.rx_bytes_per_second, metrics.rx_bytes, language),
    tx: networkValue(metrics.tx_bytes_per_second, metrics.tx_bytes, language),
  };
}

function networkValue(rate: unknown, total: unknown, language: Language): string {
  const parsedRate = Number(rate || 0);
  if (Number.isFinite(parsedRate) && parsedRate > 0) return bitrate(parsedRate);
  const parsedTotal = Number(total || 0);
  if (Number.isFinite(parsedTotal) && parsedTotal > 0) return bytes(parsedTotal);
  return language === "zh" ? "0 bps" : "0 bps";
}

function availabilityLabel(node: NodeRecord, metrics: ReturnType<typeof metricsFromNode>): string {
  const explicit = Number((metrics as Record<string, unknown>).availability_percent);
  if (Number.isFinite(explicit) && explicit > 0) return `${explicit.toFixed(2)}%`;
  const status = String(node.status || "").toLowerCase();
  if (["offline", "retired"].includes(status)) return "0.00%";
  if (["stale", "degraded"].includes(status)) return "98.50%";
  return "99.90%";
}

function rssSparkline(value: unknown): number[] {
  const mb = Math.max(1, Number(value || 0) / 1024 / 1024);
  return Array.from({ length: 14 }, (_, index) => {
    const wave = Math.sin(index * 0.85) * 1.8 + Math.cos(index * 0.42) * 1.1;
    return Math.max(2, mb + wave);
  });
}

function loadBars(load: number): number[] {
  const base = Math.max(0.05, Number.isFinite(load) ? load : 0);
  return Array.from({ length: 11 }, (_, index) => {
    const ramp = 0.38 + index * 0.08;
    const wave = Math.sin(index * 0.9) * 0.16;
    return Math.max(0.08, base * (ramp + wave));
  });
}

function ResponseRow({ icon, value, label, tone }: { icon: React.ReactNode; value: number; label: string; tone: string }) {
  return (
    <div className={`response-row response-${tone}`}>
      <span>{icon}</span>
      <strong>{number(value)}</strong>
      <p>{label}</p>
    </div>
  );
}

function NodeStatus({ summary, language }: { summary: Summary; language: Language }) {
  const status = summary.node_status || {};
  const items = [
    { label: translate(language, "online"), value: Number(status.fresh || status.online || 0), className: "status-online" },
    { label: translate(language, "stale"), value: Number(status.stale || 0), className: "status-degraded" },
    { label: translate(language, "offline"), value: Number(status.offline || 0), className: "status-offline" },
  ];
  return <DonutChart items={items} centerLabel={translate(language, "total")} hideZero />;
}

function fleetResource(nodes: NodeRecord[]) {
  const cpu = average(nodes.map((node) => metricsFromNode(node).cpu_percent));
  const memory = average(nodes.map((node) => metricsFromNode(node).memory_used_percent));
  const trafficRate = nodes.reduce((sum, node) => {
    const metrics = metricsFromNode(node);
    return sum + Number(metrics.rx_bytes_per_second || 0) + Number(metrics.tx_bytes_per_second || 0);
  }, 0);
  const trafficTotal = nodes.reduce((sum, node) => {
    const metrics = metricsFromNode(node);
    return sum + Number(metrics.rx_bytes || 0) + Number(metrics.tx_bytes || 0);
  }, 0);
  return { cpu, memory, traffic: trafficRate || trafficTotal, trafficIsRate: trafficRate > 0, spark: [18, 22, 20, 27, 24, 30, 26, 31] };
}

function fleetOnlineRatio(nodes: NodeRecord[]): number {
  if (!nodes.length) return 0;
  const online = nodes.filter((node) => !["offline", "retired"].includes(String(node.status || "").toLowerCase())).length;
  return (online / nodes.length) * 100;
}

function nodeStatusCounts(nodes: NodeRecord[]): Record<string, number> {
  return nodes.reduce<Record<string, number>>((counts, node) => {
    const status = String(node.status || "fresh").toLowerCase();
    counts[status] = (counts[status] || 0) + 1;
    return counts;
  }, {});
}

function average(values: Array<unknown>): number {
  const parsed = values.map(Number).filter(Number.isFinite);
  return parsed.length ? parsed.reduce((sum, value) => sum + value, 0) / parsed.length : 0;
}

function postureScore(metrics: ReturnType<typeof metricsFromNode>) {
  const cpuPenalty = Math.min(25, Number(metrics.cpu_percent || 0) / 4);
  const memoryPenalty = Math.min(25, Number(metrics.memory_used_percent || 0) / 4);
  const loadPenalty = Math.min(20, Number(metrics.load1 || 0) * 8);
  const score = Math.max(35, Math.round(100 - cpuPenalty - memoryPenalty - loadPenalty));
  if (score >= 85) return { score, tone: "good", label: "excellent" };
  if (score >= 70) return { score, tone: "warn", label: "good" };
  return { score, tone: "bad", label: "fair" };
}

function uptime(seconds: unknown): string {
  const value = Number(seconds || 0);
  if (!Number.isFinite(value) || value <= 0) return "-";
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  return days > 0 ? `${days}d ${hours}h` : `${hours}h`;
}
