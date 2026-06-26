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
import { countryDisplay, metricsFromNode, nodeLocation, number, percent, relativeTime, bitrate, bytes, sortedNodes } from "@/lib/format";
import { translate } from "@/lib/i18n";
import { roleAllows } from "@/lib/rbac";
import type { DatasetPage, DatasetState, Language, NodeRecord, PageConfig, PanelActionRequestInput, PanelDictionaries, PanelDictionaryItem, PanelRecord, PanelRole, Summary, TrendPoint } from "@/types";

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
  const findingTrend = sparklineFromTrend(trends, "total", "orange");
  const highTrend = sparklineFromTrend(trends, "high", "red");
  const mediumTrend = sparklineFromTrend(trends, "medium", "green");

  return (
    <div className="page-stack overview-page">
      <section className="mobile-overview-live" aria-label={translate(language, "live")}>
        <span><i aria-hidden="true" />{translate(language, "live")}</span>
        <em>{translate(language, "updatedJustNow")}</em>
      </section>
      <section className="metric-grid">
        <MetricCard label={translate(language, "nodesMetric")} value={summary.nodes || 0} detail={translate(language, "online")} tone="blue" icon={<Server />} />
        <MetricCard label={translate(language, "findingsMetric")} value={summary.findings || 0} detail={translate(language, "riskTrend")} tone="orange" icon={<ShieldAlert />} sparkline={findingTrend} />
        <MetricCard label={translate(language, "incidentsMetric")} value={summary.incidents || 0} detail={translate(language, "activeIncidents")} tone="red" icon={<Bell />} sparkline={highTrend} />
        <MetricCard label={translate(language, "baselineMetric")} value={summary.baseline_drifts || 0} detail={translate(language, "drifts")} tone="green" icon={<ShieldCheck />} sparkline={mediumTrend} />
        <MetricCard label={translate(language, "blocksMetric")} value={summary.active_blocks || 0} detail={translate(language, "blocksInEffect")} tone="blue" icon={<ShieldPlus />} />
      </section>

      <section className="overview-grid">
        <Card title={translate(language, "riskTrend")} className="wide-card" action={<span className="timeframe-badge">{translate(language, "range_7d")}</span>}>
          <RiskTrend rows={trends} language={language} />
        </Card>
        <Card title={translate(language, "findingsBySeverity")} className="overview-severity-card">
          <DonutChart
            centerLabel={translate(language, "total")}
            hideZero
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
        <Card title={translate(language, "responseActivity")} className="response-activity-card">
          <div className="response-list">
            <ResponseRow icon={<Siren />} value={summary.incidents || incidents.length} label={translate(language, "activeIncidents")} tone="red" />
            <ResponseRow icon={<ShieldCheck />} value={summary.active_blocks || blocks.length} label={translate(language, "blocksInEffect")} tone="orange" />
            <ResponseRow icon={<Cpu />} value={Math.max(0, highRisk)} label={translate(language, "highRiskPressure")} tone="green" />
          </div>
        </Card>
        <Card title={translate(language, "nodeFreshness")} className="node-freshness-card" action={<button className="link-button" type="button" onClick={() => onNavigate("nodes")}>{translate(language, "nodes")}</button>}>
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
        {roleAllows(role, "private") && (
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
  const rows = page.items;
  const activeRows = activeRiskRows(rows);
  const counts = severityCounts(activeRows);
  const alertVolume = volumeBars(rows, "timestamp");
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
          <div className="desktop-table-panel">
            <DataTable rows={rows} columns={["timestamp", "severity", "node_name", "rule_id", "category", "review_verdict"]} language={language} onDetails={onDetails} tableId="findings" />
          </div>
          <MobileRiskList rows={rows} language={language} kind="finding" onDetails={onDetails} />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
        <aside className="feature-side-stack">
          <SideCard title={copy(language, "Alert Volume", "告警量")} action={copy(language, "Current result set", "当前结果集")}>
            {alertVolume.length ? <MiniBars values={alertVolume} /> : <div className="chart-empty compact">{translate(language, "noTrendData")}</div>}
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
  const rows = page.items;
  const activeRows = activeRiskRows(rows);
  const selected = activeRows[0] || rows[0] || null;
  const selectedScore = Number(selected?.score || 0);
  const correlatedSignals = activeRows.reduce((sum, row) => sum + Number(row.finding_count || row.event_count || row.score || 0), 0);
  const chainStages = selected ? attackChainFromIncident(selected, language) : [];
  const scoreTone = postureToneFromSeverity(selected?.severity);
  const scoreLabel = selected ? translate(language, String(selected.severity || "unknown").toLowerCase()) : "-";
  const scorePercent = Math.max(0, Math.min(100, Number.isFinite(selectedScore) ? selectedScore : 0));
  const signalFacts = selected ? correlationFacts(selected, language) : [];
  return (
    <div className="page-stack feature-page incidents-design">
      <div className="incident-main">
          <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
          <section className="feature-metrics six">
            <StatTile icon={<GitBranch />} tone="red" label={copy(language, "Active Incidents", "活跃事件")} value={activeRows.length} detail={copy(language, "False positives excluded", "已排除误报")} />
            <StatTile icon={<Clock3 />} tone="orange" label={copy(language, "Needs Review", "待复核")} value={reviewVerdictCount(rows, "needs_review")} detail={copy(language, "Require triage", "需要分流")} />
            <StatTile icon={<CheckCircle2 />} tone="green" label={copy(language, "Confirmed", "已确认")} value={reviewVerdictCount(rows, "confirmed")} detail={copy(language, "Containment in progress", "处置中")} />
            <StatTile icon={<ShieldAlert />} tone="red" label={copy(language, "High Severity", "高危事件")} value={severityCounts(activeRows).critical + severityCounts(activeRows).high} detail={copy(language, "Critical impact", "影响较高")} />
            <StatTile icon={<Server />} tone="blue" label={copy(language, "Affected Nodes", "受影响节点")} value={topNodes(activeRows).length || 0} detail={topNodes(activeRows).slice(0, 2).map((row) => row.label).join(", ") || "-"} />
            <StatTile icon={<Network />} tone="blue" label={copy(language, "Events Correlated", "关联信号")} value={number(correlatedSignals)} detail={copy(language, "From incident data", "来自事件数据")} />
          </section>
          <section className="incident-workbench">
            <Card title={copy(language, "Attack Chain", "攻击链")} className="attack-chain-card">
              <div className="attack-chain">
                {chainStages.length ? (
                  chainStages.map((stage) => (
                    <div className="chain-stage" key={stage.label}>
                      <span>{stage.icon}</span>
                      <strong>{copy(language, stage.label, chainZh(stage.label))}</strong>
                      <Badge value={translate(language, stage.severity)} tone={stage.severity} />
                      <small>{stage.evidence}</small>
                    </div>
                  ))
                ) : (
                  <div className="chart-empty compact">{translate(language, "noData")}</div>
                )}
              </div>
            </Card>
            <Card title={copy(language, "Correlation Score", "关联评分")} className="correlation-card">
              <div className="score-panel">
                <div className={`posture-ring posture-${scoreTone}`} style={{ "--score": `${scorePercent}%` } as React.CSSProperties}>
                  <strong>{selectedScore || 0}</strong>
                  <span>{scoreLabel}</span>
                </div>
                {signalFacts.length ? (
                  <ul>
                    {signalFacts.map((fact) => <li key={fact}>{fact}</li>)}
                  </ul>
                ) : (
                  <div className="chart-empty compact">{translate(language, "noData")}</div>
                )}
              </div>
            </Card>
          </section>
          <Filters state={state} language={language} onChange={onStateChange} />
          <Card title={translate(language, config.labelKey)} className="feature-table-card">
            <div className="desktop-table-panel">
              <DataTable rows={rows} columns={["last_seen", "severity", "score", "node_name", "title", "review_verdict"]} language={language} onDetails={onDetails} tableId="incidents" />
            </div>
            <MobileRiskList rows={rows} language={language} kind="incident" onDetails={onDetails} />
            <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
          </Card>
      </div>
    </div>
  );
}

export function BaselinePageView({
  config,
  page,
  state,
  language,
  dictionaries,
  onStateChange,
  onDetails,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  dictionaries: PanelDictionaries;
  onStateChange: (patch: Partial<DatasetState>) => void;
  onDetails: (row: PanelRecord) => void;
}) {
  const rows = page.items;
  const activeRows = activeRiskRows(rows);
  const suspicious = activeRows.filter((row) => String(row.tier || "").includes("suspicious")).length;
  const driftTrend = driftTrendRows(rows);
  const queueRef = useRef<HTMLDivElement>(null);
  const reviewFilters = dictionaryOptions(dictionaries, "baselineReviewFilters", baselineReviewFilterFallback());

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
        <Card title={copy(language, "Drift Timeline", "漂移时间线")} className="wide-card baseline-timeline-card">
          <RiskTrend rows={driftTrend} language={language} variant="drift" />
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
            {reviewFilters.map((filter) => (
              <button
                className={state.query === filter.value ? "active" : ""}
                key={filter.value || "all"}
                type="button"
                onClick={() => focusQueue(filter.value)}
              >
                {dictionaryLabel(filter, language)}
              </button>
            ))}
          </div>
          <div className="desktop-table-panel">
            <DataTable rows={rows} columns={["timestamp", "node_name", "category", "subject", "tier", "review_verdict", "review_action"]} language={language} onDetails={onDetails} detailLabelKey="review" tableId="baseline-drifts" />
          </div>
          <MobileRiskList rows={rows} language={language} kind="baseline" onDetails={onDetails} />
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
  onActionRequest,
}: {
  config: PageConfig;
  page: DatasetPage;
  state: DatasetState;
  language: Language;
  role: PanelRole;
  onStateChange: (patch: Partial<DatasetState>) => void;
  onActionRequest?: (request: PanelActionRequestInput) => Promise<void>;
}) {
  const [pendingActionId, setPendingActionId] = useState("");
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const rows = page.items;
  const temporaryBlocks = rows.filter((row) => blockMode(row) === "temporary").length;
  const permanentBlocks = rows.length - temporaryBlocks;
  const activeBlocks = rows.filter((row) => !truthy(row.expired)).length || page.total;
  const recentBlocks = rows.filter((row) => isWithinPastHours(row.blocked_at, 24)).length;
  const firewallSynced = rows.filter((row) => truthy(row.firewall_present)).length;
  const expiringSoon = rows.filter((row) => isFutureWithinHours(row.expires_at, 24)).length;
  const columns = roleAllows(role, "private") && config.privateColumns
    ? config.privateColumns
    : config.columns || ["blocked_at", "node_name", "rule_id", "reason", "expires_at"];
  const canRequestActions = roleAllows(role, "private") && Boolean(onActionRequest);

  async function requestUnblock(row: PanelRecord) {
    if (!onActionRequest) return;
    const targetId = String(row.id || "");
    if (!targetId) {
      setActionMessage({ type: "error", text: translate(language, "actionFailed") });
      return;
    }
    setPendingActionId(targetId);
    setActionMessage(null);
    try {
      await onActionRequest({
        action: "unblock",
        target_type: "active_block",
        target_id: targetId,
        node_name: String(row.node_name || ""),
        payload: {
          ip: String(row.ip || ""),
          rule_id: String(row.rule_id || ""),
          backend: String(row.backend || ""),
          reason: String(row.reason || ""),
        },
      });
      setActionMessage({ type: "success", text: translate(language, "actionQueued") });
    } catch {
      setActionMessage({ type: "error", text: translate(language, "actionFailed") });
    } finally {
      setPendingActionId("");
    }
  }

  function unblockButton(row: PanelRecord) {
    const targetId = String(row.id || "");
    return (
      <button
        className="ghost-button compact"
        type="button"
        disabled={!targetId || pendingActionId === targetId}
        onClick={() => void requestUnblock(row)}
      >
        {translate(language, "requestUnblock")}
      </button>
    );
  }

  return (
    <div className="page-stack feature-page blocks-design">
      <FeatureHeader title={translate(language, config.titleKey)} description={translate(language, config.descriptionKey)} />
      <section className="blocks-grid full-width">
        <div className="blocks-main">
          <section className="feature-metrics six">
            <StatTile icon={<ShieldCheck />} tone="green" label={copy(language, "Currently Blocked", "当前封禁")} value={number(activeBlocks)} detail={copy(language, "Across all nodes", "全部节点")} />
            <StatTile icon={<Ban />} tone="red" label={copy(language, "Evidence Confirmed", "证据确认")} value={rows.length} detail={copy(language, "Blocked by policy", "策略已生效")} />
            <StatTile icon={<Clock3 />} tone="orange" label={copy(language, "New Blocks (24h)", "24 小时新增")} value={recentBlocks} detail={copy(language, "Recent response", "近期响应")} />
            <StatTile icon={<ShieldPlus />} tone="blue" label={copy(language, "Firewall Synced", "防火墙同步")} value={firewallSynced} detail={copy(language, "Backend active", "后端已生效")} />
            <StatTile icon={<Clock3 />} tone="orange" label={copy(language, "Temporary Blocks", "临时封禁")} value={temporaryBlocks} detail={copy(language, "Auto-expire", "自动过期")} />
            <StatTile icon={<Infinity />} tone="green" label={copy(language, "Permanent Blocks", "永久封禁")} value={permanentBlocks} detail={copy(language, "Expiring soon", "即将过期") + ` ${expiringSoon}`} />
          </section>
          <Filters state={state} language={language} onChange={onStateChange} />
          <Card title={translate(language, config.labelKey)} className="feature-table-card">
            {actionMessage && <p className={`review-message review-message-${actionMessage.type}`}>{actionMessage.text}</p>}
            <div className="desktop-table-panel">
              <DataTable
                rows={rows}
                columns={columns}
                language={language}
                tableId="active-blocks"
                rowAction={canRequestActions ? unblockButton : undefined}
              />
            </div>
            <MobileBlocksList
              rows={rows}
              language={language}
              visibleColumns={columns}
              rowAction={canRequestActions ? unblockButton : undefined}
            />
            <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
          </Card>
        </div>
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
  const rows = page.items;
  const blocked = rows.filter((row) => String(row.block_status || "").toLowerCase().includes("block")).length;
  const columns = roleAllows(role, "private") && config.privateColumns
    ? config.privateColumns
    : config.publicColumns || config.columns || [];
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
      <section className="feature-main-grid full-width">
        <Card title={translate(language, config.labelKey)} className="feature-table-card">
          <div className="desktop-table-panel">
            <DataTable rows={rows} columns={columns} language={language} tableId="probe_sources" />
          </div>
          <MobileSourcesList rows={rows} language={language} visibleColumns={columns} />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
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
  const rows = page.items;
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
      <section className="feature-main-grid full-width">
        <Card title={translate(language, config.labelKey)} className="feature-table-card">
          <div className="desktop-table-panel">
            <DataTable rows={rows} columns={config.columns || []} language={language} tableId="audit_logs" />
          </div>
          <MobileAuditTimeline rows={rows} language={language} />
          <Pagination total={page.total} limit={page.limit} offset={page.offset} language={language} onPage={(offset) => onStateChange({ offset })} />
        </Card>
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
  const columns = roleAllows(role, "private") && config.privateColumns ? config.privateColumns : config.columns || [];
  const rows = page.items;

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
  dictionaries,
  onStateChange,
}: {
  page: DatasetPage<NodeRecord>;
  state: DatasetState;
  language: Language;
  dictionaries: PanelDictionaries;
  onStateChange: (patch: Partial<DatasetState>) => void;
}) {
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");
  const statusFilters = dictionaryOptions(dictionaries, "nodeStatusFilters", nodeStatusFilterFallback());
  const searchedNodes = sortedNodes(page.items);
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
                {statusFilters.map((filter) => (
                  <button
                    className={statusFilter === filter.value ? "active" : ""}
                    key={filter.value}
                    type="button"
                    onClick={() => setStatusFilter(filter.value)}
                  >
                    <span>{dictionaryLabel(filter, language)}</span>
                    <strong>{filter.value === "all" ? searchedNodes.length : statusCounts[filter.value] || 0}</strong>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </header>
      <section className="node-summary-grid">
        <MetricCard label={translate(language, "fleetCpu")} value={percent(resource.cpu, 0)} detail={translate(language, "avgUtilization")} tone="blue" icon={<Cpu />} sparkline={<Sparkline values={resource.cpuValues} />} />
        <MetricCard label={translate(language, "fleetMemory")} value={percent(resource.memory, 0)} detail={translate(language, "avgUtilization")} tone="green" icon={<Database />} sparkline={<Sparkline tone="green" values={resource.memoryValues} />} />
        <MetricCard label={translate(language, "fleetTraffic")} value={resource.trafficIsRate ? bitrate(resource.traffic) : bytes(resource.traffic)} detail={translate(language, "inOut")} tone="violet" icon={<Wifi />} sparkline={<Sparkline tone="violet" values={resource.trafficValues} />} />
        <MetricCard label={translate(language, "onlineFreshness")} value={percent(fleetOnlineRatio(nodes), 0)} detail={translate(language, "nodes")} tone="green" icon={<BarChart3 />} sparkline={<MiniBars values={freshnessBars(nodes)} />} />
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
        total={statusFilter === "all" ? page.total : nodes.length}
        limit={page.limit}
        offset={statusFilter === "all" ? page.offset : 0}
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

type MobileRiskKind = "finding" | "incident" | "baseline";

function MobileRiskList({
  rows,
  language,
  kind,
  onDetails,
}: {
  rows: PanelRecord[];
  language: Language;
  kind: MobileRiskKind;
  onDetails: (row: PanelRecord) => void;
}) {
  if (!rows.length) return <MobileEmptyState language={language} />;
  return (
    <div className={`mobile-record-list mobile-risk-list mobile-${kind}-list`}>
      {rows.map((row, index) => {
        const severity = mobileRiskSeverity(row, kind);
        const title = mobileRiskTitle(row, kind, language);
        const time = recordText(row, kind === "incident" ? ["last_seen", "timestamp"] : ["timestamp", "last_seen"], "");
        const meta = mobileRiskMeta(row, kind, language);
        return (
          <article className={`mobile-record-card mobile-risk-card risk-${severity}`} key={recordKey(row, index)}>
            <span className={`mobile-record-icon tone-${riskTone(severity)}`}>{mobileRiskIcon(kind)}</span>
            <div className="mobile-record-body">
              <header className="mobile-record-title-row">
                <div>
                  <strong>{title}</strong>
                  <span>{meta.primary}</span>
                </div>
                <time>{formatRecordDate(time, language)}</time>
              </header>
              <div className="mobile-record-subline">
                {meta.items.map((item) => <span key={item}>{item}</span>)}
              </div>
              <div className="mobile-risk-footer">
                <Badge value={translate(language, severity)} tone={severity} />
                {kind === "incident" && <span className="mobile-score-pill">{recordText(row, ["score"], "0")}</span>}
                <button className="ghost-button compact" type="button" onClick={() => onDetails(row)}>
                  {translate(language, kind === "baseline" ? "review" : "details")}
                </button>
              </div>
            </div>
          </article>
        );
      })}
    </div>
  );
}

function MobileBlocksList({
  rows,
  language,
  visibleColumns,
  rowAction,
}: {
  rows: PanelRecord[];
  language: Language;
  visibleColumns: string[];
  rowAction?: (row: PanelRecord) => React.ReactNode;
}) {
  const [mode, setMode] = useState<"temporary" | "permanent">("temporary");
  if (!rows.length) return <MobileEmptyState language={language} />;
  const canShowIp = visibleColumns.includes("ip") || visibleColumns.includes("source_ip");
  const canShowAttribution = visibleColumns.some((column) => ["country", "asn", "organization"].includes(column));
  const temporaryRows = rows.filter((row) => blockMode(row) === "temporary");
  const permanentRows = rows.filter((row) => blockMode(row) === "permanent");
  const visibleRows = mode === "temporary" ? temporaryRows : permanentRows;
  return (
    <div className="mobile-record-list mobile-block-list">
      <div className="mobile-segment-tabs" role="group" aria-label={copy(language, "Block type", "封禁类型")}>
        <button className={mode === "temporary" ? "active" : ""} type="button" aria-pressed={mode === "temporary"} onClick={() => setMode("temporary")}>{copy(language, "Temporary", "临时")} ({temporaryRows.length})</button>
        <button className={mode === "permanent" ? "active" : ""} type="button" aria-pressed={mode === "permanent"} onClick={() => setMode("permanent")}>{copy(language, "Permanent", "永久")} ({permanentRows.length})</button>
      </div>
      {!visibleRows.length && <div className="empty-state mobile-empty-inline">{translate(language, "noData")}</div>}
      {visibleRows.map((row, index) => {
        const reason = recordText(row, ["reason", "block_reason", "latest_reason", "rule_id"], copy(language, "Blocked source", "已封禁来源"));
        const title = blockTitle(row, reason, language);
        const source = recordText(row, ["ip", "source_ip", "network_prefix"], copy(language, "Hidden source", "隐藏来源"));
        const expires = recordText(row, ["expires_at"], copy(language, "Manual review", "人工复核"));
        return (
          <article className="mobile-record-card block-card" key={recordKey(row, index)}>
            <span className="mobile-record-icon tone-orange"><Globe2 size={20} /></span>
            <div className="mobile-record-body">
              <header className="mobile-record-title-row">
                <div>
                  <strong>{title}</strong>
                  {canShowIp && <span>{source}</span>}
                </div>
                <Badge value={copy(language, "High", "高危")} tone="high" />
              </header>
              {canShowAttribution && (
                <div className="mobile-record-subline">
                  <CountryInline value={recordText(row, ["country"], translate(language, "unknown"))} />
                  <span>{recordText(row, ["asn"], translate(language, "unknown"))}</span>
                  <span>{recordText(row, ["organization"], "")}</span>
                </div>
              )}
              <div className="mobile-evidence-row">
                <span>{copy(language, "Evidence", "证据")}</span>
                <ScoreDots value={Math.min(5, Math.max(2, Number(row.seen_count || 4)))} total={5} showLabel={false} />
                <em>{copy(language, "Expires", "到期")} {formatRecordDate(expires, language)}</em>
              </div>
              {rowAction && <div className="mobile-card-actions">{rowAction(row)}</div>}
            </div>
          </article>
        );
      })}
    </div>
  );
}

function MobileSourcesList({
  rows,
  language,
  visibleColumns,
}: {
  rows: PanelRecord[];
  language: Language;
  visibleColumns: string[];
}) {
  if (!rows.length) return <MobileEmptyState language={language} />;
  const canShowSource = visibleColumns.includes("source_ip");
  return (
    <div className="mobile-record-list mobile-source-list">
      {rows.map((row, index) => {
        const source = canShowSource ? recordText(row, ["source_ip", "network_prefix"], copy(language, "Hidden source", "隐藏来源")) : copy(language, "Hidden source", "隐藏来源");
        const status = String(row.block_status || "observe").toLowerCase();
        return (
          <article className="mobile-record-card source-card" key={recordKey(row, index)}>
            <header className="source-card-head">
              <div>
                <small>{translate(language, severityFromSource(row))}</small>
                <strong>{source}</strong>
              </div>
              <Badge value={translate(language, status)} tone={status} />
            </header>
            <div className="mobile-record-subline">
              <CountryInline value={recordText(row, ["country"], translate(language, "unknown"))} />
              <span>{recordText(row, ["asn"], translate(language, "unknown"))}</span>
              <span>{recordText(row, ["organization"], "")}</span>
            </div>
            <div className="mobile-record-meta">
              <span>{copy(language, "Seen", "出现")} {number(Number(row.seen_count || 0))}</span>
              <span>{copy(language, "Last seen", "最近")} {formatRecordDate(recordText(row, ["last_seen"], ""), language)}</span>
            </div>
            <TagList values={[...recordValues(row.categories), ...recordValues(row.rule_ids)].slice(0, 4)} />
          </article>
        );
      })}
    </div>
  );
}

function CountryInline({ value }: { value: string }) {
  const country = countryDisplay(value);
  return (
    <span className="country-inline">
      <span className="country-flag" aria-hidden="true">{country.flag}</span>
      <span>{country.label}</span>
    </span>
  );
}

function MobileAuditTimeline({ rows, language }: { rows: PanelRecord[]; language: Language }) {
  if (!rows.length) return <MobileEmptyState language={language} />;
  return (
    <div className="mobile-record-list mobile-audit-timeline">
      {rows.map((row, index) => (
        <article className="audit-timeline-item" key={recordKey(row, index)}>
          <span className={`audit-dot tone-${auditTone(row.action)}`}>{auditIcon(row.action)}</span>
          <div className="audit-card">
            <header>
              <div>
                <strong>{recordText(row, ["action"], copy(language, "Panel action", "面板操作"))}</strong>
                <span>{recordText(row, ["target_id", "target_type"], "")}</span>
              </div>
              <time>{formatRecordDate(recordText(row, ["created_at"], ""), language)}</time>
            </header>
            <div className="mobile-record-meta">
              <span>{copy(language, "Actor", "操作者")} {recordText(row, ["actor"], "-")}</span>
              <Badge value={copy(language, "Success", "成功")} tone="success" />
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function MobileEmptyState({ language }: { language: Language }) {
  return <div className="mobile-record-list"><div className="empty-state">{translate(language, "noData")}</div></div>;
}

function TagList({ values }: { values: string[] }) {
  if (!values.length) return null;
  return (
    <div className="mobile-tag-list">
      {values.map((value) => <span key={value}>{value}</span>)}
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

function mobileRiskSeverity(row: PanelRecord, kind: MobileRiskKind): string {
  if (kind === "baseline") {
    const tier = String(row.tier || row.review_action || "").toLowerCase();
    if (tier.includes("suspicious")) return "high";
    if (tier.includes("expected") || reviewVerdict(row) === "confirmed") return "low";
    return "medium";
  }
  const severity = String(row.severity || row.risk_level || "").toLowerCase();
  if (["critical", "high", "medium", "low"].includes(severity)) return severity;
  const score = Number(row.score || 0);
  if (score >= 85) return "critical";
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return "low";
}

function mobileRiskTitle(row: PanelRecord, kind: MobileRiskKind, language: Language): string {
  if (kind === "baseline") return recordText(row, ["subject", "rule_id", "category"], copy(language, "Baseline change", "基线变更"));
  if (kind === "incident") return recordText(row, ["title", "incident_id", "rule_id"], copy(language, "Correlated incident", "关联事件"));
  return recordText(row, ["title", "rule_id", "category"], copy(language, "Security finding", "安全告警"));
}

function mobileRiskMeta(row: PanelRecord, kind: MobileRiskKind, language: Language): { primary: string; items: string[] } {
  const node = recordText(row, ["node_name"], copy(language, "Unknown node", "未知节点"));
  if (kind === "baseline") {
    return {
      primary: node,
      items: [
        recordText(row, ["category"], translate(language, "unknown")),
        translate(language, reviewVerdict(row)),
        recordText(row, ["review_action", "tier"], ""),
      ].filter(Boolean),
    };
  }
  if (kind === "incident") {
    return {
      primary: node,
      items: [
        recordText(row, ["category"], copy(language, "Incident", "事件")),
        `${copy(language, "Score", "评分")} ${recordText(row, ["score"], "0")}`,
        translate(language, reviewVerdict(row)),
      ],
    };
  }
  return {
    primary: node,
    items: [
      recordText(row, ["category"], translate(language, "unknown")),
      recordText(row, ["rule_id"], ""),
      translate(language, reviewVerdict(row)),
    ].filter(Boolean),
  };
}

function mobileRiskIcon(kind: MobileRiskKind): React.ReactNode {
  if (kind === "incident") return <GitBranch size={20} />;
  if (kind === "baseline") return <ShieldQuestion size={20} />;
  return <ShieldAlert size={20} />;
}

function riskTone(severity: string): string {
  if (severity === "critical" || severity === "high") return "red";
  if (severity === "medium") return "orange";
  return "green";
}

function blockMode(row: PanelRecord): "temporary" | "permanent" {
  const status = String(row.block_status || row.mode || "").toLowerCase();
  if (status.includes("permanent")) return "permanent";
  if (status.includes("temporary") || status.includes("temp")) return "temporary";
  const expires = row.expires_at;
  if (expires === undefined || expires === null) return "permanent";
  const value = String(expires).trim().toLowerCase();
  if (!value || ["-", "never", "none", "null", "manual", "manual review"].includes(value)) return "permanent";
  return "temporary";
}

function timestampMs(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  if (value instanceof Date) return value.getTime();
  const text = String(value).trim();
  if (!text || ["-", "never", "none", "null", "manual", "manual review"].includes(text.toLowerCase())) return null;
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : null;
}

function isWithinPastHours(value: unknown, hours: number): boolean {
  const timestamp = timestampMs(value);
  if (timestamp === null) return false;
  const age = Date.now() - timestamp;
  return age >= 0 && age <= hours * 60 * 60 * 1000;
}

function isFutureWithinHours(value: unknown, hours: number): boolean {
  const timestamp = timestampMs(value);
  if (timestamp === null) return false;
  const delta = timestamp - Date.now();
  return delta >= 0 && delta <= hours * 60 * 60 * 1000;
}

function truthy(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  const text = String(value || "").trim().toLowerCase();
  return ["1", "true", "yes", "y", "on", "active", "present", "synced"].includes(text);
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

function dictionaryOptions(
  dictionaries: PanelDictionaries,
  key: string,
  fallback: PanelDictionaryItem[],
): PanelDictionaryItem[] {
  const items = dictionaries[key]?.length ? dictionaries[key] : fallback;
  return [...items].sort((left, right) => Number(left.rank || 0) - Number(right.rank || 0));
}

function dictionaryLabel(item: PanelDictionaryItem, language: Language): string {
  if (item.labelKey) return translate(language, item.labelKey);
  return item.labels?.[language] || item.labels?.en || item.labels?.zh || item.value || "-";
}

function nodeStatusFilterFallback(): PanelDictionaryItem[] {
  return [
    { value: "all", labelKey: "allNodes", rank: 0 },
    { value: "fresh", labelKey: "online", rank: 10 },
    { value: "stale", labelKey: "stale", rank: 20 },
    { value: "offline", labelKey: "offline", rank: 30 },
    { value: "retired", labelKey: "retired", rank: 40 },
  ];
}

function baselineReviewFilterFallback(): PanelDictionaryItem[] {
  return [
    { value: "", labels: { zh: "全部", en: "All" }, rank: 0 },
    { value: "suspicious", labelKey: "suspicious", rank: 10 },
    { value: "needs_confirmation", labelKey: "needs_confirmation", rank: 20 },
    { value: "expected", labelKey: "expected", rank: 30 },
  ];
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

function recordKey(row: PanelRecord, index: number): string {
  return String(row.id || row.event_id || row.source_ip || row.ip || row.created_at || `${row.node_name || "row"}-${index}`);
}

function recordText(row: PanelRecord, keys: string[], fallback = "-"): string {
  for (const key of keys) {
    const value = row[key];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      const text = value.map((item) => String(item).trim()).filter(Boolean).join(", ");
      if (text) return text;
      continue;
    }
    const text = String(value).trim();
    if (text && text.toLowerCase() !== "unknown") return text;
  }
  return fallback;
}

function recordValues(value: unknown): string[] {
  const values = Array.isArray(value) ? value : String(value || "").split(",");
  return values.map((item) => String(item).trim()).filter(Boolean).filter((item) => item.toLowerCase() !== "unknown");
}

function compactReason(value: string): string {
  return value
    .replace(/\s+/g, " ")
    .replace(/attack fingerprint id=/gi, "")
    .replace(/policy=/gi, "")
    .trim();
}

function blockTitle(row: PanelRecord, reason: string, language: Language): string {
  const normalized = `${reason} ${recordText(row, ["rule_id"], "")}`.toLowerCase();
  if (normalized.includes("cgi") || normalized.includes("web_probe") || normalized.includes("web attack")) {
    return copy(language, "Web Attack / CGI Probe", "Web 攻击 / CGI 探查");
  }
  if (normalized.includes("ssh")) return copy(language, "SSH Brute Force", "SSH 暴力尝试");
  if (normalized.includes("scan") || normalized.includes("probe")) return copy(language, "External Probe", "外部探查");
  const compact = compactReason(reason);
  if (compact.startsWith("WEB-FP-")) return copy(language, "Web Attack Fingerprint", "Web 攻击指纹");
  return compact || copy(language, "Blocked Source", "已封禁来源");
}

function formatRecordDate(value: string, language: Language): string {
  if (!value || value === "-") return "-";
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toLocaleString(language === "zh" ? "zh-CN" : "en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }
  return value.length > 18 ? value.slice(0, 18) : value;
}

function severityFromSource(row: PanelRecord): string {
  const status = String(row.block_status || "").toLowerCase();
  const count = Number(row.seen_count || 0);
  if (status.includes("permanent") || count >= 20) return "high";
  if (status.includes("block") || count >= 10) return "medium";
  return "low";
}

function auditTone(action: unknown): string {
  const value = String(action || "").toLowerCase();
  if (value.includes("block")) return "red";
  if (value.includes("review")) return "green";
  if (value.includes("baseline") || value.includes("update")) return "orange";
  return "blue";
}

function auditIcon(action: unknown): React.ReactNode {
  const tone = auditTone(action);
  if (tone === "red") return <Ban size={18} />;
  if (tone === "green") return <ShieldCheck size={18} />;
  if (tone === "orange") return <ShieldAlert size={18} />;
  return <FileText size={18} />;
}

function copy(language: Language, en: string, zh: string): string {
  return language === "zh" ? zh : en;
}

interface AttackChainStage {
  label: string;
  severity: string;
  evidence: string;
  icon: React.ReactNode;
}

function attackChainFromIncident(row: PanelRecord, language: Language): AttackChainStage[] {
  const text = [
    row.tactics,
    row.techniques,
    row.category,
    row.rule_id,
    row.title,
    row.summary,
    row.description,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  const severity = normalizedSeverity(row.severity);
  const score = Number(row.score || 0);
  const primaryEvidence = compactReason(recordText(row, ["rule_id", "title", "summary"], copy(language, "observed correlation", "已观测关联")));
  const stages = [
    {
      label: "Initial Access",
      icon: <Target size={16} />,
      matches: ["initial", "access", "ssh", "web", "probe", "brute", "login"],
      fallback: copy(language, "Incident correlation started on this node", "该节点出现事件关联入口"),
    },
    {
      label: "Execution",
      icon: <Zap size={16} />,
      matches: ["execution", "process", "command", "shell", "exec", "script"],
      fallback: copy(language, "No direct execution evidence in incident summary", "事件摘要中暂无直接执行证据"),
    },
    {
      label: "Privilege Escalation",
      icon: <ShieldAlert size={16} />,
      matches: ["privilege", "sudo", "root", "escalation", "admin"],
      fallback: copy(language, "Privilege context needs review", "权限上下文需复核"),
    },
    {
      label: "Lateral Movement",
      icon: <Network size={16} />,
      matches: ["lateral", "network", "scan", "spread", "multi-node", "multiple nodes"],
      fallback: copy(language, "No lateral spread observed from available fields", "可用字段中未观测到横向扩散"),
    },
    {
      label: "Impact",
      icon: <Siren size={16} />,
      matches: ["impact", "block", "deny", "tamper", "ransom", "contain"],
      fallback: copy(language, "Containment review required by score and severity", "需按评分和等级复核处置"),
    },
  ];
  return stages.map((stage) => {
    const matched = stage.matches.some((keyword) => text.includes(keyword));
    const inferredImpact = stage.label === "Impact" && (score >= 70 || ["critical", "high"].includes(severity));
    const stageSeverity = matched || inferredImpact ? severity : "unknown";
    return {
      label: stage.label,
      severity: stageSeverity,
      evidence: matched ? primaryEvidence : stage.fallback,
      icon: stage.icon,
    };
  });
}

function normalizedSeverity(value: unknown): string {
  const severity = String(value || "unknown").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(severity) ? severity : "unknown";
}

function postureToneFromSeverity(value: unknown): "good" | "warn" | "bad" {
  const severity = normalizedSeverity(value);
  if (["critical", "high"].includes(severity)) return "bad";
  if (severity === "medium") return "warn";
  return "good";
}

function correlationFacts(row: PanelRecord, language: Language): string[] {
  const facts: string[] = [];
  const nodeCount = Number(row.node_count || row.affected_nodes || 0);
  const findingCount = Number(row.finding_count || 0);
  const eventCount = Number(row.event_count || 0);
  const score = Number(row.score || 0);
  const nodeName = recordText(row, ["node_name", "node_id"], "");
  const firstSeen = parseDate(row.first_seen || row.created_at || row.timestamp);
  const lastSeen = parseDate(row.last_seen || row.updated_at || row.timestamp);
  if (Number.isFinite(nodeCount) && nodeCount > 1) facts.push(copy(language, `${number(nodeCount)} affected nodes`, `${number(nodeCount)} 个受影响节点`));
  if (Number.isFinite(findingCount) && findingCount > 0) facts.push(copy(language, `${number(findingCount)} linked findings`, `${number(findingCount)} 条关联告警`));
  if (Number.isFinite(eventCount) && eventCount > 0) facts.push(copy(language, `${number(eventCount)} linked events`, `${number(eventCount)} 条关联事件`));
  if (firstSeen && lastSeen && lastSeen.getTime() >= firstSeen.getTime()) {
    facts.push(copy(language, `Window ${durationLabel(lastSeen.getTime() - firstSeen.getTime(), "en")}`, `窗口 ${durationLabel(lastSeen.getTime() - firstSeen.getTime(), "zh")}`));
  }
  if (nodeName) facts.push(copy(language, `Node ${nodeName}`, `节点 ${nodeName}`));
  if (Number.isFinite(score) && score > 0) facts.push(copy(language, `Correlation score ${number(score)}`, `关联评分 ${number(score)}`));
  if (lastSeen) facts.push(copy(language, `Last seen ${relativeTime(lastSeen.toISOString(), "en")}`, `最后出现 ${relativeTime(lastSeen.toISOString(), "zh")}`));
  return facts;
}

function parseDate(value: unknown): Date | null {
  if (!value) return null;
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function durationLabel(ms: number, language: Language): string {
  const minutes = Math.max(0, Math.round(ms / 60000));
  if (minutes < 60) return language === "zh" ? `${minutes} 分钟` : `${minutes}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return language === "zh" ? `${hours} 小时` : `${hours}h`;
  const days = Math.round(hours / 24);
  return language === "zh" ? `${days} 天` : `${days}d`;
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
  const availability = availabilityLabel(metrics);
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
            <span className="node-flag" aria-hidden="true">{location.flag}</span>
            <span>{location.label}</span>
          </small>
          <small className="node-uptime-mobile">
            {translate(language, "uptime")} {uptime(metrics.uptime_seconds)}
          </small>
        </div>
      </div>
      <NodeStatusBadge status={status} language={language} />
      <MetricMini className="metric-uptime" label={translate(language, "uptime")} value={uptime(metrics.uptime_seconds)} detail={availability} />
      <MetricMini className="metric-cpu" label={translate(language, "cpu")} value={percent(metrics.cpu_percent)} meter={Number(metrics.cpu_percent || 0)} />
      <MetricMini className="metric-memory" label={translate(language, "memory")} value={percent(metrics.memory_used_percent)} detail={memoryDetail(metrics)} meter={Number(metrics.memory_used_percent || 0)} />
      <LoadMini value={load} load5={Number(metrics.load5 || 0)} load15={Number(metrics.load15 || 0)} />
      <div className="traffic-cell">
        <span aria-label={translate(language, "download")}><ArrowDown size={12} />{traffic.rx}</span>
        <span aria-label={translate(language, "upload")}><ArrowUp size={12} />{traffic.tx}</span>
      </div>
      <div className="agent-rss-cell">
        <strong>{bytes(metrics.agent_rss_bytes)}</strong>
        {rssSpark.length >= 2 && <MiniBars values={rssSpark} />}
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

function MetricMini({
  label,
  value,
  detail,
  meter,
  className = "",
}: {
  label: string;
  value: string;
  detail?: string;
  meter?: number;
  className?: string;
}) {
  return (
    <div className={`metric-mini ${className}`}>
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
  const bars = loadBars(value, load5, load15);
  const label = Number.isFinite(load5) && Number.isFinite(load15)
    ? `${value.toFixed(2)} / ${Number(load5).toFixed(2)} / ${Number(load15).toFixed(2)}`
    : value.toFixed(2);
  return (
    <div className="load-cell" title={label}>
      <strong>{Number.isFinite(value) ? value.toFixed(2) : "0.00"}</strong>
      {bars.length >= 2 && <MiniBars values={bars} />}
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

function availabilityLabel(metrics: ReturnType<typeof metricsFromNode>): string | undefined {
  const explicit = Number((metrics as Record<string, unknown>).availability_percent);
  if (Number.isFinite(explicit) && explicit > 0) return `${explicit.toFixed(2)}%`;
  return undefined;
}

function rssSparkline(value: unknown): number[] {
  const mb = Number(value || 0) / 1024 / 1024;
  return Number.isFinite(mb) && mb > 0 ? [mb] : [];
}

function loadBars(load1: number, load5?: number, load15?: number): number[] {
  return [load1, load5, load15].map(Number).filter((value) => Number.isFinite(value) && value >= 0);
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

function sparklineFromTrend(rows: TrendPoint[], key: "total" | "critical" | "high" | "medium" | "low", tone?: string): React.ReactNode {
  const values = rows.slice(-16).map((row) => trendMetric(row, key)).filter((value) => Number.isFinite(value));
  if (!values.length) return undefined;
  return <Sparkline tone={tone} values={values} />;
}

function trendMetric(row: TrendPoint, key: "total" | "critical" | "high" | "medium" | "low"): number {
  if (key === "total") {
    const direct = Number(row.total);
    if (Number.isFinite(direct)) return direct;
    return trendMetric(row, "critical") + trendMetric(row, "high") + trendMetric(row, "medium") + trendMetric(row, "low");
  }
  const direct = Number(row[key]);
  if (Number.isFinite(direct)) return direct;
  return Number(row.severity?.[key] || 0);
}

function driftTrendRows(rows: PanelRecord[]): TrendPoint[] {
  const buckets = new Map<string, TrendPoint>();
  rows.forEach((row) => {
    const bucket = dayBucket(row.timestamp || row.last_seen || row.created_at || row.reviewed_at);
    const point = buckets.get(bucket) || { bucket, total: 0, severity: {} };
    const key = driftBucketKey(row);
    point.total = Number(point.total || 0) + 1;
    point.severity = { ...(point.severity || {}), [key]: Number(point.severity?.[key] || 0) + 1 };
    buckets.set(bucket, point);
  });
  return Array.from(buckets.values()).sort((left, right) => String(left.bucket).localeCompare(String(right.bucket))).slice(-7);
}

function driftBucketKey(row: PanelRecord): "smart" | "expected" | "suspicious" | "needs_confirmation" {
  const text = [
    row.review_verdict,
    row.review_action,
    row.tier,
    row.status,
    row.summary,
    row.title,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  if (text.includes("false_positive") || text.includes("smart")) return "smart";
  if (text.includes("confirmed") || text.includes("expected")) return "expected";
  if (text.includes("suspicious") || text.includes("high")) return "suspicious";
  return "needs_confirmation";
}

function dayBucket(value: unknown): string {
  const parsed = value ? new Date(String(value)) : null;
  if (parsed && !Number.isNaN(parsed.getTime())) return parsed.toISOString().slice(0, 10);
  return "unknown";
}

function fleetResource(nodes: NodeRecord[]) {
  const cpu = average(nodes.map((node) => metricsFromNode(node).cpu_percent));
  const memory = average(nodes.map((node) => metricsFromNode(node).memory_used_percent));
  const cpuValues = metricSeries(nodes, (metrics) => metrics.cpu_percent);
  const memoryValues = metricSeries(nodes, (metrics) => metrics.memory_used_percent);
  const trafficValues = metricSeries(nodes, (metrics) => {
    const rate = Number(metrics.rx_bytes_per_second || 0) + Number(metrics.tx_bytes_per_second || 0);
    if (Number.isFinite(rate) && rate > 0) return rate;
    return Number(metrics.rx_bytes || 0) + Number(metrics.tx_bytes || 0);
  });
  const trafficRate = nodes.reduce((sum, node) => {
    const metrics = metricsFromNode(node);
    return sum + Number(metrics.rx_bytes_per_second || 0) + Number(metrics.tx_bytes_per_second || 0);
  }, 0);
  const trafficTotal = nodes.reduce((sum, node) => {
    const metrics = metricsFromNode(node);
    return sum + Number(metrics.rx_bytes || 0) + Number(metrics.tx_bytes || 0);
  }, 0);
  return { cpu, memory, traffic: trafficRate || trafficTotal, trafficIsRate: trafficRate > 0, cpuValues, memoryValues, trafficValues };
}

function metricSeries(nodes: NodeRecord[], pick: (metrics: ReturnType<typeof metricsFromNode>) => unknown): number[] {
  return sortedNodes(nodes)
    .map((node) => Number(pick(metricsFromNode(node))))
    .filter((value) => Number.isFinite(value) && value >= 0)
    .slice(-16);
}

function freshnessBars(nodes: NodeRecord[]): number[] {
  return sortedNodes(nodes).map((node) => {
    const status = String(node.status || "fresh").toLowerCase();
    if (["offline", "retired"].includes(status)) return 0;
    if (["stale", "degraded"].includes(status)) return 50;
    return 100;
  }).slice(-16);
}

function volumeBars(rows: PanelRecord[], timeField: string): number[] {
  if (!rows.length) return [];
  const buckets = new Map<string, number>();
  rows.forEach((row) => {
    const bucket = hourBucket(row[timeField] || row.last_seen || row.created_at || row.blocked_at);
    buckets.set(bucket, (buckets.get(bucket) || 0) + 1);
  });
  return Array.from(buckets.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, value]) => value)
    .slice(-24);
}

function hourBucket(value: unknown): string {
  const parsed = value ? new Date(String(value)) : null;
  if (parsed && !Number.isNaN(parsed.getTime())) return parsed.toISOString().slice(0, 13);
  return "unknown";
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
