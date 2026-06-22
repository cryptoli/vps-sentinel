import { formatTemplate } from "./components.js";

const OVERVIEW_FINDING_COLUMNS = ["timestamp", "node_name", "severity", "rule_id", "subject"];
const OVERVIEW_INCIDENT_COLUMNS = ["last_seen", "node_name", "severity", "score", "title"];
const OVERVIEW_DRIFT_COLUMNS = ["timestamp", "node_name", "severity", "rule_id", "tier", "subject"];

export function renderOverviewDashboard(ctx) {
  const { state, t, ui } = ctx;
  const summary = state.summary || {};
  const datasets = state.datasets || {};
  const findings = datasets.findings?.items || [];
  const incidents = datasets.incidents?.items || [];
  const drifts = datasets.baseline_drifts?.items || [];
  const blocks = datasets.active_blocks?.items || [];
  const nodes = datasets.nodes?.items || [];
  const trends = datasets.trends?.items || [];
  const severityRows = summary.by_severity || [];
  const status = fleetStatus(summary.node_status || {}, t);
  const operatorView = roleAllows(state.role, "operator");

  const root = ctx.mountPage("overview-page");
  const shell = ctx.ensureRegion(root, "dashboard");
  shell.className = "page-region page-region-dashboard dashboard-shell";

  const shellRegions = ["overview-metrics", "overview-charts"];
  if (operatorView) shellRegions.push("overview-operator", "overview-latest", "overview-drifts");
  ctx.retainRegions(shell, shellRegions);

  ctx.replaceRegionIfChanged(
    shell,
    "overview-metrics",
    {
      language: state.language,
      nodes: summary.nodes,
      fleet: status,
      highRisk: highRiskCount(severityRows),
      incidents: summary.incidents,
      drifts: summary.baseline_drifts,
      blocks: summary.active_blocks,
    },
    ui.metrics([
      metric(t("nodesMetric"), summary.nodes, "nodes", t("nodesMetricHint")),
      metric(t("fleetFreshness"), status.label, "freshness", status.detail),
      metric(t("highRiskPressure"), highRiskCount(severityRows), "findings", t("highRiskPressureDetail")),
      metric(t("incidentsMetric"), summary.incidents, "incidents", t("incidentsMetricHint")),
      metric(t("driftsMetric"), summary.baseline_drifts, "drifts", t("driftsMetricHint")),
      metric(t("blocksMetric"), summary.active_blocks, "blocks", t("blocksMetricHint")),
    ]),
  );

  const charts = ctx.ensureRegion(shell, "overview-charts");
  charts.className = "overview-bento";
  ctx.retainRegions(charts, [
    "activity-trend",
    "severity-distribution",
    "node-status",
    "node-resource",
    "category-distribution",
    "block-status",
    "activity-mix",
  ]);
  ctx.replaceRegionIfChanged(
    charts,
    "activity-trend",
    { language: state.language, trends },
    ui.panel(t("activityTrend"), ui.trendChart(trends), { meta: t("activityTrendMeta"), tone: "wide" }),
  );
  ctx.replaceRegionIfChanged(
    charts,
    "severity-distribution",
    { language: state.language, rows: severityRows },
    ui.panel(t("severityDistribution"), ui.barChart(severityRows, "severity", "count"), { meta: t("severityDistributionMeta") }),
  );
  ctx.replaceRegionIfChanged(
    charts,
    "node-status",
    { language: state.language, rows: summary.node_status || {} },
    ui.panel(t("nodeStatusDistribution"), ui.nodeStatusChart(summary.node_status || {}), { meta: t("nodeStatusDistributionMeta") }),
  );
  ctx.replaceRegionIfChanged(
    charts,
    "node-resource",
    { language: state.language, nodes },
    ui.panel(t("nodeResourceOverview"), nodeResourceOverview(nodes, t, ui), { meta: t("nodeResourceOverviewMeta") }),
  );
  ctx.replaceRegionIfChanged(
    charts,
    "category-distribution",
    { language: state.language, rows: summary.by_category || [] },
    ui.panel(t("categoryDistribution"), ui.barChart(summary.by_category || [], "category", "count"), { meta: t("categoryDistributionMeta") }),
  );
  ctx.replaceRegionIfChanged(
    charts,
    "block-status",
    { language: state.language, rows: summary.by_block_status || [] },
    ui.panel(t("blockStatusDistribution"), ui.barChart(summary.by_block_status || [], "block_status", "count"), { meta: t("blockStatusDistributionMeta") }),
  );
  ctx.replaceRegionIfChanged(
    charts,
    "activity-mix",
    {
      language: state.language,
      findings: summary.findings,
      incidents: summary.incidents,
      drifts: summary.baseline_drifts,
      blocks: summary.active_blocks,
      blacklist: summary.probe_sources,
    },
    ui.panel(t("activityMix"), signalMix(summary, t, ui), { meta: t("activityMixMeta") }),
  );

  if (!operatorView) return;

  ctx.replaceRegionIfChanged(
    shell,
    "overview-operator",
    { language: state.language, blocks },
    ui.panel(t("activeBlocksSnapshot"), ui.compactRecords(blocks, blockRecord(t, ui)), {
      meta: t("activeBlocksSnapshotMeta"),
      tone: "response",
    }),
  );
  ctx.replaceRegionIfChanged(
    shell,
    "overview-latest",
    { language: state.language, findings, incidents },
    ui.splitPanels(
      ui.panel(t("latestFindings"), ui.renderTable(findings, OVERVIEW_FINDING_COLUMNS), { meta: t("latestFindingsMeta") }),
      ui.panel(t("latestIncidents"), ui.renderTable(incidents, OVERVIEW_INCIDENT_COLUMNS), { meta: t("latestIncidentsMeta") }),
    ),
  );
  ctx.replaceRegionIfChanged(
    shell,
    "overview-drifts",
    { language: state.language, drifts },
    ui.panel(t("recentBaselineDrift"), ui.renderTable(drifts, OVERVIEW_DRIFT_COLUMNS), { meta: t("recentBaselineDriftMeta") }),
  );
}

function nodeResourceOverview(nodes, t, ui) {
  const summary = averageNodeMetrics(nodes);
  return ui.insightStrip([
    {
      label: t("cpuUsage"),
      value: percent(summary.cpu),
      detail: t("nodeResourceAverage"),
      tone: "neutral",
    },
    {
      label: t("memoryUsage"),
      value: percent(summary.memory),
      detail: t("nodeResourceAverage"),
      tone: "attention",
    },
    {
      label: t("loadAverage"),
      value: summary.load === null ? "-" : summary.load.toFixed(2),
      detail: t("nodeResourceAverage"),
      tone: "fresh",
    },
  ]);
}

function averageNodeMetrics(nodes) {
  const values = { cpu: [], memory: [], load: [] };
  for (const node of nodes || []) {
    const metrics = node.metrics && typeof node.metrics === "object" ? node.metrics : {};
    pushFinite(values.cpu, metrics.cpu_percent);
    pushFinite(values.memory, metrics.memory_used_percent);
    pushFinite(values.load, metrics.load1);
  }
  return {
    cpu: average(values.cpu),
    memory: average(values.memory),
    load: average(values.load),
  };
}

function pushFinite(items, value) {
  const number = Number(value);
  if (Number.isFinite(number)) items.push(number);
}

function average(items) {
  if (!items.length) return null;
  return items.reduce((sum, value) => sum + value, 0) / items.length;
}

function percent(value) {
  return value === null ? "-" : `${value.toFixed(1)}%`;
}

function metric(label, value, tone, caption) {
  return { label, value, tone, caption };
}

function signalMix(summary, t, ui) {
  return ui.donutChart([
    { label: t("findingsMetric"), value: summary.findings || 0, className: "chart-high" },
    { label: t("incidentsMetric"), value: summary.incidents || 0, className: "chart-critical" },
    { label: t("driftsMetric"), value: summary.baseline_drifts || 0, className: "chart-medium" },
    { label: t("blocksMetric"), value: summary.active_blocks || 0, className: "chart-low" },
    { label: t("blacklistMetric"), value: summary.probe_sources || 0, className: "chart-fresh" },
  ]);
}

function highRiskCount(rows) {
  return rows
    .filter((row) => ["critical", "high"].includes(String(row.severity || "").toLowerCase()))
    .reduce((sum, row) => sum + Number(row.count || 0), 0);
}

function roleAllows(role, minRole) {
  const levels = { public: 0, operator: 1, admin: 2 };
  return (levels[String(role || "public")] ?? 0) >= (levels[minRole] ?? 0);
}

function blockRecord(t, ui) {
  return (block) => ({
    title: block.rule_id || t("activeResponse"),
    meta: [block.node_name, block.rule_id].filter(Boolean).join(" / "),
    detail: ui.reasonText(block.reason),
    tone: "blocked",
  });
}

function fleetStatus(counts, t) {
  if (counts.offline > 0) {
    return {
      label: formatTemplate(t("offlineCount"), { count: counts.offline }),
      tone: "offline",
      detail: t("fleetStatusOffline"),
    };
  }
  if (counts.stale > 0) {
    return {
      label: formatTemplate(t("staleCount"), { count: counts.stale }),
      tone: "stale",
      detail: t("fleetStatusStale"),
    };
  }
  return {
    label: t("fresh"),
    tone: "fresh",
    detail: counts.retired > 0 ? t("fleetStatusRetired") : t("fleetStatusFresh"),
  };
}
