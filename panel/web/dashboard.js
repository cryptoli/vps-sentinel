import { formatTemplate } from "./components.js";

const OVERVIEW_FINDING_COLUMNS = ["timestamp", "node_name", "severity", "rule_id", "subject"];
const OVERVIEW_INCIDENT_COLUMNS = ["last_seen", "node_name", "severity", "score", "title"];
const OVERVIEW_DRIFT_COLUMNS = ["timestamp", "node_name", "severity", "rule_id", "tier", "subject"];

export function renderOverviewDashboard(ctx) {
  const { app, state, t, ui } = ctx;
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

  const sections = [
    ui.heroBand({
      eyebrow: t("securityPosture"),
      title: t("overviewTitle"),
      description: t("overviewDescription"),
      status: ui.statusSummary(status.label, status.tone, status.detail),
      actions: [ui.timeRangeHint(t("range_24h"))],
    }),
    ui.insightStrip([
      {
        label: t("attentionQueue"),
        value: queueCount(summary),
        detail: t("attentionQueueDetail"),
        tone: "attention",
      },
      {
        label: t("fleetFreshness"),
        value: status.label,
        detail: status.detail,
        tone: status.tone,
      },
      {
        label: t("highRiskPressure"),
        value: highRiskCount(severityRows),
        detail: t("highRiskPressureDetail"),
        tone: "risk",
      },
    ]),
    ui.metrics([
      metric(t("nodesMetric"), summary.nodes, "nodes", t("nodesMetricHint")),
      metric(t("findingsMetric"), summary.findings, "findings", t("findingsMetricHint")),
      metric(t("incidentsMetric"), summary.incidents, "incidents", t("incidentsMetricHint")),
      metric(t("driftsMetric"), summary.baseline_drifts, "drifts", t("driftsMetricHint")),
      metric(t("blocksMetric"), summary.active_blocks, "blocks", t("blocksMetricHint")),
      metric(t("blacklistMetric"), summary.probe_sources, "blacklist", t("blacklistMetricHint")),
    ]),
    ui.dashboardGrid(
      ui.panel(t("activityTrend"), ui.trendChart(trends), {
        meta: t("activityTrendMeta"),
        tone: "wide",
      }),
      ui.panel(t("severityDistribution"), ui.barChart(severityRows, "severity", "count"), {
        meta: t("severityDistributionMeta"),
      }),
      ui.panel(t("nodeStatusDistribution"), ui.nodeStatusChart(summary.node_status || {}), {
        meta: t("nodeStatusDistributionMeta"),
      }),
      ui.panel(t("nodeResourceOverview"), nodeResourceOverview(nodes, t, ui), {
        meta: t("nodeResourceOverviewMeta"),
      }),
      ui.panel(t("categoryDistribution"), ui.barChart(summary.by_category || [], "category", "count"), {
        meta: t("categoryDistributionMeta"),
      }),
      ui.panel(t("blockStatusDistribution"), ui.barChart(summary.by_block_status || [], "block_status", "count"), {
        meta: t("blockStatusDistributionMeta"),
      }),
      ui.panel(t("activityMix"), signalMix(summary, t, ui), {
        meta: t("activityMixMeta"),
      }),
    ),
  ];

  if (operatorView) {
    sections.push(
      ui.dashboardGrid(
        ui.panel(t("activeBlocksSnapshot"), ui.compactRecords(blocks, blockRecord(t, ui)), {
          meta: t("activeBlocksSnapshotMeta"),
          tone: "response",
        }),
      ),
      ui.splitPanels(
        ui.panel(t("latestFindings"), ui.renderTable(findings, OVERVIEW_FINDING_COLUMNS), {
          meta: t("latestFindingsMeta"),
        }),
        ui.panel(t("latestIncidents"), ui.renderTable(incidents, OVERVIEW_INCIDENT_COLUMNS), {
          meta: t("latestIncidentsMeta"),
        }),
      ),
      ui.panel(t("recentBaselineDrift"), ui.renderTable(drifts, OVERVIEW_DRIFT_COLUMNS), {
        meta: t("recentBaselineDriftMeta"),
      }),
    );
  }

  app.append(ui.dashboardShell(...sections));
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

function queueCount(summary) {
  return Number(summary.findings || 0) + Number(summary.baseline_drifts || 0);
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
