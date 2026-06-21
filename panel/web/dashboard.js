import { formatTemplate } from "./components.js";

const OVERVIEW_FINDING_COLUMNS = ["timestamp", "node_name", "severity", "rule_id", "subject"];
const OVERVIEW_INCIDENT_COLUMNS = ["last_seen", "node_name", "severity", "score", "title"];
const OVERVIEW_DRIFT_COLUMNS = ["timestamp", "node_name", "severity", "rule_id", "tier", "subject"];

export function renderOverviewDashboard(ctx) {
  const { app, state, t, ui } = ctx;
  const summary = state.summary || {};
  const datasets = state.datasets || {};
  const nodes = canonicalNodes(datasets.nodes?.items || [], state.settings || {});
  const findings = datasets.findings?.items || [];
  const incidents = datasets.incidents?.items || [];
  const drifts = datasets.baseline_drifts?.items || [];
  const blocks = datasets.active_blocks?.items || [];
  const severityRows = summary.by_severity || [];
  const status = fleetStatus(nodes, ui, t);

  app.append(
    ui.dashboardShell(
      ui.heroBand({
        eyebrow: t("securityPosture"),
        title: t("overviewTitle"),
        description: t("overviewDescription"),
        status: ui.statusSummary(status.label, status.tone, status.detail),
        actions: [ui.timeRangeHint(t("range_24h")), ui.freshnessBadge(nodes)],
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
        metric(t("nodesMetric"), summary.nodes ?? nodes.length, "nodes", t("nodesMetricHint")),
        metric(t("findingsMetric"), summary.findings, "findings", t("findingsMetricHint")),
        metric(t("incidentsMetric"), summary.incidents, "incidents", t("incidentsMetricHint")),
        metric(t("driftsMetric"), summary.baseline_drifts, "drifts", t("driftsMetricHint")),
        metric(t("blocksMetric"), summary.active_blocks, "blocks", t("blocksMetricHint")),
      ]),
      ui.dashboardGrid(
        ui.panel(t("severityDistribution"), ui.barChart(severityRows, "severity", "count"), {
          meta: t("severityDistributionMeta"),
          tone: "wide",
        }),
        ui.panel(t("activityMix"), signalMix(summary, t, ui), {
          meta: t("activityMixMeta"),
        }),
        ui.panel(t("fleetFreshness"), ui.nodeFreshness(nodes), {
          meta: t("fleetFreshnessMeta"),
          tone: "fleet",
        }),
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
    ),
  );
}

function canonicalNodes(nodes, settings) {
  const freshnessThresholdMinutes = positiveNumber(settings.freshness_threshold_minutes, 30);
  const retiredThresholdMinutes = Math.max(
    freshnessThresholdMinutes + 1,
    positiveNumber(settings.node_retired_threshold_minutes, 720),
  );
  const groups = new Map();
  for (const node of nodes) {
    const key = String(node.node_name || "").trim();
    if (!key) continue;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key).push(node);
  }

  const merged = [];
  for (const group of groups.values()) {
    const ordered = group.sort((left, right) => lastSeenMs(right) - lastSeenMs(left));
    const freshNodes = ordered.filter((node) => ageMinutes(node.last_seen_at) <= freshnessThresholdMinutes);
    if (freshNodes.length) {
      merged.push(...freshNodes);
      continue;
    }
    const retainedNodes = ordered.filter((node) => ageMinutes(node.last_seen_at) <= retiredThresholdMinutes);
    merged.push(...(retainedNodes.length ? retainedNodes : ordered.slice(0, 1)));
  }

  return merged.sort((left, right) => lastSeenMs(right) - lastSeenMs(left));
}

function positiveNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function ageMinutes(value) {
  const timestamp = lastSeenMs(value);
  if (!Number.isFinite(timestamp)) return Number.POSITIVE_INFINITY;
  return Math.max(0, Math.floor((Date.now() - timestamp) / 60000));
}

function lastSeenMs(value) {
  const timestamp = new Date(value).getTime();
  return Number.isNaN(timestamp) ? 0 : timestamp;
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

function blockRecord(t, ui) {
  return (block) => ({
    title: block.rule_id || t("activeResponse"),
    meta: [block.node_name, block.rule_id].filter(Boolean).join(" / "),
    detail: ui.reasonText(block.reason),
    tone: "blocked",
  });
}

function fleetStatus(nodes, ui, t) {
  const counts = ui.freshnessCounts(nodes);
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
