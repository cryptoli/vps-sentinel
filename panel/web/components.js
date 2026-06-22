export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = 30;
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = 720;

export function createView({ t, language, freshness = {} }) {
  const freshnessThresholdMinutes = Number.isFinite(Number(freshness.thresholdMinutes))
    ? Math.max(1, Number(freshness.thresholdMinutes))
    : DEFAULT_FRESHNESS_THRESHOLD_MINUTES;
  const offlineThresholdMinutes = freshnessThresholdMinutes * 6;
  const retiredThresholdMinutes = Number.isFinite(Number(freshness.retiredThresholdMinutes))
    ? Math.max(offlineThresholdMinutes + 1, Number(freshness.retiredThresholdMinutes))
    : DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES;
  const nowMs = Number.isFinite(Number(freshness.nowMs)) ? Number(freshness.nowMs) : Date.now();

  function sectionHeader(title, description, action) {
    const wrapper = document.createElement("div");
    wrapper.className = "section-head";
    const text = document.createElement("div");
    const heading = document.createElement("h2");
    heading.textContent = title;
    const body = document.createElement("p");
    body.textContent = description;
    text.append(heading, body);
    wrapper.append(text);
    if (action) wrapper.append(action);
    return wrapper;
  }

  function metrics(items) {
    const wrapper = document.createElement("div");
    wrapper.className = "grid metrics";
    const max = Math.max(
      1,
      ...items.map((itemConfig) => Number((Array.isArray(itemConfig) ? itemConfig[1] : itemConfig.value) || 0)),
    );
    for (const itemConfig of items) {
      const { label, value, tone, caption } = Array.isArray(itemConfig)
        ? { label: itemConfig[0], value: itemConfig[1], tone: itemConfig[2], caption: "" }
        : itemConfig;
      const ratio = Math.max(8, Math.min(100, (Number(value || 0) / max) * 100));
      const item = document.createElement("div");
      item.className = `metric metric-${tone}`;
      item.style.setProperty("--metric-ratio", `${ratio}%`);
      const head = document.createElement("div");
      head.className = "metric-head";
      head.append(span("label", label), span("metric-signal", ""));
      const visual = document.createElement("div");
      visual.className = "metric-visual";
      visual.append(span("metric-bar", ""));
      item.append(head, span("value", number(value)), visual);
      if (caption) item.append(span("metric-caption", caption));
      wrapper.append(item);
    }
    return wrapper;
  }

  function dashboardShell(...children) {
    const wrapper = document.createElement("div");
    wrapper.className = "dashboard-shell";
    wrapper.append(...children);
    return wrapper;
  }

  function heroBand({ eyebrow, title, description, status, actions = [] }) {
    const wrapper = document.createElement("section");
    wrapper.className = "hero-band";
    const copy = document.createElement("div");
    copy.className = "hero-copy";
    copy.append(span("hero-eyebrow", eyebrow), heading("h2", title), paragraph(description));
    const aside = document.createElement("div");
    aside.className = "hero-actions";
    aside.append(...actions.filter(Boolean));
    wrapper.append(copy);
    if (status || aside.childElementCount) {
      const rail = document.createElement("div");
      rail.className = "hero-rail";
      if (status) rail.append(status);
      if (aside.childElementCount) rail.append(aside);
      wrapper.append(rail);
    }
    return wrapper;
  }

  function statusSummary(label, tone, detail) {
    const wrapper = document.createElement("div");
    wrapper.className = `status-summary ${tone || "fresh"}`;
    wrapper.append(span("status-summary-label", label), span("status-summary-detail", detail));
    return wrapper;
  }

  function timeRangeHint(label) {
    return span("time-range-hint", label);
  }

  function chartsGrid(items) {
    const wrapper = document.createElement("div");
    wrapper.className = "charts-grid";
    wrapper.append(...items);
    return wrapper;
  }

  function dashboardGrid(...items) {
    const wrapper = document.createElement("div");
    wrapper.className = "dashboard-grid";
    wrapper.append(...items);
    return wrapper;
  }

  function insightStrip(items) {
    const wrapper = document.createElement("div");
    wrapper.className = "insight-strip";
    for (const item of items) {
      const card = document.createElement("article");
      card.className = `insight-card ${item.tone || "neutral"}`;
      card.append(
        span("insight-label", item.label),
        span("insight-value", item.value),
        span("insight-detail", item.detail),
      );
      wrapper.append(card);
    }
    return wrapper;
  }

  function splitPanels(...items) {
    const wrapper = document.createElement("div");
    wrapper.className = "split-panels";
    wrapper.append(...items);
    return wrapper;
  }

  function panel(title, content, options = {}) {
    const wrapper = document.createElement("section");
    wrapper.className = `panel${options.tone ? ` panel-${options.tone}` : ""}`;
    const head = document.createElement("div");
    head.className = "panel-title";
    const text = document.createElement("div");
    text.className = "panel-title-copy";
    text.append(heading("h3", title));
    if (options.meta) text.append(span("panel-meta", options.meta));
    head.append(text);
    if (options.action) head.append(options.action);
    wrapper.append(head, content);
    return wrapper;
  }

  function compactRecords(rows, mapRecord) {
    const wrapper = document.createElement("div");
    wrapper.className = "compact-records";
    if (!rows.length) return emptyChart();
    for (const row of rows.slice(0, 5).map(mapRecord)) {
      const item = document.createElement("article");
      item.className = `compact-record ${row.tone || "neutral"}`;
      item.append(
        span("compact-record-title", row.title || "-"),
        span("compact-record-meta", row.meta || "-"),
        span("compact-record-detail", row.detail || "-"),
      );
      wrapper.append(item);
    }
    return wrapper;
  }

  function renderTable(rows, columns, options = {}) {
    if (!rows || rows.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = t("noData");
      return empty;
    }
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    const table = document.createElement("table");
    const thead = document.createElement("thead");
    const headerRow = document.createElement("tr");
    for (const column of columns) {
      const th = document.createElement("th");
      th.textContent = columnLabel(column);
      headerRow.append(th);
    }
    if (typeof options.onRowAction === "function") {
      const th = document.createElement("th");
      th.textContent = options.actionHeader || t("actions");
      headerRow.append(th);
    }
    thead.append(headerRow);
    const tbody = document.createElement("tbody");
    for (const row of rows) {
      const tr = document.createElement("tr");
      tr.className = tableRowClass(row);
      for (const column of columns) {
        const td = document.createElement("td");
        td.dataset.label = columnLabel(column);
        td.append(formatValue(column, row[column]));
        tr.append(td);
      }
      if (typeof options.onRowAction === "function") {
        const td = document.createElement("td");
        const action = button(options.actionLabel || t("details"), "button", "secondary compact");
        action.addEventListener("click", () => options.onRowAction(row));
        td.append(action);
        tr.append(td);
      }
      tbody.append(tr);
    }
    table.append(thead, tbody);
    wrap.append(table);
    return wrap;
  }

  function barChart(rows, labelKey, valueKey) {
    const wrapper = document.createElement("div");
    wrapper.className = "bar-chart";
    const max = Math.max(1, ...rows.map((row) => Number(row[valueKey] || 0)));
    if (!rows.length) return emptyChart();
    for (const row of rows) {
      const labelValue = String(row[labelKey] || "unknown").toLowerCase();
      const value = Number(row[valueKey] || 0);
      const item = document.createElement("div");
      item.className = "bar-row";
      item.append(span("bar-label", translateValue(labelKey, labelValue)));
      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = labelKey === "severity"
        ? `bar-fill severity-${labelValue}`
        : `bar-fill bar-fill-${safeCssClass(labelValue)}`;
      fill.style.width = `${Math.max(4, (value / max) * 100)}%`;
      track.append(fill);
      item.append(track, span("bar-value", number(value)));
      wrapper.append(item);
    }
    return wrapper;
  }

  function donutChart(items) {
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    if (total === 0) return emptyChart();
    const wrapper = document.createElement("div");
    wrapper.className = "donut-card";
    const donut = document.createElement("div");
    donut.className = "donut";
    donut.style.background = donutGradient(items);
    donut.append(span("donut-value", number(total)));
    const legend = document.createElement("div");
    legend.className = "legend";
    for (const item of items) {
      const row = document.createElement("div");
      row.className = "legend-row";
      row.append(
        span(`legend-dot ${item.className}`, ""),
        span("legend-label", item.label),
        span("legend-value", number(item.value)),
      );
      legend.append(row);
    }
    wrapper.append(donut, legend);
    return wrapper;
  }

  function trendChart(rows) {
    if (!rows?.length) return emptyChart();
    const wrapper = document.createElement("div");
    wrapper.className = "trend-chart trend-chart-line";
    const values = rows.slice(-24).map((row) => ({
      label: String(row.bucket || "").slice(11, 16) || "-",
      value: Number(row.total || 0),
    }));
    const max = Math.max(1, ...values.map((row) => row.value));
    const width = 360;
    const height = 180;
    const padding = { top: 18, right: 14, bottom: 30, left: 18 };
    const innerWidth = width - padding.left - padding.right;
    const innerHeight = height - padding.top - padding.bottom;
    const points = values.map((row, index) => {
      const x = padding.left + (values.length <= 1 ? 0 : (index / (values.length - 1)) * innerWidth);
      const y = padding.top + innerHeight - (row.value / max) * innerHeight;
      return { ...row, x, y };
    });
    const linePath = points.map((point, index) => `${index === 0 ? "M" : "L"} ${point.x.toFixed(2)} ${point.y.toFixed(2)}`).join(" ");
    const areaPath = `${linePath} L ${padding.left + innerWidth} ${padding.top + innerHeight} L ${padding.left} ${padding.top + innerHeight} Z`;
    const svg = svgNode("svg", {
      class: "trend-svg",
      viewBox: `0 0 ${width} ${height}`,
      role: "img",
      "aria-label": t("activityTrend"),
      preserveAspectRatio: "none",
    });
    for (const ratio of [0, 0.25, 0.5, 0.75, 1]) {
      const y = padding.top + innerHeight - ratio * innerHeight;
      svg.append(svgNode("line", { class: "trend-grid-line", x1: padding.left, x2: padding.left + innerWidth, y1: y, y2: y }));
    }
    svg.append(svgNode("path", { class: "trend-area", d: areaPath }));
    svg.append(svgNode("path", { class: "trend-line-path", d: linePath }));
    const last = points.at(-1);
    if (last) {
      svg.append(svgNode("circle", { class: "trend-pulse", cx: last.x, cy: last.y, r: 5 }));
    }
    const axis = document.createElement("div");
    axis.className = "trend-axis";
    for (const point of points.filter((_, index) => index % Math.ceil(points.length / 6) === 0 || index === points.length - 1)) {
      axis.append(span("trend-axis-label", point.label));
    }
    wrapper.append(svg, axis);
    return wrapper;
  }

  function svgNode(name, attributes = {}) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (const [key, value] of Object.entries(attributes)) {
      node.setAttribute(key, String(value));
    }
    return node;
  }

  function donutGradient(items) {
    const colors = {
      "chart-critical": "var(--critical)",
      "chart-high": "var(--high)",
      "chart-medium": "var(--medium)",
      "chart-low": "var(--low)",
      "chart-fresh": "var(--success)",
      "chart-retired": "var(--retired)",
    };
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    let start = 0;
    const segments = items
      .filter((item) => Number(item.value || 0) > 0)
      .map((item) => {
        const pct = (Number(item.value) / total) * 100;
        const segment = `${colors[item.className] || "var(--accent)"} ${start}% ${start + pct}%`;
        start += pct;
        return segment;
      });
    return `conic-gradient(${segments.join(", ")})`;
  }

  function nodeFreshness(nodes) {
    const wrapper = document.createElement("div");
    wrapper.className = "node-health-widget";
    if (!nodes.length) return emptyChart();

    const counts = freshnessCounts(nodes);
    const summary = document.createElement("div");
    summary.className = "freshness-summary-grid";
    for (const status of ["fresh", "stale", "offline", "retired"]) {
      const item = document.createElement("div");
      item.className = `freshness-summary ${status}`;
      item.append(span("freshness-summary-value", number(counts[status])), span("freshness-summary-label", t(status)));
      summary.append(item);
    }

    const list = document.createElement("div");
    list.className = "node-freshness";
    const visibleNodes = nodes.slice(0, 8);
    for (const node of visibleNodes) {
      const age = ageMinutes(node.last_seen_at);
      const status = freshnessStatus(age, node);
      const row = document.createElement("div");
      row.className = `freshness-row ${status}`;
      row.title = formatTemplate(t(`${status}Reason`), {
        age: relativeAge(age),
        threshold: freshnessThresholdMinutes,
        offlineThreshold: offlineThresholdMinutes,
        retiredThreshold: retiredThresholdMinutes,
      });
      row.append(
        span(`status-dot ${status}`, ""),
        span("freshness-name", node.node_name || "-"),
        span("freshness-state", t(status)),
        span("freshness-age", relativeAge(age)),
      );
      list.append(row);
    }
    if (nodes.length > visibleNodes.length) {
      const note = document.createElement("div");
      note.className = "node-overflow-note";
      note.textContent = formatTemplate(t("moreNodes"), { count: nodes.length - visibleNodes.length });
      list.append(note);
    }
    wrapper.append(summary, list);
    return wrapper;
  }

  function nodeStatusChart(counts = {}) {
    return donutChart([
      { label: t("fresh"), value: counts.fresh || 0, className: "chart-fresh" },
      { label: t("stale"), value: counts.stale || 0, className: "chart-medium" },
      { label: t("offline"), value: counts.offline || 0, className: "chart-critical" },
      { label: t("retired"), value: counts.retired || 0, className: "chart-retired" },
    ]);
  }

  function nodeProbeGrid(nodes) {
    const wrapper = document.createElement("div");
    wrapper.className = "node-probe-grid";
    if (!nodes?.length) {
      wrapper.append(emptyChart());
      return wrapper;
    }
    const orderedNodes = [...nodes].sort((left, right) => {
      const priority = { offline: 0, stale: 1, fresh: 2, retired: 3 };
      const leftStatus = freshnessStatus(ageMinutes(left.last_seen_at), left);
      const rightStatus = freshnessStatus(ageMinutes(right.last_seen_at), right);
      return (priority[leftStatus] ?? 9) - (priority[rightStatus] ?? 9);
    });
    for (const node of orderedNodes) {
      const age = ageMinutes(node.last_seen_at);
      const status = freshnessStatus(age, node);
      const metrics = normalizeNodeMetrics(node.metrics);
      const card = document.createElement("article");
      card.className = `node-probe-card ${status}`;
      const head = document.createElement("div");
      head.className = "node-probe-head";
      head.append(
        span(`status-dot ${status}`, ""),
        span("node-probe-name", node.node_name || "-"),
        span("node-probe-state", t(status)),
      );
      const meta = document.createElement("div");
      meta.className = "node-probe-meta";
      meta.append(nodeProbeMeta(t("last_seen_at"), relativeAge(age)));
      if (node.agent_version) {
        meta.append(nodeProbeMeta(t("agent_version"), node.agent_version));
      }
      if (node.privacy_mode) {
        meta.append(nodeProbeMeta(t("privacy_mode"), translateValue("privacy_mode", node.privacy_mode)));
      }
      const gauges = document.createElement("div");
      gauges.className = "node-probe-gauges";
      gauges.append(
        nodeProbeGauge(t("cpuUsage"), percentText(metrics.cpu_percent), metrics.cpu_percent, "cpu"),
        nodeProbeGauge(t("memoryUsage"), percentText(metrics.memory_used_percent), metrics.memory_used_percent, "memory"),
        nodeProbeGauge(t("loadAverage"), loadText(metrics), loadRatio(metrics), "load"),
      );
      const traffic = document.createElement("div");
      traffic.className = "node-probe-traffic";
      traffic.append(
        nodeProbeMeta(t("uploadSpeed"), rateText(metrics.network_tx_rate_bps)),
        nodeProbeMeta(t("downloadSpeed"), rateText(metrics.network_rx_rate_bps)),
        nodeProbeMeta(t("outboundTraffic"), bytesText(metrics.network_tx_bytes)),
        nodeProbeMeta(t("inboundTraffic"), bytesText(metrics.network_rx_bytes)),
        nodeProbeMeta(t("uptimeDays"), uptimeText(metrics.uptime_days)),
        nodeProbeMeta(t("agentMemory"), metrics.agent_rss_kb ? `${number(metrics.agent_rss_kb)} KiB` : "-"),
      );
      card.append(head, meta, gauges, traffic);
      wrapper.append(card);
    }
    return wrapper;
  }

  function nodeProbeGauge(label, value, percent, tone) {
    const item = document.createElement("div");
    item.className = `node-probe-gauge gauge-${tone}`;
    item.style.setProperty("--gauge-value", `${clampedPercent(percent)}%`);
    const ring = document.createElement("span");
    ring.className = "gauge-ring";
    ring.append(span("gauge-value", value));
    item.append(ring, span("gauge-label", label));
    return item;
  }

  function nodeProbeMeta(label, value) {
    const item = document.createElement("span");
    item.className = "node-probe-meta-item";
    item.append(span("node-probe-meta-label", label), span("node-probe-meta-value", value || "-"));
    return item;
  }

  function normalizeNodeMetrics(metrics) {
    return metrics && typeof metrics === "object" && !Array.isArray(metrics) ? metrics : {};
  }

  function percentText(value) {
    return Number.isFinite(Number(value)) ? `${Number(value).toFixed(1)}%` : "-";
  }

  function loadText(metrics) {
    return Number.isFinite(Number(metrics.load1)) ? Number(metrics.load1).toFixed(2) : "-";
  }

  function loadRatio(metrics) {
    const load = Number(metrics.load1);
    const cores = Number(metrics.cpu_cores || 1);
    if (!Number.isFinite(load) || !Number.isFinite(cores) || cores <= 0) return null;
    return Math.min(100, (load / cores) * 100);
  }

  function rateText(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "-";
    return `${bytesText(bytes)}/s`;
  }

  function bytesText(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "-";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let index = 0;
    let size = bytes;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
  }

  function uptimeText(value) {
    const days = Number(value);
    if (!Number.isFinite(days)) return "-";
    if (days < 1) return formatTemplate(t("hoursValue"), { value: Math.max(1, Math.round(days * 24)) });
    return formatTemplate(t("daysValue"), { value: days.toFixed(days < 10 ? 1 : 0) });
  }

  function clampedPercent(value) {
    const numberValue = Number(value);
    if (!Number.isFinite(numberValue)) return 0;
    return Math.max(0, Math.min(100, numberValue));
  }

  function freshnessBadge(nodes) {
    const counts = freshnessCounts(nodes);
    const status = counts.offline > 0 ? "offline" : counts.stale > 0 ? "stale" : counts.retired > 0 ? "retired" : "fresh";
    const text =
      status === "offline"
        ? formatTemplate(t("offlineCount"), { count: counts.offline })
        : status === "stale"
          ? formatTemplate(t("staleCount"), { count: counts.stale })
          : status === "retired"
            ? formatTemplate(t("retiredCount"), { count: counts.retired })
          : t("fresh");
    const badge = span(
      `freshness-badge ${status}`,
      text,
    );
    badge.title = formatTemplate(t("freshnessThreshold"), {
      threshold: freshnessThresholdMinutes,
      offlineThreshold: offlineThresholdMinutes,
      retiredThreshold: retiredThresholdMinutes,
    });
    return badge;
  }

  function freshnessCounts(nodes) {
    return nodes.reduce(
      (acc, node) => {
        acc[freshnessStatus(ageMinutes(node.last_seen_at), node)] += 1;
        return acc;
      },
      { fresh: 0, stale: 0, offline: 0, retired: 0 },
    );
  }

  function emptyChart() {
    const empty = document.createElement("div");
    empty.className = "empty chart-empty";
    empty.textContent = t("noData");
    return empty;
  }

  function formatValue(column, value) {
    if (column === "severity") {
      return span(`badge severity-${String(value || "").toLowerCase()}`, translateValue("severity", value));
    }
    if (["rule_id", "tier"].includes(column) && value) {
      return span(`code-pill code-pill-${column}`, String(value));
    }
    if (column === "score" && value !== null && value !== undefined && value !== "") {
      return span("score-pill", number(value));
    }
    if (column === "reason") {
      return document.createTextNode(detailedReasonText(value));
    }
    if (column === "block_status") {
      return span(`badge block-${String(value || "observed").toLowerCase()}`, translateValue("block_status", value));
    }
    if (column === "privacy_mode") {
      return document.createTextNode(translateValue("privacy_mode", value));
    }
    if (Array.isArray(value)) {
      return document.createTextNode(value.length ? value.join(", ") : "-");
    }
    if (value === null || value === undefined || value === "") return span("muted", "-");
    if (isTimeColumn(column)) {
      const date = new Date(value);
      if (!Number.isNaN(date.getTime())) {
        return document.createTextNode(date.toLocaleString(language === "zh" ? "zh-CN" : "en-US"));
      }
    }
    return document.createTextNode(String(value));
  }

  function tableRowClass(row) {
    const severity = String(row?.severity || "").toLowerCase();
    return ["critical", "high", "medium", "low"].includes(severity) ? `row-${severity}` : "";
  }

  function columnLabel(column) {
    return t(column) || column.replaceAll("_", " ");
  }

  function translateValue(column, value) {
    const normalized = String(value || "unknown").toLowerCase();
    if (column === "severity" || column === "privacy_mode") return t(normalized) || value || t("unknown");
    if (column === "block_status") return t(`block_status_${normalized}`) || value || t("unknown");
    if (column === "category") return t(`category_${normalized}`) || value || t("unknown");
    return value || t("unknown");
  }

  function safeCssClass(value) {
    return String(value || "unknown").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  }

  function reasonText(value) {
    const reason = String(value || "").toLowerCase();
    if (!reason) return t("noReason");
    if (reason.includes("web") || reason.includes("http")) return t("webBlockReason");
    if (reason.includes("ssh")) return t("sshBlockReason");
    if (reason.includes("repeated") || reason.includes("permanent")) return t("repeatedBlockReason");
    return t("activeBlockReason");
  }

  function detailedReasonText(value) {
    const text = String(value || "").trim();
    if (!text) return reasonText(text);
    if (text.includes("=") || text.includes(" ")) return text;
    return reasonText(text);
  }

  function isTimeColumn(column) {
    return column.includes("_at") || column.includes("time") || column === "timestamp" || column === "last_seen" || column === "first_seen";
  }

  function ageMinutes(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return Number.POSITIVE_INFINITY;
    return Math.max(0, Math.floor((nowMs - date.getTime()) / 60000));
  }

  function freshnessStatus(minutes, node = {}) {
    if (placeholderNode(node) || !Number.isFinite(minutes) || minutes > retiredThresholdMinutes) return "retired";
    if (minutes > offlineThresholdMinutes) return "offline";
    if (minutes > freshnessThresholdMinutes) return "stale";
    return "fresh";
  }

  function placeholderNode(node) {
    const name = String(node.node_name || "").trim().toLowerCase();
    const version = String(node.agent_version || "").trim().toLowerCase();
    return version.includes("smoke") || !name || name === "local-host";
  }

  function relativeAge(minutes) {
    if (!Number.isFinite(minutes)) return "-";
    if (minutes < 60) return formatTemplate(t("minutesAgo"), { value: minutes });
    return formatTemplate(t("hoursAgo"), { value: Math.floor(minutes / 60) });
  }

  function option(value, label, selected) {
    const item = document.createElement("option");
    item.value = value;
    item.textContent = label;
    item.selected = selected;
    return item;
  }

  function input(type, name, value) {
    const item = document.createElement("input");
    item.type = type;
    item.name = name;
    item.value = value || "";
    return item;
  }

  function select(name, values, selectedValue) {
    const item = document.createElement("select");
    item.name = name;
    item.replaceChildren(...values.map((value) => option(String(value), String(value), Number(value) === Number(selectedValue))));
    return item;
  }

  function labelControl(label, control) {
    const wrapper = document.createElement("label");
    wrapper.className = "field";
    wrapper.append(span("field-label", label), control);
    return wrapper;
  }

  function detailList(items) {
    const wrapper = document.createElement("dl");
    wrapper.className = "detail-list";
    for (const [label, value] of items) {
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.append(value instanceof Node ? value : document.createTextNode(String(value || "-")));
      wrapper.append(dt, dd);
    }
    return wrapper;
  }

  function jsonBlock(value) {
    const pre = document.createElement("pre");
    pre.className = "json-block";
    pre.textContent = JSON.stringify(value ?? null, null, 2);
    return pre;
  }

  function button(label, type, variant) {
    const item = document.createElement("button");
    item.type = type;
    item.className = `button ${variant}`;
    item.textContent = label;
    return item;
  }

  function span(className, text) {
    const item = document.createElement("span");
    item.className = className;
    item.textContent = text;
    return item;
  }

  function heading(level, text) {
    const item = document.createElement(level);
    item.textContent = text;
    return item;
  }

  function paragraph(text) {
    const item = document.createElement("p");
    item.textContent = text;
    return item;
  }

  function fragment(...children) {
    const item = document.createDocumentFragment();
    item.append(...children);
    return item;
  }

  function loading() {
    const item = document.createElement("div");
    item.className = "empty";
    item.textContent = t("loading");
    return item;
  }

  function number(value) {
    return new Intl.NumberFormat(language === "zh" ? "zh-CN" : "en-US").format(Number(value || 0));
  }

  return {
    barChart,
    button,
    chartsGrid,
    compactRecords,
    dashboardGrid,
    dashboardShell,
    detailList,
    donutChart,
    fragment,
    freshnessBadge,
    freshnessCounts,
    heroBand,
    input,
    insightStrip,
    labelControl,
    loading,
    metrics,
    nodeFreshness,
    nodeProbeGrid,
    nodeStatusChart,
    option,
    panel,
    reasonText,
    renderTable,
    jsonBlock,
    sectionHeader,
    select,
    span,
    splitPanels,
    statusSummary,
    timeRangeHint,
    trendChart,
  };
}

export function formatTemplate(template, values) {
  return template.replace(/\{(\w+)\}/g, (_, key) => values[key] ?? "");
}

export function rangeInfo(page) {
  const total = page.total || 0;
  if (total === 0) return { from: 0, to: 0, total };
  return {
    from: page.offset + 1,
    to: Math.min(page.offset + page.limit, total),
    total,
  };
}
