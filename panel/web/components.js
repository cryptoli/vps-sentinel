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
    for (const itemConfig of items) {
      const { label, value, tone, caption } = Array.isArray(itemConfig)
        ? { label: itemConfig[0], value: itemConfig[1], tone: itemConfig[2], caption: "" }
        : itemConfig;
      const item = document.createElement("div");
      item.className = `metric metric-${tone}`;
      const head = document.createElement("div");
      head.className = "metric-head";
      head.append(span("label", label), span("metric-signal", ""));
      item.append(head, span("value", number(value)));
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
      for (const column of columns) {
        const td = document.createElement("td");
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
      const severity = String(row[labelKey] || "unknown").toLowerCase();
      const value = Number(row[valueKey] || 0);
      const item = document.createElement("div");
      item.className = "bar-row";
      item.append(span("bar-label", translateValue("severity", severity)));
      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = `bar-fill severity-${severity}`;
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

  function donutGradient(items) {
    const colors = {
      "chart-critical": "var(--critical)",
      "chart-high": "var(--high)",
      "chart-medium": "var(--medium)",
      "chart-low": "var(--low)",
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
    wrapper.className = "node-freshness";
    if (!nodes.length) return emptyChart();
    for (const node of nodes.slice(0, 8)) {
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
        span("freshness-name", node.node_name || node.node_id || "-"),
        span("freshness-state", t(status)),
        span("freshness-age", relativeAge(age)),
      );
      wrapper.append(row);
    }
    return wrapper;
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
    if (column === "privacy_mode") {
      return document.createTextNode(translateValue("privacy_mode", value));
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

  function columnLabel(column) {
    return t(column) || column.replaceAll("_", " ");
  }

  function translateValue(column, value) {
    const normalized = String(value || "unknown").toLowerCase();
    if (column === "severity" || column === "privacy_mode") return t(normalized) || value || t("unknown");
    return value || t("unknown");
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
    const id = String(node.node_id || "").trim().toLowerCase();
    const name = String(node.node_name || "").trim().toLowerCase();
    const hostname = String(node.hostname || "").trim();
    const version = String(node.agent_version || "").trim().toLowerCase();
    return version.includes("smoke") || (id === "local-host" && !hostname && (!name || name === "local-host"));
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
    labelControl,
    loading,
    metrics,
    nodeFreshness,
    option,
    panel,
    renderTable,
    jsonBlock,
    sectionHeader,
    select,
    span,
    splitPanels,
    statusSummary,
    timeRangeHint,
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
