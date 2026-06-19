const API_BASE = "/api/v1";
const BUILTIN_PAGES = [
  { id: "overview", label: "Overview", render: renderOverview },
  { id: "findings", label: "Findings", render: (ctx) => renderDataset(ctx, "findings") },
  { id: "incidents", label: "Incidents", render: (ctx) => renderDataset(ctx, "incidents") },
  { id: "drifts", label: "Baseline Drift", render: (ctx) => renderDataset(ctx, "baseline_drifts") },
  { id: "blocks", label: "Active Blocks", render: (ctx) => renderDataset(ctx, "active_blocks") },
  { id: "nodes", label: "Nodes", render: (ctx) => renderDataset(ctx, "nodes") },
];

const DATASETS = {
  findings: {
    title: "Recent findings",
    description: "Risk-scored alerts received from fleet nodes.",
    endpoint: "/findings",
    columns: ["timestamp", "node_id", "severity", "rule_id", "category", "subject", "title"],
  },
  incidents: {
    title: "Recent incidents",
    description: "Correlated attack chains and repeated signal groups.",
    endpoint: "/incidents",
    columns: ["last_seen", "node_id", "severity", "score", "title", "summary"],
  },
  baseline_drifts: {
    title: "Baseline drift",
    description: "Changes that need operator review before baseline refresh.",
    endpoint: "/baseline-drifts",
    columns: ["timestamp", "node_id", "severity", "rule_id", "tier", "subject", "review_action"],
  },
  active_blocks: {
    title: "Active blocks",
    description: "Firewall blocks that are still active on reporting nodes.",
    endpoint: "/active-blocks",
    columns: ["blocked_at", "node_id", "ip", "rule_id", "backend", "reason", "expires_at"],
  },
  nodes: {
    title: "Fleet nodes",
    description: "Hosts that recently pushed security telemetry.",
    endpoint: "/nodes",
    columns: ["last_seen_at", "node_id", "node_name", "hostname", "agent_version", "privacy_mode"],
  },
};

const state = {
  currentPage: "overview",
  pages: [],
  datasets: {},
  settings: {},
  theme: null,
  manifest: null,
};

const app = document.querySelector("#app");
const nav = document.querySelector("#nav");
const refreshButton = document.querySelector("#refresh-button");
const themeSelect = document.querySelector("#theme-select");

init().catch((error) => renderError(error));

async function init() {
  state.settings = await fetchJson(`${API_BASE}/settings`).catch(() => ({ theme: "default" }));
  state.theme = selectedTheme(state.settings.theme || "default");
  state.manifest = await loadTheme(state.theme);
  state.pages = await buildPages(state.manifest);
  bindToolbar();
  await refresh();
}

function bindToolbar() {
  const themes = new Set(["default", state.theme]);
  for (const theme of state.manifest.available_themes || []) themes.add(theme.id || theme);
  themeSelect.replaceChildren(
    ...[...themes].map((theme) => {
      const option = document.createElement("option");
      option.value = theme;
      option.textContent = theme;
      option.selected = theme === state.theme;
      return option;
    }),
  );
  themeSelect.addEventListener("change", () => {
    localStorage.setItem("vps-sentinel-theme", themeSelect.value);
    location.reload();
  });
  refreshButton.addEventListener("click", () => refresh());
}

async function refresh() {
  renderNav();
  await loadDatasets();
  await renderCurrentPage();
}

function selectedTheme(defaultTheme) {
  const params = new URLSearchParams(location.search);
  return params.get("theme") || localStorage.getItem("vps-sentinel-theme") || defaultTheme;
}

async function loadTheme(theme) {
  const manifest = await fetchJson(`/themes/${encodeURIComponent(theme)}/theme.json`).catch(() => ({
    name: "default",
    styles: ["theme.css"],
    pages: [],
    available_themes: ["default"],
  }));
  for (const style of manifest.styles || []) {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = themeAsset(theme, style);
    document.head.appendChild(link);
  }
  return manifest;
}

function themeAsset(theme, assetPath) {
  if (/^https?:\/\//i.test(assetPath) || assetPath.startsWith("/")) return assetPath;
  return `/themes/${encodeURIComponent(theme)}/${assetPath}`;
}

async function buildPages(manifest) {
  const pages = [...BUILTIN_PAGES];
  for (const page of manifest.pages || []) {
    if (!page.id || !page.label || !page.module) continue;
    const mod = await import(themeAsset(state.theme, page.module));
    if (typeof mod.render !== "function") continue;
    pages.push({
      id: page.id,
      label: page.label,
      render: (ctx) => mod.render({ ...ctx, page, manifest }),
    });
  }
  return pages;
}

async function loadDatasets() {
  const entries = await Promise.all(
    Object.entries(DATASETS).map(async ([key, meta]) => [key, await fetchJson(`${API_BASE}${meta.endpoint}`)]),
  );
  state.datasets = Object.fromEntries(entries);
  state.summary = await fetchJson(`${API_BASE}/summary`);
}

function renderNav() {
  nav.replaceChildren(
    ...state.pages.map((page) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `nav-button${page.id === state.currentPage ? " active" : ""}`;
      button.textContent = page.label;
      button.addEventListener("click", async () => {
        state.currentPage = page.id;
        renderNav();
        await renderCurrentPage();
      });
      return button;
    }),
  );
}

async function renderCurrentPage() {
  const page = state.pages.find((item) => item.id === state.currentPage) || state.pages[0];
  app.replaceChildren();
  await page.render(context());
}

function context() {
  return {
    api: (path) => fetchJson(`${API_BASE}${path}`),
    app,
    datasets: state.datasets,
    manifest: state.manifest,
    renderTable,
    state,
  };
}

function renderOverview(ctx) {
  const summary = ctx.state.summary || {};
  app.append(
    header("Overview", "Fleet-level signal summary from pushed agent telemetry."),
    metrics([
      ["Nodes", summary.nodes],
      ["Findings", summary.findings],
      ["Incidents", summary.incidents],
      ["Drifts", summary.baseline_drifts],
      ["Blocks", summary.active_blocks],
    ]),
    panel("Severity distribution", renderTable(summary.by_severity || [], ["severity", "count"])),
    panel("Newest findings", renderTable((ctx.datasets.findings || []).slice(0, 10), DATASETS.findings.columns)),
  );
}

function renderDataset(ctx, datasetKey) {
  const meta = DATASETS[datasetKey];
  app.append(header(meta.title, meta.description), panel(meta.title, renderTable(ctx.datasets[datasetKey] || [], meta.columns)));
}

function header(title, description) {
  const wrapper = document.createElement("div");
  wrapper.className = "section-head";
  const text = document.createElement("div");
  const heading = document.createElement("h2");
  heading.textContent = title;
  const body = document.createElement("p");
  body.textContent = description;
  text.append(heading, body);
  wrapper.append(text);
  return wrapper;
}

function metrics(items) {
  const wrapper = document.createElement("div");
  wrapper.className = "grid metrics";
  for (const [label, value] of items) {
    const item = document.createElement("div");
    item.className = "metric";
    item.append(span("label", label), span("value", String(value ?? 0)));
    wrapper.append(item);
  }
  return wrapper;
}

function panel(title, content) {
  const wrapper = document.createElement("section");
  wrapper.className = "panel";
  const head = document.createElement("div");
  head.className = "panel-title";
  const heading = document.createElement("h3");
  heading.textContent = title;
  head.append(heading);
  wrapper.append(head, content);
  return wrapper;
}

function renderTable(rows, columns) {
  if (!rows || rows.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No data in the selected range.";
    return empty;
  }
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  const thead = document.createElement("thead");
  const headerRow = document.createElement("tr");
  for (const column of columns) {
    const th = document.createElement("th");
    th.textContent = column.replaceAll("_", " ");
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
    tbody.append(tr);
  }
  table.append(thead, tbody);
  wrap.append(table);
  return wrap;
}

function formatValue(column, value) {
  if (column === "severity") {
    const badge = span(`badge severity-${String(value || "").toLowerCase()}`, value || "unknown");
    return badge;
  }
  if (value === null || value === undefined || value === "") return span("muted", "-");
  if (column.includes("_at") || column.includes("time") || column === "timestamp" || column === "last_seen") {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return document.createTextNode(date.toLocaleString());
  }
  return document.createTextNode(String(value));
}

function span(className, text) {
  const item = document.createElement("span");
  item.className = className;
  item.textContent = text;
  return item;
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  return response.json();
}

function renderError(error) {
  app.replaceChildren();
  const box = document.createElement("div");
  box.className = "error";
  box.textContent = error?.message || String(error);
  app.append(box);
}
