import {
  DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
  DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
  createView,
  formatTemplate,
  rangeInfo,
} from "./components.js";
import { DATASETS } from "./datasets.js";
import { createTranslator, selectedLanguage } from "./i18n.js";

const API_BASE = "/api/v1";
const DEFAULT_LIMIT = 25;
const OVERVIEW_LIMIT = 12;
const TOKEN_STORAGE_KEY = "vps-sentinel-panel-token";
const TIME_PRESETS = ["1h", "6h", "24h", "today", "7d"];
const BUILTIN_PAGES = [
  { id: "overview", labelKey: "overview", render: renderOverview },
  { id: "findings", labelKey: "findings", render: (ctx) => renderDatasetPage(ctx, "findings") },
  { id: "incidents", labelKey: "incidents", render: (ctx) => renderDatasetPage(ctx, "incidents") },
  { id: "drifts", labelKey: "drifts", render: (ctx) => renderDatasetPage(ctx, "baseline_drifts") },
  { id: "blocks", labelKey: "blocks", render: (ctx) => renderDatasetPage(ctx, "active_blocks") },
  { id: "audit", labelKey: "auditLogs", render: (ctx) => renderDatasetPage(ctx, "audit_logs") },
  { id: "nodes", labelKey: "nodes", render: (ctx) => renderDatasetPage(ctx, "nodes") },
];

const state = {
  currentPage: "overview",
  pages: [],
  datasets: {},
  datasetState: {},
  settings: {},
  summary: {},
  panelClockOffsetMs: 0,
  theme: null,
  language: selectedLanguage(),
  manifest: null,
};

const app = document.querySelector("#app");
const nav = document.querySelector("#nav");
const refreshButton = document.querySelector("#refresh-button");
const themeSelect = document.querySelector("#theme-select");
const languageSelect = document.querySelector("#language-select");

init().catch((error) => renderError(error));

async function init() {
  state.settings = await fetchJson(`${API_BASE}/settings`).catch(() => ({ theme: "default" }));
  state.panelClockOffsetMs = panelClockOffsetMs(state.settings.server_time);
  state.theme = selectedTheme(state.settings.theme || "default");
  state.manifest = await loadTheme(state.theme);
  state.pages = await buildPages(state.manifest);
  bindToolbar();
  applyLanguage();
  if (state.settings.auth_required && !panelToken()) {
    renderNav();
    renderAccessGate();
    return;
  }
  await refresh();
}

function bindToolbar() {
  const { option } = view();
  const themes = new Set(["default", state.theme]);
  for (const theme of state.manifest.available_themes || []) themes.add(theme.id || theme);
  themeSelect.replaceChildren(...[...themes].map((theme) => option(theme, theme, theme === state.theme)));
  themeSelect.addEventListener("change", () => {
    localStorage.setItem("vps-sentinel-theme", themeSelect.value);
    location.reload();
  });
  languageSelect.replaceChildren(option("zh", "中文", state.language === "zh"), option("en", "English", state.language === "en"));
  languageSelect.addEventListener("change", async () => {
    state.language = languageSelect.value;
    localStorage.setItem("vps-sentinel-language", state.language);
    applyLanguage();
    renderNav();
    await renderCurrentPage();
  });
  refreshButton.addEventListener("click", () => refresh());
}

async function refresh() {
  renderNav();
  state.summary = await fetchJson(`${API_BASE}/summary`);
  if (state.currentPage === "overview") {
    await loadOverviewDatasets();
  }
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
      labelKey: null,
      label: page.label,
      render: (ctx) => mod.render({ ...ctx, page, manifest }),
    });
  }
  return pages;
}

function renderNav() {
  nav.replaceChildren(
    ...state.pages.map((page) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `nav-button${page.id === state.currentPage ? " active" : ""}`;
      button.textContent = page.labelKey ? t(page.labelKey) : page.label;
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
  app.replaceChildren(view().loading());
  try {
    app.replaceChildren();
    await page.render(context());
  } catch (error) {
    if (isAuthError(error)) {
      renderAccessGate(error.message);
      return;
    }
    renderError(error);
  }
}

function context() {
  const ui = view();
  return {
    api: (path) => fetchJson(`${API_BASE}${path}`),
    app,
    datasets: datasetItemsMap(),
    datasetPages: state.datasets,
    manifest: state.manifest,
    renderTable: ui.renderTable,
    state,
    t,
    ui,
  };
}

function datasetItemsMap() {
  return Object.fromEntries(
    Object.entries(state.datasets).map(([key, value]) => [key, Array.isArray(value) ? value : value?.items || []]),
  );
}

async function loadOverviewDatasets() {
  const entries = await Promise.all(
    Object.entries(DATASETS).map(async ([key, meta]) => [key, await loadDataset(meta, { limit: OVERVIEW_LIMIT, offset: 0 })]),
  );
  state.datasets = Object.fromEntries(entries);
}

async function renderOverview(ctx) {
  if (Object.keys(DATASETS).some((key) => !state.datasets[key]?.items)) {
    await loadOverviewDatasets();
  }
  const ui = view();
  const summary = ctx.state.summary || {};
  app.append(
    ui.sectionHeader(t("overviewTitle"), t("overviewDescription"), ui.freshnessBadge(ctx.state.datasets.nodes?.items || [])),
    ui.metrics([
      [t("nodesMetric"), summary.nodes, "nodes"],
      [t("findingsMetric"), summary.findings, "findings"],
      [t("incidentsMetric"), summary.incidents, "incidents"],
      [t("driftsMetric"), summary.baseline_drifts, "drifts"],
      [t("blocksMetric"), summary.active_blocks, "blocks"],
    ]),
    ui.chartsGrid([
      ui.panel(t("severityDistribution"), ui.barChart(summary.by_severity || [], "severity", "count")),
      ui.panel(t("activityMix"), ui.donutChart([
        { label: t("findingsMetric"), value: summary.findings || 0, className: "chart-high" },
        { label: t("incidentsMetric"), value: summary.incidents || 0, className: "chart-critical" },
        { label: t("driftsMetric"), value: summary.baseline_drifts || 0, className: "chart-medium" },
        { label: t("blocksMetric"), value: summary.active_blocks || 0, className: "chart-low" },
      ])),
      ui.panel(t("fleetFreshness"), ui.nodeFreshness(ctx.state.datasets.nodes?.items || [])),
    ]),
    ui.panel(t("latestFindings"), ui.renderTable(ctx.state.datasets.findings?.items || [], DATASETS.findings.columns)),
    ui.panel(t("latestIncidents"), ui.renderTable(ctx.state.datasets.incidents?.items || [], DATASETS.incidents.columns)),
  );
}

async function renderDatasetPage(ctx, datasetKey) {
  const meta = DATASETS[datasetKey];
  const pageState = datasetPageState(datasetKey);
  const page = await loadDataset(meta, pageState);
  const ui = view();
  state.datasets[datasetKey] = page;
  app.append(
    ui.sectionHeader(t(meta.titleKey), t(meta.descriptionKey), ui.span("record-count", formatTemplate(t("pageInfo"), rangeInfo(page)))),
    filters(datasetKey, pageState),
    ui.panel(
      t(meta.titleKey),
      ui.fragment(
        ui.renderTable(page.items, meta.columns, tableOptions(datasetKey)),
        pagination(datasetKey, page),
      ),
    ),
  );
}

function tableOptions(datasetKey) {
  if (!["findings", "incidents"].includes(datasetKey)) return {};
  return {
    actionHeader: t("actions"),
    actionLabel: t("details"),
    onRowAction: (row) => openDetail(datasetKey, row),
  };
}

async function openDetail(datasetKey, row) {
  if (!row?.id) return;
  const endpoint = datasetKey === "findings" ? "/finding" : "/incident";
  const detail = await fetchJson(`${API_BASE}${endpoint}?id=${encodeURIComponent(row.id)}`);
  const ui = view();
  const overlay = document.createElement("div");
  overlay.className = "detail-overlay";
  const panel = document.createElement("section");
  panel.className = "detail-drawer";
  const close = ui.button(t("close"), "button", "secondary compact");
  close.addEventListener("click", () => overlay.remove());
  panel.append(ui.sectionHeader(t("details"), detail.title || detail.id, close));
  panel.append(datasetKey === "findings" ? findingDetailContent(detail) : incidentDetailContent(detail));
  overlay.append(panel);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) overlay.remove();
  });
  document.body.append(overlay);
}

function findingDetailContent(detail) {
  const ui = view();
  const wrapper = document.createElement("div");
  wrapper.className = "detail-content";
  wrapper.append(
    ui.detailList([
      [t("node_id"), detail.node_id],
      [t("severity"), detail.severity],
      [t("rule_id"), detail.rule_id],
      [t("category"), detail.category],
      [t("subject"), detail.subject],
      [t("timestamp"), detail.timestamp],
      [t("reviewStatus"), detail.review?.verdict ? t(detail.review.verdict) : t("unreviewed")],
    ]),
    ui.panel(t("evidence"), ui.jsonBlock(detail.evidence || [])),
    ui.panel(t("impact"), ui.jsonBlock(detail.impact || [])),
    ui.panel(t("recommendations"), ui.jsonBlock(detail.recommendations || [])),
    reviewForm(detail),
  );
  return wrapper;
}

function incidentDetailContent(detail) {
  const ui = view();
  const wrapper = document.createElement("div");
  wrapper.className = "detail-content";
  wrapper.append(
    ui.detailList([
      [t("node_id"), detail.node_id],
      [t("severity"), detail.severity],
      [t("score"), detail.score],
      [t("first_seen"), detail.first_seen],
      [t("last_seen"), detail.last_seen],
      [t("summary"), detail.summary],
    ]),
    ui.panel(t("payload"), ui.jsonBlock(detail.payload || {})),
  );
  return wrapper;
}

function reviewForm(detail) {
  const ui = view();
  const form = document.createElement("form");
  form.className = "review-form";
  const verdict = document.createElement("select");
  verdict.name = "verdict";
  for (const value of ["needs_review", "confirmed", "false_positive"]) {
    verdict.append(ui.option(value, t(value), detail.review?.verdict === value));
  }
  const note = document.createElement("textarea");
  note.name = "note";
  note.rows = 3;
  note.value = detail.review?.note || "";
  const status = ui.span("review-status", "");
  form.append(
    ui.sectionHeader(t("reviewFinding"), t("reviewDescription")),
    ui.labelControl(t("reviewStatus"), verdict),
    ui.labelControl(t("reviewNote"), note),
    ui.button(t("saveReview"), "submit", "primary"),
    status,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = new FormData(form);
    try {
      await postJson(`${API_BASE}/finding-review`, {
        finding_id: detail.id,
        verdict: String(values.get("verdict") || "needs_review"),
        note: String(values.get("note") || ""),
        reviewer: "panel",
      });
      await renderCurrentPage();
      form.querySelector("button").textContent = t("saved");
      status.textContent = t("saved");
    } catch (error) {
      status.textContent = `${t("errorPrefix")}: ${error?.message || String(error)}`;
    }
  });
  return form;
}

function datasetPageState(datasetKey) {
  state.datasetState[datasetKey] ||= {
    from: "",
    to: "",
    limit: DEFAULT_LIMIT,
    offset: 0,
    preset: "",
  };
  return state.datasetState[datasetKey];
}

async function loadDataset(meta, request) {
  const params = new URLSearchParams();
  params.set("limit", String(request.limit || DEFAULT_LIMIT));
  params.set("offset", String(request.offset || 0));
  if (request.from) params.set("from", toApiTime(request.from));
  if (request.to) params.set("to", toApiTime(request.to));
  const payload = await fetchJson(`${API_BASE}${meta.endpoint}?${params.toString()}`);
  return Array.isArray(payload)
    ? { items: payload, total: payload.length, limit: request.limit || DEFAULT_LIMIT, offset: request.offset || 0 }
    : payload;
}

function filters(datasetKey, pageState) {
  const ui = view();
  const form = document.createElement("form");
  form.className = "filters";
  const quickRanges = document.createElement("div");
  quickRanges.className = "quick-ranges";
  for (const preset of TIME_PRESETS) {
    const button = ui.button(
      t(`range_${preset}`),
      "button",
      `secondary compact${pageState.preset === preset ? " active" : ""}`,
    );
    button.addEventListener("click", async () => {
      Object.assign(pageState, rangePreset(preset), { preset, offset: 0 });
      await renderCurrentPage();
    });
    quickRanges.append(button);
  }
  const applyButton = ui.button(t("apply"), "submit", "primary");
  const resetButton = ui.button(t("reset"), "button", "secondary");
  form.append(
    quickRanges,
    ui.labelControl(t("from"), ui.input("datetime-local", "from", pageState.from)),
    ui.labelControl(t("to"), ui.input("datetime-local", "to", pageState.to)),
    ui.labelControl(t("pageSize"), ui.select("limit", [10, 25, 50, 100, 200], pageState.limit)),
    applyButton,
    resetButton,
  );
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = new FormData(form);
    Object.assign(pageState, {
      from: String(values.get("from") || ""),
      to: String(values.get("to") || ""),
      limit: Number(values.get("limit") || DEFAULT_LIMIT),
      offset: 0,
      preset: "",
    });
    await renderCurrentPage();
  });
  resetButton.addEventListener("click", async () => {
    Object.assign(pageState, { from: "", to: "", limit: DEFAULT_LIMIT, offset: 0, preset: "" });
    await renderCurrentPage();
  });
  return form;
}

function rangePreset(preset) {
  const now = new Date();
  const from = new Date(now);
  switch (preset) {
    case "1h":
      from.setHours(from.getHours() - 1);
      break;
    case "6h":
      from.setHours(from.getHours() - 6);
      break;
    case "24h":
      from.setDate(from.getDate() - 1);
      break;
    case "today":
      from.setHours(0, 0, 0, 0);
      break;
    case "7d":
      from.setDate(from.getDate() - 7);
      break;
    default:
      return { from: "", to: "" };
  }
  return { from: toDatetimeLocalValue(from), to: toDatetimeLocalValue(now) };
}

function toDatetimeLocalValue(date) {
  const offsetMs = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}

function pagination(datasetKey, page) {
  const ui = view();
  const pageState = datasetPageState(datasetKey);
  const wrapper = document.createElement("div");
  wrapper.className = "pagination";
  const info = ui.span("muted", formatTemplate(t("pageInfo"), rangeInfo(page)));
  const prev = ui.button(t("previous"), "button", "secondary");
  const next = ui.button(t("next"), "button", "secondary");
  prev.disabled = page.offset <= 0;
  next.disabled = page.offset + page.limit >= page.total;
  prev.addEventListener("click", async () => {
    pageState.offset = Math.max(0, pageState.offset - page.limit);
    await renderCurrentPage();
  });
  next.addEventListener("click", async () => {
    pageState.offset += page.limit;
    await renderCurrentPage();
  });
  wrapper.append(info, prev, next);
  return wrapper;
}

function applyLanguage() {
  document.documentElement.lang = state.language === "zh" ? "zh-CN" : "en";
  const subtitle = document.querySelector("[data-i18n='subtitle']");
  if (subtitle) subtitle.textContent = t("appSubtitle");
  refreshButton.textContent = t("refresh");
  themeSelect.setAttribute("aria-label", t("theme"));
  languageSelect.setAttribute("aria-label", t("language"));
}

function t(key) {
  return createTranslator(state.language)(key);
}

function view() {
  return createView({
    t,
    language: state.language,
    freshness: {
      thresholdMinutes: state.settings.freshness_threshold_minutes || DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
      retiredThresholdMinutes: state.settings.node_retired_threshold_minutes || DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
      nowMs: Date.now() - state.panelClockOffsetMs,
    },
  });
}

function panelClockOffsetMs(serverTime) {
  const serverDate = new Date(serverTime);
  if (Number.isNaN(serverDate.getTime())) return 0;
  return Date.now() - serverDate.getTime();
}

function renderAccessGate(message = "") {
  const ui = view();
  nav.replaceChildren();
  const form = document.createElement("form");
  form.className = "access-gate";
  const tokenInput = ui.input("password", "token", "");
  tokenInput.autocomplete = "current-password";
  form.append(
    ui.sectionHeader(t("accessTitle"), t(state.settings.auth_configured ? "accessDescription" : "accessNotConfigured")),
    ui.labelControl(t("accessToken"), tokenInput),
    ui.button(t("unlock"), "submit", "primary"),
  );
  if (message) form.append(ui.span("access-error", t("invalidAccessToken")));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const token = String(new FormData(form).get("token") || "").trim();
    if (!token) return;
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
    renderNav();
    await refresh();
  });
  app.replaceChildren(form);
  tokenInput.focus();
}

function panelToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

function authHeaders() {
  const headers = { accept: "application/json" };
  const token = panelToken();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

function isAuthError(error) {
  return error?.status === 401 || error?.status === 403;
}

function toApiTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

async function postJson(url, payload) {
  return fetchJson(url, {
    method: "POST",
    body: JSON.stringify(payload),
    headers: { "content-type": "application/json" },
  });
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
  });
  if (!response.ok) {
    if (response.status === 401) localStorage.removeItem(TOKEN_STORAGE_KEY);
    const error = new Error(`${url} returned HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function renderError(error) {
  app.replaceChildren();
  const box = document.createElement("div");
  box.className = "error";
  box.textContent = `${t("errorPrefix")}: ${error?.message || String(error)}`;
  app.append(box);
}
