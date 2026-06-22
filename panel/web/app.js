import {
  DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
  DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
  createView,
  formatTemplate,
  rangeInfo,
} from "./components.js";
import { DATASETS } from "./datasets.js";
import { renderOverviewDashboard } from "./dashboard.js";
import { createTranslator, selectedLanguage } from "./i18n.js";

const API_BASE = "/api/v1";
const DEFAULT_LIMIT = 25;
const OVERVIEW_LIMIT = 12;
const STREAM_RECONNECT_MS = 5000;
const TOKEN_STORAGE_KEY = "vps-sentinel-panel-token";
const TIME_PRESETS = ["1h", "6h", "24h", "today", "7d"];
const ROLE_LEVELS = { public: 0, operator: 1, admin: 2 };
const PANEL_HIDDEN_KEYS = new Set([
  "active_response_backend",
  "backend",
  "dedup_id",
  "event_id",
  "firewall_backend",
  "host_id",
  "idempotency_key",
  "local_addr",
  "local_ip",
  "node_id",
  "raw_ip",
  "remote_addr",
  "remote_ip",
  "response_backend",
  "source_ip",
  "target_ip",
]);
const BUILTIN_PAGES = [
  { id: "overview", labelKey: "overview", minRole: "public", render: renderOverview },
  { id: "findings", labelKey: "findings", minRole: "operator", render: (ctx) => renderDatasetPage(ctx, "findings") },
  { id: "incidents", labelKey: "incidents", minRole: "operator", render: (ctx) => renderDatasetPage(ctx, "incidents") },
  { id: "drifts", labelKey: "drifts", minRole: "operator", render: (ctx) => renderDatasetPage(ctx, "baseline_drifts") },
  { id: "blocks", labelKey: "blocks", minRole: "operator", render: (ctx) => renderDatasetPage(ctx, "active_blocks") },
  { id: "blacklist", labelKey: "blacklist", minRole: "admin", render: (ctx) => renderDatasetPage(ctx, "probe_sources") },
  { id: "audit", labelKey: "auditLogs", minRole: "admin", render: (ctx) => renderDatasetPage(ctx, "audit_logs") },
  { id: "nodes", labelKey: "nodes", minRole: "public", render: renderNodesPage },
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
  role: "public",
  stream: null,
  refreshInFlight: null,
};

const app = document.querySelector("#app");
const nav = document.querySelector("#nav");
const refreshButton = document.querySelector("#refresh-button");
const themeSelect = document.querySelector("#theme-select");
const languageSelect = document.querySelector("#language-select");

init().catch((error) => renderError(error));

async function init() {
  state.settings = await fetchJson(`${API_BASE}/settings`).catch(() => ({ theme: "default" }));
  state.role = selectedRole(state.settings.role, Boolean(panelToken()));
  state.panelClockOffsetMs = panelClockOffsetMs(state.settings.server_time);
  state.theme = selectedTheme(state.settings.theme || "default");
  applyThemeScope(state.theme);
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
  connectStream();
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
  refreshButton.disabled = true;
  refreshButton.classList.add("stream-status");
}

async function refresh() {
  if (state.refreshInFlight) return state.refreshInFlight;
  state.refreshInFlight = (async () => {
    renderNav();
    state.summary = await fetchJson(`${API_BASE}/summary`);
    if (state.currentPage === "overview") {
      await loadOverviewDatasets();
    }
    await renderCurrentPage();
  })();
  try {
    await state.refreshInFlight;
  } finally {
    state.refreshInFlight = null;
  }
}

function selectedTheme(defaultTheme) {
  const params = new URLSearchParams(location.search);
  return params.get("theme") || localStorage.getItem("vps-sentinel-theme") || defaultTheme;
}

async function loadTheme(theme) {
  const loaded = await fetchJson(`/themes/${encodeURIComponent(theme)}/theme.json`).catch(() => fallbackThemeManifest());
  const manifest = loaded && typeof loaded === "object" && !Array.isArray(loaded) ? loaded : fallbackThemeManifest();
  if (!Array.isArray(manifest.styles)) manifest.styles = [];
  if (!Array.isArray(manifest.pages)) manifest.pages = [];
  if (!Array.isArray(manifest.available_themes)) manifest.available_themes = ["default"];
  for (const style of manifest.styles) {
    const href = themeAsset(theme, style);
    if (!href) continue;
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.dataset.panelTheme = theme;
    link.href = href;
    document.head.appendChild(link);
  }
  return manifest;
}

function fallbackThemeManifest() {
  return {
    name: "default",
    styles: ["theme.css"],
    pages: [],
    available_themes: ["default"],
  };
}

function themeAsset(theme, assetPath) {
  const asset = String(assetPath || "").trim();
  if (!asset || asset.includes("..") || asset.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(asset)) {
    return "";
  }
  if (asset.startsWith("/")) return asset;
  const encoded = asset.split("/").map(encodeURIComponent).join("/");
  return `/themes/${encodeURIComponent(theme)}/${encoded}`;
}

async function buildPages(manifest) {
  const pages = BUILTIN_PAGES.filter((page) => roleAllows(page.minRole || "public"));
  for (const page of manifest.pages || []) {
    if (!page.id || !page.label || !page.module) continue;
    if (!roleAllows(page.min_role || page.minRole || "admin")) continue;
    const moduleUrl = themeAsset(state.theme, page.module);
    if (!moduleUrl) continue;
    let mod;
    try {
      mod = await import(moduleUrl);
    } catch (error) {
      console.warn(`failed to load panel theme page '${page.id}'`, error);
      continue;
    }
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
    ...state.pages.map((page, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `nav-button${page.id === state.currentPage ? " active" : ""}`;
      if (page.id === state.currentPage) button.setAttribute("aria-current", "page");
      const marker = document.createElement("span");
      marker.className = "nav-marker";
      marker.textContent = String(index + 1).padStart(2, "0");
      const label = document.createElement("span");
      label.className = "nav-label";
      label.textContent = page.labelKey ? t(page.labelKey) : page.label;
      button.append(marker, label);
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
  document.body.dataset.page = page?.id || "overview";
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

function applyThemeScope(theme) {
  document.documentElement.dataset.theme = theme;
  document.body.dataset.theme = theme;
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
    role: state.role,
    t,
    ui,
  };
}

function datasetItemsMap() {
  return Object.fromEntries(
    Object.entries(state.datasets).map(([key, value]) => [key, Array.isArray(value) ? value : value?.items || []]),
  );
}

function visibleDatasetEntries() {
  return Object.entries(DATASETS).filter(([, meta]) => roleAllows(meta.minRole || "operator"));
}

function overviewTrendParams() {
  const params = new URLSearchParams();
  const range = rangePreset("24h");
  if (range.from) params.set("from", toApiTime(range.from));
  if (range.to) params.set("to", toApiTime(range.to));
  params.set("limit", "200");
  return params.toString();
}

async function loadOverviewDatasets() {
  const visible = visibleDatasetEntries().filter(([key]) => key !== "nodes" && key !== "probe_sources");
  const entries = await Promise.all(
    visible.map(async ([key, meta]) => [
      key,
      await loadDataset(meta, { limit: OVERVIEW_LIMIT, offset: 0 }),
    ]),
  );
  const trends = await fetchJson(`${API_BASE}/trends?${overviewTrendParams()}`).catch(() => ({ items: [] }));
  state.datasets = { ...Object.fromEntries(entries), trends };
}

async function renderOverview(ctx) {
  if (visibleDatasetEntries().some(([key]) => key !== "nodes" && key !== "probe_sources" && !state.datasets[key]?.items)) {
    await loadOverviewDatasets();
  }
  renderOverviewDashboard(ctx);
}

async function renderNodesPage(ctx) {
  const meta = DATASETS.nodes;
  const pageState = datasetPageState("nodes");
  const page = await loadDataset(meta, pageState);
  const ui = view();
  state.datasets.nodes = page;
  app.append(
    ui.sectionHeader(t(meta.titleKey), t(meta.descriptionKey), ui.span("record-count", formatTemplate(t("pageInfo"), rangeInfo(page)))),
    filters("nodes", pageState),
    ui.nodeProbeGrid(page.items || []),
    pagination("nodes", page),
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
        ui.renderTable(page.items, datasetColumns(meta), tableOptions(datasetKey)),
        pagination(datasetKey, page),
      ),
    ),
  );
}

function datasetColumns(meta) {
  return roleAllows("admin") && meta.adminColumns ? meta.adminColumns : meta.columns;
}

function tableOptions(datasetKey) {
  if (!["findings", "incidents"].includes(datasetKey)) return {};
  if (!roleAllows("operator")) return {};
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
  const details = [
      [t("node_name"), detail.node_name],
      [t("severity"), detail.severity],
      [t("rule_id"), detail.rule_id],
      [t("category"), detail.category],
      [t("subject"), detail.subject],
      [t("timestamp"), detail.timestamp],
  ];
  if (roleAllows("admin")) details.push([t("reviewStatus"), detail.review?.verdict ? t(detail.review.verdict) : t("unreviewed")]);
  wrapper.append(ui.detailList(details));
  if (roleAllows("admin")) wrapper.append(ui.panel(t("evidence"), ui.jsonBlock(detail.evidence || [])));
  wrapper.append(ui.panel(t("impact"), ui.jsonBlock(detail.impact || [])));
  wrapper.append(ui.panel(t("recommendations"), ui.jsonBlock(detail.recommendations || [])));
  if (roleAllows("admin")) wrapper.append(reviewForm(detail));
  return wrapper;
}

function incidentDetailContent(detail) {
  const ui = view();
  const wrapper = document.createElement("div");
  wrapper.className = "detail-content";
  const details = [
      [t("node_name"), detail.node_name],
      [t("severity"), detail.severity],
      [t("score"), detail.score],
      [t("first_seen"), detail.first_seen],
      [t("last_seen"), detail.last_seen],
      [t("summary"), detail.summary],
  ];
  wrapper.append(ui.detailList(details));
  if (roleAllows("admin")) wrapper.append(ui.panel(t("payload"), ui.jsonBlock(detail.payload || {})));
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
    timeRangeControl(t("from"), "from", pageState.from),
    timeRangeControl(t("to"), "to", pageState.to),
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

function timeRangeControl(label, name, value) {
  const ui = view();
  const wrapper = document.createElement("label");
  wrapper.className = "field range-field";
  const hidden = ui.input("hidden", name, value || "");
  const date = ui.input("date", `${name}_date`, datePart(value));
  const time = ui.input("time", `${name}_time`, timePart(value));
  time.step = 60;
  date.setAttribute("aria-label", `${label} ${t("date")}`);
  time.setAttribute("aria-label", `${label} ${t("time")}`);
  const controls = document.createElement("span");
  controls.className = "range-control";
  controls.append(date, time);
  const sync = () => {
    hidden.value = date.value ? `${date.value}T${time.value || "00:00"}` : "";
  };
  date.addEventListener("input", sync);
  time.addEventListener("input", sync);
  wrapper.append(ui.span("field-label", label), controls, hidden);
  return wrapper;
}

function datePart(value) {
  return String(value || "").slice(0, 10);
}

function timePart(value) {
  return String(value || "").slice(11, 16);
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
  setStreamStatus(state.stream?.status || "idle");
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

function selectedRole(value, hasToken = false) {
  const role = String(value || "").toLowerCase();
  if (ROLE_LEVELS[role] !== undefined) return role;
  return hasToken ? "operator" : "public";
}

function roleAllows(minRole) {
  return (ROLE_LEVELS[state.role] ?? 0) >= (ROLE_LEVELS[minRole] ?? 0);
}

function connectStream() {
  if (state.stream?.socket && [WebSocket.CONNECTING, WebSocket.OPEN].includes(state.stream.socket.readyState)) return;
  if (!("WebSocket" in window)) {
    setStreamStatus("fallback");
    return;
  }
  state.stream = { ...(state.stream || {}), status: "connecting" };
  setStreamStatus("connecting");
  fetchJson(`${API_BASE}/stream-ticket`)
    .then(({ ticket }) => {
      if (!ticket) throw new Error("missing stream ticket");
      const scheme = location.protocol === "https:" ? "wss" : "ws";
      const socket = new WebSocket(`${scheme}://${location.host}${API_BASE}/stream?ticket=${encodeURIComponent(ticket)}`);
      state.stream.socket = socket;
      socket.addEventListener("open", () => {
        state.stream.status = "live";
        setStreamStatus("live");
      });
      socket.addEventListener("message", async (event) => {
        const message = parseStreamMessage(event.data);
        if (message?.type === "hello") {
          state.role = selectedRole(message.role || state.role, Boolean(panelToken()));
          setStreamStatus("live");
          return;
        }
        if (message?.type === "refresh") {
          state.role = selectedRole(message.role || state.role, Boolean(panelToken()));
          await refresh().catch((error) => {
            if (isAuthError(error)) renderAccessGate(error.message);
          });
        }
      });
      socket.addEventListener("close", () => scheduleStreamReconnect());
      socket.addEventListener("error", () => scheduleStreamReconnect());
    })
    .catch((error) => {
      if (error?.status === 404 || error?.status === 501) {
        setStreamStatus("fallback");
        return;
      }
      scheduleStreamReconnect();
    });
}

function parseStreamMessage(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function scheduleStreamReconnect() {
  if (state.stream?.reconnectTimer) return;
  state.stream = { ...(state.stream || {}), status: "reconnecting" };
  setStreamStatus("reconnecting");
  state.stream.reconnectTimer = setTimeout(() => {
    state.stream.reconnectTimer = null;
    connectStream();
  }, STREAM_RECONNECT_MS);
}

function setStreamStatus(status) {
  state.stream = { ...(state.stream || {}), status };
  refreshButton.textContent = t(`stream_${status}`) || t("stream_idle");
  refreshButton.title = t("streamStatus");
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
    state.settings = await fetchJson(`${API_BASE}/settings`);
    state.role = selectedRole(state.settings.role, Boolean(panelToken()));
    state.pages = await buildPages(state.manifest);
    if (!state.pages.some((page) => page.id === state.currentPage)) state.currentPage = "overview";
    renderNav();
    await refresh();
    connectStream();
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
  return sanitizePanelValue(await response.json());
}

function sanitizePanelValue(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return roleAllows("admin") ? value : redactIpText(value);
  if (Array.isArray(value)) return value.map((item) => sanitizePanelValue(item));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).flatMap(([key, item]) => {
        const lower = key.toLowerCase();
        if (shouldHidePanelField(lower)) return [];
        return [!roleAllows("admin") && (lower === "ip" || lower.includes("_ip") || lower.includes("addr"))
          ? [key, "redacted"]
          : [key, sanitizePanelValue(item)]];
      }),
    );
  }
  return value;
}

function shouldHidePanelField(key) {
  if (roleAllows("admin") && (key === "backend" || key.endsWith("_backend"))) return false;
  return PANEL_HIDDEN_KEYS.has(key) || key.endsWith("_backend");
}

function redactIpText(value) {
  const withoutIpv4 = String(value).replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, (match) => {
    const parts = match.split(":")[0].split(".").map((part) => Number(part));
    return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
      ? "redacted"
      : match;
  });
  return withoutIpv4
    .split(/(\s+)/)
    .map((token) => tokenContainsIpLiteral(token) ? "redacted" : token)
    .join("");
}

function tokenContainsIpLiteral(token) {
  const bracketed = token.match(/\[([0-9a-fA-F:.%]+)\](?::\d+)?/);
  if (bracketed && ipv6Like(bracketed[1])) return true;
  const candidate = token.replace(/^[,;"'({<\[]+|[,;"')}\]>.]+$/g, "");
  return ipv6Like(candidate);
}

function ipv6Like(value) {
  const candidate = String(value || "").split("%")[0];
  const colonCount = (candidate.match(/:/g) || []).length;
  if (colonCount < 2 || !/^[0-9a-fA-F:.]+$/.test(candidate)) return false;
  return candidate.includes("::") || colonCount >= 3 || /[a-fA-F]/.test(candidate);
}

function renderError(error) {
  app.replaceChildren();
  const box = document.createElement("div");
  box.className = "error";
  box.textContent = `${t("errorPrefix")}: ${error?.message || String(error)}`;
  app.append(box);
}
