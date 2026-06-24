import {
  Activity,
  Bell,
  Blocks,
  ChevronDown,
  ClipboardList,
  Database,
  FileClock,
  LayoutDashboard,
  LogOut,
  Menu,
  RefreshCw,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Sun,
  UserRound,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DetailDrawer } from "@/components/DetailDrawer";
import { SelectMenu, TextField } from "@/components/Controls";
import { PanelApiError, clearPanelToken, fetchDataset, fetchJson, fetchSettings, fetchTrends, panelToken, setPanelToken } from "@/lib/api";
import {
  API_BASE,
  DATASET_BY_ID,
  DEFAULT_LIMIT,
  DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
  DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
  OVERVIEW_LIMIT,
  PAGES,
  STREAM_RECONNECT_MS,
} from "@/lib/datasets";
import { selectedLanguage, translate } from "@/lib/i18n";
import { roleAllows, selectedRole } from "@/lib/rbac";
import {
  AuditPageView,
  BaselinePageView,
  BlocksPageView,
  DatasetPageView,
  FindingsPageView,
  IncidentsPageView,
  NodesPageView,
  OverviewPage,
  SourcesPageView,
} from "@/features/Pages";
import type {
  DatasetPage,
  DatasetState,
  Language,
  NodeRecord,
  PageConfig,
  PageId,
  PanelRecord,
  PanelRole,
  PanelSettings,
  StreamState,
  Summary,
  ThemeOption,
  TrendPoint,
} from "@/types";

const ICONS: Record<PageId, React.ReactNode> = {
  overview: <LayoutDashboard size={18} />,
  findings: <Bell size={18} />,
  incidents: <ShieldAlert size={18} />,
  baseline_drifts: <FileClock size={18} />,
  active_blocks: <Blocks size={18} />,
  probe_sources: <Shield size={18} />,
  audit_logs: <ClipboardList size={18} />,
  nodes: <Database size={18} />,
};

export function PanelApp() {
  const [language, setLanguage] = useState<Language>("zh");
  const [theme, setTheme] = useState("default");
  const [role, setRole] = useState<PanelRole>("public");
  const [settings, setSettings] = useState<PanelSettings>({});
  const [currentPage, setCurrentPage] = useState<PageId>(() => initialPageFromLocation());
  const [summary, setSummary] = useState<Summary>({});
  const [datasets, setDatasets] = useState<Record<string, DatasetPage>>({});
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [datasetStates, setDatasetStates] = useState<Record<string, DatasetState>>({});
  const datasetStatesRef = useRef<Record<string, DatasetState>>({});
  const [streamState, setStreamState] = useState<StreamState>("idle");
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [loading, setLoading] = useState(true);
  const [accessMessage, setAccessMessage] = useState("");
  const [drawer, setDrawer] = useState<{ dataset: string; row: PanelRecord } | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<number | null>(null);
  const activeRoleRef = useRef<PanelRole>("public");

  const publicPages = useMemo(() => new Set(settings.public_pages || []), [settings.public_pages]);
  const adminRouteActive = settingsLoaded && isAdminRoute(settings.admin_path);
  const themeOptions = useMemo(() => normalizeThemeOptions(settings.themes), [settings.themes]);
  const pageMinRole = useCallback(
    (page: PageConfig): PanelRole => (publicPages.has(page.id) ? "public" : page.minRole),
    [publicPages],
  );
  const visiblePages = useMemo(
    () => PAGES.filter((page) => roleAllows(role, pageMinRole(page))),
    [pageMinRole, role],
  );
  const activePage = visiblePages.find((page) => page.id === currentPage) || visiblePages[0] || PAGES[0];

  const datasetState = useCallback((id: string): DatasetState => datasetStates[id] || defaultDatasetState(), [datasetStates]);

  const updateDatasetState = useCallback((id: string, patch: Partial<DatasetState>) => {
    setDatasetStates((current) => {
      const next = {
        ...current,
        [id]: { ...(current[id] || defaultDatasetState()), ...patch },
      };
      datasetStatesRef.current = next;
      return next;
    });
  }, []);

  const navigatePage = useCallback((id: PageId) => {
    setCurrentPage(id);
    setMobileNavOpen(false);
    syncPageToLocation(id);
  }, []);

  const loadVisibleData = useCallback(async (pageId: PageId, nextRole = activeRoleRef.current) => {
    const stateFor = (id: string) => datasetStatesRef.current[id] || defaultDatasetState();
    setLoading(true);
    try {
      const nextSummary = await fetchJson<Summary>("/summary", nextRole);
      setSummary(nextSummary);

      if (pageId === "overview") {
        const configuredPublicPages = new Set(settings.public_pages || []);
        const visibleDatasets = PAGES.filter((page) => {
          const minRole = configuredPublicPages.has(page.id) ? "public" : page.minRole;
          return page.endpoint && page.id !== "probe_sources" && roleAllows(nextRole, minRole);
        });
        const pages = await Promise.all(
          visibleDatasets.map(async (page) => [
            page.id,
            await fetchDataset(page.endpoint || "", { ...stateFor(page.id), limit: OVERVIEW_LIMIT, offset: 0 }, nextRole),
          ] as const),
        );
        const trendPayload = await fetchTrends(nextRole).catch((error) => {
          setAccessMessage(error instanceof Error ? error.message : String(error));
          return { items: [] };
        });
        setDatasets((current) => ({ ...current, ...Object.fromEntries(pages) }));
        setTrends(trendPayload.items || []);
      } else {
        const config = DATASET_BY_ID.get(pageId);
        if (config?.endpoint) {
          const page = await fetchDataset(config.endpoint, stateFor(pageId), nextRole);
          setDatasets((current) => ({ ...current, [pageId]: page }));
        }
      }
    } catch (error) {
      if (error instanceof PanelApiError && error.status === 401) {
        clearPanelToken();
        activeRoleRef.current = "public";
        setRole("public");
        setAccessMessage(translate(language, "invalidAccessToken"));
      } else {
        setAccessMessage(error instanceof Error ? error.message : String(error));
      }
    } finally {
      setLoading(false);
    }
  }, [language, settings.public_pages]);

  useEffect(() => {
    setLanguage(selectedLanguage());
    const storedTheme = window.localStorage.getItem("vps-sentinel-theme") || "default";
    setTheme(storedTheme);
  }, []);

  useEffect(() => {
    document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
    document.documentElement.dataset.theme = theme;
    document.body.dataset.theme = theme;
    window.localStorage.setItem("vps-sentinel-language", language);
    window.localStorage.setItem("vps-sentinel-theme", theme);
  }, [language, theme]);

  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.dataset.panelTheme = theme;
    link.href = `/themes/${encodeURIComponent(theme)}/theme.css`;
    document.head.append(link);
    return () => link.remove();
  }, [theme]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const initialRole = selectedRole(undefined, Boolean(panelToken()));
        const nextSettings = await fetchSettings(initialRole);
        if (cancelled) return;
        setSettings(nextSettings);
        const nextRole = selectedRole(nextSettings.role, Boolean(panelToken()));
        activeRoleRef.current = nextRole;
        setRole(nextRole);
        setTheme(selectConfiguredTheme(nextSettings.theme, nextSettings.themes));
        setSettingsLoaded(true);
        setLoading(false);
      } catch (error) {
        if (cancelled) return;
        setAccessMessage(error instanceof Error ? error.message : String(error));
        setSettingsLoaded(true);
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!settingsLoaded) return;
    if (settings.auth_required && !panelToken() && !roleAllows("public", pageMinRole(activePage))) return;
    connectStream();
    return () => {
      socketRef.current?.close();
      if (reconnectRef.current) window.clearTimeout(reconnectRef.current);
    };
  }, [activePage, pageMinRole, settingsLoaded, settings.auth_required, role]);

  useEffect(() => {
    if (!settingsLoaded) return;
    if (!visiblePages.some((page) => page.id === currentPage)) {
      navigatePage(visiblePages[0]?.id || "overview");
    }
  }, [currentPage, navigatePage, settingsLoaded, visiblePages]);

  useEffect(() => {
    if (!settingsLoaded) return;
    if (settings.auth_required && !panelToken() && !roleAllows("public", pageMinRole(activePage))) return;
    void loadVisibleData(currentPage, role);
  }, [activePage, currentPage, datasetStates, loadVisibleData, pageMinRole, role, settingsLoaded, settings.auth_required]);

  async function unlock(token: string) {
    setPanelToken(token);
    try {
      const nextSettings = await fetchSettings(role);
      const nextRole = selectedRole(nextSettings.role, true);
      if (isAdminRoute(nextSettings.admin_path) && nextRole !== "admin") {
        throw new PanelApiError("admin token required", 403);
      }
      activeRoleRef.current = nextRole;
      setRole(nextRole);
      setSettings(nextSettings);
      setTheme(selectConfiguredTheme(nextSettings.theme, nextSettings.themes));
      setAccessMessage("");
      setSettingsLoaded(true);
      await loadVisibleData(currentPage, nextRole);
      connectStream();
    } catch {
      clearPanelToken();
      setAccessMessage(translate(language, "invalidAccessToken"));
    }
  }

  function logout() {
    clearPanelToken();
    socketRef.current?.close();
    setRole("public");
    setDatasets({});
    setSummary({});
  }

  function connectStream() {
    if (
      socketRef.current &&
      (socketRef.current.readyState === WebSocket.CONNECTING || socketRef.current.readyState === WebSocket.OPEN)
    ) {
      return;
    }
    if (!("WebSocket" in window)) {
      setStreamState("fallback");
      return;
    }
    setStreamState("connecting");
    fetchJson<{ ticket: string }>("/stream-ticket", activeRoleRef.current)
      .then(({ ticket }) => {
        const scheme = window.location.protocol === "https:" ? "wss" : "ws";
        const socket = new WebSocket(`${scheme}://${window.location.host}${API_BASE}/stream?ticket=${encodeURIComponent(ticket)}`);
        socketRef.current = socket;
        socket.addEventListener("open", () => setStreamState("live"));
        socket.addEventListener("message", (event) => {
          const message = parseStreamMessage(event.data);
          if (message?.role) {
            const nextRole = selectedRole(message.role, Boolean(panelToken()));
            activeRoleRef.current = nextRole;
            setRole(nextRole);
          }
          if (message?.type === "refresh") void loadVisibleData(currentPage, activeRoleRef.current);
        });
        socket.addEventListener("close", scheduleReconnect);
        socket.addEventListener("error", scheduleReconnect);
      })
      .catch(() => scheduleReconnect());
  }

  function scheduleReconnect() {
    setStreamState("reconnecting");
    if (reconnectRef.current) return;
    reconnectRef.current = window.setTimeout(() => {
      reconnectRef.current = null;
      connectStream();
    }, STREAM_RECONNECT_MS);
  }

  const needsAccess = Boolean(
    settingsLoaded
      && (
        (adminRouteActive && role !== "admin")
        || (settings.auth_required && !panelToken() && !roleAllows("public", pageMinRole(activePage)))
      ),
  );

  return (
    <main className={`app-shell page-${activePage.id}`}>
      <Sidebar pages={visiblePages} currentPage={activePage.id} language={language} onNavigate={navigatePage} />
      <section className="stage">
        <Topbar
          page={activePage}
          language={language}
          theme={theme}
          themeOptions={themeOptions}
          streamState={streamState}
          role={role}
          pages={visiblePages}
          onLanguage={setLanguage}
          onTheme={setTheme}
          onLogout={logout}
          onRefresh={() => void loadVisibleData(currentPage, role)}
          currentPage={activePage.id}
          mobileNavOpen={mobileNavOpen}
          onMobileNavToggle={() => setMobileNavOpen((open) => !open)}
          onMobileNavigate={navigatePage}
        />
        <section className="content-shell">
          {needsAccess ? (
            <AccessGate language={language} settings={settings} message={accessMessage} onUnlock={unlock} />
          ) : (
            <Content
              page={activePage}
              loading={loading || !settingsLoaded}
              language={language}
              role={role}
              summary={summary}
              datasets={datasets}
              trends={trends}
              datasetState={datasetState}
              updateDatasetState={updateDatasetState}
              onNavigate={(id) => navigatePage(id as PageId)}
              onDetails={(dataset, row) => setDrawer({ dataset, row })}
            />
          )}
        </section>
      </section>
      <DetailDrawer
        row={drawer?.row || null}
        dataset={drawer?.dataset || ""}
        role={role}
        language={language}
        onClose={() => setDrawer(null)}
        onSaved={(review) => {
          if (drawer?.dataset && review) {
            const targetId = String(review.target_id || drawer.row.id || drawer.row.finding_id || "");
            setDatasets((current) => {
              const page = current[drawer.dataset];
              if (!page?.items?.length) return current;
              return {
                ...current,
                [drawer.dataset]: {
                  ...page,
                  items: page.items.map((item) => {
                    const itemId = String(item.id || item.finding_id || "");
                    return itemId === targetId
                      ? { ...item, review, review_verdict: review.verdict || "needs_review", status: review.verdict || "needs_review" }
                      : item;
                  }),
                },
              };
            });
            setDrawer((current) => current && String(current.row.id || current.row.finding_id || "") === targetId
              ? { ...current, row: { ...current.row, review, review_verdict: review.verdict || "needs_review", status: review.verdict || "needs_review" } }
              : current);
          }
          void loadVisibleData(currentPage, role);
        }}
      />
    </main>
  );
}

function Sidebar({
  pages,
  currentPage,
  language,
  onNavigate,
}: {
  pages: PageConfig[];
  currentPage: PageId;
  language: Language;
  onNavigate: (id: PageId) => void;
}) {
  return (
    <aside className="sidebar-shell">
      <div className="brand-lockup">
        <span className="brand-mark"><ShieldCheck size={36} /></span>
        <div>
          <strong>VPS Sentinel</strong>
          <small>{translate(language, "appSubtitle")}</small>
        </div>
      </div>
      <nav className="main-nav">
        {pages.map((page) => (
          <button className={page.id === currentPage ? "active" : ""} key={page.id} type="button" onClick={() => onNavigate(page.id)}>
            {ICONS[page.id]}
            <span>{translate(language, page.labelKey)}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-status">
        <Shield size={20} />
        <div>
          <strong>{translate(language, "allSystemsOperational")}</strong>
          <small>{translate(language, "updatedJustNow")}</small>
        </div>
      </div>
    </aside>
  );
}

function Topbar({
  page,
  language,
  theme,
  themeOptions,
  streamState,
  role,
  pages,
  onLanguage,
  onTheme,
  onLogout,
  onRefresh,
  currentPage,
  mobileNavOpen,
  onMobileNavToggle,
  onMobileNavigate,
}: {
  page: PageConfig;
  language: Language;
  theme: string;
  themeOptions: ThemeOption[];
  streamState: StreamState;
  role: PanelRole;
  pages: PageConfig[];
  onLanguage: (language: Language) => void;
  onTheme: (theme: string) => void;
  onLogout: () => void;
  onRefresh: () => void;
  currentPage: PageId;
  mobileNavOpen: boolean;
  onMobileNavToggle: () => void;
  onMobileNavigate: (id: PageId) => void;
}) {
  const languageOptions = [
    { value: "zh" as Language, label: translate(language, "chinese") },
    { value: "en" as Language, label: translate(language, "english") },
  ];

  return (
    <header className="topbar">
      <div className="mobile-appbar">
        <button className="mobile-icon-button" type="button" aria-label="menu" aria-expanded={mobileNavOpen} onClick={onMobileNavToggle}>
          <Menu size={20} />
        </button>
        <div className="mobile-brand">
          <ShieldCheck size={20} />
          <span>
            <strong>VPS Sentinel</strong>
            <small>{language === "zh" ? "多服务器安全面板" : "Multi-server Security Guard"}</small>
          </span>
        </div>
        <button className="mobile-icon-button" type="button" aria-label={translate(language, "refresh")} onClick={onRefresh}>
          <RefreshCw size={18} />
        </button>
        {mobileNavOpen && (
          <nav className="mobile-nav-popover" aria-label="mobile navigation">
            <div className="mobile-nav-list">
              {pages.map((item) => (
                <button className={item.id === currentPage ? "active" : ""} key={item.id} type="button" onClick={() => onMobileNavigate(item.id)}>
                  {ICONS[item.id]}
                  <span>{translate(language, item.labelKey)}</span>
                </button>
              ))}
            </div>
            <div className="mobile-toolbar-controls" aria-label={translate(language, "theme")}>
              <SelectMenu
                className="mobile-toolbar-select"
                value={theme}
                ariaLabel={translate(language, "theme")}
                options={themeOptions.map((item) => ({ value: item.id, label: item.label }))}
                onChange={onTheme}
              />
              <SelectMenu
                className="mobile-toolbar-select"
                value={language}
                ariaLabel={translate(language, "language")}
                options={languageOptions}
                onChange={onLanguage}
              />
            </div>
          </nav>
        )}
      </div>
      <div>
        <h1>{translate(language, page.labelKey)}</h1>
      </div>
      <div className="toolbar">
        <span className={`live-pill live-${streamState}`}>
          <Activity size={14} />
          {streamLabel(streamState, language)}
        </span>
        <span className="icon-button theme-indicator" aria-hidden="true">
          <Sun size={18} />
        </span>
        <SelectMenu
          className="toolbar-select"
          value={theme}
          ariaLabel={translate(language, "theme")}
          options={themeOptions.map((item) => ({ value: item.id, label: item.label }))}
          onChange={onTheme}
        />
        <SelectMenu
          className="toolbar-select"
          value={language}
          ariaLabel={translate(language, "language")}
          options={languageOptions}
          onChange={onLanguage}
        />
        {roleAllows(role, "operator") && <UserMenu role={role} language={language} onLogout={onLogout} />}
      </div>
    </header>
  );
}

function UserMenu({
  role,
  language,
  onLogout,
}: {
  role: PanelRole;
  language: Language;
  onLogout: () => void;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return undefined;
    function handlePointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div className="user-menu-wrap" ref={rootRef}>
      <button
        className="user-menu"
        type="button"
        aria-expanded={open}
        aria-label={translate(language, "currentRole")}
        onClick={() => setOpen((current) => !current)}
      >
        <span className="user-avatar"><UserRound size={18} /></span>
        <span className="user-role-label">{roleLabel(role, language)}</span>
        <ChevronDown size={15} />
      </button>
      {open && (
        <div className="user-popover">
          <div className="user-popover-head">
            <span className="user-avatar small"><UserRound size={15} /></span>
            <div>
              <strong>{translate(language, "currentRole")}</strong>
              <small>{roleLabel(role, language)}</small>
            </div>
          </div>
          <button
            className="logout-button"
            type="button"
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            <LogOut size={15} />
            {translate(language, "logout")}
          </button>
        </div>
      )}
    </div>
  );
}

function roleLabel(role: PanelRole, language: Language): string {
  if (role === "admin") return translate(language, "adminRole");
  if (role === "operator") return translate(language, "operatorRole");
  return translate(language, "publicRole");
}

function Content({
  page,
  loading,
  language,
  role,
  summary,
  datasets,
  trends,
  datasetState,
  updateDatasetState,
  onNavigate,
  onDetails,
}: {
  page: PageConfig;
  loading: boolean;
  language: Language;
  role: PanelRole;
  summary: Summary;
  datasets: Record<string, DatasetPage>;
  trends: TrendPoint[];
  datasetState: (id: string) => DatasetState;
  updateDatasetState: (id: string, patch: Partial<DatasetState>) => void;
  onNavigate: (id: string) => void;
  onDetails: (dataset: string, row: PanelRecord) => void;
}) {
  if (loading && !Object.keys(datasets).length) {
    return <div className="loading-card">{translate(language, "loading")}</div>;
  }
  if (page.id === "overview") {
    return <OverviewPage summary={summary} datasets={datasets} trends={trends} language={language} role={role} onNavigate={onNavigate} />;
  }
  if (page.id === "nodes") {
    return (
      <NodesPageView
        page={(datasets.nodes || emptyPage()) as DatasetPage<NodeRecord>}
        state={datasetState("nodes")}
        language={language}
        onStateChange={(patch) => updateDatasetState("nodes", patch)}
      />
    );
  }
  if (page.id === "findings") {
    return (
      <FindingsPageView
        config={page}
        page={datasets.findings || emptyPage()}
        state={datasetState("findings")}
        language={language}
        onStateChange={(patch) => updateDatasetState("findings", patch)}
        onDetails={(row) => onDetails("findings", row)}
      />
    );
  }
  if (page.id === "incidents") {
    return (
      <IncidentsPageView
        config={page}
        page={datasets.incidents || emptyPage()}
        state={datasetState("incidents")}
        language={language}
        onStateChange={(patch) => updateDatasetState("incidents", patch)}
        onDetails={(row) => onDetails("incidents", row)}
      />
    );
  }
  if (page.id === "baseline_drifts") {
    return (
      <BaselinePageView
        config={page}
        page={datasets.baseline_drifts || emptyPage()}
        state={datasetState("baseline_drifts")}
        language={language}
        onStateChange={(patch) => updateDatasetState("baseline_drifts", patch)}
        onDetails={(row) => onDetails("baseline_drifts", row)}
      />
    );
  }
  if (page.id === "active_blocks") {
    return (
      <BlocksPageView
        config={page}
        page={datasets.active_blocks || emptyPage()}
        state={datasetState("active_blocks")}
        language={language}
        role={role}
        onStateChange={(patch) => updateDatasetState("active_blocks", patch)}
      />
    );
  }
  if (page.id === "probe_sources") {
    return (
      <SourcesPageView
        config={page}
        page={datasets.probe_sources || emptyPage()}
        state={datasetState("probe_sources")}
        language={language}
        role={role}
        onStateChange={(patch) => updateDatasetState("probe_sources", patch)}
      />
    );
  }
  if (page.id === "audit_logs") {
    return (
      <AuditPageView
        config={page}
        page={datasets.audit_logs || emptyPage()}
        state={datasetState("audit_logs")}
        language={language}
        onStateChange={(patch) => updateDatasetState("audit_logs", patch)}
      />
    );
  }
  return (
    <DatasetPageView
      config={page}
      page={datasets[page.id] || emptyPage()}
      state={datasetState(page.id)}
      language={language}
      role={role}
      onStateChange={(patch) => updateDatasetState(page.id, patch)}
      onDetails={onDetails}
    />
  );
}

function AccessGate({
  language,
  settings,
  message,
  onUnlock,
}: {
  language: Language;
  settings: PanelSettings;
  message: string;
  onUnlock: (token: string) => void;
}) {
  const [token, setToken] = useState("");
  return (
    <form
      className="access-card"
      onSubmit={(event) => {
        event.preventDefault();
        if (token.trim()) void onUnlock(token.trim());
      }}
    >
      <Shield size={34} />
      <h2>{translate(language, "protectedAccess")}</h2>
      <p>{translate(language, settings.auth_configured ? "accessDescription" : "accessNotConfigured")}</p>
      <TextField
        className="access-token-field"
        type="password"
        value={token}
        placeholder={translate(language, "accessToken")}
        onChange={setToken}
      />
      {message && <span className="access-error">{message}</span>}
      <button className="primary-button" type="submit">
        {translate(language, "unlock")}
      </button>
    </form>
  );
}

function streamLabel(state: StreamState, language: Language): string {
  if (state === "connecting") return translate(language, "connecting");
  if (state === "reconnecting") return translate(language, "reconnecting");
  if (state === "fallback") return translate(language, "waiting");
  return translate(language, "live");
}

function parseStreamMessage(value: string): { type?: string; role?: string } | null {
  try {
    return JSON.parse(value) as { type?: string; role?: string };
  } catch {
    return null;
  }
}

function emptyPage<T extends PanelRecord>(): DatasetPage<T> {
  return { items: [], total: 0, limit: DEFAULT_LIMIT, offset: 0 };
}

function initialPageFromLocation(): PageId {
  if (typeof window === "undefined") return "overview";
  const page = new URLSearchParams(window.location.search).get("page");
  return isPageId(page) ? page : "overview";
}

function isAdminRoute(adminPath: string | undefined): boolean {
  if (typeof window === "undefined") return false;
  return normalizeLocationPath(window.location.pathname) === normalizeAdminPath(adminPath || "/cryptocaigou");
}

function normalizeAdminPath(value: string): string {
  const withSlash = value.startsWith("/") ? value : `/${value}`;
  const normalized = withSlash.replace(/\/+$/, "");
  return normalized || "/cryptocaigou";
}

function normalizeLocationPath(value: string): string {
  const withSlash = value.startsWith("/") ? value : `/${value}`;
  return withSlash.replace(/\/+$/, "") || "/";
}

function normalizeThemeOptions(themes: ThemeOption[] | undefined): ThemeOption[] {
  const seen = new Set<string>();
  const options = (themes || [])
    .map((theme) => ({
      id: String(theme.id || "").replace(/[^a-zA-Z0-9_-]/g, ""),
      label: String(theme.label || theme.id || "").trim(),
    }))
    .filter((theme) => theme.id && !seen.has(theme.id) && seen.add(theme.id));
  return options.length ? options : [{ id: "default", label: "default" }];
}

function selectConfiguredTheme(theme: string | undefined, themes: ThemeOption[] | undefined): string {
  const options = normalizeThemeOptions(themes);
  const requested = String(theme || "default").replace(/[^a-zA-Z0-9_-]/g, "");
  return options.some((option) => option.id === requested) ? requested : options[0].id;
}

function syncPageToLocation(page: PageId): void {
  if (typeof window === "undefined") return;
  const url = new URL(window.location.href);
  if (page === "overview") {
    url.searchParams.delete("page");
  } else {
    url.searchParams.set("page", page);
  }
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function isPageId(value: unknown): value is PageId {
  return typeof value === "string" && PAGES.some((page) => page.id === value);
}

function defaultDatasetState(): DatasetState {
  return { from: "", to: "", limit: DEFAULT_LIMIT, offset: 0, preset: "", query: "" };
}
