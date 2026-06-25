export type PanelRole = "public" | "private";
export type Language = "zh" | "en";
export type StreamState = "idle" | "connecting" | "live" | "reconnecting" | "fallback";
export type PageId =
  | "overview"
  | "findings"
  | "incidents"
  | "baseline_drifts"
  | "active_blocks"
  | "probe_sources"
  | "audit_logs"
  | "nodes";

export type Primitive = string | number | boolean | null;
export type JsonValue = Primitive | JsonValue[] | { [key: string]: JsonValue };
export type PanelRecord = Record<string, unknown>;

export interface PanelSettings {
  admin_path?: string | null;
  theme?: string;
  themes?: ThemeOption[];
  auth_required?: boolean;
  auth_configured?: boolean;
  management_route?: boolean;
  stream_supported?: boolean;
  public_enabled?: boolean;
  public_pages?: PageId[];
  role?: PanelRole | null;
  freshness_threshold_minutes?: number;
  offline_threshold_minutes?: number;
  node_retired_threshold_minutes?: number;
  server_time?: string;
}

export interface ThemeOption {
  id: string;
  label: string;
}

export interface DatasetPage<T extends PanelRecord = PanelRecord> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface DatasetState {
  from: string;
  to: string;
  limit: number;
  offset: number;
  preset: string;
  query: string;
}

export interface Summary {
  nodes?: number;
  findings?: number;
  incidents?: number;
  baseline_drifts?: number;
  active_blocks?: number;
  probe_sources?: number;
  by_severity?: Array<{ severity: string; count: number }>;
  by_category?: Array<{ category: string; count: number }>;
  by_block_status?: Array<{ block_status: string; count: number }>;
  node_status?: Record<string, number>;
}

export interface TrendPoint {
  bucket?: string;
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  severity?: Record<string, number>;
}

export interface NodeMetrics {
  cpu_cores?: number;
  cpu_percent?: number;
  memory_used_percent?: number;
  memory_total_bytes?: number;
  memory_used_bytes?: number;
  swap_total_bytes?: number;
  swap_used_bytes?: number;
  disk_total_bytes?: number;
  disk_used_bytes?: number;
  disk_used_percent?: number;
  load1?: number;
  load5?: number;
  load15?: number;
  rx_bytes?: number;
  tx_bytes?: number;
  rx_bytes_per_second?: number;
  tx_bytes_per_second?: number;
  network_rx_bytes?: number;
  network_tx_bytes?: number;
  network_rx_rate_bps?: number;
  network_tx_rate_bps?: number;
  network_rx_bytes_per_second?: number;
  network_tx_bytes_per_second?: number;
  network_interfaces?: number;
  uptime_seconds?: number;
  uptime_days?: number;
  agent_rss_bytes?: number;
  agent_rss_kb?: number;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
}

export interface NodeRecord extends PanelRecord {
  node_name?: string;
  agent_version?: string;
  privacy_mode?: string;
  last_seen_at?: string;
  metrics?: NodeMetrics;
  metrics_json?: string | NodeMetrics;
  storage?: PanelRecord;
  storage_json?: string | PanelRecord;
  status?: string;
}

export interface PageConfig {
  id: PageId;
  labelKey: string;
  titleKey: string;
  descriptionKey: string;
  minRole: PanelRole;
  endpoint?: string;
  columns?: string[];
  publicColumns?: string[];
  privateColumns?: string[];
}
