import { API_BASE, TOKEN_STORAGE_KEY } from "@/lib/datasets";
import { sanitizePanelValue } from "@/lib/security";
import type { DatasetPage, DatasetState, PanelRecord, PanelRole, PanelSettings, TrendPoint } from "@/types";

export class PanelApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "PanelApiError";
    this.status = status;
  }
}

export function panelToken(): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
}

export function setPanelToken(token: string): void {
  window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function clearPanelToken(): void {
  window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export async function fetchJson<T>(path: string, role: PanelRole, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path.startsWith("http") ? path : `${API_BASE}${path}`, {
    ...init,
    headers: {
      accept: "application/json",
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...authHeader(),
      ...(init.headers || {}),
    },
  });
  if (!response.ok) {
    if (response.status === 401) clearPanelToken();
    throw new PanelApiError(`${path} returned HTTP ${response.status}`, response.status);
  }
  return sanitizePanelValue((await response.json()) as T, role);
}

export async function fetchSettings(role: PanelRole): Promise<PanelSettings> {
  return fetchJson<PanelSettings>("/settings", role);
}

export async function fetchDataset<T extends PanelRecord>(
  endpoint: string,
  state: DatasetState,
  role: PanelRole,
): Promise<DatasetPage<T>> {
  const params = new URLSearchParams();
  params.set("limit", String(state.limit));
  params.set("offset", String(state.offset));
  if (state.from) params.set("from", toApiTime(state.from));
  if (state.to) params.set("to", toApiTime(state.to));
  const payload = await fetchJson<DatasetPage<T> | T[]>(`${endpoint}?${params.toString()}`, role);
  return Array.isArray(payload)
    ? { items: payload, total: payload.length, limit: state.limit, offset: state.offset }
    : payload;
}

export async function fetchTrends(role: PanelRole): Promise<{ items: TrendPoint[] }> {
  const range = rangePreset("24h");
  const params = new URLSearchParams();
  if (range.from) params.set("from", toApiTime(range.from));
  if (range.to) params.set("to", toApiTime(range.to));
  params.set("limit", "200");
  return fetchJson<{ items: TrendPoint[] }>(`/trends?${params.toString()}`, role);
}

export async function postJson<T>(path: string, role: PanelRole, payload: unknown): Promise<T> {
  return fetchJson<T>(path, role, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

function authHeader(): Record<string, string> {
  const token = panelToken();
  return token ? { authorization: `Bearer ${token}` } : {};
}

export function toApiTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

export function rangePreset(preset: string): { from: string; to: string } {
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

function toDatetimeLocalValue(date: Date): string {
  const offsetMs = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}
