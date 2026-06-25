import type { PageConfig, PageId } from "@/types";
import {
  DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
  DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
  PAGES,
  ROLE_LEVELS,
} from "@/lib/panel-contract.generated";

export {
  DEFAULT_FRESHNESS_THRESHOLD_MINUTES,
  DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES,
  PAGES,
  ROLE_LEVELS,
};

export const DEFAULT_LIMIT = 25;
export const OVERVIEW_LIMIT = 12;
export const API_BASE = "/api/v1";
export const TOKEN_STORAGE_KEY = "vps-sentinel-panel-token";
export const STREAM_RECONNECT_MS = 5000;
export const TIME_PRESETS = ["1h", "6h", "24h", "today", "7d"] as const;

export const DATASET_BY_ID = new Map(PAGES.filter((page) => page.endpoint).map((page) => [page.id, page]));

export function pageById(id: PageId): PageConfig {
  return PAGES.find((page) => page.id === id) ?? PAGES[0];
}
