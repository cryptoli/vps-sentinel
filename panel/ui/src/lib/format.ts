import type { NodeMetrics, NodeRecord, PanelRecord } from "@/types";

export function number(value: unknown): string {
  const parsed = Number(value || 0);
  if (!Number.isFinite(parsed)) return "0";
  return new Intl.NumberFormat().format(parsed);
}

export function percent(value: unknown, digits = 0): string {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return "-";
  return `${parsed.toFixed(digits)}%`;
}

export function bytes(value: unknown): string {
  const parsed = Number(value || 0);
  if (!Number.isFinite(parsed) || parsed <= 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(parsed) / Math.log(1024)), units.length - 1);
  return `${(parsed / 1024 ** exponent).toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

export function bitrate(value: unknown): string {
  const parsed = Number(value || 0);
  if (!Number.isFinite(parsed) || parsed <= 0) return "-";
  const bits = parsed * 8;
  if (bits >= 1_000_000_000) return `${(bits / 1_000_000_000).toFixed(2)} Gbps`;
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(1)} Mbps`;
  if (bits >= 1_000) return `${(bits / 1_000).toFixed(1)} Kbps`;
  return `${bits.toFixed(0)} bps`;
}

export function formatTime(value: unknown, language: "zh" | "en"): string {
  if (!value) return "-";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(language === "zh" ? "zh-CN" : "en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function relativeTime(value: unknown, language: "zh" | "en", nowMs = Date.now()): string {
  if (!value) return "-";
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return "-";
  const seconds = Math.max(0, Math.round((nowMs - date.getTime()) / 1000));
  if (seconds < 60) return language === "zh" ? "\u521a\u521a" : "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return language === "zh" ? `${minutes} \u5206\u949f\u524d` : `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return language === "zh" ? `${hours} \u5c0f\u65f6\u524d` : `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return language === "zh" ? `${days} \u5929\u524d` : `${days}d ago`;
}

export function formatValue(column: string, value: unknown, language: "zh" | "en"): string {
  if (value === null || value === undefined || value === "") return "-";
  if (column.includes("time") || column.endsWith("_at") || column.endsWith("_seen")) return formatTime(value, language);
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function categoryFromRuleId(ruleId: unknown): string {
  const prefix = String(ruleId || "").split("-")[0]?.toUpperCase();
  const categories: Record<string, string> = {
    AUTH: "ssh",
    SSH: "ssh",
    USER: "user",
    PRIV: "privilege",
    PERSIST: "persistence",
    PROC: "process",
    NET: "network",
    SERVICE: "network",
    FILE: "file_integrity",
    WEB: "web",
    DOCKER: "docker",
    ROOTKIT: "rootkit",
    CONFIG: "config_risk",
    SYS: "system",
    SYSTEM: "system",
  };
  return categories[prefix] || "system";
}

export function fingerprintConclusion(row: PanelRecord): string {
  const existing = String(row.conclusion || "").trim().toLowerCase();
  if (["malicious", "benign", "suspicious", "needs_review"].includes(existing)) return existing;
  const verdict = String(row.verdict || "").trim().toLowerCase();
  if (verdict === "malicious" || verdict === "benign") return verdict;
  if (verdict === "false_positive") return "benign";
  const score = Number(row.score || 0);
  const confidence = Number(row.confidence || 0);
  const sourceCount = Number(row.source_count || 0);
  const seenCount = Number(row.seen_count || 0);
  if (score >= 75 || confidence >= 80 || sourceCount >= 2 || seenCount >= 3) return "suspicious";
  return "needs_review";
}

export function countryDisplay(value: unknown): { flag: string; label: string } {
  const label = String(value || "").trim();
  const code = countryCodeFromValue(label);
  return {
    flag: code ? flagForCountry(code) : "\u25CF",
    label: label && label.toLowerCase() !== "unknown" ? label : "Unknown",
  };
}

export function metricsFromNode(node: NodeRecord): NodeMetrics {
  if (node.metrics && typeof node.metrics === "object") return normalizeNodeMetrics(node.metrics as NodeMetrics);
  if (node.metrics_json && typeof node.metrics_json === "object") return normalizeNodeMetrics(node.metrics_json as NodeMetrics);
  if (typeof node.metrics_json === "string") {
    try {
      return normalizeNodeMetrics(JSON.parse(node.metrics_json) as NodeMetrics);
    } catch {
      return {};
    }
  }
  return {};
}

export function storageFromNode(node: NodeRecord): PanelRecord {
  if (node.storage && typeof node.storage === "object") return node.storage;
  if (node.storage_json && typeof node.storage_json === "object") return node.storage_json as PanelRecord;
  if (typeof node.storage_json === "string") {
    try {
      return JSON.parse(node.storage_json) as PanelRecord;
    } catch {
      return {};
    }
  }
  return {};
}

function normalizeNodeMetrics(metrics: NodeMetrics): NodeMetrics {
  const rxBytes = firstNumber(metrics.rx_bytes, metrics.network_rx_bytes);
  const txBytes = firstNumber(metrics.tx_bytes, metrics.network_tx_bytes);
  const rxRate = firstNumber(
    metrics.rx_bytes_per_second,
    metrics.network_rx_bytes_per_second,
    metrics.network_rx_rate_bps,
  );
  const txRate = firstNumber(
    metrics.tx_bytes_per_second,
    metrics.network_tx_bytes_per_second,
    metrics.network_tx_rate_bps,
  );
  const agentRssBytes = firstNumber(metrics.agent_rss_bytes, Number(metrics.agent_rss_kb) * 1024);
  const memoryUsedPercent = firstNumber(
    metrics.memory_used_percent,
    ratioPercent(metrics.memory_used_bytes, metrics.memory_total_bytes),
  );
  const diskUsedPercent = firstNumber(
    metrics.disk_used_percent,
    ratioPercent(metrics.disk_used_bytes, metrics.disk_total_bytes),
  );
  return {
    ...metrics,
    ...(rxBytes === undefined ? {} : { rx_bytes: rxBytes }),
    ...(txBytes === undefined ? {} : { tx_bytes: txBytes }),
    ...(rxRate === undefined ? {} : { rx_bytes_per_second: rxRate }),
    ...(txRate === undefined ? {} : { tx_bytes_per_second: txRate }),
    ...(agentRssBytes === undefined ? {} : { agent_rss_bytes: agentRssBytes }),
    ...(memoryUsedPercent === undefined ? {} : { memory_used_percent: memoryUsedPercent }),
    ...(diskUsedPercent === undefined ? {} : { disk_used_percent: diskUsedPercent }),
  };
}

function firstNumber(...values: Array<unknown>): number | undefined {
  for (const value of values) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function ratioPercent(used: unknown, total: unknown): number | undefined {
  const usedNumber = Number(used);
  const totalNumber = Number(total);
  if (!Number.isFinite(usedNumber) || !Number.isFinite(totalNumber) || totalNumber <= 0) return undefined;
  return (usedNumber / totalNumber) * 100;
}

export function nodeLocation(node: NodeRecord): { countryCode: string; flag: string; label: string } {
  const metrics = metricsFromNode(node);
  const countryCode = countryCodeFromValue(metrics.country_code) || countryCodeFromValue(metrics.country);
  if (countryCode) {
    const label = [metrics.city, metrics.region, metrics.country].filter(Boolean).join(", ") || countryCode;
    return { countryCode, flag: flagForCountry(countryCode), label };
  }
  return { countryCode: "", flag: "\u25CF", label: "Unknown" };
}

export function flagForCountry(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return "\u25CF";
  const base = 0x1f1e6;
  return String.fromCodePoint(...[...code].map((letter) => base + letter.charCodeAt(0) - 65));
}

function countryCodeFromValue(value: unknown): string {
  const text = String(value || "").trim();
  if (/^[A-Za-z]{2}$/.test(text)) return text.toUpperCase();
  const normalized = text.toLowerCase().replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return COUNTRY_NAME_TO_CODE[normalized] || "";
}

const COUNTRY_NAME_TO_CODE: Record<string, string> = {
  "argentina": "AR",
  "australia": "AU",
  "austria": "AT",
  "belgium": "BE",
  "brazil": "BR",
  "canada": "CA",
  "chile": "CL",
  "china": "CN",
  "colombia": "CO",
  "czech republic": "CZ",
  "denmark": "DK",
  "finland": "FI",
  "france": "FR",
  "georgia": "GE",
  "germany": "DE",
  "hong kong": "HK",
  "india": "IN",
  "indonesia": "ID",
  "ireland": "IE",
  "israel": "IL",
  "italy": "IT",
  "japan": "JP",
  "malaysia": "MY",
  "mexico": "MX",
  "netherlands": "NL",
  "new zealand": "NZ",
  "norway": "NO",
  "poland": "PL",
  "portugal": "PT",
  "romania": "RO",
  "russia": "RU",
  "russian federation": "RU",
  "singapore": "SG",
  "south africa": "ZA",
  "south korea": "KR",
  "spain": "ES",
  "sweden": "SE",
  "switzerland": "CH",
  "taiwan": "TW",
  "thailand": "TH",
  "turkey": "TR",
  "ukraine": "UA",
  "united arab emirates": "AE",
  "united kingdom": "GB",
  "uk": "GB",
  "united states": "US",
  "united states of america": "US",
  "usa": "US",
  "vietnam": "VN",
};

export function sortedNodes(nodes: NodeRecord[]): NodeRecord[] {
  return [...nodes].sort((left, right) =>
    String(left.node_name || "").localeCompare(String(right.node_name || ""), undefined, { sensitivity: "base" }),
  );
}

export function rowTone(row: PanelRecord): string {
  const reviewVerdict = String(row.review_verdict || "").toLowerCase();
  if (reviewVerdict === "false_positive") return "muted";
  if (reviewVerdict === "confirmed") return "success";
  const severity = String(row.severity || row.block_status || "").toLowerCase();
  if (["critical", "high", "blocked", "permanent_block"].includes(severity)) return "danger";
  if (["medium", "stale", "observed"].includes(severity)) return "warning";
  if (["low", "fresh", "confirmed"].includes(severity)) return "success";
  return "neutral";
}
