import type { PanelRole } from "@/types";
import { roleAllows } from "@/lib/rbac";

const HIDDEN_KEYS = new Set([
  "active_response_backend",
  "backend",
  "dedup_id",
  "event_id",
  "firewall_backend",
  "host_id",
  "hostname",
  "idempotency_key",
  "local_addr",
  "local_ip",
  "node_id",
  "raw_ip",
  "remote_addr",
  "remote_ip",
  "response_backend",
  "review_signature",
  "target_ip",
]);

export function sanitizePanelValue<T>(value: T, role: PanelRole): T {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return (roleAllows(role, "private") ? value : redactIpText(value)) as T;
  if (Array.isArray(value)) return value.map((item) => sanitizePanelValue(item, role)) as T;
  if (typeof value === "object") {
    const clean: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      const lower = key.toLowerCase();
      if (shouldHidePanelField(lower, role)) continue;
      if (!roleAllows(role, "private") && lower === "source_ip") {
        clean[key] = item;
      } else if (!roleAllows(role, "private") && (lower === "ip" || lower.includes("_ip") || lower.includes("addr"))) {
        clean[key] = "redacted";
      } else {
        clean[key] = sanitizePanelValue(item, role);
      }
    }
    return clean as T;
  }
  return value;
}

function shouldHidePanelField(key: string, role: PanelRole): boolean {
  if (roleAllows(role, "private")) return ["node_id", "host_id", "hostname", "review_signature"].includes(key);
  return HIDDEN_KEYS.has(key) || key.endsWith("_backend");
}

export function redactIpText(value: string): string {
  const withoutIpv4 = value.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g, (match) => {
    const parts = match.split(":")[0].split(".").map((part) => Number(part));
    return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
      ? "redacted"
      : match;
  });
  return withoutIpv4
    .split(/(\s+)/)
    .map((token) => (tokenContainsIpLiteral(token) ? "redacted" : token))
    .join("");
}

function tokenContainsIpLiteral(token: string): boolean {
  const bracketed = token.match(/\[([0-9a-fA-F:.%]+)\](?::\d+)?/);
  if (bracketed && ipv6Like(bracketed[1])) return true;
  const candidate = token.replace(/^[,;"'({<\[]+|[,;"')}\]>.]+$/g, "");
  return ipv6Like(candidate);
}

function ipv6Like(value: string): boolean {
  return value.includes(":") && /^[0-9a-fA-F:.%]+$/.test(value);
}
