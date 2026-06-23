import { ROLE_LEVELS } from "@/lib/datasets";
import type { PanelRole } from "@/types";

export function selectedRole(value: unknown, hasToken = false): PanelRole {
  const role = String(value || "").toLowerCase() as PanelRole;
  if (role in ROLE_LEVELS) return role;
  return hasToken ? "operator" : "public";
}

export function roleAllows(role: PanelRole, minRole: PanelRole): boolean {
  return ROLE_LEVELS[role] >= ROLE_LEVELS[minRole];
}
