#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const contractPath = resolve(repoRoot, "panel/shared/contract.json");
const check = process.argv.includes("--check");

const contract = JSON.parse(readFileSync(contractPath, "utf8"));
validateContract(contract);

const outputs = new Map([
  ["crates/sentinel-panel/src/panel_contract.rs", formatRust(renderRust(contract))],
  ["panel/cloudflare/panel-contract.generated.js", renderWorkerJs(contract)],
  ["panel/ui/src/lib/panel-contract.generated.ts", renderUiTs(contract)],
  ["panel/shared/contract.env", renderShellEnv(contract)],
]);

let stale = false;
for (const [relativePath, content] of outputs) {
  const target = resolve(repoRoot, relativePath);
  if (check) {
    let existing = "";
    try {
      existing = readFileSync(target, "utf8");
    } catch {
      stale = true;
      console.error(`${relativePath} is missing; run node scripts/generate-panel-contract.mjs`);
      continue;
    }
    if (existing !== content) {
      stale = true;
      console.error(`${relativePath} is out of date; run node scripts/generate-panel-contract.mjs`);
    }
  } else {
    writeFileSync(target, content, "utf8");
    console.log(`generated ${relativePath}`);
  }
}

if (stale) process.exit(1);

function validateContract(value) {
  const pageIds = new Set();
  for (const page of value.pages || []) {
    if (!page.id || pageIds.has(page.id)) throw new Error(`duplicate or missing page id: ${page.id}`);
    pageIds.add(page.id);
  }
  for (const [path, dataset] of Object.entries(value.datasets || {})) {
    if (!path.startsWith("/api/v1/")) throw new Error(`dataset path must be an API path: ${path}`);
    if (!pageIds.has(dataset.pageId)) throw new Error(`dataset ${path} references unknown page ${dataset.pageId}`);
    for (const key of ["table", "orderColumn", "columns"]) {
      if (!dataset[key]) throw new Error(`dataset ${path} missing ${key}`);
    }
  }
}

function renderRust(value) {
  const constants = value.constants;
  const datasets = value.datasets;
  const rustColumns = value.rustColumnSets;
  const functions = [
    rustDatasetFn("findings_dataset", datasets["/api/v1/findings"]),
    rustDatasetFn("incidents_dataset", datasets["/api/v1/incidents"]),
    rustDatasetFn("baseline_drifts_dataset", datasets["/api/v1/baseline-drifts"]),
    rustDatasetFn("active_blocks_private_dataset", datasets["/api/v1/active-blocks"]),
    rustDatasetFn("audit_logs_dataset", datasets["/api/v1/audit-logs"]),
  ].join("\n\n");
  return `${generatedHeader("//")}
use super::{PanelDataset, PanelRole};

pub(crate) const SIGNATURE_WINDOW_SECONDS: i64 = ${constants.signatureWindowSeconds};
pub(crate) const DEFAULT_PAGE_LIMIT: usize = ${constants.defaultPageLimit};
pub(crate) const MAX_PAGE_LIMIT: usize = ${constants.maxPageLimit};
pub(crate) const DEFAULT_FRESHNESS_THRESHOLD_MINUTES: u64 = ${constants.defaultFreshnessThresholdMinutes};
pub(crate) const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES: u64 = ${constants.defaultNodeRetiredThresholdMinutes};
pub(crate) const PANEL_TRANSPORT_ENCODING: &str = ${rustString(constants.panelTransportEncoding)};
pub(crate) const DEFAULT_PUBLIC_PAGES: &str = ${rustString(constants.defaultPublicPages.join(","))};
pub(crate) const DEFAULT_ADMIN_PATH: &str = ${rustString(constants.defaultAdminPath)};
pub(crate) const DEFAULT_THEMES: &str = ${rustString(constants.defaultThemes)};

const STREAM_REFRESH_DATASETS: &[&str] = &${rustArray(constants.streamRefreshDatasets)};
pub(crate) const PUBLIC_PROBE_SOURCE_HIDDEN_KEYS: &[&str] = &${rustArray(constants.publicProbeSourceHiddenKeys)};
const NODES_PUBLIC_COLUMNS: &[&str] = &${rustArray(rustColumns.nodesPublic)};
const NODES_PRIVATE_COLUMNS: &[&str] = &${rustArray(rustColumns.nodesPrivate)};

pub(crate) fn stream_refresh_datasets() -> Vec<&'static str> {
    STREAM_REFRESH_DATASETS.to_vec()
}

pub(crate) fn node_columns(role: PanelRole) -> &'static [&'static str] {
    match role {
        PanelRole::Public => NODES_PUBLIC_COLUMNS,
        PanelRole::Private => NODES_PRIVATE_COLUMNS,
    }
}

${functions}

pub(crate) fn active_blocks_dataset(role: PanelRole) -> PanelDataset {
    match role {
        PanelRole::Public => PanelDataset {
            table: ${rustString(datasets["/api/v1/active-blocks"].table)},
            order_column: ${rustString(datasets["/api/v1/active-blocks"].orderColumn)},
            active_filter: ${rustOption(datasets["/api/v1/active-blocks"].activeFilter)},
            columns: &${rustArray(datasets["/api/v1/active-blocks"].publicColumns)},
        },
        PanelRole::Private => active_blocks_private_dataset(),
    }
}
`;
}

function formatRust(source) {
  const rustfmt = process.env.RUSTFMT || "rustfmt";
  const result = spawnSync(rustfmt, ["--edition", "2021"], {
    input: source,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  if (result.status === 0 && result.stdout) return result.stdout;
  return source;
}

function rustDatasetFn(name, dataset) {
  return `pub(crate) fn ${name}() -> PanelDataset {
    PanelDataset {
        table: ${rustString(dataset.table)},
        order_column: ${rustString(dataset.orderColumn)},
        active_filter: ${rustOption(dataset.activeFilter)},
        columns: &${rustArray(dataset.columns)},
    }
}`;
}

function renderWorkerJs(value) {
  const constants = value.constants;
  return `${generatedHeader("//")}
export const SIGNATURE_WINDOW_SECONDS = ${constants.signatureWindowSeconds};
export const DEFAULT_PAGE_LIMIT = ${constants.defaultPageLimit};
export const MAX_PAGE_LIMIT = ${constants.maxPageLimit};
export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = ${constants.defaultFreshnessThresholdMinutes};
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = ${constants.defaultNodeRetiredThresholdMinutes};
export const ROLE_LEVELS = Object.freeze({ public: 0, private: 1 });
export const PANEL_TRANSPORT_ENCODING = ${jsonInline(constants.panelTransportEncoding)};
export const DEFAULT_PUBLIC_PAGES = ${jsonInline(constants.defaultPublicPages.join(","))};
export const DEFAULT_ADMIN_PATH = ${jsonInline(constants.defaultAdminPath)};
export const DEFAULT_THEMES = ${jsonInline(constants.defaultThemes)};
export const PUBLIC_PROBE_SOURCE_HIDDEN_KEYS = Object.freeze(${json(constants.publicProbeSourceHiddenKeys)});
export const DATASETS = deepFreeze(${json(value.datasets)});

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return Object.freeze(value);
}
`;
}

function renderUiTs(value) {
  const constants = value.constants;
  return `${generatedHeader("//")}
import type { PageConfig } from "@/types";

export const ROLE_LEVELS = {
  public: 0,
  private: 1,
} as const;

export const DEFAULT_FRESHNESS_THRESHOLD_MINUTES = ${constants.defaultFreshnessThresholdMinutes};
export const DEFAULT_NODE_RETIRED_THRESHOLD_MINUTES = ${constants.defaultNodeRetiredThresholdMinutes};
export const PAGES = ${jsonExpression(value.pages)} satisfies PageConfig[];
`;
}

function renderShellEnv(value) {
  const constants = value.constants;
  return `${generatedHeader("#")}
PANEL_CONTRACT_DEFAULT_PUBLIC_PAGES='${shellQuote(constants.defaultPublicPages.join(","))}'
PANEL_CONTRACT_DEFAULT_ADMIN_PATH='${shellQuote(constants.defaultAdminPath)}'
PANEL_CONTRACT_DEFAULT_THEMES='${shellQuote(constants.defaultThemes)}'
`;
}

function generatedHeader(prefix) {
  return `${prefix} This file is generated from panel/shared/contract.json.
${prefix} Run: node scripts/generate-panel-contract.mjs

`;
}

function json(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function jsonInline(value) {
  return JSON.stringify(value);
}

function jsonExpression(value) {
  return JSON.stringify(value, null, 2);
}

function rustString(value) {
  return JSON.stringify(value);
}

function rustOption(value) {
  return value ? `Some(${rustString(value)})` : "None";
}

function rustArray(values) {
  return `[${values.map(rustString).join(", ")}]`;
}

function shellQuote(value) {
  return String(value).replaceAll("'", "'\\''");
}
