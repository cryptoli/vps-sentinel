import { formatValue, rowTone } from "@/lib/format";
import { formatTemplate, translate } from "@/lib/i18n";
import type { Language, PanelRecord } from "@/types";
import type { CSSProperties } from "react";

export function Card({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel-card ${className}`}>
      {(title || subtitle || action) && (
        <header className="panel-card-head">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function MetricCard({
  label,
  value,
  detail,
  tone = "blue",
  icon,
  sparkline,
}: {
  label: string;
  value: string | number;
  detail?: string;
  tone?: string;
  icon?: React.ReactNode;
  sparkline?: React.ReactNode;
}) {
  return (
    <article className={`metric-card tone-${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div className="metric-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        {detail && <small>{detail}</small>}
      </div>
      {sparkline}
    </article>
  );
}

export function Badge({ value, tone }: { value: string; tone?: string }) {
  const toneClass = String(tone || value).toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return <span className={`badge badge-${toneClass}`}>{value}</span>;
}

export function DataTable({
  rows,
  columns,
  language,
  onDetails,
  detailLabelKey = "details",
  tableId,
}: {
  rows: PanelRecord[];
  columns: string[];
  language: Language;
  onDetails?: (row: PanelRecord) => void;
  detailLabelKey?: string;
  tableId?: string;
}) {
  if (!rows.length) return <div className="empty-state">{translate(language, "noData")}</div>;
  const layout = tableLayout(tableId, columns, Boolean(onDetails));
  return (
    <div className="table-wrap">
      <table
        className={`data-table ${tableId ? `data-table-${tableId}` : ""}`}
        style={{ "--table-min-width": layout.minWidth } as CSSProperties}
      >
        <colgroup>
          {columns.map((column) => (
            <col key={column} style={{ width: layout.widths[column] || layout.defaultWidth }} />
          ))}
          {onDetails && <col style={{ width: layout.detailsWidth }} />}
        </colgroup>
        <thead>
          <tr>
            {columns.map((column) => (
              <th className={`col-${columnClass(column)}`} key={column}>{translate(language, column)}</th>
            ))}
            {onDetails && <th className="col-details">{translate(language, detailLabelKey)}</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr className={`row-${rowTone(row)}`} key={String(row.id || `${row.node_name || "row"}-${index}`)}>
              {columns.map((column) => (
                <td className={`col-${columnClass(column)}`} data-label={translate(language, column)} key={column} title={plainCellValue(column, cellValue(row, column), language)}>
                  {renderCell(column, cellValue(row, column), language)}
                </td>
              ))}
              {onDetails && (
                <td className="col-details">
                  <button className="ghost-button compact" type="button" onClick={() => onDetails(row)}>
                    {translate(language, detailLabelKey)}
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

type TableLayout = {
  defaultWidth: string;
  detailsWidth: string;
  minWidth: string;
  widths: Record<string, string>;
};

const TABLE_LAYOUTS: Record<string, TableLayout> = {
  "overview-findings": {
    defaultWidth: "140px",
    detailsWidth: "100px",
    minWidth: "760px",
    widths: {
      timestamp: "152px",
      severity: "104px",
      title: "280px",
      node_name: "140px",
      status: "110px",
    },
  },
  findings: {
    defaultWidth: "128px",
    detailsWidth: "104px",
    minWidth: "930px",
    widths: {
      timestamp: "160px",
      severity: "104px",
      node_name: "144px",
      rule_id: "132px",
      category: "142px",
      review_verdict: "128px",
    },
  },
  incidents: {
    defaultWidth: "132px",
    detailsWidth: "104px",
    minWidth: "980px",
    widths: {
      last_seen: "160px",
      severity: "104px",
      score: "88px",
      node_name: "144px",
      title: "340px",
      review_verdict: "128px",
    },
  },
  "baseline-drifts": {
    defaultWidth: "136px",
    detailsWidth: "104px",
    minWidth: "1120px",
    widths: {
      timestamp: "158px",
      node_name: "138px",
      category: "128px",
      subject: "300px",
      tier: "108px",
      review_verdict: "128px",
      review_action: "182px",
    },
  },
  "active-blocks": {
    defaultWidth: "138px",
    detailsWidth: "104px",
    minWidth: "1560px",
    widths: {
      blocked_at: "150px",
      node_name: "136px",
      ip: "142px",
      network_prefix: "148px",
      country: "92px",
      asn: "118px",
      organization: "220px",
      rule_id: "130px",
      backend: "112px",
      reason: "300px",
      expires_at: "150px",
    },
  },
  probe_sources: {
    defaultWidth: "140px",
    detailsWidth: "104px",
    minWidth: "2040px",
    widths: {
      last_seen: "150px",
      node_name: "136px",
      source_ip: "146px",
      ip_version: "88px",
      network_prefix: "150px",
      seen_count: "96px",
      block_status: "118px",
      country: "92px",
      asn: "118px",
      organization: "230px",
      categories: "180px",
      rule_ids: "180px",
      latest_reason: "300px",
      block_reason: "290px",
    },
  },
  audit_logs: {
    defaultWidth: "150px",
    detailsWidth: "104px",
    minWidth: "860px",
    widths: {
      created_at: "152px",
      action: "190px",
      actor: "140px",
      target_type: "140px",
      target_id: "300px",
    },
  },
};

function tableLayout(tableId: string | undefined, columns: string[], hasDetails: boolean): TableLayout {
  const layout = tableId ? TABLE_LAYOUTS[tableId] : undefined;
  if (layout) return layout;
  const width = columns.length * 132 + (hasDetails ? 104 : 0);
  return {
    defaultWidth: "132px",
    detailsWidth: "104px",
    minWidth: `${Math.max(720, width)}px`,
    widths: {},
  };
}

export function Pagination({
  total,
  limit,
  offset,
  language,
  onPage,
}: {
  total: number;
  limit: number;
  offset: number;
  language: Language;
  onPage: (offset: number) => void;
}) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="pagination">
      <span>{formatTemplate(translate(language, "pageInfo"), { from, to, total })}</span>
      <div>
        <button className="ghost-button" disabled={offset <= 0} type="button" onClick={() => onPage(Math.max(0, offset - limit))}>
          {translate(language, "previous")}
        </button>
        <button className="primary-button" disabled={offset + limit >= total} type="button" onClick={() => onPage(offset + limit)}>
          {translate(language, "next")}
        </button>
      </div>
    </div>
  );
}

function renderCell(column: string, value: unknown, language: Language) {
  if (["severity", "status", "block_status", "tier", "review_verdict"].includes(column)) {
    const key = String(value || "unknown").toLowerCase();
    return <Badge value={translate(language, key)} tone={key} />;
  }
  if (["category", "review_action", "backend"].includes(column)) {
    const key = String(value || "unknown").toLowerCase().replace(/[\s-]+/g, "_");
    const translated = translate(language, key);
    return translated === key ? formatValue(column, value, language) : translated;
  }
  if (Array.isArray(value)) {
    return (
      <span className="cell-chip-list">
        {value.slice(0, 4).map((item) => (
          <span key={String(item)}>{formatValue(column, item, language)}</span>
        ))}
        {value.length > 4 && <em>+{value.length - 4}</em>}
      </span>
    );
  }
  if (["country", "asn", "organization", "network_prefix"].includes(column) && (!value || String(value).toLowerCase() === "unknown")) {
    return <span className="muted-cell">{translate(language, "unknown")}</span>;
  }
  return formatValue(column, value, language);
}

function plainCellValue(column: string, value: unknown, language: Language): string {
  if (Array.isArray(value)) return value.map((item) => formatValue(column, item, language)).join(", ");
  return formatValue(column, value, language);
}

function columnClass(column: string): string {
  return column.replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase();
}

function cellValue(row: PanelRecord, column: string): unknown {
  if (row[column] !== undefined && row[column] !== null && row[column] !== "") return row[column];
  if (column === "category") return categoryFromRow(row);
  return row[column];
}

function categoryFromRow(row: PanelRecord): string {
  const byRule = categoryFromRule(row.rule_id);
  if (byRule !== "unknown") return byRule;
  const subject = String(row.subject || "").toLowerCase();
  if (subject.includes("service") || subject.includes("port") || subject.includes("listen")) return "network";
  if (subject.includes("authorized") || subject.includes(".ssh")) return "ssh";
  if (subject.includes("systemd") || subject.includes("unit")) return "persistence";
  if (subject.includes("process") || subject.includes("pid")) return "process";
  if (subject.includes("file") || subject.includes("/")) return "file_integrity";
  return "unknown";
}

function categoryFromRule(ruleId: unknown): string {
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
  return categories[prefix] || "unknown";
}
