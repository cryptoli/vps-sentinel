import { categoryFromRuleId, countryDisplay, fingerprintConclusion, formatValue, number, rowTone } from "@/lib/format";
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
  rowAction,
  actionLabelKey = "actions",
  tableId,
}: {
  rows: PanelRecord[];
  columns: string[];
  language: Language;
  onDetails?: (row: PanelRecord) => void;
  detailLabelKey?: string;
  rowAction?: (row: PanelRecord) => React.ReactNode;
  actionLabelKey?: string;
  tableId?: string;
}) {
  if (!rows.length) return <div className="empty-state">{translate(language, "noData")}</div>;
  const layout = tableLayout(tableId, columns, Boolean(onDetails || rowAction));
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
          {rowAction && <col style={{ width: layout.detailsWidth }} />}
        </colgroup>
        <thead>
          <tr>
            {columns.map((column) => (
              <th className={`col-${columnClass(column)}`} key={column}>{translate(language, column)}</th>
            ))}
            {onDetails && <th className="col-details">{translate(language, detailLabelKey)}</th>}
            {rowAction && <th className="col-actions">{translate(language, actionLabelKey)}</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr className={`row-${rowTone(row)}`} key={String(row.id || `${row.node_name || "row"}-${index}`)}>
              {columns.map((column) => (
                <td className={`col-${columnClass(column)}`} data-label={translate(language, column)} key={column} title={plainCellValue(column, cellValue(row, column), language)}>
                  <span className="cell-value">{renderCell(column, cellValue(row, column), language)}</span>
                </td>
              ))}
              {onDetails && (
                <td className="col-details">
                  <button className="ghost-button compact" type="button" onClick={() => onDetails(row)}>
                    {translate(language, detailLabelKey)}
                  </button>
                </td>
              )}
              {rowAction && <td className="col-actions">{rowAction(row)}</td>}
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
    defaultWidth: "128px",
    detailsWidth: "92px",
    minWidth: "720px",
    widths: {
      timestamp: "148px",
      severity: "96px",
      title: "260px",
      node_name: "132px",
      status: "96px",
    },
  },
  findings: {
    defaultWidth: "116px",
    detailsWidth: "90px",
    minWidth: "812px",
    widths: {
      timestamp: "142px",
      severity: "84px",
      node_name: "116px",
      rule_id: "122px",
      category: "122px",
      review_verdict: "116px",
      subject: "260px",
      title: "280px",
    },
  },
  incidents: {
    defaultWidth: "116px",
    detailsWidth: "90px",
    minWidth: "846px",
    widths: {
      last_seen: "142px",
      severity: "84px",
      score: "70px",
      node_name: "118px",
      title: "246px",
      summary: "300px",
      review_verdict: "110px",
    },
  },
  "baseline-drifts": {
    defaultWidth: "116px",
    detailsWidth: "90px",
    minWidth: "940px",
    widths: {
      timestamp: "142px",
      node_name: "118px",
      category: "112px",
      subject: "246px",
      tier: "88px",
      review_verdict: "112px",
      review_action: "142px",
    },
  },
  "active-blocks": {
    defaultWidth: "122px",
    detailsWidth: "96px",
    minWidth: "930px",
    widths: {
      blocked_at: "142px",
      node_name: "128px",
      ip: "138px",
      categories: "138px",
      evidence: "106px",
      network_prefix: "138px",
      country: "84px",
      asn: "104px",
      organization: "180px",
      rule_id: "116px",
      backend: "96px",
      reason: "210px",
      expires_at: "142px",
    },
  },
  "attack-fingerprints": {
    defaultWidth: "118px",
    detailsWidth: "96px",
    minWidth: "940px",
    widths: {
      last_seen_at: "146px",
      kind: "118px",
      score: "76px",
      confidence: "96px",
      conclusion: "116px",
      verdict: "112px",
      node_count: "94px",
      source_count: "104px",
      seen_count: "96px",
    },
  },
  probe_sources: {
    defaultWidth: "120px",
    detailsWidth: "96px",
    minWidth: "1680px",
    widths: {
      last_seen: "142px",
      node_name: "126px",
      source_ip: "136px",
      ip_version: "76px",
      network_prefix: "136px",
      seen_count: "86px",
      block_status: "112px",
      country: "84px",
      asn: "104px",
      organization: "180px",
      categories: "148px",
      rule_ids: "148px",
      latest_reason: "230px",
      block_reason: "230px",
    },
  },
  audit_logs: {
    defaultWidth: "132px",
    detailsWidth: "96px",
    minWidth: "760px",
    widths: {
      created_at: "146px",
      action: "160px",
      actor: "126px",
      target_type: "120px",
      target_id: "230px",
    },
  },
};

function tableLayout(tableId: string | undefined, columns: string[], hasDetails: boolean): TableLayout {
  const layout = tableId ? TABLE_LAYOUTS[tableId] : undefined;
  if ((tableId === "probe_sources" || tableId === "active-blocks") && layout) {
    const width = columns.reduce((sum, column) => sum + px(layout.widths[column] || layout.defaultWidth), hasDetails ? px(layout.detailsWidth) : 0);
    return { ...layout, minWidth: `${Math.max(860, width)}px` };
  }
  if (layout) return layout;
  const width = columns.length * 132 + (hasDetails ? 104 : 0);
  return {
    defaultWidth: "132px",
    detailsWidth: "104px",
    minWidth: `${Math.max(720, width)}px`,
    widths: {},
  };
}

function px(value: string): number {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : 0;
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
  if (column === "score") {
    const score = Math.max(0, Math.min(100, Number(value || 0)));
    return (
      <span className="score-badge" style={{ "--score": `${score}%` } as CSSProperties}>
        {number(score)}
      </span>
    );
  }
  if (column === "evidence") {
    const score = Math.max(0, Math.min(5, Number(value || 0)));
    return (
      <span className="evidence-dots" aria-label={`${score}/5`}>
        {[0, 1, 2, 3, 4].map((item) => <i className={item < score ? "active" : ""} key={item} />)}
        <small>{score} / 5</small>
      </span>
    );
  }
  if (column === "reason") {
    return <span className="reason-chip">{formatValue(column, value, language)}</span>;
  }
  if (["severity", "status", "block_status", "tier", "review_verdict", "verdict", "conclusion"].includes(column)) {
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
  if (column === "country") {
    const country = countryDisplay(value);
    return (
      <span className="country-cell">
        <span className="country-flag" aria-hidden="true">{country.flag}</span>
        <span>{country.label}</span>
      </span>
    );
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
  if (column === "evidence") return evidenceScore(row);
  if (column === "category") return categoryFromRow(row);
  if (column === "conclusion") return fingerprintConclusion(row);
  return row[column];
}

function evidenceScore(row: PanelRecord): number {
  const candidates = [row.evidence, row.evidence_count, row.seen_count, row.score, row.confidence];
  const value = candidates.map(Number).find((item) => Number.isFinite(item) && item > 0) || 0;
  if (value <= 5) return Math.round(value);
  if (value <= 100) return Math.max(1, Math.ceil(value / 20));
  return 5;
}

function categoryFromRow(row: PanelRecord): string {
  if (String(row.rule_id || "").trim()) return categoryFromRuleId(row.rule_id);
  const subject = String(row.subject || "").toLowerCase();
  if (subject.includes("service") || subject.includes("port") || subject.includes("listen")) return "network";
  if (subject.includes("authorized") || subject.includes(".ssh")) return "ssh";
  if (subject.includes("systemd") || subject.includes("unit")) return "persistence";
  if (subject.includes("process") || subject.includes("pid")) return "process";
  if (subject.includes("file") || subject.includes("/")) return "file_integrity";
  return "unknown";
}
