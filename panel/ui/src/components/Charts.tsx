import type { Language, TrendPoint } from "@/types";
import { number } from "@/lib/format";
import { translate } from "@/lib/i18n";

interface ChartSlice {
  label: string;
  value: number;
  className: string;
}

export function Sparkline({ values, tone = "blue" }: { values: number[]; tone?: string }) {
  const points = normalizePoints(values, 120, 34, 4);
  const path = smoothPath(points);
  const area = `${path} L116,34 L4,34 Z`;
  return (
    <svg className={`sparkline sparkline-${tone}`} viewBox="0 0 120 34" preserveAspectRatio="none" aria-hidden="true">
      <path className="spark-area" d={area} />
      <path className="spark-line" d={path} />
    </svg>
  );
}

export function RiskTrend({ rows, language }: { rows: TrendPoint[]; language: Language }) {
  const windowRows = rows.slice(-7);
  const base = windowRows.length
    ? windowRows.map((row) => Number(row.total ?? sumRisk(row) ?? 0))
    : [28, 31, 35, 33, 39, 36, 34];
  const series = [
    trendSeries("critical", windowRows, base, 0.08, language),
    trendSeries("high", windowRows, base, 0.52, language),
    trendSeries("medium", windowRows, base, 0.3, language),
    trendSeries("low", windowRows, base, 0.14, language),
    { key: "total", label: translate(language, "total"), values: base },
  ];
  const max = niceMax(Math.max(1, ...series.flatMap((item) => item.values)));
  const width = 720;
  const height = 274;
  const padding = { left: 42, right: 16, top: 14, bottom: 34 };
  const pointsBySeries = series.map((item) => ({
    ...item,
    points: chartPoints(item.values, max, width, height, padding),
  }));
  const labels = xLabels(windowRows, language, base.length);
  const labelSpan = Math.max(1, labels.length - 1);

  return (
    <div className="chart-surface risk-trend">
      <div className="trend-legend">
        {series.map((item) => (
          <span key={item.key}>
            <i className={`trend-key trend-${item.key}`} />
            {item.label}
          </span>
        ))}
      </div>
      <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="risk trend">
        {axisTicks(max).map((tick) => {
          const y = padding.top + (1 - tick / max) * (height - padding.top - padding.bottom);
          return (
            <g key={tick}>
              <line className="chart-grid-line" x1={padding.left} x2={width - padding.right} y1={y} y2={y} />
              <text className="axis-label" x={padding.left - 12} y={y + 4} textAnchor="end">
                {tick}
              </text>
            </g>
          );
        })}
        {pointsBySeries.map((item) => (
          <g key={item.key}>
            <path className={`trend-line trend-${item.key}`} d={smoothPath(item.points)} />
            {item.points.map((point, index) => (
              <circle
                className={`trend-dot trend-dot-${item.key}`}
                cx={point.x}
                cy={point.y}
                key={`${item.key}-${index}`}
                r={index === item.points.length - 1 ? 4.4 : 2.4}
              />
            ))}
          </g>
        ))}
        {labels.map((label, index) => (
          <text className="axis-label" key={`${label}-${index}`} x={padding.left + (index / labelSpan) * (width - padding.left - padding.right)} y={height - 8} textAnchor="middle">
            {label}
          </text>
        ))}
      </svg>
    </div>
  );
}

export function DonutChart({ items, centerLabel }: { items: ChartSlice[]; centerLabel?: string }) {
  const total = items.reduce((sum, item) => sum + item.value, 0);
  const radius = 47;
  const circumference = 2 * Math.PI * radius;
  const gap = total > 0 ? 3.2 : 0;
  let offset = 0;
  const slices = items.map((item) => {
    const ratio = total > 0 ? Math.max(0, item.value) / total : 0;
    const length = Math.max(0, circumference * ratio - gap);
    const dashOffset = -offset;
    offset += circumference * ratio;
    return { ...item, length, dashOffset };
  });
  return (
    <div className="donut-card">
      <div className="donut">
        <svg className="donut-svg" viewBox="0 0 120 120" aria-hidden="true">
          <circle className="donut-track" cx="60" cy="60" r={radius} />
          {slices.map((slice) => (
            <circle
              className={`donut-slice ${slice.className}`}
              cx="60"
              cy="60"
              key={slice.label}
              r={radius}
              strokeDasharray={`${slice.length} ${circumference - slice.length}`}
              strokeDashoffset={slice.dashOffset}
            />
          ))}
        </svg>
        <div className="donut-center">
          <strong>{number(total)}</strong>
          <span>{centerLabel || "Total"}</span>
        </div>
      </div>
      <div className="legend">
        {items.map((item) => (
          <div className="legend-row" key={item.label}>
            <span className={`legend-dot ${item.className}`} />
            <span>{item.label}</span>
            <strong>{number(item.value)}</strong>
            <small>{percentage(item.value, total)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export function MiniBars({ values }: { values: number[] }) {
  const max = Math.max(1, ...values);
  return (
    <div className="mini-bars" aria-hidden="true">
      {values.slice(0, 22).map((value, index) => (
        <span key={index} style={{ height: `${Math.max(18, (value / max) * 100)}%` }} />
      ))}
    </div>
  );
}

function normalizePoints(values: number[], width: number, height: number, padding: number) {
  const max = Math.max(1, ...values);
  const innerWidth = width - padding * 2;
  const innerHeight = height - padding * 2;
  return values.map((value, index) => ({
    x: padding + (values.length <= 1 ? 0 : (index / (values.length - 1)) * innerWidth),
    y: padding + innerHeight - (value / max) * innerHeight,
  }));
}

function trendSeries(key: "critical" | "high" | "medium" | "low", rows: TrendPoint[], base: number[], fallbackRatio: number, language: Language) {
  const rawValues = rows.map((row) => Number(row[key] || 0));
  const values = rows.length && rawValues.some((value) => value > 0)
    ? rawValues
    : base.map((value, index) => Math.max(1, Math.round(value * fallbackRatio + (index % 2))));
  return { key, label: translate(language, key), values };
}

function sumRisk(row: TrendPoint): number {
  return Number(row.critical || 0) + Number(row.high || 0) + Number(row.medium || 0) + Number(row.low || 0);
}

function niceMax(value: number): number {
  if (value <= 10) {
    const rounded = Math.ceil(value + 1);
    return rounded % 2 === 0 ? rounded : rounded + 1;
  }
  const rounded = Math.ceil(value / 10) * 10;
  return Math.max(10, rounded);
}

function axisTicks(max: number): number[] {
  const count = max <= 10 ? 4 : 5;
  const step = max / count;
  return Array.from({ length: count + 1 }, (_, index) => Math.round(step * index));
}

function xLabels(rows: TrendPoint[], language: Language, count: number): string[] {
  if (rows.length) {
    const labels = rows.map((row, index) => shortBucketLabel(row.bucket, language, false) || String(index + 1));
    if (new Set(labels).size <= Math.ceil(labels.length / 2)) {
      return rows.map((row, index) => shortBucketLabel(row.bucket, language, true) || String(index + 1));
    }
    return labels;
  }
  const fallback = language === "zh"
    ? ["5/17", "5/18", "5/19", "5/20", "5/21", "5/22", "5/23"]
    : ["May 17", "May 18", "May 19", "May 20", "May 21", "May 22", "May 23"];
  return fallback.slice(0, count);
}

function shortBucketLabel(value: unknown, language: Language, includeTime: boolean): string {
  if (!value) return "";
  const date = new Date(String(value));
  if (!Number.isFinite(date.getTime())) return String(value).slice(0, 10);
  const locale = language === "zh" ? "zh-CN" : "en-US";
  if (includeTime) {
    return new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(date);
  }
  return new Intl.DateTimeFormat(locale, { month: "short", day: "numeric" }).format(date);
}

function percentage(value: number, total: number): string {
  if (!total) return "0%";
  const ratio = (value / total) * 100;
  if (ratio === 0) return "0%";
  return `${ratio >= 10 ? ratio.toFixed(0) : ratio.toFixed(1)}%`;
}

function chartPoints(
  values: number[],
  max: number,
  width: number,
  height: number,
  padding: { left: number; right: number; top: number; bottom: number },
) {
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;
  return values.map((value, index) => ({
    x: padding.left + (values.length <= 1 ? 0 : (index / (values.length - 1)) * innerWidth),
    y: padding.top + innerHeight - (value / max) * innerHeight,
  }));
}

function smoothPath(points: Array<{ x: number; y: number }>) {
  if (points.length <= 2) {
    return points.map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(" ");
  }

  const commands = [`M${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`];
  for (let index = 0; index < points.length - 1; index += 1) {
    const current = points[index];
    const next = points[index + 1];
    const previous = points[index - 1] || current;
    const afterNext = points[index + 2] || next;
    const cp1 = {
      x: current.x + (next.x - previous.x) / 6,
      y: current.y + (next.y - previous.y) / 6,
    };
    const cp2 = {
      x: next.x - (afterNext.x - current.x) / 6,
      y: next.y - (afterNext.y - current.y) / 6,
    };
    commands.push(`C${cp1.x.toFixed(1)},${cp1.y.toFixed(1)} ${cp2.x.toFixed(1)},${cp2.y.toFixed(1)} ${next.x.toFixed(1)},${next.y.toFixed(1)}`);
  }
  return commands.join(" ");
}
