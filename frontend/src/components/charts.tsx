/*
  Chart layer.

  Two deliberate choices, both about legibility rather than taste:

  1. Trends are single-series. Hosts, open ports and risk each get their own
     panel instead of sharing one plot with two y-scales - a dual-axis chart
     invites false correlation and there is no honest shared scale between a
     host count and a 0-100 score.

  2. Severity is never encoded by colour alone. The reserved status hues for
     critical/high/medium sit too close together to be told apart as adjacent
     stacked segments, so severity-over-time is faceted into one small panel
     per level, and the severity breakdown is a direct-labelled bar list.
*/

import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { Severity, TrendPoint } from '@/types';
import { SEVERITY_META, SEVERITY_ORDER, cx } from './ui';

const AXIS = { stroke: 'var(--color-line-strong)', fontSize: 11 };

function shortTime(value: string): string {
  const date = new Date(value.endsWith('Z') ? value : `${value}Z`);
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/* ------------------------------------------------------------------ tooltip */

interface TooltipEntry {
  name?: string;
  value?: number | string;
  color?: string;
}

function ChartTooltip({
  active,
  payload,
  label,
  unit,
}: {
  active?: boolean;
  payload?: TooltipEntry[];
  label?: string | number;
  unit?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-[var(--color-line-strong)] bg-[var(--color-overlay)] px-3 py-2 shadow-xl">
      {label !== undefined && (
        <p className="mb-1 text-[10px] tracking-wide text-[var(--color-ink-muted)] uppercase">
          {typeof label === 'string' ? shortTime(label) : label}
        </p>
      )}
      {payload.map((entry, index) => (
        <p key={index} className="flex items-center gap-2 text-xs text-[var(--color-ink)]">
          {entry.color && (
            <span
              className="size-2 rounded-[2px]"
              style={{ background: entry.color }}
              aria-hidden
            />
          )}
          <span className="text-[var(--color-ink-secondary)]">{entry.name}</span>
          <span className="tabular ml-auto font-medium">
            {entry.value}
            {unit ?? ''}
          </span>
        </p>
      ))}
    </div>
  );
}

/* --------------------------------------------------------------- risk trend */

export function RiskTrendChart({ points }: { points: TrendPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      {/* Left margin stays at zero: this axis runs to 100, and pulling it
          negative clips the leading digit so the top tick reads "00". */}
      <AreaChart data={points} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-accent)" stopOpacity={0.35} />
            <stop offset="100%" stopColor="var(--color-accent)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={shortTime} {...AXIS} tickLine={false} />
        <YAxis domain={[0, 100]} {...AXIS} tickLine={false} width={44} />
        <Tooltip
          content={<ChartTooltip />}
          cursor={{ stroke: 'var(--color-line-strong)', strokeWidth: 1 }}
        />
        <Area
          type="monotone"
          dataKey="risk_score"
          name="Risk score"
          stroke="var(--color-accent)"
          strokeWidth={2}
          fill="url(#riskFill)"
          dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: 'var(--color-surface)' }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

/* ------------------------------------------------------- single-metric line */

export function MetricTrendChart({
  points,
  dataKey,
  name,
  color = 'var(--color-accent)',
  height = 170,
}: {
  points: TrendPoint[];
  dataKey: keyof TrendPoint;
  name: string;
  color?: string;
  height?: number;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={points} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="timestamp" tickFormatter={shortTime} {...AXIS} tickLine={false} />
        <YAxis allowDecimals={false} {...AXIS} tickLine={false} width={36} />
        <Tooltip
          content={<ChartTooltip />}
          cursor={{ stroke: 'var(--color-line-strong)', strokeWidth: 1 }}
        />
        <Line
          type="monotone"
          dataKey={dataKey}
          name={name}
          stroke={color}
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: 'var(--color-surface)' }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}

/* ------------------------------------------------- severity small multiples */

/**
 * One panel per severity. Faceting keeps each series in a single hue, which
 * is what lets the reserved status colours be used at all - as adjacent
 * stacked bands they fail the legibility floor.
 */
export function SeverityFacets({ points }: { points: TrendPoint[] }) {
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg bg-[var(--color-line)] sm:grid-cols-3 lg:grid-cols-5">
      {SEVERITY_ORDER.map((severity) => {
        const meta = SEVERITY_META[severity];
        const total = points.reduce((sum, p) => sum + (p[severity] as number), 0);
        return (
          <div key={severity} className="bg-[var(--color-surface)] p-3">
            <div className="mb-1 flex items-center gap-1.5">
              <span
                className="size-2 rounded-[2px]"
                style={{ background: meta.color }}
                aria-hidden
              />
              <span className="text-[11px] font-medium text-[var(--color-ink-secondary)]">
                {meta.label}
              </span>
            </div>
            <p className="tabular mb-1 text-lg font-semibold text-[var(--color-ink)]">{total}</p>
            <ResponsiveContainer width="100%" height={44}>
              <AreaChart data={points} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
                <Tooltip
                  content={<ChartTooltip />}
                  cursor={{ stroke: 'var(--color-line-strong)', strokeWidth: 1 }}
                />
                <Area
                  type="monotone"
                  dataKey={severity}
                  name={meta.label}
                  stroke={meta.color}
                  strokeWidth={1.5}
                  fill={meta.color}
                  fillOpacity={0.15}
                  dot={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------ severity breakdown (bars) */

/**
 * Horizontal bars, each direct-labelled with its severity name and count.
 * Colour is redundant with the label here, which is what makes the reserved
 * status hues safe to use side by side.
 */
export function SeverityBreakdown({
  counts,
  onSelect,
  selected,
}: {
  counts: Record<Severity, number>;
  onSelect?: (severity: Severity) => void;
  selected?: Severity | null;
}) {
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s] ?? 0));
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] ?? 0), 0);

  if (total === 0) {
    return (
      <p className="px-5 py-8 text-center text-xs text-[var(--color-ink-muted)]">
        No findings recorded yet.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-2.5 px-5 py-4">
      {SEVERITY_ORDER.map((severity) => {
        const meta = SEVERITY_META[severity];
        const value = counts[severity] ?? 0;
        const Icon = meta.icon;
        const isSelected = selected === severity;
        const Element = onSelect ? 'button' : 'div';
        return (
          <li key={severity}>
            <Element
              {...(onSelect
                ? {
                    onClick: () => onSelect(severity),
                    'aria-pressed': isSelected,
                    type: 'button' as const,
                  }
                : {})}
              className={cx(
                'group flex w-full items-center gap-3 rounded-md px-1 py-1 text-left transition-colors',
                onSelect && 'hover:bg-[var(--color-raised)]',
                isSelected && 'bg-[var(--color-raised)]',
              )}
            >
              <span className="flex w-24 shrink-0 items-center gap-1.5">
                <Icon size={12} style={{ color: meta.color }} aria-hidden />
                <span className="text-xs text-[var(--color-ink-secondary)]">{meta.label}</span>
              </span>
              <span className="h-2 flex-1 overflow-hidden rounded-full bg-[var(--color-line)]">
                <span
                  className="block h-full rounded-full transition-[width] duration-500"
                  style={{
                    width: `${(value / max) * 100}%`,
                    background: meta.color,
                    minWidth: value > 0 ? 6 : 0,
                  }}
                />
              </span>
              <span className="tabular w-8 shrink-0 text-right text-xs font-medium text-[var(--color-ink)]">
                {value}
              </span>
            </Element>
          </li>
        );
      })}
    </ul>
  );
}
