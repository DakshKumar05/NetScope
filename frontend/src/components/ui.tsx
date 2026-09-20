import type { ReactNode } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CircleAlert,
  Info,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import type { Confidence, ScanStatus, Severity } from '@/types';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/* ------------------------------------------------------------------ surface */

export function Card({
  children,
  className,
  title,
  subtitle,
  actions,
}: {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section
      className={cx(
        'rounded-xl border border-[var(--color-line)] bg-[var(--color-surface)]/80 backdrop-blur-sm',
        className,
      )}
    >
      {(title || actions) && (
        <header className="flex items-start justify-between gap-4 border-b border-[var(--color-line)] px-5 py-3.5">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-[var(--color-ink)]">{title}</h2>}
            {subtitle && (
              <p className="mt-0.5 text-xs text-[var(--color-ink-muted)]">{subtitle}</p>
            )}
          </div>
          {actions && <div className="shrink-0">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ severity */

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; icon: LucideIcon; rank: number }
> = {
  critical: { label: 'Critical', color: 'var(--color-critical)', icon: AlertOctagon, rank: 5 },
  high: { label: 'High', color: 'var(--color-high)', icon: AlertTriangle, rank: 4 },
  medium: { label: 'Medium', color: 'var(--color-medium)', icon: CircleAlert, rank: 3 },
  low: { label: 'Low', color: 'var(--color-low)', icon: Info, rank: 2 },
  info: { label: 'Info', color: 'var(--color-info)', icon: ShieldCheck, rank: 1 },
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Severity is never carried by colour alone: the badge always pairs the hue
 * with an icon and the severity name.
 */
export function SeverityBadge({
  severity,
  size = 'md',
}: {
  severity: Severity;
  size?: 'sm' | 'md';
}) {
  const meta = SEVERITY_META[severity];
  const Icon = meta.icon;
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 rounded-md border font-medium whitespace-nowrap',
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs',
      )}
      style={{
        color: meta.color,
        borderColor: `color-mix(in srgb, ${meta.color} 35%, transparent)`,
        background: `color-mix(in srgb, ${meta.color} 12%, transparent)`,
      }}
    >
      <Icon size={size === 'sm' ? 11 : 13} aria-hidden />
      {meta.label}
    </span>
  );
}

/* -------------------------------------------------------------- confidence */

const CONFIDENCE_COPY: Record<Confidence, string> = {
  confirmed: 'Verified against this host',
  probable: 'Version-range match',
  possible: 'Lead to verify - not confirmed',
};

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return (
    <span
      title={CONFIDENCE_COPY[confidence]}
      className="inline-flex items-center rounded border border-[var(--color-line-strong)] px-1.5 py-0.5 font-mono text-[10px] tracking-wide text-[var(--color-ink-muted)] uppercase"
    >
      {confidence}
    </span>
  );
}

/* ------------------------------------------------------------------- status */

const STATUS_STYLE: Record<ScanStatus, { label: string; color: string }> = {
  queued: { label: 'Queued', color: 'var(--color-ink-muted)' },
  running: { label: 'Running', color: 'var(--color-accent)' },
  completed: { label: 'Completed', color: 'var(--color-good)' },
  failed: { label: 'Failed', color: 'var(--color-critical)' },
  cancelled: { label: 'Cancelled', color: 'var(--color-ink-muted)' },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const meta = STATUS_STYLE[status] ?? STATUS_STYLE.queued;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium"
      style={{
        color: meta.color,
        background: `color-mix(in srgb, ${meta.color} 12%, transparent)`,
      }}
    >
      <span
        className={cx('size-1.5 rounded-full', status === 'running' && 'animate-pulse')}
        style={{ background: meta.color }}
        aria-hidden
      />
      {meta.label}
    </span>
  );
}

/* ------------------------------------------------------------------- states */

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('skeleton rounded-md', className)} />;
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="rounded-full border border-[var(--color-line)] bg-[var(--color-raised)] p-3">
        <Icon size={20} className="text-[var(--color-ink-muted)]" aria-hidden />
      </div>
      <div>
        <p className="text-sm font-medium text-[var(--color-ink)]">{title}</p>
        {description && (
          <p className="mx-auto mt-1 max-w-sm text-xs text-[var(--color-ink-muted)]">
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
      <AlertOctagon size={22} style={{ color: 'var(--color-critical)' }} aria-hidden />
      <p className="max-w-md text-sm text-[var(--color-ink-secondary)]">{message}</p>
      {onRetry && (
        <Button variant="secondary" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ controls */

export function Button({
  children,
  variant = 'primary',
  size = 'md',
  className,
  ...rest
}: {
  children: ReactNode;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-accent)]';
  const sizes = size === 'sm' ? 'px-2.5 py-1.5 text-xs' : 'px-3.5 py-2 text-sm';
  const variants = {
    primary: 'bg-[var(--color-accent)] text-white hover:bg-[var(--color-accent-soft)]',
    secondary:
      'border border-[var(--color-line-strong)] bg-[var(--color-raised)] text-[var(--color-ink)] hover:border-[var(--color-ink-muted)]',
    ghost: 'text-[var(--color-ink-secondary)] hover:bg-[var(--color-raised)]',
    danger:
      'border border-[color-mix(in_srgb,var(--color-critical)_40%,transparent)] text-[var(--color-critical)] hover:bg-[color-mix(in_srgb,var(--color-critical)_12%,transparent)]',
  }[variant];
  return (
    <button className={cx(base, sizes, variants, className)} {...rest}>
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-[var(--color-ink-secondary)]">
        {label}
      </span>
      {children}
      {error ? (
        <span className="mt-1 block text-xs" style={{ color: 'var(--color-critical)' }}>
          {error}
        </span>
      ) : (
        hint && <span className="mt-1 block text-xs text-[var(--color-ink-muted)]">{hint}</span>
      )}
    </label>
  );
}

export const inputClass =
  'w-full rounded-lg border border-[var(--color-line-strong)] bg-[var(--color-plane)] px-3 py-2 text-sm text-[var(--color-ink)] placeholder:text-[var(--color-ink-muted)] focus:border-[var(--color-accent)] focus:outline-none';

/* ------------------------------------------------------------------ progress */

export function ProgressBar({
  value,
  label,
  color = 'var(--color-accent)',
}: {
  value: number;
  label?: string;
  color?: string;
}) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div className="flex items-center gap-3">
      {label && (
        <span className="w-44 shrink-0 truncate text-xs text-[var(--color-ink-secondary)]">
          {label}
        </span>
      )}
      <div
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--color-line)]"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label ?? 'Progress'}
      >
        <div
          className="h-full rounded-full transition-[width] duration-300"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className="tabular w-10 shrink-0 text-right text-xs text-[var(--color-ink-muted)]">
        {pct}%
      </span>
    </div>
  );
}

/* --------------------------------------------------------------------- misc */

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cx('font-mono text-[var(--color-ink-secondary)]', className)}>
      {children}
    </span>
  );
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null || Number.isNaN(seconds)) return '-';
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

export function formatTimestamp(value: string): string {
  const date = new Date(value.endsWith('Z') ? value : `${value}Z`);
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}
