import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowUpRight,
  DoorOpen,
  Network,
  Radar,
  ScanLine,
  Server,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react';
import { api, errorMessage } from '@/services/api';
import {
  MetricTrendChart,
  RiskTrendChart,
  SeverityBreakdown,
  SeverityFacets,
} from '@/components/charts';
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Skeleton,
  StatusBadge,
  cx,
  formatTimestamp,
} from '@/components/ui';

function StatTile({
  label,
  value,
  icon: Icon,
  hint,
}: {
  label: string;
  value: number | string;
  icon: LucideIcon;
  hint?: string;
}) {
  return (
    <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-surface)]/80 p-4">
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs text-[var(--color-ink-secondary)]">{label}</span>
        <Icon size={15} className="text-[var(--color-ink-muted)]" aria-hidden />
      </div>
      <p className="tabular text-2xl font-semibold text-[var(--color-ink)]">{value}</p>
      {hint && <p className="mt-1 text-[11px] text-[var(--color-ink-muted)]">{hint}</p>}
    </div>
  );
}

function riskTone(score: number): string {
  if (score >= 75) return 'var(--color-critical)';
  if (score >= 50) return 'var(--color-high)';
  if (score >= 25) return 'var(--color-medium)';
  if (score > 0) return 'var(--color-low)';
  return 'var(--color-good)';
}

export default function DashboardPage() {
  const summary = useQuery({ queryKey: ['dashboard', 'summary'], queryFn: api.dashboardSummary });
  const trends = useQuery({
    queryKey: ['dashboard', 'trends'],
    queryFn: () => api.trends(20),
  });

  if (summary.isError) {
    return <ErrorState message={errorMessage(summary.error)} onRetry={() => summary.refetch()} />;
  }

  const data = summary.data;
  const points = trends.data?.points ?? [];

  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[var(--color-ink)]">
            Network exposure overview
          </h1>
          <p className="mt-0.5 text-xs text-[var(--color-ink-muted)]">
            Aggregated across every scan stored locally.
          </p>
        </div>
        <Link to="/scans/new">
          <Button>
            <ScanLine size={15} aria-hidden />
            New scan
          </Button>
        </Link>
      </header>

      {/* Hero: the one number the dashboard leads with. */}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_2fr]">
        <div className="rounded-xl border border-[var(--color-line)] bg-[var(--color-surface)]/80 p-5">
          <p className="text-xs text-[var(--color-ink-secondary)]">Latest risk score</p>
          {summary.isLoading ? (
            <Skeleton className="mt-3 h-12 w-28" />
          ) : (
            <>
              <p
                className="tabular mt-1 text-5xl font-semibold"
                style={{ color: riskTone(data?.latest_risk_score ?? 0) }}
              >
                {(data?.latest_risk_score ?? 0).toFixed(1)}
              </p>
              <p className="mt-2 text-[11px] leading-relaxed text-[var(--color-ink-muted)]">
                Bounded 0-100, derived from finding severity weighted by how confident the
                scanner is in each match. Every point traces back to a listed finding.
              </p>
            </>
          )}
        </div>

        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {summary.isLoading
            ? Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-[92px]" />)
            : (
                [
                  { label: 'Hosts', value: data?.hosts_discovered ?? 0, icon: Server },
                  { label: 'Open ports', value: data?.open_ports ?? 0, icon: DoorOpen },
                  { label: 'Services', value: data?.services_detected ?? 0, icon: Network },
                  { label: 'Scans', value: data?.total_scans ?? 0, icon: Radar },
                ] as const
              ).map((tile) => <StatTile key={tile.label} {...tile} />)}
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[2fr_minmax(0,1fr)]">
        <Card title="Risk trend" subtitle="Score per completed scan, oldest first">
          {trends.isLoading ? (
            <Skeleton className="m-5 h-[180px]" />
          ) : points.length < 2 ? (
            <EmptyState
              icon={Radar}
              title="Not enough history yet"
              description="Run at least two scans to see how exposure moves over time."
            />
          ) : (
            <div className="p-3">
              <RiskTrendChart points={points} />
            </div>
          )}
        </Card>

        <Card
          title="Findings by severity"
          subtitle="All stored findings"
          actions={
            <Link
              to="/findings"
              className="flex items-center gap-1 text-xs text-[var(--color-accent)] hover:underline"
            >
              View all <ArrowUpRight size={12} />
            </Link>
          }
        >
          {summary.isLoading ? (
            <Skeleton className="m-5 h-[180px]" />
          ) : (
            <SeverityBreakdown counts={data!.findings} />
          )}
        </Card>
      </div>

      {points.length >= 2 && (
        <Card
          title="Findings by severity over time"
          subtitle="One panel per level - severity is never distinguished by colour alone"
        >
          <div className="p-3">
            <SeverityFacets points={points} />
          </div>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Hosts discovered" subtitle="Per scan">
          {points.length < 2 ? (
            <EmptyState icon={Server} title="Awaiting more scans" />
          ) : (
            <div className="p-3">
              <MetricTrendChart points={points} dataKey="hosts" name="Hosts" />
            </div>
          )}
        </Card>
        <Card title="Open ports" subtitle="Per scan">
          {points.length < 2 ? (
            <EmptyState icon={DoorOpen} title="Awaiting more scans" />
          ) : (
            <div className="p-3">
              <MetricTrendChart
                points={points}
                dataKey="open_ports"
                name="Open ports"
                color="var(--color-high)"
              />
            </div>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Recent scans">
          {summary.isLoading ? (
            <Skeleton className="m-5 h-32" />
          ) : !data?.recent_scans.length ? (
            <EmptyState
              icon={Radar}
              title="No scans yet"
              description="Start with a quick scan of a host you own."
              action={
                <Link to="/scans/new">
                  <Button size="sm">Run the first scan</Button>
                </Link>
              }
            />
          ) : (
            <ul className="divide-y divide-[var(--color-line)]">
              {data.recent_scans.map((scan) => (
                <li key={scan.id}>
                  <Link
                    to={`/scans/${scan.id}`}
                    className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-[var(--color-raised)]/60"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-xs text-[var(--color-ink)]">
                        {scan.target}
                      </span>
                      <span className="text-[11px] text-[var(--color-ink-muted)]">
                        {formatTimestamp(scan.started_at)} · {scan.host_count} host
                        {scan.host_count === 1 ? '' : 's'} · {scan.finding_count} finding
                        {scan.finding_count === 1 ? '' : 's'}
                      </span>
                    </span>
                    <StatusBadge status={scan.status} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Most exposed hosts" subtitle="Ranked by risk score">
          {summary.isLoading ? (
            <Skeleton className="m-5 h-32" />
          ) : !data?.most_exposed_hosts.length ? (
            <EmptyState icon={ShieldAlert} title="Nothing exposed yet" />
          ) : (
            <ul className="divide-y divide-[var(--color-line)]">
              {data.most_exposed_hosts.map((host) => (
                <li key={host.host_id}>
                  <Link
                    to={`/hosts/${host.host_id}`}
                    className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-[var(--color-raised)]/60"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-xs text-[var(--color-ink)]">
                        {host.hostname ?? host.ip}
                      </span>
                      <span className="text-[11px] text-[var(--color-ink-muted)]">
                        {host.open_ports} open port{host.open_ports === 1 ? '' : 's'}
                        {host.critical > 0 && ` · ${host.critical} critical`}
                        {host.high > 0 && ` · ${host.high} high`}
                      </span>
                    </span>
                    <span
                      className={cx('tabular text-sm font-semibold')}
                      style={{ color: riskTone(host.risk_score) }}
                    >
                      {host.risk_score.toFixed(1)}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
