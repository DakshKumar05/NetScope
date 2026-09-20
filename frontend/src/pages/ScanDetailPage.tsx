import { useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, DoorOpen, Network, Server, ShieldAlert } from 'lucide-react';
import { api, errorMessage } from '@/services/api';
import { useScanStream } from '@/hooks/useScanStream';
import { useToast } from '@/hooks/useToast';
import ScanProgress from '@/components/ScanProgress';
import Topology from '@/components/Topology';
import FindingDrawer from '@/components/FindingDrawer';
import { SeverityBreakdown } from '@/components/charts';
import {
  Card,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  SEVERITY_META,
  SeverityBadge,
  Skeleton,
  StatusBadge,
  cx,
  formatDuration,
  formatTimestamp,
} from '@/components/ui';
import type { Finding, Host, Port, Severity } from '@/types';

type Tab = 'hosts' | 'ports' | 'services' | 'findings' | 'topology';

const TABS: Array<[Tab, string]> = [
  ['hosts', 'Hosts'],
  ['ports', 'Ports'],
  ['services', 'Services'],
  ['findings', 'Findings'],
  ['topology', 'Topology'],
];

function Stat({ label, value, icon: Icon }: { label: string; value: string | number; icon: typeof Server }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-[var(--color-line)] bg-[var(--color-surface)]/70 px-4 py-3">
      <Icon size={16} className="text-[var(--color-ink-muted)]" aria-hidden />
      <div>
        <p className="text-[11px] text-[var(--color-ink-muted)]">{label}</p>
        <p className="tabular text-sm font-semibold text-[var(--color-ink)]">{value}</p>
      </div>
    </div>
  );
}

export default function ScanDetailPage() {
  const { scanId } = useParams();
  const id = Number(scanId);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState<Tab>('hosts');
  const [selected, setSelected] = useState<Finding | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);

  const scan = useQuery({
    queryKey: ['scan', id],
    queryFn: () => api.getScan(id),
    enabled: Number.isFinite(id),
  });

  const isLive = scan.data?.status === 'queued' || scan.data?.status === 'running';

  const { event } = useScanStream(Number.isFinite(id) ? id : null, {
    enabled: isLive,
    onFinish: (status) => {
      queryClient.invalidateQueries({ queryKey: ['scan', id] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      toast.push(status === 'completed' ? 'success' : 'info', `Scan #${id} ${status}.`);
    },
  });

  const topology = useQuery({
    queryKey: ['topology', id],
    queryFn: () => api.topology(id),
    enabled: tab === 'topology' && !isLive,
  });

  const cancel = useMutation({
    mutationFn: () => api.cancelScan(id),
    onSuccess: () => toast.push('info', 'Cancellation requested.'),
    onError: (error) => toast.push('error', errorMessage(error)),
  });

  const allPorts = useMemo(() => {
    const rows: Array<{ host: Host; port: Port }> = [];
    for (const host of scan.data?.hosts ?? []) {
      for (const port of host.ports ?? []) rows.push({ host, port });
    }
    return rows;
  }, [scan.data]);

  const findings = useMemo(() => {
    const list = scan.data?.findings ?? [];
    return severityFilter ? list.filter((f) => f.severity === severityFilter) : list;
  }, [scan.data, severityFilter]);

  if (scan.isLoading) {
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-24" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (scan.isError || !scan.data) {
    return <ErrorState message={errorMessage(scan.error)} onRetry={() => scan.refetch()} />;
  }

  const data = scan.data;

  return (
    <div className="flex flex-col gap-5">
      <div>
        <Link
          to="/scans"
          className="mb-3 inline-flex items-center gap-1.5 text-xs text-[var(--color-ink-muted)] hover:text-[var(--color-ink)]"
        >
          <ArrowLeft size={13} /> All scans
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="flex items-center gap-2.5 text-lg font-semibold text-[var(--color-ink)]">
              Scan #{data.id}
              <StatusBadge status={data.status} />
            </h1>
            <p className="mt-1 font-mono text-xs text-[var(--color-ink-secondary)]">
              {data.target} · {data.scan_type} profile · {data.engine} engine
              {data.udp_enabled && ' · UDP enabled'}
            </p>
            <p className="mt-0.5 text-[11px] text-[var(--color-ink-muted)]">
              Started {formatTimestamp(data.started_at)}
              {data.duration_seconds !== null &&
                ` · took ${formatDuration(data.duration_seconds)}`}
            </p>
          </div>
        </div>
      </div>

      {data.error && (
        <div
          className="rounded-lg border px-4 py-3 text-xs"
          style={{
            borderColor: 'color-mix(in srgb, var(--color-critical) 40%, transparent)',
            background: 'color-mix(in srgb, var(--color-critical) 8%, transparent)',
            color: 'var(--color-ink)',
          }}
        >
          <strong className="font-medium">Scan failed:</strong> {data.error}
        </div>
      )}

      {isLive && (
        <Card title="Live progress">
          <ScanProgress
            event={event}
            onCancel={() => cancel.mutate()}
            cancelling={cancel.isPending}
          />
        </Card>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Hosts" value={data.host_count} icon={Server} />
        <Stat label="Open ports" value={data.open_port_count} icon={DoorOpen} />
        <Stat label="Findings" value={data.finding_count} icon={ShieldAlert} />
        <Stat label="Risk score" value={data.risk_score.toFixed(1)} icon={Network} />
      </div>

      {data.finding_count > 0 && (
        <Card
          title="Severity breakdown"
          subtitle={severityFilter ? `Filtered to ${severityFilter}` : 'Select a level to filter'}
        >
          <SeverityBreakdown
            counts={data.severity_counts}
            selected={severityFilter}
            onSelect={(severity) => {
              setSeverityFilter((current) => (current === severity ? null : severity));
              setTab('findings');
            }}
          />
        </Card>
      )}

      <div>
        <div
          className="mb-3 flex gap-1 overflow-x-auto border-b border-[var(--color-line)]"
          role="tablist"
        >
          {TABS.map(([key, label]) => (
            <button
              key={key}
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
              className={cx(
                '-mb-px border-b-2 px-3.5 py-2 text-xs font-medium whitespace-nowrap transition-colors',
                tab === key
                  ? 'border-[var(--color-accent)] text-[var(--color-ink)]'
                  : 'border-transparent text-[var(--color-ink-muted)] hover:text-[var(--color-ink-secondary)]',
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <Card>
          {tab === 'hosts' && (
            data.hosts.length === 0 ? (
              <EmptyState
                icon={Server}
                title="No responsive hosts"
                description="Nothing in the target range answered on the probed ports."
              />
            ) : (
              <ul className="divide-y divide-[var(--color-line)]">
                {data.hosts.map((host) => (
                  <li key={host.id}>
                    <Link
                      to={`/hosts/${host.id}`}
                      className="flex items-center gap-4 px-5 py-3.5 transition-colors hover:bg-[var(--color-raised)]/60"
                    >
                      <Server size={15} className="text-[var(--color-ink-muted)]" aria-hidden />
                      <div className="min-w-0 flex-1">
                        <p className="font-mono text-xs text-[var(--color-ink)]">{host.ip}</p>
                        {host.hostname && (
                          <p className="text-[11px] text-[var(--color-ink-muted)]">
                            {host.hostname}
                          </p>
                        )}
                      </div>
                      <span className="text-[11px] text-[var(--color-ink-muted)]">
                        {host.open_port_count} open
                      </span>
                      <span className="tabular w-12 text-right text-xs font-semibold text-[var(--color-ink)]">
                        {host.risk_score.toFixed(1)}
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )
          )}

          {tab === 'ports' && (
            allPorts.length === 0 ? (
              <EmptyState icon={DoorOpen} title="No open ports found" />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-[var(--color-line)] text-[10px] tracking-wider text-[var(--color-ink-muted)] uppercase">
                    <tr>
                      <th className="px-5 py-2.5 font-medium">Host</th>
                      <th className="px-3 py-2.5 font-medium">Port</th>
                      <th className="px-3 py-2.5 font-medium">State</th>
                      <th className="px-3 py-2.5 font-medium">Service</th>
                      <th className="px-5 py-2.5 text-right font-medium">Latency</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-line)]">
                    {allPorts.map(({ host, port }) => (
                      <tr key={port.id} className="hover:bg-[var(--color-raised)]/50">
                        <td className="px-5 py-2.5 font-mono text-[var(--color-ink-secondary)]">
                          {host.ip}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[var(--color-ink)]">
                          {port.port}/{port.protocol}
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="font-mono text-[11px] text-[var(--color-ink-muted)]">
                            {port.state}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-[var(--color-ink-secondary)]">
                          {port.service?.product
                            ? `${port.service.product} ${port.service.version ?? ''}`.trim()
                            : (port.service_name ?? 'unknown')}
                        </td>
                        <td className="tabular px-5 py-2.5 text-right text-[var(--color-ink-muted)]">
                          {port.latency_ms !== null ? `${port.latency_ms.toFixed(0)} ms` : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'services' && (
            <ul className="divide-y divide-[var(--color-line)]">
              {allPorts
                .filter(({ port }) => port.service)
                .map(({ host, port }) => {
                  const service = port.service!;
                  const tls = service.details?.tls;
                  return (
                    <li key={port.id} className="px-5 py-3.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-[var(--color-ink)]">
                          {host.ip}:{port.port}
                        </span>
                        <span className="text-xs text-[var(--color-ink-secondary)]">
                          {service.product ?? service.name}
                          {service.version ? ` ${service.version}` : ''}
                        </span>
                        <ConfidenceBadge confidence={service.confidence} />
                      </div>
                      {service.banner && (
                        <p className="mt-1.5 truncate font-mono text-[11px] text-[var(--color-ink-muted)]">
                          {service.banner}
                        </p>
                      )}
                      {tls && (
                        <p className="mt-1 font-mono text-[10px] text-[var(--color-ink-muted)]">
                          {tls.tls_version} · issuer {tls.issuer_cn ?? 'unknown'} ·{' '}
                          {tls.expired
                            ? 'EXPIRED'
                            : `${tls.days_remaining ?? '?'} days remaining`}
                        </p>
                      )}
                    </li>
                  );
                })}
              {allPorts.filter(({ port }) => port.service).length === 0 && (
                <EmptyState icon={Network} title="No services fingerprinted" />
              )}
            </ul>
          )}

          {tab === 'findings' && (
            findings.length === 0 ? (
              <EmptyState
                icon={ShieldAlert}
                title={severityFilter ? `No ${severityFilter} findings` : 'No findings'}
              />
            ) : (
              <ul className="divide-y divide-[var(--color-line)]">
                {findings.map((finding) => (
                  <li key={finding.id}>
                    <button
                      onClick={() => setSelected(finding)}
                      className="flex w-full items-start gap-3 px-5 py-3 text-left transition-colors hover:bg-[var(--color-raised)]/60"
                    >
                      <span
                        className="mt-1.5 size-2 shrink-0 rounded-full"
                        style={{ background: SEVERITY_META[finding.severity].color }}
                        aria-hidden
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block text-xs text-[var(--color-ink)]">
                          {finding.title}
                        </span>
                        <span className="mt-0.5 block font-mono text-[10px] text-[var(--color-ink-muted)]">
                          {finding.host_ip}
                          {finding.port_number ? `:${finding.port_number}` : ''}
                        </span>
                      </span>
                      <SeverityBadge severity={finding.severity} size="sm" />
                    </button>
                  </li>
                ))}
              </ul>
            )
          )}

          {tab === 'topology' && (
            topology.isLoading ? (
              <Skeleton className="m-5 h-64" />
            ) : topology.data ? (
              <Topology nodes={topology.data.nodes} />
            ) : (
              <EmptyState icon={Network} title="Topology unavailable while the scan runs" />
            )
          )}
        </Card>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
