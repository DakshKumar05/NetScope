import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, DoorOpen, Lock, Server, ShieldAlert } from 'lucide-react';
import { api, errorMessage } from '@/services/api';
import FindingDrawer from '@/components/FindingDrawer';
import {
  Card,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  SEVERITY_META,
  SeverityBadge,
  Skeleton,
  cx,
} from '@/components/ui';
import type { Finding, Port } from '@/types';

function TlsPanel({ tls }: { tls: NonNullable<Port['service']>['details']['tls'] }) {
  if (!tls) return null;
  const problems = [
    tls.expired && 'expired',
    tls.not_yet_valid && 'not yet valid',
    tls.self_signed && 'self-signed',
    tls.hostname_mismatch && 'hostname mismatch',
    tls.weak_protocol && 'obsolete protocol',
  ].filter(Boolean) as string[];

  return (
    <div className="mt-2 rounded-md border border-[var(--color-line)] bg-[var(--color-plane)] px-3 py-2">
      <p className="mb-1 flex items-center gap-1.5 text-[10px] tracking-wider text-[var(--color-ink-muted)] uppercase">
        <Lock size={10} aria-hidden /> TLS certificate
      </p>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px]">
        <div>
          <dt className="inline text-[var(--color-ink-muted)]">subject </dt>
          <dd className="inline text-[var(--color-ink-secondary)]">{tls.subject_cn ?? '-'}</dd>
        </div>
        <div>
          <dt className="inline text-[var(--color-ink-muted)]">issuer </dt>
          <dd className="inline text-[var(--color-ink-secondary)]">{tls.issuer_cn ?? '-'}</dd>
        </div>
        <div>
          <dt className="inline text-[var(--color-ink-muted)]">version </dt>
          <dd className="inline text-[var(--color-ink-secondary)]">{tls.tls_version ?? '-'}</dd>
        </div>
        <div>
          <dt className="inline text-[var(--color-ink-muted)]">expires </dt>
          <dd className="inline text-[var(--color-ink-secondary)]">
            {tls.not_after ? new Date(tls.not_after).toLocaleDateString() : '-'}
          </dd>
        </div>
      </dl>
      {problems.length > 0 && (
        <p className="mt-1.5 text-[11px]" style={{ color: 'var(--color-high)' }}>
          {problems.join(' · ')}
        </p>
      )}
    </div>
  );
}

export default function HostDetailPage() {
  const { hostId } = useParams();
  const id = Number(hostId);
  const [selected, setSelected] = useState<Finding | null>(null);

  const host = useQuery({
    queryKey: ['host', id],
    queryFn: () => api.getHost(id),
    enabled: Number.isFinite(id),
  });
  const findings = useQuery({
    queryKey: ['host', id, 'findings'],
    queryFn: () => api.hostFindings(id),
    enabled: Number.isFinite(id),
  });

  if (host.isLoading) return <Skeleton className="h-64" />;
  if (host.isError || !host.data) {
    return <ErrorState message={errorMessage(host.error)} onRetry={() => host.refetch()} />;
  }

  const data = host.data;
  const ports = data.ports ?? [];
  const findingsByPort = new Map<number, Finding[]>();
  for (const finding of findings.data ?? []) {
    if (finding.port_id === null) continue;
    const list = findingsByPort.get(finding.port_id) ?? [];
    list.push(finding);
    findingsByPort.set(finding.port_id, list);
  }

  return (
    <div className="flex flex-col gap-5">
      <div>
        <Link
          to={`/scans/${data.scan_id}`}
          className="mb-3 inline-flex items-center gap-1.5 text-xs text-[var(--color-ink-muted)] hover:text-[var(--color-ink)]"
        >
          <ArrowLeft size={13} /> Back to scan #{data.scan_id}
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <Server size={20} className="text-[var(--color-ink-muted)]" aria-hidden />
          <div>
            <h1 className="font-mono text-lg font-semibold text-[var(--color-ink)]">{data.ip}</h1>
            <p className="text-xs text-[var(--color-ink-muted)]">
              {data.hostname ?? 'no reverse name'} · {data.status} · risk{' '}
              <span className="tabular font-medium text-[var(--color-ink-secondary)]">
                {data.risk_score.toFixed(1)}
              </span>
            </p>
          </div>
        </div>
      </div>

      <Card title="Open ports" subtitle={`${ports.length} reachable`}>
        {ports.length === 0 ? (
          <EmptyState icon={DoorOpen} title="No open ports recorded" />
        ) : (
          <ul className="divide-y divide-[var(--color-line)]">
            {ports.map((port) => {
              const service = port.service;
              const portFindings = findingsByPort.get(port.id) ?? [];
              const worst = portFindings.reduce<Finding | null>(
                (acc, f) =>
                  !acc || SEVERITY_META[f.severity].rank > SEVERITY_META[acc.severity].rank
                    ? f
                    : acc,
                null,
              );
              return (
                <li key={port.id} className="px-5 py-4">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="font-mono text-sm font-medium text-[var(--color-ink)]">
                      {port.port}/{port.protocol}
                    </span>
                    <span className="text-xs text-[var(--color-ink-secondary)]">
                      {service?.product
                        ? `${service.product}${service.version ? ` ${service.version}` : ''}`
                        : (port.service_name ?? 'unknown')}
                    </span>
                    {service && <ConfidenceBadge confidence={service.confidence} />}
                    {worst && <SeverityBadge severity={worst.severity} size="sm" />}
                    <span className="tabular ml-auto text-[11px] text-[var(--color-ink-muted)]">
                      {port.latency_ms !== null ? `${port.latency_ms.toFixed(0)} ms` : ''}
                    </span>
                  </div>

                  {service?.banner && (
                    <p className="mt-1.5 truncate font-mono text-[11px] text-[var(--color-ink-muted)]">
                      {service.banner}
                    </p>
                  )}

                  {service?.details?.title && (
                    <p className="mt-1 text-[11px] text-[var(--color-ink-muted)]">
                      Page title: {service.details.title}
                    </p>
                  )}

                  <TlsPanel tls={service?.details?.tls} />

                  {portFindings.length > 0 && (
                    <ul className="mt-2.5 flex flex-col gap-1">
                      {portFindings.map((finding) => (
                        <li key={finding.id}>
                          <button
                            onClick={() => setSelected(finding)}
                            className={cx(
                              'flex w-full items-center gap-2 rounded px-2 py-1 text-left text-[11px] transition-colors',
                              'hover:bg-[var(--color-raised)]',
                            )}
                          >
                            <span
                              className="size-1.5 shrink-0 rounded-full"
                              style={{ background: SEVERITY_META[finding.severity].color }}
                              aria-hidden
                            />
                            <span className="truncate text-[var(--color-ink-secondary)]">
                              {finding.title}
                            </span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card title="All findings on this host">
        {findings.isLoading ? (
          <Skeleton className="m-5 h-24" />
        ) : !findings.data?.length ? (
          <EmptyState icon={ShieldAlert} title="No findings for this host" />
        ) : (
          <ul className="divide-y divide-[var(--color-line)]">
            {findings.data.map((finding) => (
              <li key={finding.id}>
                <button
                  onClick={() => setSelected(finding)}
                  className="flex w-full items-start gap-3 px-5 py-3 text-left transition-colors hover:bg-[var(--color-raised)]/60"
                >
                  <span className="min-w-0 flex-1 text-xs text-[var(--color-ink)]">
                    {finding.title}
                  </span>
                  <SeverityBadge severity={finding.severity} size="sm" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
