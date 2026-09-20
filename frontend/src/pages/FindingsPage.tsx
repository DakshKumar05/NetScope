import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, ShieldAlert, X } from 'lucide-react';
import { api, errorMessage } from '@/services/api';
import FindingDrawer from '@/components/FindingDrawer';
import {
  Button,
  Card,
  ConfidenceBadge,
  EmptyState,
  ErrorState,
  SEVERITY_ORDER,
  SeverityBadge,
  Skeleton,
  cx,
  inputClass,
} from '@/components/ui';
import type { Finding, Severity } from '@/types';

const TYPES: Array<[string, string]> = [
  ['', 'All types'],
  ['exposed_service', 'Exposed service'],
  ['sensitive_service', 'Sensitive service'],
  ['known_vulnerability', 'Known vulnerability'],
  ['tls_issue', 'TLS issue'],
  ['http_issue', 'HTTP issue'],
  ['ftp_issue', 'FTP issue'],
  ['admin_interface', 'Admin interface'],
  ['credential_review', 'Credential review'],
];

export default function FindingsPage() {
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [type, setType] = useState('');
  const [search, setSearch] = useState('');
  const [cve, setCve] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);

  const findings = useQuery({
    queryKey: ['findings', severity, type, search, cve],
    queryFn: () =>
      api.listFindings({
        severity: severity || undefined,
        finding_type: type || undefined,
        search: search || undefined,
        cve: cve || undefined,
        limit: 300,
      }),
  });

  const hasFilters = Boolean(severity || type || search || cve);
  const clear = () => {
    setSeverity('');
    setType('');
    setSearch('');
    setCve('');
  };

  return (
    <div className="flex flex-col gap-5">
      <header>
        <h1 className="text-lg font-semibold text-[var(--color-ink)]">Findings</h1>
        <p className="mt-0.5 text-xs text-[var(--color-ink-muted)]">
          Across every stored scan. Select a finding to see its evidence and reasoning.
        </p>
      </header>

      {/* Filters in one row above the results. */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-[200px] flex-1">
          <Search
            size={14}
            className="absolute top-1/2 left-3 -translate-y-1/2 text-[var(--color-ink-muted)]"
            aria-hidden
          />
          <input
            className={cx(inputClass, 'pl-9')}
            placeholder="Search titles…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search findings"
          />
        </div>

        <select
          className={cx(inputClass, 'w-auto')}
          value={severity}
          onChange={(e) => setSeverity(e.target.value as Severity | '')}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s[0].toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>

        <select
          className={cx(inputClass, 'w-auto')}
          value={type}
          onChange={(e) => setType(e.target.value)}
          aria-label="Filter by finding type"
        >
          {TYPES.map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>

        <input
          className={cx(inputClass, 'w-36 font-mono')}
          placeholder="CVE-…"
          value={cve}
          onChange={(e) => setCve(e.target.value)}
          aria-label="Filter by CVE"
        />

        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={clear}>
            <X size={13} /> Clear
          </Button>
        )}
      </div>

      <Card>
        {findings.isLoading ? (
          <div className="flex flex-col gap-2 p-5">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        ) : findings.isError ? (
          <ErrorState message={errorMessage(findings.error)} onRetry={() => findings.refetch()} />
        ) : !findings.data?.length ? (
          <EmptyState
            icon={ShieldAlert}
            title={hasFilters ? 'No findings match these filters' : 'No findings yet'}
            description={
              hasFilters ? 'Try widening the filters.' : 'Run a scan to populate this view.'
            }
            action={
              hasFilters ? (
                <Button size="sm" variant="secondary" onClick={clear}>
                  Clear filters
                </Button>
              ) : undefined
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[var(--color-line)] text-[10px] tracking-wider text-[var(--color-ink-muted)] uppercase">
                <tr>
                  <th className="px-5 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 font-medium">Finding</th>
                  <th className="px-3 py-2.5 font-medium">Host</th>
                  <th className="px-3 py-2.5 font-medium">Port</th>
                  <th className="px-3 py-2.5 font-medium">Confidence</th>
                  <th className="px-5 py-2.5 text-right font-medium">CVSS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-line)]">
                {findings.data.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setSelected(finding)}
                    className="cursor-pointer hover:bg-[var(--color-raised)]/50"
                  >
                    <td className="px-5 py-2.5">
                      <SeverityBadge severity={finding.severity} size="sm" />
                    </td>
                    <td className="max-w-md px-3 py-2.5">
                      <span className="block truncate text-[var(--color-ink)]">
                        {finding.title}
                      </span>
                      <span className="block truncate text-[10px] text-[var(--color-ink-muted)]">
                        {finding.evidence}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[var(--color-ink-secondary)]">
                      {finding.host_ip ?? '-'}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[var(--color-ink-secondary)]">
                      {finding.port_number ?? '-'}
                    </td>
                    <td className="px-3 py-2.5">
                      <ConfidenceBadge confidence={finding.confidence} />
                    </td>
                    <td className="tabular px-5 py-2.5 text-right text-[var(--color-ink-secondary)]">
                      {finding.cvss !== null ? finding.cvss.toFixed(1) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
