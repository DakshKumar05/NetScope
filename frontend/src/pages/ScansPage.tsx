import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Radar, ScanLine, Trash2 } from 'lucide-react';
import { api, errorMessage } from '@/services/api';
import { useToast } from '@/hooks/useToast';
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Skeleton,
  StatusBadge,
  formatDuration,
  formatTimestamp,
} from '@/components/ui';

export default function ScansPage() {
  const toast = useToast();
  const queryClient = useQueryClient();

  const scans = useQuery({
    queryKey: ['scans'],
    queryFn: () => api.listScans(50),
    // Keep the list fresh while anything is still running.
    refetchInterval: (query) =>
      query.state.data?.some((s) => s.status === 'running' || s.status === 'queued')
        ? 3000
        : false,
  });

  const remove = useMutation({
    mutationFn: api.deleteScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      toast.push('success', 'Scan deleted.');
    },
    onError: (error) => toast.push('error', errorMessage(error)),
  });

  return (
    <div className="flex flex-col gap-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[var(--color-ink)]">Scan history</h1>
          <p className="mt-0.5 text-xs text-[var(--color-ink-muted)]">
            Every scan stored in the local database.
          </p>
        </div>
        <Link to="/scans/new">
          <Button>
            <ScanLine size={15} aria-hidden />
            New scan
          </Button>
        </Link>
      </header>

      <Card>
        {scans.isLoading ? (
          <div className="flex flex-col gap-2 p-5">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-12" />
            ))}
          </div>
        ) : scans.isError ? (
          <ErrorState message={errorMessage(scans.error)} onRetry={() => scans.refetch()} />
        ) : !scans.data?.length ? (
          <EmptyState
            icon={Radar}
            title="No scans yet"
            description="Run a scan against a host you own to populate this view."
            action={
              <Link to="/scans/new">
                <Button size="sm">Run the first scan</Button>
              </Link>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[var(--color-line)] text-[10px] tracking-wider text-[var(--color-ink-muted)] uppercase">
                <tr>
                  <th className="px-5 py-2.5 font-medium">Target</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Started</th>
                  <th className="px-3 py-2.5 text-right font-medium">Hosts</th>
                  <th className="px-3 py-2.5 text-right font-medium">Ports</th>
                  <th className="px-3 py-2.5 text-right font-medium">Findings</th>
                  <th className="px-3 py-2.5 text-right font-medium">Risk</th>
                  <th className="px-3 py-2.5 text-right font-medium">Duration</th>
                  <th className="px-5 py-2.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-line)]">
                {scans.data.map((scan) => (
                  <tr key={scan.id} className="group hover:bg-[var(--color-raised)]/50">
                    <td className="px-5 py-2.5">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="font-mono text-[var(--color-ink)] hover:text-[var(--color-accent)]"
                      >
                        {scan.target}
                      </Link>
                      <span className="ml-2 text-[10px] text-[var(--color-ink-muted)]">
                        #{scan.id} · {scan.scan_type}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-3 py-2.5 text-[var(--color-ink-muted)]">
                      {formatTimestamp(scan.started_at)}
                    </td>
                    <td className="tabular px-3 py-2.5 text-right text-[var(--color-ink-secondary)]">
                      {scan.host_count}
                    </td>
                    <td className="tabular px-3 py-2.5 text-right text-[var(--color-ink-secondary)]">
                      {scan.open_port_count}
                    </td>
                    <td className="tabular px-3 py-2.5 text-right text-[var(--color-ink-secondary)]">
                      {scan.finding_count}
                    </td>
                    <td className="tabular px-3 py-2.5 text-right font-medium text-[var(--color-ink)]">
                      {scan.risk_score.toFixed(1)}
                    </td>
                    <td className="tabular px-3 py-2.5 text-right text-[var(--color-ink-muted)]">
                      {formatDuration(scan.duration_seconds)}
                    </td>
                    <td className="px-5 py-2.5 text-right">
                      <button
                        onClick={() => {
                          if (window.confirm(`Delete scan #${scan.id} and all its results?`)) {
                            remove.mutate(scan.id);
                          }
                        }}
                        className="rounded p-1 text-[var(--color-ink-muted)] opacity-0 transition-opacity group-hover:opacity-100 hover:text-[var(--color-critical)] focus:opacity-100"
                        aria-label={`Delete scan ${scan.id}`}
                      >
                        <Trash2 size={13} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
