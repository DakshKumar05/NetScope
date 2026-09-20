import { Link } from 'react-router-dom';
import { Radar, Server } from 'lucide-react';
import type { TopologyNode } from '@/types';
import { SEVERITY_META } from './ui';

/**
 * A picture of what the scan discovered - scanner to hosts to open ports.
 * It is not a routing or packet-path map, and does not claim to be one.
 */
export default function Topology({ nodes }: { nodes: TopologyNode[] }) {
  const hosts = nodes.filter((n) => n.kind === 'host');
  const portsByHost = new Map<string, TopologyNode[]>();
  for (const node of nodes) {
    if (node.kind === 'port' && node.parent) {
      const list = portsByHost.get(node.parent) ?? [];
      list.push(node);
      portsByHost.set(node.parent, list);
    }
  }

  if (hosts.length === 0) {
    return (
      <p className="px-5 py-10 text-center text-xs text-[var(--color-ink-muted)]">
        No responsive hosts were discovered in this scan.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto p-6">
      <div className="flex min-w-max flex-col items-center gap-0">
        <div className="flex items-center gap-2 rounded-lg border border-[var(--color-accent)] bg-[color-mix(in_srgb,var(--color-accent)_12%,transparent)] px-3.5 py-2">
          <Radar size={15} style={{ color: 'var(--color-accent)' }} aria-hidden />
          <span className="text-xs font-medium text-[var(--color-ink)]">Scanner</span>
        </div>

        <span className="h-6 w-px bg-[var(--color-line-strong)]" aria-hidden />

        <div className="flex items-start gap-5">
          {hosts.map((host, index) => {
            const ports = portsByHost.get(host.id) ?? [];
            const severity = host.severity ?? 'info';
            const meta = SEVERITY_META[severity];
            return (
              <div key={host.id} className="flex flex-col items-center">
                {/* Connector from the shared bus down to this host. */}
                {hosts.length > 1 && (
                  <div className="relative h-px w-full">
                    <span
                      className="absolute top-0 h-px bg-[var(--color-line-strong)]"
                      style={{
                        left: index === 0 ? '50%' : 0,
                        right: index === hosts.length - 1 ? '50%' : 0,
                      }}
                      aria-hidden
                    />
                  </div>
                )}
                <span className="h-5 w-px bg-[var(--color-line-strong)]" aria-hidden />

                <Link
                  to={`/hosts/${host.id.replace('host-', '')}`}
                  className="flex min-w-[150px] flex-col items-center gap-1 rounded-lg border px-3.5 py-2.5 transition-colors hover:border-[var(--color-ink-muted)]"
                  style={{
                    borderColor: `color-mix(in srgb, ${meta.color} 40%, transparent)`,
                    background: `color-mix(in srgb, ${meta.color} 7%, transparent)`,
                  }}
                >
                  <Server size={14} style={{ color: meta.color }} aria-hidden />
                  <span className="font-mono text-xs text-[var(--color-ink)]">{host.label}</span>
                  <span className="text-[10px] text-[var(--color-ink-muted)]">
                    {ports.length} open · {meta.label.toLowerCase()}
                  </span>
                </Link>

                {ports.length > 0 && (
                  <>
                    <span className="h-5 w-px bg-[var(--color-line-strong)]" aria-hidden />
                    <ul className="flex max-w-[190px] flex-wrap justify-center gap-1.5">
                      {ports.map((port) => (
                        <li
                          key={port.id}
                          title={
                            [port.meta.service, port.meta.product, port.meta.version]
                              .filter(Boolean)
                              .join(' ') || undefined
                          }
                          className="rounded border border-[var(--color-line-strong)] bg-[var(--color-raised)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-ink-secondary)]"
                        >
                          {port.label}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
