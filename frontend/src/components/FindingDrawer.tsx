import { useEffect } from 'react';
import { ExternalLink, X } from 'lucide-react';
import type { Finding } from '@/types';
import { ConfidenceBadge, SeverityBadge, Mono } from './ui';

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1.5 text-[10px] font-semibold tracking-wider text-[var(--color-ink-muted)] uppercase">
        {label}
      </h3>
      <div className="text-xs leading-relaxed text-[var(--color-ink-secondary)]">{children}</div>
    </div>
  );
}

export default function FindingDrawer({
  finding,
  onClose,
}: {
  finding: Finding | null;
  onClose: () => void;
}) {
  useEffect(() => {
    if (!finding) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [finding, onClose]);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <button
        className="absolute inset-0 bg-black/50 backdrop-blur-[2px]"
        onClick={onClose}
        aria-label="Close details"
      />
      <aside className="relative flex h-full w-full max-w-lg flex-col border-l border-[var(--color-line-strong)] bg-[var(--color-surface)] shadow-2xl">
        <header className="flex items-start justify-between gap-3 border-b border-[var(--color-line)] px-5 py-4">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ConfidenceBadge confidence={finding.confidence} />
              {finding.cvss !== null && (
                <span className="tabular font-mono text-[10px] text-[var(--color-ink-muted)]">
                  CVSS {finding.cvss.toFixed(1)}
                </span>
              )}
            </div>
            <h2 className="text-sm leading-snug font-semibold text-[var(--color-ink)]">
              {finding.title}
            </h2>
            <p className="mt-1 font-mono text-[11px] text-[var(--color-ink-muted)]">
              {finding.host_ip}
              {finding.port_number ? `:${finding.port_number}` : ''} · {finding.type}
            </p>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded p-1 text-[var(--color-ink-muted)] hover:bg-[var(--color-raised)] hover:text-[var(--color-ink)]"
            aria-label="Close"
          >
            <X size={16} />
          </button>
        </header>

        <div className="flex flex-1 flex-col gap-5 overflow-y-auto px-5 py-5">
          {finding.description && <Section label="Description">{finding.description}</Section>}

          <Section label="Why this severity">{finding.reason}</Section>

          <Section label="Evidence">
            <pre className="overflow-x-auto rounded-md border border-[var(--color-line)] bg-[var(--color-plane)] p-3 font-mono text-[11px] whitespace-pre-wrap text-[var(--color-ink-secondary)]">
              {finding.evidence}
            </pre>
          </Section>

          <Section label="Recommendation">{finding.recommendation}</Section>

          {finding.cve_id && (
            <Section label="Identifier">
              <Mono className="text-[var(--color-ink)]">{finding.cve_id}</Mono>
            </Section>
          )}

          {finding.references.length > 0 && (
            <Section label="References">
              <ul className="flex flex-col gap-1.5">
                {finding.references.map((ref) => (
                  <li key={ref}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex items-start gap-1.5 break-all text-[var(--color-accent)] hover:underline"
                    >
                      <ExternalLink size={11} className="mt-0.5 shrink-0" aria-hidden />
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      </aside>
    </div>
  );
}
