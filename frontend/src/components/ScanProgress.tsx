import { Check, Loader2 } from 'lucide-react';
import type { ScanProgressEvent } from '@/types';
import { Button, ProgressBar, cx } from './ui';

const PHASE_LABELS: Array<[string, string]> = [
  ['target_validation', 'Target validation'],
  ['host_discovery', 'Host discovery'],
  ['port_scanning', 'Port scanning'],
  ['service_fingerprinting', 'Service fingerprinting'],
  ['vulnerability_lookup', 'Vulnerability lookup'],
  ['risk_calculation', 'Risk calculation'],
  ['storing_results', 'Storing results'],
];

export default function ScanProgress({
  event,
  onCancel,
  cancelling,
}: {
  event: ScanProgressEvent | null;
  onCancel?: () => void;
  cancelling?: boolean;
}) {
  const phases = event?.phases ?? {};
  const overall = event?.progress ?? 0;

  return (
    <div className="flex flex-col gap-4 p-5">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <Loader2
            size={15}
            className="animate-spin text-[var(--color-accent)]"
            aria-hidden
          />
          <span className="text-sm font-medium text-[var(--color-ink)]">
            {event?.message || 'Starting…'}
          </span>
        </div>
        {onCancel && (
          <Button variant="danger" size="sm" onClick={onCancel} disabled={cancelling}>
            {cancelling ? 'Cancelling…' : 'Cancel scan'}
          </Button>
        )}
      </div>

      <ProgressBar value={overall} label="Overall" />

      <ul className="flex flex-col gap-2 border-t border-[var(--color-line)] pt-4">
        {PHASE_LABELS.map(([key, label]) => {
          const value = phases[key] ?? 0;
          const done = value >= 1;
          const active = event?.phase === key && !done;
          return (
            <li key={key} className="flex items-center gap-3">
              <span className="grid w-4 shrink-0 place-items-center">
                {done ? (
                  <Check size={13} style={{ color: 'var(--color-good)' }} aria-hidden />
                ) : (
                  <span
                    className={cx(
                      'size-1.5 rounded-full',
                      active ? 'animate-pulse bg-[var(--color-accent)]' : 'bg-[var(--color-line-strong)]',
                    )}
                    aria-hidden
                  />
                )}
              </span>
              <ProgressBar
                value={value}
                label={label}
                color={done ? 'var(--color-good)' : 'var(--color-accent)'}
              />
            </li>
          );
        })}
      </ul>
    </div>
  );
}
