import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldAlert, ScanLine } from 'lucide-react';
import { api, errorMessage } from '@/services/api';
import { useToast } from '@/hooks/useToast';
import { Button, Card, Field, inputClass, cx } from '@/components/ui';
import type { ScanProfile } from '@/types';

const PROFILES: Array<{ value: ScanProfile; label: string; description: string }> = [
  { value: 'quick', label: 'Quick', description: '26 high-signal ports' },
  { value: 'standard', label: 'Standard', description: '~75 common service ports' },
  { value: 'custom', label: 'Custom', description: 'Ports you specify' },
];

export default function NewScanPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const queryClient = useQueryClient();

  const [target, setTarget] = useState('127.0.0.1');
  const [profile, setProfile] = useState<ScanProfile>('quick');
  const [ports, setPorts] = useState('');
  const [udp, setUdp] = useState(false);
  const [timeout, setTimeoutValue] = useState(1.0);
  const [concurrency, setConcurrency] = useState(100);
  const [authorized, setAuthorized] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: api.createScan,
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      toast.push('success', `Scan #${scan.id} queued for ${scan.target}`);
      navigate(`/scans/${scan.id}`);
    },
    onError: (error) => {
      const message = errorMessage(error);
      setFieldError(message);
      toast.push('error', message);
    },
  });

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    setFieldError(null);
    if (!authorized) {
      setFieldError('Confirm you are authorised to scan this target before continuing.');
      return;
    }
    if (profile === 'custom' && !ports.trim()) {
      setFieldError('A custom scan needs an explicit port list, for example 22,80,443.');
      return;
    }
    mutation.mutate({
      target: target.trim(),
      profile,
      ports: profile === 'custom' ? ports.trim() : null,
      udp,
      udp_ports: null,
      timeout,
      concurrency,
      engine: 'auto',
      authorized,
    });
  };

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-5">
      <header>
        <h1 className="text-lg font-semibold text-[var(--color-ink)]">New scan</h1>
        <p className="mt-0.5 text-xs text-[var(--color-ink-muted)]">
          Probes reachable services and reports exposure. Nothing is exploited or modified.
        </p>
      </header>

      <div
        className="flex items-start gap-3 rounded-xl border px-4 py-3"
        style={{
          borderColor: 'color-mix(in srgb, var(--color-medium) 35%, transparent)',
          background: 'color-mix(in srgb, var(--color-medium) 8%, transparent)',
        }}
      >
        <ShieldAlert size={17} style={{ color: 'var(--color-medium)' }} aria-hidden />
        <div className="text-xs leading-relaxed">
          <p className="font-medium text-[var(--color-ink)]">
            Only scan systems and networks you own or have explicit authorisation to test.
          </p>
          <p className="mt-0.5 text-[var(--color-ink-secondary)]">
            Scanning third-party infrastructure without permission is unlawful in many
            jurisdictions. Public addresses are blocked unless the operator enables them
            server-side.
          </p>
        </div>
      </div>

      <form onSubmit={submit}>
        <Card title="Target">
          <div className="flex flex-col gap-4 p-5">
            <Field
              label="Host, CIDR range or hostname"
              hint="Examples: 192.168.1.10 · 192.168.1.0/24 · nas.local"
              error={fieldError ?? undefined}
            >
              <input
                className={cx(inputClass, 'font-mono')}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.0/24"
                spellCheck={false}
                autoComplete="off"
                required
              />
            </Field>

            <div>
              <span className="mb-1.5 block text-xs font-medium text-[var(--color-ink-secondary)]">
                Scan profile
              </span>
              <div className="grid gap-2 sm:grid-cols-3">
                {PROFILES.map((option) => (
                  <button
                    key={option.value}
                    type="button"
                    onClick={() => setProfile(option.value)}
                    aria-pressed={profile === option.value}
                    className={cx(
                      'rounded-lg border px-3 py-2.5 text-left transition-colors',
                      profile === option.value
                        ? 'border-[var(--color-accent)] bg-[color-mix(in_srgb,var(--color-accent)_10%,transparent)]'
                        : 'border-[var(--color-line-strong)] hover:border-[var(--color-ink-muted)]',
                    )}
                  >
                    <span className="block text-sm font-medium text-[var(--color-ink)]">
                      {option.label}
                    </span>
                    <span className="mt-0.5 block text-[11px] text-[var(--color-ink-muted)]">
                      {option.description}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {profile === 'custom' && (
              <Field label="Ports" hint="Comma-separated and/or ranges: 22,80,443 or 1-1024">
                <input
                  className={cx(inputClass, 'font-mono')}
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="22,80,443,8080"
                  spellCheck={false}
                />
              </Field>
            )}

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label={`Timeout — ${timeout.toFixed(1)}s`} hint="Per connection attempt">
                <input
                  type="range"
                  min={0.2}
                  max={5}
                  step={0.1}
                  value={timeout}
                  onChange={(e) => setTimeoutValue(Number(e.target.value))}
                  className="w-full accent-[var(--color-accent)]"
                />
              </Field>
              <Field
                label={`Concurrency — ${concurrency}`}
                hint="Parallel probes; lower is gentler on the target"
              >
                <input
                  type="range"
                  min={10}
                  max={500}
                  step={10}
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value))}
                  className="w-full accent-[var(--color-accent)]"
                />
              </Field>
            </div>

            <label className="flex items-start gap-2.5 rounded-lg border border-[var(--color-line-strong)] px-3 py-2.5">
              <input
                type="checkbox"
                checked={udp}
                onChange={(e) => setUdp(e.target.checked)}
                className="mt-0.5 accent-[var(--color-accent)]"
              />
              <span className="text-xs">
                <span className="block font-medium text-[var(--color-ink)]">
                  Also probe common UDP ports
                </span>
                <span className="mt-0.5 block text-[var(--color-ink-muted)]">
                  UDP results are inferential: silence reads as open|filtered, not as a
                  confirmed service.
                </span>
              </span>
            </label>

            <label className="flex items-start gap-2.5">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-0.5 accent-[var(--color-accent)]"
                required
              />
              <span className="text-xs text-[var(--color-ink-secondary)]">
                I confirm I own this target or have explicit written authorisation to scan it.
              </span>
            </label>
          </div>

          <footer className="flex items-center justify-end gap-2 border-t border-[var(--color-line)] px-5 py-3.5">
            <Button type="button" variant="ghost" onClick={() => navigate('/')}>
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending || !authorized}>
              <ScanLine size={15} aria-hidden />
              {mutation.isPending ? 'Starting…' : 'Start scan'}
            </Button>
          </footer>
        </Card>
      </form>
    </div>
  );
}
