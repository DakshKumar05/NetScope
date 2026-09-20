import { NavLink, Outlet } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  LayoutDashboard,
  Moon,
  Radar,
  ScanLine,
  ShieldAlert,
  Sun,
} from 'lucide-react';
import { api } from '@/services/api';
import { useTheme } from '@/hooks/useTheme';
import { cx } from '@/components/ui';

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/scans/new', label: 'New scan', icon: ScanLine, end: false },
  { to: '/scans', label: 'Scans', icon: Radar, end: true },
  { to: '/findings', label: 'Findings', icon: ShieldAlert, end: false },
];

export default function AppLayout() {
  const { theme, toggle } = useTheme();
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: api.health,
    refetchInterval: 20_000,
  });

  return (
    <div className="flex min-h-screen bg-[var(--color-plane)]">
      <aside className="sticky top-0 flex h-screen w-14 shrink-0 flex-col items-center gap-1 border-r border-[var(--color-line)] bg-[var(--color-surface)]/60 py-4 md:w-56 md:items-stretch md:px-3">
        <div className="mb-5 flex items-center gap-2.5 px-1 md:px-2">
          <div className="grid size-8 shrink-0 place-items-center rounded-lg bg-[var(--color-accent)]">
            <Radar size={17} className="text-white" aria-hidden />
          </div>
          <div className="hidden min-w-0 md:block">
            <p className="truncate text-[13px] leading-tight font-semibold text-[var(--color-ink)]">
              Exposure Scanner
            </p>
            <p className="truncate font-mono text-[10px] text-[var(--color-ink-muted)]">
              authorised targets only
            </p>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-0.5">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx(
                  'flex items-center gap-3 rounded-lg px-2.5 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-[var(--color-raised)] font-medium text-[var(--color-ink)]'
                    : 'text-[var(--color-ink-secondary)] hover:bg-[var(--color-raised)]/60 hover:text-[var(--color-ink)]',
                )
              }
              title={label}
            >
              <Icon size={17} aria-hidden />
              <span className="hidden md:inline">{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-2 md:px-1">
          <div className="hidden rounded-lg border border-[var(--color-line)] px-2.5 py-2 md:block">
            <p className="mb-1 flex items-center gap-1.5 text-[10px] text-[var(--color-ink-muted)]">
              <Activity size={11} aria-hidden />
              Engine
            </p>
            <p className="font-mono text-[11px] text-[var(--color-ink-secondary)]">
              {health?.engines.nmap ? 'nmap + socket' : 'socket'}
            </p>
            {health && (
              <p className="mt-1 font-mono text-[10px] text-[var(--color-ink-muted)]">
                {health.public_targets_allowed ? 'public: allowed' : 'public: blocked'}
              </p>
            )}
          </div>
          <button
            onClick={toggle}
            className="flex items-center justify-center gap-2 rounded-lg px-2.5 py-2 text-sm text-[var(--color-ink-secondary)] transition-colors hover:bg-[var(--color-raised)] hover:text-[var(--color-ink)] md:justify-start"
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            <span className="hidden md:inline">{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <div className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
