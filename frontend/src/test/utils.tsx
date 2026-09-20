import type { ReactElement, ReactNode } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ToastProvider } from '@/hooks/useToast';
import type { DashboardSummary, Finding, Scan, ScanDetail, TrendPoint } from '@/types';

/**
 * Renders a page under a real route so `useParams` resolves. Pass `path` when
 * the page reads a URL parameter - without it the component mounts with empty
 * params and sits in its loading state forever.
 */
export function renderWithProviders(
  ui: ReactElement,
  {
    route = '/',
    path,
    ...options
  }: RenderOptions & { route?: string; path?: string } = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={[route]}>
          <ToastProvider>
            {path ? (
              <Routes>
                <Route path={path} element={children} />
              </Routes>
            ) : (
              children
            )}
          </ToastProvider>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  return { ...render(ui, { wrapper: Wrapper, ...options }), queryClient };
}

/* --------------------------------------------------------------- factories */

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 1,
    scan_id: 1,
    host_id: 1,
    port_id: 1,
    type: 'sensitive_service',
    severity: 'high',
    title: 'SSH exposed on port 22',
    description: '',
    reason: 'The port accepted a connection.',
    evidence: 'SSH-2.0-OpenSSH_9.6',
    recommendation: 'Restrict SSH to trusted ranges.',
    cve_id: null,
    cvss: null,
    confidence: 'confirmed',
    references: [],
    extra: {},
    created_at: '2026-01-01T00:00:00',
    host_ip: '192.168.1.10',
    port_number: 22,
    ...overrides,
  };
}

export function makeScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: 1,
    target: '192.168.1.10',
    scan_type: 'quick',
    status: 'completed',
    engine: 'socket',
    started_at: '2026-01-01T00:00:00',
    completed_at: '2026-01-01T00:01:00',
    duration_seconds: 60,
    risk_score: 42,
    error: null,
    udp_enabled: false,
    host_count: 1,
    open_port_count: 2,
    finding_count: 1,
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    ...overrides,
  };
}

export function makeScanDetail(overrides: Partial<ScanDetail> = {}): ScanDetail {
  return {
    ...makeScan(),
    hosts: [
      {
        id: 1,
        scan_id: 1,
        ip: '192.168.1.10',
        hostname: null,
        status: 'up',
        risk_score: 42,
        open_port_count: 1,
        ports: [
          {
            id: 1,
            port: 22,
            protocol: 'tcp',
            state: 'open',
            service_name: 'ssh',
            latency_ms: 3.2,
            service: {
              id: 1,
              name: 'ssh',
              product: 'OpenSSH',
              version: '9.6',
              banner: 'SSH-2.0-OpenSSH_9.6',
              confidence: 'confirmed',
              details: {},
            },
          },
        ],
      },
    ],
    findings: [makeFinding()],
    ...overrides,
  };
}

export function makeSummary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    total_scans: 2,
    hosts_discovered: 3,
    open_ports: 7,
    services_detected: 5,
    findings: { critical: 1, high: 2, medium: 3, low: 0, info: 4 },
    latest_risk_score: 61.5,
    recent_scans: [makeScan()],
    most_exposed_hosts: [
      {
        host_id: 1,
        ip: '192.168.1.10',
        hostname: null,
        open_ports: 4,
        risk_score: 61.5,
        critical: 1,
        high: 2,
      },
    ],
    ...overrides,
  };
}

export function makeTrendPoints(count = 3): TrendPoint[] {
  return Array.from({ length: count }, (_, i) => ({
    scan_id: i + 1,
    timestamp: `2026-01-0${i + 1}T00:00:00`,
    target: '192.168.1.10',
    hosts: i + 1,
    open_ports: (i + 1) * 2,
    services: i + 1,
    risk_score: 30 + i * 10,
    critical: i,
    high: 1,
    medium: 2,
    low: 0,
    info: 3,
  }));
}
