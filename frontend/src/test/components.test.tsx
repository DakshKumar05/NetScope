import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { makeFinding, makeScan, renderWithProviders } from './utils';

vi.mock('@/services/api', async () => {
  const actual = await vi.importActual<typeof import('@/services/api')>('@/services/api');
  return {
    ...actual,
    api: {
      health: vi.fn(),
      listScans: vi.fn(),
      getScan: vi.fn(),
      createScan: vi.fn(),
      cancelScan: vi.fn(),
      deleteScan: vi.fn(),
      scanHosts: vi.fn(),
      topology: vi.fn(),
      getHost: vi.fn(),
      hostPorts: vi.fn(),
      hostFindings: vi.fn(),
      listFindings: vi.fn(),
      getFinding: vi.fn(),
      dashboardSummary: vi.fn(),
      trends: vi.fn(),
      streamUrl: (id: number) => `/api/scans/${id}/stream`,
    },
  };
});

import { api } from '@/services/api';
import FindingDrawer from '@/components/FindingDrawer';
import ScanProgress from '@/components/ScanProgress';
import Topology from '@/components/Topology';
import HostDetailPage from '@/pages/HostDetailPage';
import ScansPage from '@/pages/ScansPage';
import type { TopologyNode } from '@/types';

const mocked = vi.mocked(api);

beforeEach(() => {
  vi.clearAllMocks();
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as never;
});

describe('ScansPage', () => {
  it('lists scans with their status and totals', async () => {
    mocked.listScans.mockResolvedValue([
      makeScan(),
      makeScan({ id: 2, target: '10.0.0.0/29', status: 'failed', risk_score: 0 }),
    ]);

    renderWithProviders(<ScansPage />);

    expect(await screen.findByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.0/29')).toBeInTheDocument();
    expect(screen.getByText('Completed')).toBeInTheDocument();
    expect(screen.getByText('Failed')).toBeInTheDocument();
  });

  it('invites a first scan when the history is empty', async () => {
    mocked.listScans.mockResolvedValue([]);
    renderWithProviders(<ScansPage />);
    expect(await screen.findByText('No scans yet')).toBeInTheDocument();
  });

  it('asks for confirmation before deleting', async () => {
    const user = userEvent.setup();
    mocked.listScans.mockResolvedValue([makeScan()]);
    mocked.deleteScan.mockResolvedValue(undefined);
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);

    renderWithProviders(<ScansPage />);
    await user.click(await screen.findByRole('button', { name: /delete scan 1/i }));

    expect(confirm).toHaveBeenCalled();
    // Declining the prompt must not delete anything.
    expect(mocked.deleteScan).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it('surfaces a backend failure', async () => {
    mocked.listScans.mockRejectedValue(new Error('connection refused'));
    renderWithProviders(<ScansPage />);
    expect(await screen.findByText(/connection refused/i)).toBeInTheDocument();
  });
});

describe('HostDetailPage', () => {
  const host = {
    id: 1,
    scan_id: 1,
    ip: '192.168.1.15',
    hostname: 'server.local',
    status: 'up',
    risk_score: 55.1,
    open_port_count: 1,
    ports: [
      {
        id: 1,
        port: 443,
        protocol: 'tcp',
        state: 'open' as const,
        service_name: 'https',
        latency_ms: 2.1,
        service: {
          id: 1,
          name: 'https',
          product: 'nginx',
          version: '1.24.0',
          banner: 'HTTP 200 nginx/1.24.0',
          confidence: 'confirmed' as const,
          details: {
            title: 'Example Site',
            tls: {
              subject_cn: 'example.local',
              issuer_cn: 'example.local',
              tls_version: 'TLSv1.3',
              not_after: '2020-01-01T00:00:00+00:00',
              expired: true,
              self_signed: true,
              days_remaining: -400,
            },
          },
        },
      },
    ],
  };

  it('shows the host, its ports and the TLS certificate state', async () => {
    mocked.getHost.mockResolvedValue(host);
    mocked.hostFindings.mockResolvedValue([]);

    renderWithProviders(<HostDetailPage />, { route: '/hosts/1', path: '/hosts/:hostId' });

    expect(await screen.findByText('192.168.1.15')).toBeInTheDocument();
    expect(screen.getByText(/server\.local/)).toBeInTheDocument();
    expect(screen.getByText('443/tcp')).toBeInTheDocument();
    expect(screen.getByText(/nginx 1\.24\.0/)).toBeInTheDocument();
    // TLS problems are named in words, not signalled by colour alone.
    expect(screen.getByText(/expired/)).toBeInTheDocument();
    expect(screen.getByText(/self-signed/)).toBeInTheDocument();
  });

  it('renders findings attached to the host', async () => {
    mocked.getHost.mockResolvedValue(host);
    mocked.hostFindings.mockResolvedValue([
      makeFinding({ title: 'Expired TLS certificate on port 443', severity: 'high' }),
    ]);

    renderWithProviders(<HostDetailPage />, { route: '/hosts/1', path: '/hosts/:hostId' });

    expect(
      (await screen.findAllByText('Expired TLS certificate on port 443')).length,
    ).toBeGreaterThan(0);
  });
});

describe('Topology', () => {
  const nodes: TopologyNode[] = [
    { id: 'scanner', label: 'Scanner', kind: 'scanner', severity: null, parent: null, meta: {} },
    {
      id: 'host-1',
      label: '192.168.1.10',
      kind: 'host',
      severity: 'high',
      parent: 'scanner',
      meta: {},
    },
    {
      id: 'port-1',
      label: '22/tcp',
      kind: 'port',
      severity: null,
      parent: 'host-1',
      meta: { service: 'ssh' },
    },
  ];

  it('draws scanner, hosts and their ports', () => {
    renderWithProviders(<Topology nodes={nodes} />);
    expect(screen.getByText('Scanner')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('22/tcp')).toBeInTheDocument();
    expect(screen.getByText(/1 open · high/)).toBeInTheDocument();
  });

  it('says so when nothing responded', () => {
    renderWithProviders(<Topology nodes={[nodes[0]]} />);
    expect(screen.getByText(/No responsive hosts/i)).toBeInTheDocument();
  });
});

describe('ScanProgress', () => {
  const event = {
    scan_id: 1,
    status: 'running' as const,
    phase: 'port_scanning',
    progress: 0.42,
    message: '120/300 TCP probes',
    phases: {
      target_validation: 1,
      host_discovery: 1,
      port_scanning: 0.7,
      service_fingerprinting: 0,
      vulnerability_lookup: 0,
      risk_calculation: 0,
      storing_results: 0,
    },
  };

  it('shows every phase with its own progress', () => {
    renderWithProviders(<ScanProgress event={event} />);
    expect(screen.getByText('120/300 TCP probes')).toBeInTheDocument();
    for (const label of [
      'Target validation',
      'Host discovery',
      'Port scanning',
      'Service fingerprinting',
      'Vulnerability lookup',
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it('exposes progress to assistive technology', () => {
    renderWithProviders(<ScanProgress event={event} />);
    const overall = screen.getByRole('progressbar', { name: 'Overall' });
    expect(overall).toHaveAttribute('aria-valuenow', '42');
  });

  it('offers cancellation while a scan runs', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();
    renderWithProviders(<ScanProgress event={event} onCancel={onCancel} />);

    await user.click(screen.getByRole('button', { name: /cancel scan/i }));
    expect(onCancel).toHaveBeenCalledOnce();
  });

  it('falls back to a starting message before the first event', () => {
    renderWithProviders(<ScanProgress event={null} />);
    expect(screen.getByText(/Starting/)).toBeInTheDocument();
  });
});

describe('FindingDrawer', () => {
  it('renders nothing when no finding is selected', () => {
    const { container } = renderWithProviders(
      <FindingDrawer finding={null} onClose={() => {}} />,
    );
    expect(container.querySelector('[role="dialog"]')).toBeNull();
  });

  it('shows the reasoning, evidence and references', () => {
    renderWithProviders(
      <FindingDrawer
        finding={makeFinding({
          cve_id: 'CVE-2024-0001',
          cvss: 9.8,
          severity: 'critical',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2024-0001'],
        })}
        onClose={() => {}}
      />,
    );

    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Why this severity')).toBeInTheDocument();
    expect(within(dialog).getByText('CVSS 9.8')).toBeInTheDocument();
    expect(within(dialog).getByText('CVE-2024-0001')).toBeInTheDocument();
    expect(
      within(dialog).getByRole('link', { name: /nvd\.nist\.gov/ }),
    ).toHaveAttribute('target', '_blank');
  });

  it('closes on Escape', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    renderWithProviders(<FindingDrawer finding={makeFinding()} onClose={onClose} />);

    await user.keyboard('{Escape}');
    expect(onClose).toHaveBeenCalled();
  });
});
