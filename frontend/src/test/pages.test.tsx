import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  makeFinding,
  makeScanDetail,
  makeSummary,
  makeTrendPoints,
  renderWithProviders,
} from './utils';

// The API module is mocked so no test touches a network target or a backend.
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
import DashboardPage from '@/pages/DashboardPage';
import FindingsPage from '@/pages/FindingsPage';
import NewScanPage from '@/pages/NewScanPage';
import ScanDetailPage from '@/pages/ScanDetailPage';

const mocked = vi.mocked(api);

// Recharts needs real layout dimensions, which jsdom does not provide.
beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
    configurable: true,
    value: 800,
  });
  Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
    configurable: true,
    value: 400,
  });
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as never;
  global.EventSource = class {
    close() {}
    addEventListener() {}
  } as never;
});

describe('DashboardPage', () => {
  it('renders the headline risk score and stat tiles', async () => {
    mocked.dashboardSummary.mockResolvedValue(makeSummary());
    mocked.trends.mockResolvedValue({ points: makeTrendPoints() });

    renderWithProviders(<DashboardPage />);

    expect((await screen.findAllByText('61.5')).length).toBeGreaterThan(0);
    expect(screen.getByText('Hosts')).toBeInTheDocument();
    expect(screen.getAllByText('Open ports').length).toBeGreaterThan(0);
  });

  it('shows severity counts beside their labels, not by colour alone', async () => {
    mocked.dashboardSummary.mockResolvedValue(makeSummary());
    mocked.trends.mockResolvedValue({ points: [] });

    renderWithProviders(<DashboardPage />);

    // Wait for data, not just the card title, which renders while loading.
    await screen.findAllByText('61.5');
    for (const label of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
  });

  it('prompts for a first scan when there is no history', async () => {
    mocked.dashboardSummary.mockResolvedValue(
      makeSummary({ total_scans: 0, recent_scans: [], most_exposed_hosts: [] }),
    );
    mocked.trends.mockResolvedValue({ points: [] });

    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText('No scans yet')).toBeInTheDocument();
  });

  it('surfaces an API failure instead of rendering an empty page', async () => {
    mocked.dashboardSummary.mockRejectedValue(new Error('backend down'));
    mocked.trends.mockResolvedValue({ points: [] });

    renderWithProviders(<DashboardPage />);

    expect(await screen.findByText(/backend down/i)).toBeInTheDocument();
  });
});

describe('NewScanPage', () => {
  it('keeps the submit button disabled until authorisation is confirmed', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NewScanPage />);

    const submit = screen.getByRole('button', { name: /start scan/i });
    expect(submit).toBeDisabled();

    await user.click(screen.getByRole('checkbox', { name: /authorisation to scan it/i }));
    expect(submit).toBeEnabled();
  });

  it('shows the authorisation warning', () => {
    renderWithProviders(<NewScanPage />);
    expect(
      screen.getByText(/only scan systems and networks you own/i),
    ).toBeInTheDocument();
  });

  it('requires an explicit port list for a custom profile', async () => {
    const user = userEvent.setup();
    renderWithProviders(<NewScanPage />);

    await user.click(screen.getByRole('checkbox', { name: /authorisation to scan it/i }));
    await user.click(screen.getByRole('button', { name: /^Custom/i }));
    await user.click(screen.getByRole('button', { name: /start scan/i }));

    expect(await screen.findByText(/needs an explicit port list/i)).toBeInTheDocument();
    expect(mocked.createScan).not.toHaveBeenCalled();
  });

  it('submits a valid scan request', async () => {
    const user = userEvent.setup();
    mocked.createScan.mockResolvedValue(makeScanDetail());
    renderWithProviders(<NewScanPage />);

    await user.click(screen.getByRole('checkbox', { name: /authorisation to scan it/i }));
    await user.click(screen.getByRole('button', { name: /start scan/i }));

    await waitFor(() => expect(mocked.createScan).toHaveBeenCalledOnce());
    expect(mocked.createScan.mock.calls[0][0]).toMatchObject({
      target: '127.0.0.1',
      profile: 'quick',
      authorized: true,
    });
  });
});

describe('ScanDetailPage', () => {
  it('renders scan statistics and host rows', async () => {
    mocked.getScan.mockResolvedValue(makeScanDetail());

    renderWithProviders(<ScanDetailPage />, { route: '/scans/1', path: '/scans/:scanId' });

    expect(await screen.findByText(/Scan #1/)).toBeInTheDocument();
    expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('Completed')).toBeInTheDocument();
  });

  it('shows the failure reason when a scan failed', async () => {
    mocked.getScan.mockResolvedValue(
      makeScanDetail({ status: 'failed', error: 'Target unreachable' }),
    );

    renderWithProviders(<ScanDetailPage />, { route: '/scans/1', path: '/scans/:scanId' });

    expect(await screen.findByText(/Target unreachable/)).toBeInTheDocument();
  });

  it('opens the finding drawer with evidence and reasoning', async () => {
    const user = userEvent.setup();
    mocked.getScan.mockResolvedValue(makeScanDetail());

    renderWithProviders(<ScanDetailPage />, { route: '/scans/1', path: '/scans/:scanId' });

    await user.click(await screen.findByRole('tab', { name: /Findings/i }));
    await user.click(await screen.findByText('SSH exposed on port 22'));

    expect(await screen.findByText('Why this severity')).toBeInTheDocument();
    expect(screen.getByText('Evidence')).toBeInTheDocument();
    expect(screen.getByText('Recommendation')).toBeInTheDocument();
  });
});

describe('FindingsPage', () => {
  it('lists findings with severity labels', async () => {
    mocked.listFindings.mockResolvedValue([
      makeFinding(),
      makeFinding({ id: 2, severity: 'critical', title: 'CVE-2024-0001 affects nginx 1.24.0' }),
    ]);

    renderWithProviders(<FindingsPage />);

    expect(await screen.findByText('SSH exposed on port 22')).toBeInTheDocument();
    expect(screen.getByText('CVE-2024-0001 affects nginx 1.24.0')).toBeInTheDocument();
    expect(screen.getAllByText('Critical').length).toBeGreaterThan(0);
  });

  it('passes the severity filter to the API', async () => {
    const user = userEvent.setup();
    mocked.listFindings.mockResolvedValue([makeFinding()]);

    renderWithProviders(<FindingsPage />);
    await screen.findByText('SSH exposed on port 22');

    await user.selectOptions(screen.getByLabelText('Filter by severity'), 'critical');

    await waitFor(() =>
      expect(mocked.listFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ severity: 'critical' }),
      ),
    );
  });

  it('offers a way out when filters match nothing', async () => {
    const user = userEvent.setup();
    mocked.listFindings.mockResolvedValue([]);

    renderWithProviders(<FindingsPage />);
    await user.type(screen.getByLabelText('Search findings'), 'zzz');

    expect(await screen.findByText(/No findings match these filters/i)).toBeInTheDocument();
  });
});
