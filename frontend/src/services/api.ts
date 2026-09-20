import axios, { AxiosError } from 'axios';
import type {
  ApiError,
  DashboardSummary,
  Finding,
  HealthResponse,
  Host,
  Port,
  Scan,
  ScanCreate,
  ScanDetail,
  TopologyResponse,
  TrendResponse,
} from '@/types';

export const API_BASE = import.meta.env.VITE_API_BASE ?? '';

export const client = axios.create({
  baseURL: API_BASE,
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json' },
});

/** Turn any axios failure into a single readable sentence. */
export function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<ApiError>;
    const payload = axiosError.response?.data;
    if (payload?.error) {
      const { message, detail } = payload.error;
      if (Array.isArray(detail) && detail.length > 0) {
        return detail.map((d) => d.message).join('; ');
      }
      if (typeof detail === 'string') return detail;
      return message;
    }
    if (axiosError.code === 'ECONNABORTED') return 'The request timed out.';
    if (!axiosError.response) {
      return 'Cannot reach the API. Is the backend running on port 8000?';
    }
    return axiosError.message;
  }
  return error instanceof Error ? error.message : 'Something went wrong.';
}

export interface FindingFilters {
  scan_id?: number;
  host_id?: number;
  severity?: string;
  finding_type?: string;
  cve?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export const api = {
  health: () => client.get<HealthResponse>('/api/health').then((r) => r.data),

  listScans: (limit = 25, offset = 0) =>
    client.get<Scan[]>('/api/scans', { params: { limit, offset } }).then((r) => r.data),

  getScan: (id: number) => client.get<ScanDetail>(`/api/scans/${id}`).then((r) => r.data),

  createScan: (payload: ScanCreate) =>
    client.post<Scan>('/api/scans', payload).then((r) => r.data),

  cancelScan: (id: number) =>
    client.post<Scan>(`/api/scans/${id}/cancel`).then((r) => r.data),

  deleteScan: (id: number) => client.delete(`/api/scans/${id}`).then(() => undefined),

  scanHosts: (id: number) =>
    client.get<Host[]>(`/api/scans/${id}/hosts`).then((r) => r.data),

  topology: (id: number) =>
    client.get<TopologyResponse>(`/api/scans/${id}/topology`).then((r) => r.data),

  getHost: (id: number) => client.get<Host>(`/api/hosts/${id}`).then((r) => r.data),

  hostPorts: (id: number) => client.get<Port[]>(`/api/hosts/${id}/ports`).then((r) => r.data),

  hostFindings: (id: number) =>
    client.get<Finding[]>(`/api/hosts/${id}/findings`).then((r) => r.data),

  listFindings: (filters: FindingFilters = {}) =>
    client
      .get<Finding[]>('/api/findings', {
        params: Object.fromEntries(
          Object.entries(filters).filter(([, v]) => v !== undefined && v !== ''),
        ),
      })
      .then((r) => r.data),

  getFinding: (id: number) => client.get<Finding>(`/api/findings/${id}`).then((r) => r.data),

  dashboardSummary: () =>
    client.get<DashboardSummary>('/api/dashboard/summary').then((r) => r.data),

  trends: (limit = 20) =>
    client.get<TrendResponse>('/api/dashboard/trends', { params: { limit } }).then((r) => r.data),

  /** SSE endpoint URL for a scan's live progress. */
  streamUrl: (id: number) => `${API_BASE}/api/scans/${id}/stream`,
};
