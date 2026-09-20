export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'confirmed' | 'probable' | 'possible';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanProfile = 'quick' | 'standard' | 'custom';
export type PortState = 'open' | 'closed' | 'filtered' | 'open|filtered' | 'unknown';

export interface TlsDetails {
  verified?: boolean;
  verify_error?: string | null;
  tls_version?: string | null;
  cipher?: string | null;
  weak_protocol?: boolean;
  subject_cn?: string | null;
  issuer_cn?: string | null;
  san?: string[];
  not_before?: string | null;
  not_after?: string | null;
  days_remaining?: number | null;
  expired?: boolean;
  not_yet_valid?: boolean;
  self_signed?: boolean;
  hostname_mismatch?: boolean;
  fingerprint_sha256?: string | null;
  signature_algorithm?: string | null;
}

export interface ServiceDetails {
  scheme?: string;
  url?: string;
  status_code?: number;
  server?: string | null;
  powered_by?: string | null;
  title?: string | null;
  redirects?: string[];
  missing_security_headers?: string[];
  admin_interface?: string | null;
  content_type?: string | null;
  requires_auth?: boolean;
  tls?: TlsDetails;
  [key: string]: unknown;
}

export interface Service {
  id: number;
  name: string;
  product: string | null;
  version: string | null;
  banner: string | null;
  confidence: Confidence;
  details: ServiceDetails;
}

export interface Port {
  id: number;
  port: number;
  protocol: string;
  state: PortState;
  service_name: string | null;
  latency_ms: number | null;
  service: Service | null;
}

export interface Host {
  id: number;
  scan_id: number;
  ip: string;
  hostname: string | null;
  status: string;
  risk_score: number;
  open_port_count: number;
  ports?: Port[];
}

export interface Finding {
  id: number;
  scan_id: number;
  host_id: number | null;
  port_id: number | null;
  type: string;
  severity: Severity;
  title: string;
  description: string;
  reason: string;
  evidence: string;
  recommendation: string;
  cve_id: string | null;
  cvss: number | null;
  confidence: Confidence;
  references: string[];
  extra: Record<string, unknown>;
  created_at: string;
  host_ip: string | null;
  port_number: number | null;
}

export type SeverityCounts = Record<Severity, number>;

export interface Scan {
  id: number;
  target: string;
  scan_type: string;
  status: ScanStatus;
  engine: string;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  risk_score: number;
  error: string | null;
  udp_enabled: boolean;
  host_count: number;
  open_port_count: number;
  finding_count: number;
  severity_counts: SeverityCounts;
}

export interface ScanDetail extends Scan {
  hosts: Host[];
  findings: Finding[];
}

export interface ScanCreate {
  target: string;
  profile: ScanProfile;
  ports?: string | null;
  udp: boolean;
  udp_ports?: string | null;
  timeout: number;
  concurrency: number;
  engine: 'auto' | 'socket' | 'nmap';
  authorized: boolean;
}

export interface ScanProgressEvent {
  scan_id: number;
  status: ScanStatus;
  phase: string;
  progress: number;
  message: string;
  phases: Record<string, number>;
}

export interface ExposedHost {
  host_id: number;
  ip: string;
  hostname: string | null;
  open_ports: number;
  risk_score: number;
  critical: number;
  high: number;
}

export interface DashboardSummary {
  total_scans: number;
  hosts_discovered: number;
  open_ports: number;
  services_detected: number;
  findings: SeverityCounts;
  latest_risk_score: number;
  recent_scans: Scan[];
  most_exposed_hosts: ExposedHost[];
}

export interface TrendPoint {
  scan_id: number;
  timestamp: string;
  target: string;
  hosts: number;
  open_ports: number;
  services: number;
  risk_score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface TrendResponse {
  points: TrendPoint[];
}

export interface TopologyNode {
  id: string;
  label: string;
  kind: 'scanner' | 'host' | 'port';
  severity: Severity | null;
  parent: string | null;
  meta: Record<string, unknown>;
}

export interface TopologyResponse {
  scan_id: number;
  nodes: TopologyNode[];
}

export interface HealthResponse {
  status: string;
  engines: { socket: boolean; nmap: boolean };
  public_targets_allowed: boolean;
  active_scans: number[];
}

export interface ApiError {
  error: {
    message: string;
    status: number;
    detail?: Array<{ field: string; message: string }> | string;
  };
}
