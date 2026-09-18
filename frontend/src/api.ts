const API_BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(error.detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return null as T;
  return res.json();
}

export interface Target {
  id: string;
  name: string;
  base_url: string;
  allowed_domains: string[];
  scan_config: Record<string, unknown>;
  has_auth_config: boolean;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  target_id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  urls_crawled: number;
  requests_sent: number;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  url: string;
  method: string;
  parameter: string | null;
  vulnerability_type: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  exploitability: number;
  impact: number;
  exposure: string;
  risk_score: number | null;
  priority_rank: number | null;
  remediation: string | null;
  references: string[];
  detector_name: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface FindingDetail extends Finding {
  evidence_items: { id: string; kind: string; sanitized_payload: Record<string, unknown>; created_at: string }[];
  risk_breakdowns: { id: string; factor_name: string; raw_value: number; weight: number; contribution: number }[];
}

export interface Report {
  id: string;
  scan_id: string;
  format: string;
  generated_at: string;
  storage_path: string;
}

export const api = {
  // Targets
  listTargets: () => request<Target[]>('/targets'),
  createTarget: (data: { name: string; base_url: string; allowed_domains?: string[] }) =>
    request<Target>('/targets', { method: 'POST', body: JSON.stringify(data) }),
  getTarget: (id: string) => request<Target>(`/targets/${id}`),
  updateTarget: (id: string, data: Partial<Target>) =>
    request<Target>(`/targets/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteTarget: (id: string) =>
    request<null>(`/targets/${id}`, { method: 'DELETE' }),

  // Scans
  listScans: (targetId?: string) => {
    const params = targetId ? `?target_id=${targetId}` : '';
    return request<{ items: Scan[]; total: number }>(`/scans${params}`);
  },
  createScan: (targetId: string) =>
    request<Scan>(`/scans?target_id=${targetId}`, { method: 'POST' }),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  cancelScan: (id: string) =>
    request<Scan>(`/scans/${id}/cancel`, { method: 'POST' }),
  listScanFindings: (scanId: string, params?: { severity?: string; status?: string }) => {
    const qs = new URLSearchParams(params).toString();
    return request<{ items: Finding[]; total: number }>(`/scans/${scanId}/findings${qs ? '?' + qs : ''}`);
  },

  // Findings
  getFinding: (id: string) => request<FindingDetail>(`/findings/${id}`),
  updateFindingStatus: (id: string, status: string) =>
    request<Finding>(`/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),

  // Reports
  listScanReports: (scanId: string) =>
    request<{ items: Report[]; total: number }>(`/scans/${scanId}/reports`),
  createReport: (scanId: string, format: string) =>
    request<Report>(`/scans/${scanId}/reports`, { method: 'POST', body: JSON.stringify({ format }) }),
  downloadReportUrl: (reportId: string) => `${API_BASE}/reports/${reportId}/download`,
};
