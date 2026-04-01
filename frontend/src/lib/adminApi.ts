// Admin API client — separate from main API client

const BASE = import.meta.env.VITE_API_URL ?? '/api';

async function adminRequest<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers as Record<string, string> ?? {}),
    },
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'network_error' })) as { error: string; message?: string };
    throw Object.assign(new Error(err.message ?? err.error ?? 'Request failed'), {
      status: res.status,
      data: err,
    });
  }

  return res.json() as Promise<T>;
}

// ── Auth ────────────────────────────────────────────────────────────────

export function adminLogin(password: string) {
  return adminRequest<{ message: string }>('/admin/login', {
    method: 'POST',
    body: JSON.stringify({ password }),
  });
}

export function adminLogout() {
  return adminRequest<{ message: string }>('/admin/logout', { method: 'POST' });
}

// ── Stats ───────────────────────────────────────────────────────────────

export interface AdminStats {
  total_users: number;
  total_scans: number;
  total_findings: number;
  active_scans: number;
  recent_scan_dates: number[];
}

export function getAdminStats() {
  return adminRequest<AdminStats>('/admin/stats');
}

// ── Users ───────────────────────────────────────────────────────────────

export interface AdminUser {
  id: string;
  email: string;
  created_at: number;
  last_login: number | null;
  is_verified: number;
  is_active: number;
  scan_count: number;
  daily_limit: string;
  monthly_limit: string;
}

export interface AdminUsersResponse {
  users: AdminUser[];
  total: number;
  pagination: { limit: number; offset: number };
}

export function getAdminUsers(limit = 50, offset = 0, search = '') {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (search) params.set('search', search);
  return adminRequest<AdminUsersResponse>(`/admin/users?${params}`);
}

export function updateAdminUser(id: string, data: { is_active?: number; daily_limit?: string; monthly_limit?: string }) {
  return adminRequest<{ message: string }>(`/admin/users/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export function deleteAdminUser(id: string) {
  return adminRequest<{ message: string }>(`/admin/users/${id}`, { method: 'DELETE' });
}

// ── Scans ───────────────────────────────────────────────────────────────

export interface AdminScan {
  id: string;
  user_id: string;
  user_email: string;
  target: string;
  status: string;
  findings_count: number;
  created_at: number;
  started_at: number | null;
  completed_at: number | null;
  error_message: string | null;
}

export interface AdminScansResponse {
  scans: AdminScan[];
  total: number;
  pagination: { limit: number; offset: number };
}

export function getAdminScans(limit = 50, offset = 0, filters: { status?: string; user?: string; target?: string } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (filters.status) params.set('status', filters.status);
  if (filters.user) params.set('user', filters.user);
  if (filters.target) params.set('target', filters.target);
  return adminRequest<AdminScansResponse>(`/admin/scans?${params}`);
}

export function deleteAdminScan(id: string) {
  return adminRequest<{ message: string }>(`/admin/scans/${id}`, { method: 'DELETE' });
}

// ── Config ──────────────────────────────────────────────────────────────

export interface AdminConfig {
  DAILY_SCAN_LIMIT: string;
  MONTHLY_SCAN_LIMIT: string;
  AUTH_SIGNUP_MAX_ATTEMPTS: string;
  AUTH_SIGNUP_WINDOW_SECONDS: string;
  AUTH_LOGIN_MAX_ATTEMPTS: string;
  AUTH_LOGIN_WINDOW_SECONDS: string;
}

export function getAdminConfig() {
  return adminRequest<AdminConfig>('/admin/config');
}

export function updateAdminConfig(config: Partial<AdminConfig>) {
  return adminRequest<{ message: string }>('/admin/config', {
    method: 'PUT',
    body: JSON.stringify(config),
  });
}

// ── Database ────────────────────────────────────────────────────────────

export interface QueryResult {
  columns: string[];
  rows: Record<string, unknown>[];
  meta: { rows_read?: number; duration?: number; changes?: number };
}

export function executeReadQuery(sql: string) {
  return adminRequest<QueryResult>(`/admin/db/query?sql=${encodeURIComponent(sql)}`);
}

export function executeWriteQuery(sql: string) {
  return adminRequest<QueryResult>('/admin/db/query', {
    method: 'POST',
    body: JSON.stringify({ sql }),
  });
}

export interface RateLimitEntry {
  key: string;
  type: string;
  ip: string;
  count: string;
}

export interface RateLimitsResponse {
  entries: RateLimitEntry[];
  config: Record<string, string>;
}

export function getRateLimits() {
  return adminRequest<RateLimitsResponse>('/admin/rate-limits');
}

export function clearRateLimit(key?: string) {
  return adminRequest<{ message: string }>('/admin/rate-limits', {
    method: 'DELETE',
    body: JSON.stringify(key ? { key } : {}),
  });
}
