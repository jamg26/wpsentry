// Typed API client for JWP backend

const BASE = import.meta.env.VITE_API_URL ?? '/api';

export interface ApiError {
  error: string;
  message?: string;
  daily_remaining?: number;
  monthly_remaining?: number;
  reset_daily_at?: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  created_at: string;
  last_login: string | null;
  is_verified: boolean;
}

export interface UsageStats {
  daily_used: number;
  daily_limit: number;
  daily_remaining: number;
  monthly_used: number;
  monthly_limit: number;
  monthly_remaining: number;
  reset_daily_at: string;
  reset_monthly_at: string;
}

export interface ScanSummary {
  id: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  modules_selected: number[] | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  error_message: string | null;
  tags: string[];
  is_public: boolean;
  public_token: string | null;
}

export interface Finding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  url: string;
  description: string;
  replication_steps?: string[];
  remediation?: string;
  remediation_ai?: boolean;
  evidence?: string;
}

export interface ModuleResult {
  module: string;
  target: string;
  vulnerable: boolean;
  findings: Finding[];
  errors: string[];
  duration_ms: number;
}

export interface UserStats {
  total_scans: number;
  scans_this_month: number;
  scans_this_week: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  sites_scanned: number;
  last_scan_at: string | null;
  avg_scan_duration_seconds: number | null;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  last_used_at: string | null;
  created_at: string;
  enabled: boolean;
}

export interface ScheduledScan {
  id: string;
  url: string;
  schedule_cron: 'daily' | 'weekly' | 'monthly';
  next_run_at: string;
  last_run_at: string | null;
  enabled: boolean;
  created_at: string;
}

export interface Webhook {
  id: string;
  url: string;
  events: string[];
  enabled: boolean;
  created_at: string;
}

export interface NotificationPrefs {
  scan_complete: boolean;
  critical_found: boolean;
  weekly_report: boolean;
}

export interface CompareResult {
  scan_a: ScanSummary;
  scan_b: ScanSummary;
  new_findings: Finding[];
  fixed_findings: Finding[];
  unchanged_findings: Finding[];
  summary: { new: number; fixed: number; unchanged: number };
}

export interface ScanDetail extends ScanSummary {
  report?: {
    scan_id: string;
    target: string;
    created_at: string;
    completed_at: string;
    modules_run: number;
    findings: Finding[];
    results: ModuleResult[];
    summary: {
      total_modules: number;
      vulnerable: number;
      clean: number;
      total_findings: number;
      by_severity: Record<string, number>;
    };
  };
}

export interface ScansListResponse {
  scans: ScanSummary[];
  pagination: { limit: number; offset: number };
  usage: {
    daily_used: number;
    daily_limit: number;
    monthly_used: number;
    monthly_limit: number;
  };
}

export interface FpReport {
  id: string;
  scan_id: string;
  finding_type: string;
  finding_url: string;
  finding_severity: string;
  reason: string | null;
  status: 'pending' | 'confirmed' | 'rejected';
  created_at: number;
  user_email: string;
}

class ApiClient {
  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await fetch(`${BASE}${path}`, {
      ...init,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(init.headers as Record<string, string> ?? {}),
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'network_error' })) as ApiError;
      throw Object.assign(new Error(err.message ?? err.error ?? 'Request failed'), {
        status: res.status,
        data: err,
      });
    }

    return res.json() as Promise<T>;
  }

  // ── Auth ──────────────────────────────────────────────────────────────
  signup(email: string, password: string, fullName?: string) {
    return this.request<{ message: string; user: { id: string; email: string } }>(
      '/auth/signup',
      { method: 'POST', body: JSON.stringify({ email, password, agreed_to_terms: true, full_name: fullName || undefined }) },
    );
  }

  login(email: string, password: string) {
    return this.request<{ message: string; user: { id: string; email: string } }>(
      '/auth/login',
      { method: 'POST', body: JSON.stringify({ email, password }) },
    );
  }

  logout() {
    return this.request<{ message: string }>('/auth/logout', { method: 'POST' });
  }

  // ── User ──────────────────────────────────────────────────────────────
  getMe() {
    return this.request<User>('/user/me');
  }

  updateProfile(fullName: string) {
    return this.request<{ message: string; full_name: string | null }>('/user/profile', {
      method: 'PUT',
      body: JSON.stringify({ full_name: fullName }),
    });
  }

  resendVerification() {
    return this.request<{ message: string }>('/user/resend-verification', { method: 'POST' });
  }

  getUsage() {
    return this.request<UsageStats>('/user/usage');
  }

  changePassword(currentPassword: string, newPassword: string) {
    return this.request<{ message: string }>(
      '/user/change-password',
      { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) },
    );
  }

  deleteAccount(password: string) {
    return this.request<{ message: string }>(
      '/user/me',
      { method: 'DELETE', body: JSON.stringify({ password }) },
    );
  }

  // ── Scans ─────────────────────────────────────────────────────────────
  createScan(target: string, modules?: number[], tags?: string[]) {
    return this.request<{ id: string; status: string; target: string; created_at: string; tags: string[] }>(
      '/scans',
      { method: 'POST', body: JSON.stringify({ target, modules, tags, authorization_confirmed: true }) },
    );
  }

  listScans(limit = 20, offset = 0) {
    return this.request<ScansListResponse>(`/scans?limit=${limit}&offset=${offset}`);
  }

  getScan(id: string) {
    return this.request<ScanDetail>(`/scans/${id}`);
  }

  deleteScan(id: string) {
    return this.request<{ message: string }>(`/scans/${id}`, { method: 'DELETE' });
  }

  getScanProgress(id: string) {
    return this.request<{
      scan_id: string;
      total: number;
      completed: number | null;
      current_module: string | null;
      events: Array<{ module: string; status: 'ok' | 'error'; findings: number; duration_ms: number; ts: number }>;
      status: string;
      updated_at: number;
    }>(`/scans/${id}/progress`);
  }

  updateScanTags(id: string, tags: string[]) {
    return this.request<{ id: string; tags: string[] }>(
      `/scans/${id}/tags`,
      { method: 'PUT', body: JSON.stringify({ tags }) },
    );
  }

  shareScan(id: string) {
    return this.request<{ token: string; public_url: string; api_url: string }>(
      `/scans/${id}/share`,
      { method: 'POST' },
    );
  }

  unshareScan(id: string) {
    return this.request<{ message: string }>(`/scans/${id}/share`, { method: 'DELETE' });
  }

  compareScans(a: string, b: string) {
    return this.request<CompareResult>(`/scans/compare?a=${a}&b=${b}`);
  }

  // ── Stats ─────────────────────────────────────────────────────────────
  getUserStats() {
    return this.request<UserStats>('/user/stats');
  }

  // ── Notifications ─────────────────────────────────────────────────────
  getNotifications() {
    return this.request<{ notification_prefs: NotificationPrefs }>('/user/notifications');
  }

  updateNotifications(prefs: NotificationPrefs) {
    return this.request<{ notification_prefs: NotificationPrefs }>(
      '/user/notifications',
      { method: 'PUT', body: JSON.stringify(prefs) },
    );
  }

  // ── API Keys ──────────────────────────────────────────────────────────
  listApiKeys() {
    return this.request<{ api_keys: ApiKey[] }>('/user/api-keys');
  }

  createApiKey(name: string) {
    return this.request<{ id: string; name: string; key: string; key_prefix: string; created_at: string }>(
      '/user/api-keys',
      { method: 'POST', body: JSON.stringify({ name }) },
    );
  }

  deleteApiKey(id: string) {
    return this.request<{ message: string }>(`/user/api-keys/${id}`, { method: 'DELETE' });
  }

  // ── Scheduled Scans ───────────────────────────────────────────────────
  listScheduledScans() {
    return this.request<{ scheduled_scans: ScheduledScan[] }>('/scans/schedule');
  }

  createScheduledScan(url: string, schedule_cron: string) {
    return this.request<ScheduledScan>('/scans/schedule', {
      method: 'POST',
      body: JSON.stringify({ url, schedule_cron }),
    });
  }

  updateScheduledScan(id: string, updates: Partial<ScheduledScan>) {
    return this.request<ScheduledScan>(`/scans/schedule/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  deleteScheduledScan(id: string) {
    return this.request<{ message: string }>(`/scans/schedule/${id}`, { method: 'DELETE' });
  }

  // ── Webhooks ──────────────────────────────────────────────────────────
  listWebhooks() {
    return this.request<{ webhooks: Webhook[] }>('/user/webhooks');
  }

  createWebhook(url: string, events: string[]) {
    return this.request<Webhook & { secret: string }>('/user/webhooks', {
      method: 'POST',
      body: JSON.stringify({ url, events }),
    });
  }

  deleteWebhook(id: string) {
    return this.request<{ message: string }>(`/user/webhooks/${id}`, { method: 'DELETE' });
  }

  // ── Public scan ───────────────────────────────────────────────────────
  getPublicScan(token: string) {
    return this.request<ScanDetail>(`/public/scans/${token}`);
  }

  // ── False positive reporting ──────────────────────────────────────────
  reportFalsePositive(scanId: string, data: {
    finding_type: string;
    finding_url: string;
    finding_severity: string;
    reason?: string;
  }) {
    return this.request<{ success: boolean; id: string }>(`/scans/${scanId}/report-fp`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // ── Admin — FP reports ────────────────────────────────────────────────
  adminGetFpReports() {
    return this.request<{ reports: FpReport[] }>('/admin/fp-reports');
  }

  adminUpdateFpStatus(id: string, status: 'pending' | 'confirmed' | 'rejected') {
    return this.request<{ success: boolean }>(`/admin/fp-reports/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }
}
export const api = new ApiClient();
