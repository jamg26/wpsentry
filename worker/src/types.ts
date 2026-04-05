// Shared TypeScript types for JWP Worker

export interface Env {
  DB: D1Database;
  SESSIONS_KV: KVNamespace;
  RATELIMIT_KV: KVNamespace;
  REPORTS_R2: R2Bucket;
  SCAN_QUEUE: Queue<ScanJobMessage>;
  ANALYTICS: AnalyticsEngineDataset;
  JWT_SECRET: string;
  ENVIRONMENT: string;
  DAILY_SCAN_LIMIT: string;
  MONTHLY_SCAN_LIMIT: string;
  CORS_ORIGIN: string;
  ADMIN_PASSWORD: string;
  // Email — set secret: wrangler secret put RESEND_API_KEY
  RESEND_API_KEY?: string;
  // Email — set secret: wrangler secret put BREVO_API_KEY  (Settings → API Keys in Brevo dashboard)
  BREVO_API_KEY?: string;
  // Switch provider: "resend" (default) | "brevo"
  EMAIL_PROVIDER?: string;
  EMAIL_FROM?: string;
  RESEND_FROM?: string;
  // AI remediation — set secret: wrangler secret put OPENROUTER_API_KEY
  OPENROUTER_API_KEY?: string;
}

// ── Database row types ─────────────────────────────────────────────────────

export interface UserRow {
  id: string;
  email: string;
  full_name: string | null;
  password_hash: string;
  created_at: number;
  last_login: number | null;
  is_verified: number;
  is_active: number;
  notification_prefs: string | null;
  updated_at: number | null;
  verify_token: string | null;
  verify_token_expires: number | null;
}

export interface ScanRow {
  id: string;
  user_id: string;
  target: string;
  status: ScanStatus;
  modules_selected: string | null;
  created_at: number;
  started_at: number | null;
  completed_at: number | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  report_key: string | null;
  error_message: string | null;
  tags: string | null;
  is_public: number;
  public_token: string | null;
}

export interface UsageRow {
  id: number;
  user_id: string;
  action: string;
  scan_id: string | null;
  created_at: number;
}

export interface ApiKeyRow {
  id: string;
  user_id: string;
  name: string;
  key_hash: string;
  key_prefix: string;
  last_used_at: number | null;
  created_at: number;
  enabled: number;
}

export interface ScheduledScanRow {
  id: string;
  user_id: string;
  url: string;
  schedule_cron: string;
  next_run_at: number;
  last_run_at: number | null;
  enabled: number;
  created_at: number;
}

export interface WebhookRow {
  id: string;
  user_id: string;
  url: string;
  secret: string;
  events: string;
  enabled: number;
  created_at: number;
}

// ── Domain types ──────────────────────────────────────────────────────────

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Finding {
  type: string;
  severity: Severity;
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

export interface ScanReport {
  scan_id: string;
  target: string;
  created_at: string;
  completed_at: string;
  modules_run: number;
  modules_selected: number[] | null;
  findings: Finding[];
  results: ModuleResult[];
  summary: {
    total_modules: number;
    vulnerable: number;
    clean: number;
    total_findings: number;
    by_severity: Record<Severity, number>;
  };
}

// ── Queue message ─────────────────────────────────────────────────────────

export interface ScanJobMessage {
  scan_id: string;
  user_id: string;
  target: string;
  modules: number[] | null; // null = all modules
}

// ── JWT ───────────────────────────────────────────────────────────────────

export interface JWTPayload {
  sub: string; // user_id
  email: string;
  jti: string; // session ID for KV revocation
  iat: number;
  exp: number;
}

// ── API response helpers ─────────────────────────────────────────────────

export interface ApiError {
  error: string;
  message?: string;
}

export interface UsageStats {
  daily_used: number;
  daily_limit: number;
  daily_remaining: number;
  monthly_used: number;
  monthly_limit: number;
  monthly_remaining: number;
  reset_daily_at: string; // ISO timestamp
  reset_monthly_at: string; // ISO timestamp
}
