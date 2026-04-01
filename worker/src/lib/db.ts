// D1 query helpers

import type { Env, UserRow, ScanRow, UsageRow, ApiKeyRow, ScheduledScanRow, WebhookRow } from '../types.js';

// ── Users ─────────────────────────────────────────────────────────────────

export async function getUserById(env: Env, id: string): Promise<UserRow | null> {
  const result = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<UserRow>();
  return result ?? null;
}

export async function getUserByEmail(env: Env, email: string): Promise<UserRow | null> {
  const result = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<UserRow>();
  return result ?? null;
}

export async function createUser(
  env: Env,
  id: string,
  email: string,
  passwordHash: string,
  tosAcceptedAt?: number,
  tosVersion?: string,
  verifyToken?: string,
  fullName?: string,
): Promise<void> {
  const verifyExpires = verifyToken ? Date.now() + 24 * 60 * 60 * 1000 : null;
  await env.DB.prepare(
    'INSERT INTO users (id, email, full_name, password_hash, created_at, tos_accepted_at, tos_version, verify_token, verify_token_expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(id, email, fullName ?? null, passwordHash, Date.now(), tosAcceptedAt ?? null, tosVersion ?? null, verifyToken ?? null, verifyExpires)
    .run();
}

export async function verifyUserEmail(env: Env, token: string): Promise<{ success: boolean; email?: string }> {
  const user = await env.DB.prepare(
    'SELECT id, email, verify_token_expires FROM users WHERE verify_token = ? AND is_verified = 0',
  ).bind(token).first<{ id: string; email: string; verify_token_expires: number | null }>();

  if (!user) return { success: false };
  if (user.verify_token_expires && Date.now() > user.verify_token_expires) return { success: false };

  await env.DB.prepare(
    'UPDATE users SET is_verified = 1, verify_token = NULL, verify_token_expires = NULL WHERE id = ?',
  ).bind(user.id).run();

  return { success: true, email: user.email };
}

export async function updateLastLogin(env: Env, userId: string): Promise<void> {
  await env.DB.prepare('UPDATE users SET last_login = ? WHERE id = ?')
    .bind(Date.now(), userId)
    .run();
}

// ── Scans ─────────────────────────────────────────────────────────────────

export async function createScan(
  env: Env,
  id: string,
  userId: string,
  target: string,
  modules: number[] | null,
  authConfirmedAt?: number,
  authIp?: string,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO scans (id, user_id, target, status, modules_selected, created_at, authorization_confirmed_at, authorization_ip)
     VALUES (?, ?, ?, 'queued', ?, ?, ?, ?)`,
  )
    .bind(id, userId, target, modules ? JSON.stringify(modules) : null, Date.now(), authConfirmedAt ?? null, authIp ?? null)
    .run();
}

export async function getScanById(env: Env, id: string, userId: string): Promise<ScanRow | null> {
  const result = await env.DB.prepare(
    'SELECT * FROM scans WHERE id = ? AND user_id = ?',
  )
    .bind(id, userId)
    .first<ScanRow>();
  return result ?? null;
}

export async function listScans(
  env: Env,
  userId: string,
  limit = 20,
  offset = 0,
): Promise<ScanRow[]> {
  const results = await env.DB.prepare(
    'SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
  )
    .bind(userId, limit, offset)
    .all<ScanRow>();
  return results.results;
}

export async function updateScanStatus(
  env: Env,
  scanId: string,
  status: string,
  extra?: Partial<Pick<ScanRow, 'started_at' | 'completed_at' | 'findings_count' | 'critical_count' | 'high_count' | 'medium_count' | 'low_count' | 'info_count' | 'report_key' | 'error_message'>>,
): Promise<void> {
  const fields: string[] = ['status = ?'];
  const values: unknown[] = [status];
  if (extra) {
    for (const [k, v] of Object.entries(extra)) {
      if (v !== undefined) {
        fields.push(`${k} = ?`);
        values.push(v);
      }
    }
  }
  values.push(scanId);
  await env.DB.prepare(`UPDATE scans SET ${fields.join(', ')} WHERE id = ?`)
    .bind(...values)
    .run();
}

export async function deleteScan(env: Env, scanId: string, userId: string): Promise<boolean> {
  const result = await env.DB.prepare(
    'DELETE FROM scans WHERE id = ? AND user_id = ?',
  )
    .bind(scanId, userId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

// ── Usage ─────────────────────────────────────────────────────────────────

export async function logUsage(
  env: Env,
  userId: string,
  action: string,
  scanId?: string,
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO usage (user_id, action, scan_id, created_at) VALUES (?, ?, ?, ?)',
  )
    .bind(userId, action, scanId ?? null, Date.now())
    .run();
}

export async function getDailyUsageCount(env: Env, userId: string): Promise<number> {
  const todayStart = startOfDayMs();
  const result = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM usage WHERE user_id = ? AND action = 'scan' AND created_at >= ?",
  )
    .bind(userId, todayStart)
    .first<{ cnt: number }>();
  return result?.cnt ?? 0;
}

export async function getMonthlyUsageCount(env: Env, userId: string): Promise<number> {
  const monthStart = startOfMonthMs();
  const result = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM usage WHERE user_id = ? AND action = 'scan' AND created_at >= ?",
  )
    .bind(userId, monthStart)
    .first<{ cnt: number }>();
  return result?.cnt ?? 0;
}

/**
 * Resolve effective daily + monthly scan limits for a user.
 * Priority: per-user override in system_config → global override in system_config → env default.
 */
export async function getUserLimits(
  env: Env,
  userId: string,
): Promise<{ dailyLimit: number; monthlyLimit: number }> {
  const keys = [
    `user_daily_limit:${userId}`,
    `user_monthly_limit:${userId}`,
    'DAILY_SCAN_LIMIT',
    'MONTHLY_SCAN_LIMIT',
  ];
  const rows = await env.DB.prepare(
    `SELECT key, value FROM system_config WHERE key IN (${keys.map(() => '?').join(',')})`,
  )
    .bind(...keys)
    .all<{ key: string; value: string }>();

  const config: Record<string, string> = {};
  for (const row of rows.results) config[row.key] = row.value;

  const envDaily = parseInt(env.DAILY_SCAN_LIMIT, 10) || 5;
  const envMonthly = parseInt(env.MONTHLY_SCAN_LIMIT, 10) || 50;

  const dailyLimit = parseInt(
    config[`user_daily_limit:${userId}`] ?? config['DAILY_SCAN_LIMIT'] ?? '', 10,
  ) || envDaily;
  const monthlyLimit = parseInt(
    config[`user_monthly_limit:${userId}`] ?? config['MONTHLY_SCAN_LIMIT'] ?? '', 10,
  ) || envMonthly;

  return { dailyLimit, monthlyLimit };
}

export async function getRecentUsage(
  env: Env,
  userId: string,
  limit = 100,
): Promise<UsageRow[]> {
  const results = await env.DB.prepare(
    'SELECT * FROM usage WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
  )
    .bind(userId, limit)
    .all<UsageRow>();
  return results.results;
}

// ── Helpers ───────────────────────────────────────────────────────────────

function startOfDayMs(): number {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
}

function startOfMonthMs(): number {
  const now = new Date();
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
}

function startOfWeekMs(): number {
  const now = new Date();
  const day = now.getUTCDay(); // 0=Sun
  return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - day);
}

// ── API Keys ──────────────────────────────────────────────────────────────

export async function createApiKey(
  env: Env,
  id: string,
  userId: string,
  name: string,
  keyHash: string,
  keyPrefix: string,
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, created_at, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)',
  ).bind(id, userId, name, keyHash, keyPrefix, Date.now()).run();
}

export async function listApiKeys(env: Env, userId: string): Promise<ApiKeyRow[]> {
  const r = await env.DB.prepare(
    'SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC',
  ).bind(userId).all<ApiKeyRow>();
  return r.results;
}

export async function deleteApiKey(env: Env, id: string, userId: string): Promise<boolean> {
  const r = await env.DB.prepare(
    'DELETE FROM api_keys WHERE id = ? AND user_id = ?',
  ).bind(id, userId).run();
  return (r.meta.changes ?? 0) > 0;
}

export async function getApiKeyByHash(env: Env, keyHash: string): Promise<ApiKeyRow | null> {
  const r = await env.DB.prepare(
    'SELECT * FROM api_keys WHERE key_hash = ? AND enabled = 1',
  ).bind(keyHash).first<ApiKeyRow>();
  return r ?? null;
}

export async function touchApiKey(env: Env, id: string): Promise<void> {
  await env.DB.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?')
    .bind(Date.now(), id).run();
}

// ── Scheduled Scans ───────────────────────────────────────────────────────

export async function createScheduledScan(
  env: Env,
  id: string,
  userId: string,
  url: string,
  scheduleCron: string,
  nextRunAt: number,
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO scheduled_scans (id, user_id, url, schedule_cron, next_run_at, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)',
  ).bind(id, userId, url, scheduleCron, nextRunAt, Date.now()).run();
}

export async function listScheduledScans(env: Env, userId: string): Promise<ScheduledScanRow[]> {
  const r = await env.DB.prepare(
    'SELECT * FROM scheduled_scans WHERE user_id = ? ORDER BY created_at DESC',
  ).bind(userId).all<ScheduledScanRow>();
  return r.results;
}

export async function getScheduledScanById(env: Env, id: string, userId: string): Promise<ScheduledScanRow | null> {
  const r = await env.DB.prepare(
    'SELECT * FROM scheduled_scans WHERE id = ? AND user_id = ?',
  ).bind(id, userId).first<ScheduledScanRow>();
  return r ?? null;
}

export async function updateScheduledScan(
  env: Env,
  id: string,
  userId: string,
  fields: Partial<Pick<ScheduledScanRow, 'url' | 'schedule_cron' | 'next_run_at' | 'last_run_at' | 'enabled'>>,
): Promise<boolean> {
  const sets: string[] = [];
  const vals: unknown[] = [];
  for (const [k, v] of Object.entries(fields)) {
    if (v !== undefined) { sets.push(`${k} = ?`); vals.push(v); }
  }
  if (sets.length === 0) return false;
  vals.push(id, userId);
  const r = await env.DB.prepare(
    `UPDATE scheduled_scans SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`,
  ).bind(...vals).run();
  return (r.meta.changes ?? 0) > 0;
}

export async function deleteScheduledScan(env: Env, id: string, userId: string): Promise<boolean> {
  const r = await env.DB.prepare(
    'DELETE FROM scheduled_scans WHERE id = ? AND user_id = ?',
  ).bind(id, userId).run();
  return (r.meta.changes ?? 0) > 0;
}

export async function getDueScheduledScans(env: Env): Promise<ScheduledScanRow[]> {
  const now = Date.now();
  const r = await env.DB.prepare(
    'SELECT * FROM scheduled_scans WHERE enabled = 1 AND next_run_at <= ?',
  ).bind(now).all<ScheduledScanRow>();
  return r.results;
}

// ── Webhooks ──────────────────────────────────────────────────────────────

export async function createWebhook(
  env: Env,
  id: string,
  userId: string,
  url: string,
  secret: string,
  events: string,
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO webhooks (id, user_id, url, secret, events, enabled, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)',
  ).bind(id, userId, url, secret, events, Date.now()).run();
}

export async function listWebhooks(env: Env, userId: string): Promise<WebhookRow[]> {
  const r = await env.DB.prepare(
    'SELECT * FROM webhooks WHERE user_id = ? ORDER BY created_at DESC',
  ).bind(userId).all<WebhookRow>();
  return r.results;
}

export async function deleteWebhook(env: Env, id: string, userId: string): Promise<boolean> {
  const r = await env.DB.prepare(
    'DELETE FROM webhooks WHERE id = ? AND user_id = ?',
  ).bind(id, userId).run();
  return (r.meta.changes ?? 0) > 0;
}

export async function getWebhooksByUserAndEvent(env: Env, userId: string, event: string): Promise<WebhookRow[]> {
  const r = await env.DB.prepare(
    "SELECT * FROM webhooks WHERE user_id = ? AND enabled = 1 AND (events LIKE ? OR events LIKE ? OR events = ?)",
  ).bind(userId, `${event},%`, `%,${event}`, event).all<WebhookRow>();
  return r.results;
}

// ── User stats ────────────────────────────────────────────────────────────

export async function getUserStats(env: Env, userId: string) {
  const monthStart = startOfMonthMs();
  const weekStart = startOfWeekMs();

  const [total, thisMonth, thisWeek, findings, sites, lastScan, avgDuration] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) as cnt FROM scans WHERE user_id = ?').bind(userId).first<{ cnt: number }>(),
    env.DB.prepare('SELECT COUNT(*) as cnt FROM scans WHERE user_id = ? AND created_at >= ?').bind(userId, monthStart).first<{ cnt: number }>(),
    env.DB.prepare('SELECT COUNT(*) as cnt FROM scans WHERE user_id = ? AND created_at >= ?').bind(userId, weekStart).first<{ cnt: number }>(),
    env.DB.prepare('SELECT SUM(findings_count) as total, SUM(critical_count) as critical, SUM(high_count) as high FROM scans WHERE user_id = ?').bind(userId).first<{ total: number; critical: number; high: number }>(),
    env.DB.prepare('SELECT COUNT(DISTINCT target) as cnt FROM scans WHERE user_id = ?').bind(userId).first<{ cnt: number }>(),
    env.DB.prepare('SELECT MAX(created_at) as ts FROM scans WHERE user_id = ?').bind(userId).first<{ ts: number | null }>(),
    env.DB.prepare("SELECT AVG((completed_at - started_at) / 1000.0) as avg FROM scans WHERE user_id = ? AND status = 'completed' AND started_at IS NOT NULL AND completed_at IS NOT NULL").bind(userId).first<{ avg: number | null }>(),
  ]);

  return {
    total_scans: total?.cnt ?? 0,
    scans_this_month: thisMonth?.cnt ?? 0,
    scans_this_week: thisWeek?.cnt ?? 0,
    total_findings: findings?.total ?? 0,
    critical_findings: findings?.critical ?? 0,
    high_findings: findings?.high ?? 0,
    sites_scanned: sites?.cnt ?? 0,
    last_scan_at: lastScan?.ts ? new Date(lastScan.ts).toISOString() : null,
    avg_scan_duration_seconds: avgDuration?.avg ? Math.round(avgDuration.avg) : null,
  };
}
