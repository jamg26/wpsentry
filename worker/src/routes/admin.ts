// Admin routes — protected by admin password + session token

import { Hono } from 'hono';
import type { Env } from '../types.js';
import { timingSafeEqualStrings } from '../lib/crypto.js';
import {
  adminAuthMiddleware,
  createAdminSession,
  adminSessionCookie,
  clearAdminSessionCookie,
} from '../middleware/adminAuth.js';

const admin = new Hono<{ Bindings: Env }>();

// ── POST /admin/login ────────────────────────────────────────────────────
admin.post('/login', async (c) => {
  // IP-based rate limiting: 5 attempts per 5 minutes
  const ip = c.req.header('CF-Connecting-IP') ?? c.req.header('X-Forwarded-For') ?? 'unknown';
  const rateLimitKey = `admin_login_ip:${ip}`;
  const attempts = parseInt((await c.env.RATELIMIT_KV.get(rateLimitKey)) ?? '0', 10);
  const newCount = attempts + 1;
  await c.env.RATELIMIT_KV.put(rateLimitKey, String(newCount), { expirationTtl: 300 });

  if (newCount > 5) {
    return c.json(
      { error: 'rate_limit', message: 'Too many login attempts', retryAfter: 300 },
      429,
      { 'Retry-After': '300' },
    );
  }

  const body = await c.req.json().catch(() => ({})) as { password?: string };
  const password = body.password ?? '';
  const expected = c.env.ADMIN_PASSWORD;

  if (!expected) {
    return c.json({ error: 'config', message: 'Admin password not configured' }, 500);
  }

  // Constant-time comparison to prevent timing attacks
  const match = await timingSafeEqualStrings(password, expected);
  if (!match) {
    return c.json({ error: 'unauthorized', message: 'Invalid password' }, 401);
  }

  const token = await createAdminSession(c.env);
  return c.json(
    { message: 'Authenticated' },
    200,
    { 'Set-Cookie': adminSessionCookie(token) },
  );
});

// All routes below require admin auth
admin.use('/*', adminAuthMiddleware);

// ── POST /admin/logout ───────────────────────────────────────────────────
admin.post('/logout', async (c) => {
  // Extract token from cookie to invalidate the KV session
  const cookies = c.req.raw.headers.get('Cookie') ?? '';
  const match = cookies.match(/(?:^|;\s*)jwp_admin_session=([^;]*)/);
  const token = match ? decodeURIComponent(match[1]) : '';
  if (token) {
    await c.env.SESSIONS_KV.delete(`admin_session:${token}`);
  }

  return c.json(
    { message: 'Logged out' },
    200,
    { 'Set-Cookie': clearAdminSessionCookie() },
  );
});

// ── GET /admin/stats ─────────────────────────────────────────────────────
admin.get('/stats', async (c) => {
  const [users, scans, findings, activeScans, recentScans] = await Promise.all([
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM users').first<{ cnt: number }>(),
    c.env.DB.prepare('SELECT COUNT(*) as cnt FROM scans').first<{ cnt: number }>(),
    c.env.DB.prepare('SELECT SUM(findings_count) as cnt FROM scans').first<{ cnt: number }>(),
    c.env.DB.prepare("SELECT COUNT(*) as cnt FROM scans WHERE status IN ('queued', 'running')").first<{ cnt: number }>(),
    c.env.DB.prepare(
      'SELECT created_at FROM scans ORDER BY created_at DESC LIMIT 30',
    ).all<{ created_at: number }>(),
  ]);

  return c.json({
    total_users: users?.cnt ?? 0,
    total_scans: scans?.cnt ?? 0,
    total_findings: findings?.cnt ?? 0,
    active_scans: activeScans?.cnt ?? 0,
    recent_scan_dates: recentScans.results.map((r) => r.created_at),
  });
});

// ── GET /admin/users ─────────────────────────────────────────────────────
admin.get('/users', async (c) => {
  const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 100);
  const offset = parseInt(c.req.query('offset') ?? '0', 10);
  const search = c.req.query('search') ?? '';

  let query = `
    SELECT u.id, u.email, u.created_at, u.last_login, u.is_verified, u.is_active,
           COUNT(DISTINCT s.id) as scan_count
    FROM users u
    LEFT JOIN scans s ON s.user_id = u.id
  `;
  const binds: unknown[] = [];

  if (search) {
    // HIGH-05: Escape LIKE metacharacters to prevent wildcard injection
    const escapedSearch = search.replace(/[%_\\]/g, '\\$&');
    query += " WHERE u.email LIKE ? ESCAPE '\\'";
    binds.push(`%${escapedSearch}%`);
  }

  query += ' GROUP BY u.id ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
  binds.push(limit, offset);

  const results = await c.env.DB.prepare(query).bind(...binds).all();

  // Get total count
  let countQuery = 'SELECT COUNT(*) as cnt FROM users';
  const countBinds: unknown[] = [];
  if (search) {
    const escapedSearch = search.replace(/[%_\\]/g, '\\$&');
    countQuery += " WHERE email LIKE ? ESCAPE '\\'";
    countBinds.push(`%${escapedSearch}%`);
  }
  const total = await c.env.DB.prepare(countQuery).bind(...countBinds).first<{ cnt: number }>();

  // Get custom limits from system_config per user
  const userIds = results.results.map((u: Record<string, unknown>) => u.id as string);
  const customLimits: Record<string, Record<string, string>> = {};
  for (const uid of userIds) {
    const dailyLimit = await c.env.DB.prepare(
      "SELECT value FROM system_config WHERE key = ?",
    ).bind(`user_daily_limit:${uid}`).first<{ value: string }>();
    const monthlyLimit = await c.env.DB.prepare(
      "SELECT value FROM system_config WHERE key = ?",
    ).bind(`user_monthly_limit:${uid}`).first<{ value: string }>();
    if (dailyLimit || monthlyLimit) {
      customLimits[uid] = {};
      if (dailyLimit) customLimits[uid].daily_limit = dailyLimit.value;
      if (monthlyLimit) customLimits[uid].monthly_limit = monthlyLimit.value;
    }
  }

  return c.json({
    users: results.results.map((u: Record<string, unknown>) => ({
      ...u,
      daily_limit: customLimits[u.id as string]?.daily_limit ?? c.env.DAILY_SCAN_LIMIT,
      monthly_limit: customLimits[u.id as string]?.monthly_limit ?? c.env.MONTHLY_SCAN_LIMIT,
    })),
    total: total?.cnt ?? 0,
    pagination: { limit, offset },
  });
});

// ── PUT /admin/users/:id ─────────────────────────────────────────────────
admin.put('/users/:id', async (c) => {
  const userId = c.req.param('id');
  const body = await c.req.json().catch(() => ({})) as {
    is_active?: number;
    daily_limit?: string;
    monthly_limit?: string;
  };

  // Check user exists
  const user = await c.env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
  if (!user) {
    return c.json({ error: 'not_found', message: 'User not found' }, 404);
  }

  // Update ban/unban status
  if (body.is_active !== undefined) {
    await c.env.DB.prepare('UPDATE users SET is_active = ? WHERE id = ?')
      .bind(body.is_active, userId)
      .run();
  }

  // Update custom limits in system_config
  if (body.daily_limit !== undefined) {
    await c.env.DB.prepare(
      `INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, unixepoch())
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = unixepoch()`,
    ).bind(`user_daily_limit:${userId}`, body.daily_limit).run();
  }

  if (body.monthly_limit !== undefined) {
    await c.env.DB.prepare(
      `INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, unixepoch())
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = unixepoch()`,
    ).bind(`user_monthly_limit:${userId}`, body.monthly_limit).run();
  }

  return c.json({ message: 'User updated' });
});

// ── DELETE /admin/users/:id ──────────────────────────────────────────────
admin.delete('/users/:id', async (c) => {
  const userId = c.req.param('id');

  const user = await c.env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
  if (!user) {
    return c.json({ error: 'not_found', message: 'User not found' }, 404);
  }

  // Delete user's R2 reports
  const scans = await c.env.DB.prepare(
    'SELECT report_key FROM scans WHERE user_id = ? AND report_key IS NOT NULL',
  ).bind(userId).all<{ report_key: string }>();
  for (const scan of scans.results) {
    await c.env.REPORTS_R2.delete(scan.report_key);
  }

  // Delete related data
  await c.env.DB.prepare('DELETE FROM usage WHERE user_id = ?').bind(userId).run();
  await c.env.DB.prepare('DELETE FROM scans WHERE user_id = ?').bind(userId).run();
  await c.env.DB.prepare('DELETE FROM api_keys WHERE user_id = ?').bind(userId).run();
  await c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

  // Clean up custom limits
  await c.env.DB.prepare("DELETE FROM system_config WHERE key LIKE ?").bind(`%:${userId}`).run();

  // Mark user as deleted in KV so auth middleware can reject stale sessions.
  // KV sessions (session:{jti}) can't be listed by user ID, so they will
  // expire naturally within 24h.  The flag below is a best-effort signal.
  await c.env.SESSIONS_KV.put(`user_deleted:${userId}`, '1', { expirationTtl: 86_400 });
  console.warn(
    `[Admin] User ${userId} deleted. Active JWT sessions may remain valid for up to 24h until KV TTL expires.`,
  );

  return c.json({ message: 'User deleted' });
});

// ── GET /admin/scans ─────────────────────────────────────────────────────
admin.get('/scans', async (c) => {
  const limit = Math.min(parseInt(c.req.query('limit') ?? '50', 10), 100);
  const offset = parseInt(c.req.query('offset') ?? '0', 10);
  const status = c.req.query('status') ?? '';
  const userSearch = c.req.query('user') ?? '';
  const targetSearch = c.req.query('target') ?? '';

  let query = `
    SELECT s.*, u.email as user_email
    FROM scans s
    LEFT JOIN users u ON u.id = s.user_id
    WHERE 1=1
  `;
  const binds: unknown[] = [];

  if (status) {
    query += ' AND s.status = ?';
    binds.push(status);
  }
  if (userSearch) {
    // HIGH-05: Escape LIKE metacharacters
    const escapedUser = userSearch.replace(/[%_\\]/g, '\\$&');
    query += " AND u.email LIKE ? ESCAPE '\\'";
    binds.push(`%${escapedUser}%`);
  }
  if (targetSearch) {
    const escapedTarget = targetSearch.replace(/[%_\\]/g, '\\$&');
    query += " AND s.target LIKE ? ESCAPE '\\'";
    binds.push(`%${escapedTarget}%`);
  }

  // Count query
  let countQuery = query.replace(/SELECT s\.\*, u\.email as user_email/, 'SELECT COUNT(*) as cnt');
  const total = await c.env.DB.prepare(countQuery).bind(...binds).first<{ cnt: number }>();

  query += ' ORDER BY s.created_at DESC LIMIT ? OFFSET ?';
  binds.push(limit, offset);

  const results = await c.env.DB.prepare(query).bind(...binds).all();

  return c.json({
    scans: results.results,
    total: total?.cnt ?? 0,
    pagination: { limit, offset },
  });
});

// ── DELETE /admin/scans/:id ──────────────────────────────────────────────
admin.delete('/scans/:id', async (c) => {
  const scanId = c.req.param('id');

  const scan = await c.env.DB.prepare('SELECT * FROM scans WHERE id = ?')
    .bind(scanId)
    .first<{ id: string; report_key: string | null }>();

  if (!scan) {
    return c.json({ error: 'not_found', message: 'Scan not found' }, 404);
  }

  if (scan.report_key) {
    await c.env.REPORTS_R2.delete(scan.report_key);
  }

  await c.env.DB.prepare('DELETE FROM usage WHERE scan_id = ?').bind(scanId).run();
  await c.env.DB.prepare('DELETE FROM scans WHERE id = ?').bind(scanId).run();

  return c.json({ message: 'Scan deleted' });
});

// ── GET /admin/config ────────────────────────────────────────────────────
admin.get('/config', async (c) => {
  const rows = await c.env.DB.prepare(
    "SELECT key, value FROM system_config WHERE key NOT LIKE '%:%'",
  ).all<{ key: string; value: string }>();

  const config: Record<string, string> = {};
  for (const row of rows.results) {
    config[row.key] = row.value;
  }

  return c.json({
    DAILY_SCAN_LIMIT: config['DAILY_SCAN_LIMIT'] ?? c.env.DAILY_SCAN_LIMIT,
    MONTHLY_SCAN_LIMIT: config['MONTHLY_SCAN_LIMIT'] ?? c.env.MONTHLY_SCAN_LIMIT,
    AUTH_SIGNUP_MAX_ATTEMPTS: config['AUTH_SIGNUP_MAX_ATTEMPTS'] ?? '5',
    AUTH_SIGNUP_WINDOW_SECONDS: config['AUTH_SIGNUP_WINDOW_SECONDS'] ?? '3600',
    AUTH_LOGIN_MAX_ATTEMPTS: config['AUTH_LOGIN_MAX_ATTEMPTS'] ?? '10',
    AUTH_LOGIN_WINDOW_SECONDS: config['AUTH_LOGIN_WINDOW_SECONDS'] ?? '900',
  });
});

// ── PUT /admin/config ────────────────────────────────────────────────────
admin.put('/config', async (c) => {
  const body = await c.req.json().catch(() => ({})) as Record<string, string>;
  const allowedKeys = ['DAILY_SCAN_LIMIT', 'MONTHLY_SCAN_LIMIT', 'AUTH_SIGNUP_MAX_ATTEMPTS', 'AUTH_SIGNUP_WINDOW_SECONDS', 'AUTH_LOGIN_MAX_ATTEMPTS', 'AUTH_LOGIN_WINDOW_SECONDS'];

  for (const [key, value] of Object.entries(body)) {
    if (!allowedKeys.includes(key)) continue;
    await c.env.DB.prepare(
      `INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, unixepoch())
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = unixepoch()`,
    ).bind(key, String(value)).run();
  }

  return c.json({ message: 'Config updated' });
});

// ── GET /admin/db/query — read-only SQL ──────────────────────────────────
admin.get('/db/query', async (c) => {
  const sql = c.req.query('sql') ?? '';
  if (!sql.trim()) {
    return c.json({ error: 'validation', message: 'SQL query required' }, 400);
  }

  // CRIT-07: Normalize SQL (strip comments, collapse whitespace) before prefix check
  // to prevent Unicode/comment-based bypass of the query type restriction.
  const normalizedForPrefix = sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
  const firstWord = normalizedForPrefix.split(' ')[0];
  if (!['SELECT', 'PRAGMA', 'EXPLAIN'].includes(firstWord)) {
    return c.json({ error: 'forbidden', message: 'Only SELECT, PRAGMA, and EXPLAIN queries allowed via GET' }, 403);
  }

  try {
    const result = await c.env.DB.prepare(sql).all();
    return c.json({
      columns: result.results.length > 0 ? Object.keys(result.results[0] as Record<string, unknown>) : [],
      rows: result.results,
      meta: { rows_read: result.meta.rows_read, duration: result.meta.duration },
    });
  } catch (err) {
    return c.json({ error: 'query_error', message: (err as Error).message }, 400);
  }
});

// ── POST /admin/db/query — execute SQL with safety guards ─────────────────
admin.post('/db/query', async (c) => {
  const body = await c.req.json().catch(() => ({})) as { sql?: string; confirm?: boolean };
  const sql = body.sql ?? '';
  if (!sql.trim()) {
    return c.json({ error: 'validation', message: 'SQL query required' }, 400);
  }

  // CRIT-07: Normalize SQL (strip comments, collapse whitespace) before prefix check
  const normalizedForPrefix = sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n]*/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
  const firstWordPost = normalizedForPrefix.split(' ')[0];

  // Only allow safe SQL statement types
  const ALLOWED_FIRST_WORDS = ['SELECT', 'PRAGMA', 'EXPLAIN', 'INSERT', 'UPDATE', 'DELETE'];
  if (!ALLOWED_FIRST_WORDS.includes(firstWordPost)) {
    return c.json({ error: 'forbidden', message: 'Only SELECT, PRAGMA, EXPLAIN, INSERT, UPDATE, and DELETE statements are allowed' }, 403);
  }

  // CRIT-01: Strip SQL comments before checking for dangerous DDL patterns
  // (prevents comment-based bypass: DROP/**/TABLE is stripped to DROP TABLE)
  const commentStripped = sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ');
  const DANGEROUS_PATTERN = /\b(DROP|ALTER|TRUNCATE|CREATE|RENAME)\b.*\b(TABLE|DATABASE|SCHEMA|INDEX)\b/is;
  if (DANGEROUS_PATTERN.test(commentStripped)) {
    return c.json({ error: 'forbidden', message: 'Destructive DDL statements are not allowed' }, 403);
  }

  // Non-SELECT queries require explicit confirmation
  const isReadOnly = /^(SELECT|PRAGMA|EXPLAIN)$/.test(firstWordPost);
  if (!isReadOnly && !body.confirm) {
    return c.json({ error: 'confirmation_required', message: 'Non-SELECT queries require { confirm: true }' }, 400);
  }

  // Extract admin session info for audit log
  const cookies = c.req.raw.headers.get('Cookie') ?? '';
  const tokenMatch = cookies.match(/(?:^|;\s*)jwp_admin_session=([^;]*)/);
  const sessionSnippet = tokenMatch ? decodeURIComponent(tokenMatch[1]).slice(0, 8) + '…' : 'unknown';
  console.log(`[Admin DB] ${new Date().toISOString()} session=${sessionSnippet} type=${isReadOnly ? 'READ' : 'WRITE'} sql=${sql.slice(0, 200)}`);

  try {
    if (isReadOnly) {
      const result = await c.env.DB.prepare(sql).all();
      return c.json({
        columns: result.results.length > 0 ? Object.keys(result.results[0] as Record<string, unknown>) : [],
        rows: result.results,
        meta: { rows_read: result.meta.rows_read, duration: result.meta.duration },
      });
    } else {
      const result = await c.env.DB.prepare(sql).run();
      return c.json({
        columns: [],
        rows: [],
        meta: { changes: result.meta.changes, duration: result.meta.duration },
      });
    }
  } catch (err) {
    return c.json({ error: 'query_error', message: (err as Error).message }, 400);
  }
});

// ── GET /admin/rate-limits — list currently blocked IPs ──────────────────
admin.get('/rate-limits', async (c) => {
  const prefixes = ['auth_signup_ip:', 'auth_login_ip:', 'admin_login_ip:'];
  const entries: { key: string; type: string; ip: string; count: string }[] = [];

  for (const prefix of prefixes) {
    const list = await c.env.RATELIMIT_KV.list({ prefix });
    for (const item of list.keys) {
      const value = await c.env.RATELIMIT_KV.get(item.name);
      const type = prefix.replace(/_ip:$/, '').replace('auth_', '');
      const ip = item.name.replace(prefix, '');
      entries.push({ key: item.name, type, ip, count: value ?? '0' });
    }
  }

  const configRows = await c.env.DB.prepare(
    "SELECT key, value FROM system_config WHERE key LIKE 'AUTH_%'"
  ).all<{ key: string; value: string }>();
  const config: Record<string, string> = {};
  for (const r of configRows.results) config[r.key] = r.value;

  return c.json({ entries, config });
});

// ── DELETE /admin/rate-limits — clear all or specific IP ─────────────────
admin.delete('/rate-limits', async (c) => {
  const body = await c.req.json().catch(() => ({})) as { key?: string };
  if (body.key) {
    await c.env.RATELIMIT_KV.delete(body.key);
    return c.json({ message: `Cleared: ${body.key}` });
  }
  // Clear all auth rate limit keys
  const prefixes = ['auth_signup_ip:', 'auth_login_ip:', 'admin_login_ip:'];
  let cleared = 0;
  for (const prefix of prefixes) {
    const list = await c.env.RATELIMIT_KV.list({ prefix });
    await Promise.all(list.keys.map((k) => c.env.RATELIMIT_KV.delete(k.name)));
    cleared += list.keys.length;
  }
  return c.json({ message: `Cleared ${cleared} rate limit entries` });
});

// ── GET /admin/fp-reports — list false positive reports ──────────────────
admin.get('/fp-reports', async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT r.id, r.scan_id, r.finding_type, r.finding_url, r.finding_severity, r.reason,
            r.status, r.created_at, u.email as user_email
     FROM false_positive_reports r
     LEFT JOIN users u ON r.user_id = u.id
     ORDER BY r.created_at DESC
     LIMIT 200`
  ).all<{
    id: string; scan_id: string; finding_type: string; finding_url: string;
    finding_severity: string; reason: string | null; status: string;
    created_at: number; user_email: string;
  }>();
  return c.json({ reports: results });
});

// ── PATCH /admin/fp-reports/:id — update status (pending/confirmed/rejected) ─
admin.patch('/fp-reports/:id', async (c) => {
  const id = c.req.param('id');
  const { status } = await c.req.json().catch(() => ({})) as { status?: string };
  if (!status || !['pending', 'confirmed', 'rejected'].includes(status)) {
    return c.json({ error: 'status must be pending, confirmed or rejected' }, 400);
  }
  await c.env.DB.prepare('UPDATE false_positive_reports SET status = ? WHERE id = ?')
    .bind(status, id).run();
  return c.json({ success: true });
});

export default admin;
