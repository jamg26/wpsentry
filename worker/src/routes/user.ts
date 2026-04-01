// User routes: GET /user/me, GET /user/usage, GET /user/stats, PUT /user/notifications, POST /user/change-password, DELETE /user/me

import { Hono } from 'hono';
import type { Env, UsageStats } from '../types.js';
import type { AuthContext } from '../middleware/auth.js';
import { getUserById, getDailyUsageCount, getMonthlyUsageCount, getUserLimits, getUserStats } from '../lib/db.js';
import { verifyPassword, hashPassword } from '../lib/crypto.js';
import { sendEmail } from '../lib/email.js';
import { verifyEmailTemplate } from '../lib/emailTemplates.js';
import apiKeysRoutes from './apikeys.js';
import webhooksRoutes from './webhooks.js';

const user = new Hono<{ Bindings: Env; Variables: AuthContext }>();

// Mount sub-routers
user.route('/api-keys', apiKeysRoutes);
user.route('/webhooks', webhooksRoutes);

// ── POST /user/resend-verification ───────────────────────────────────────
user.post('/resend-verification', async (c) => {
  const { sub: userId, email } = c.get('user');

  const userRow = await c.env.DB.prepare('SELECT is_verified, verify_token_expires FROM users WHERE id = ?')
    .bind(userId).first<{ is_verified: number; verify_token_expires: number | null }>();

  if (userRow?.is_verified) {
    return c.json({ message: 'Email already verified' });
  }

  const verifyToken = crypto.randomUUID();
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  await c.env.DB.prepare('UPDATE users SET verify_token = ?, verify_token_expires = ? WHERE id = ?')
    .bind(verifyToken, expires, userId).run();

  const { subject, html, text } = verifyEmailTemplate({ email, verifyToken });
  c.executionCtx.waitUntil(sendEmail(c.env, { to: email, subject, html, text }));

  return c.json({ message: 'Verification email sent' });
});

// ── GET /user/me ──────────────────────────────────────────────────────────
user.get('/me', async (c) => {
  const { sub: userId } = c.get('user');
  const row = await getUserById(c.env, userId);
  if (!row) return c.json({ error: 'not_found', message: 'User not found' }, 404);

  return c.json({
    id: row.id,
    email: row.email,
    full_name: row.full_name ?? null,
    created_at: new Date(row.created_at).toISOString(),
    last_login: row.last_login ? new Date(row.last_login).toISOString() : null,
    is_verified: row.is_verified === 1,
  });
});

// ── PUT /user/profile — update display name ───────────────────────────────
user.put('/profile', async (c) => {
  const { sub: userId } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as { full_name?: string };
  const fullName = (body.full_name ?? '').trim() || null;
  await c.env.DB.prepare('UPDATE users SET full_name = ? WHERE id = ?').bind(fullName, userId).run();
  return c.json({ message: 'Profile updated', full_name: fullName });
});

// ── GET /user/usage ───────────────────────────────────────────────────────
user.get('/usage', async (c) => {
  const { sub: userId } = c.get('user');

  const [{ dailyLimit, monthlyLimit }, daily, monthly] = await Promise.all([
    getUserLimits(c.env, userId),
    getDailyUsageCount(c.env, userId),
    getMonthlyUsageCount(c.env, userId),
  ]);

  const now = new Date();
  const tomorrow = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));

  const stats: UsageStats = {
    daily_used: daily,
    daily_limit: dailyLimit,
    daily_remaining: Math.max(0, dailyLimit - daily),
    monthly_used: monthly,
    monthly_limit: monthlyLimit,
    monthly_remaining: Math.max(0, monthlyLimit - monthly),
    reset_daily_at: tomorrow.toISOString(),
    reset_monthly_at: nextMonth.toISOString(),
  };

  return c.json(stats);
});

// ── GET /user/stats — rich usage statistics ───────────────────────────────
user.get('/stats', async (c) => {
  const { sub: userId } = c.get('user');
  const stats = await getUserStats(c.env, userId);
  return c.json(stats);
});

// ── PUT /user/notifications — update notification preferences ─────────────
user.put('/notifications', async (c) => {
  const { sub: userId } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as {
    scan_complete?: boolean;
    critical_found?: boolean;
    weekly_report?: boolean;
  };

  const defaults = { scan_complete: true, critical_found: true, weekly_report: false };
  const prefs = {
    scan_complete: body.scan_complete ?? defaults.scan_complete,
    critical_found: body.critical_found ?? defaults.critical_found,
    weekly_report: body.weekly_report ?? defaults.weekly_report,
  };

  await c.env.DB.prepare('UPDATE users SET notification_prefs = ? WHERE id = ?')
    .bind(JSON.stringify(prefs), userId).run();

  return c.json({
    message: 'Notification preferences saved.',
    notification_prefs: prefs,
  });
});

// ── GET /user/notifications — fetch notification preferences ──────────────
user.get('/notifications', async (c) => {
  const { sub: userId } = c.get('user');
  const row = await getUserById(c.env, userId);
  if (!row) return c.json({ error: 'not_found', message: 'User not found' }, 404);

  const defaults = { scan_complete: true, critical_found: true, weekly_report: false };
  const prefs = row.notification_prefs ? JSON.parse(row.notification_prefs) : defaults;
  return c.json({ notification_prefs: prefs });
});

// ── POST /user/change-password ────────────────────────────────────────────
user.post('/change-password', async (c) => {
  // HIGH-03: Rate limit password change attempts to prevent brute force
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown';
  const rlKey = `pw_change_ip:${ip}`;
  const rlCount = parseInt(await c.env.RATELIMIT_KV.get(rlKey) ?? '0');
  if (rlCount >= 5) {
    return c.json({ error: 'Too many password change attempts. Try again later.' }, 429);
  }
  await c.env.RATELIMIT_KV.put(rlKey, String(rlCount + 1), { expirationTtl: 900 }); // 15 min window

  const { sub: userId } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as {
    currentPassword?: string;
    newPassword?: string;
  };

  const currentPassword = body.currentPassword ?? '';
  const newPassword = body.newPassword ?? '';

  if (!currentPassword || !newPassword) {
    return c.json({ error: 'validation', message: 'Current and new password are required' }, 400);
  }
  if (newPassword.length < 8) {
    return c.json({ error: 'validation', message: 'New password must be at least 8 characters' }, 400);
  }

  const row = await getUserById(c.env, userId);
  if (!row) return c.json({ error: 'not_found', message: 'User not found' }, 404);

  const valid = await verifyPassword(currentPassword, row.password_hash);
  if (!valid) {
    return c.json({ error: 'auth', message: 'Current password is incorrect' }, 400);
  }

  const newHash = await hashPassword(newPassword);
  await c.env.DB.prepare(
    "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?",
  ).bind(newHash, userId).run();

  return c.json({ message: 'Password updated successfully' });
});

// ── DELETE /user/me ───────────────────────────────────────────────────────
user.delete('/me', async (c) => {
  const { sub: userId, jti } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as { password?: string };
  const password = body.password ?? '';

  if (!password) {
    return c.json({ error: 'validation', message: 'Password is required for account deletion' }, 400);
  }

  const row = await getUserById(c.env, userId);
  if (!row) return c.json({ error: 'not_found', message: 'User not found' }, 404);

  const valid = await verifyPassword(password, row.password_hash);
  if (!valid) {
    return c.json({ error: 'auth', message: 'Incorrect password' }, 400);
  }

  // Fetch scan report keys for R2 cleanup
  const scans = await c.env.DB.prepare(
    'SELECT report_key FROM scans WHERE user_id = ? AND report_key IS NOT NULL',
  ).bind(userId).all<{ report_key: string }>();

  // Delete R2 reports
  for (const scan of scans.results) {
    try {
      await c.env.REPORTS_R2.delete(scan.report_key);
    } catch (err) {
      // HIGH-06: Log R2 deletion failures explicitly — don't silently swallow them
      console.error(`[ACCOUNT_DELETE] Failed to delete R2 report ${scan.report_key}:`, err);
      // Continue deletion — don't block account deletion for R2 cleanup failures
    }
  }

  // Cascade delete D1 data
  try {
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM scans WHERE user_id = ?').bind(userId),
      c.env.DB.prepare('DELETE FROM usage WHERE user_id = ?').bind(userId),
      c.env.DB.prepare('DELETE FROM api_keys WHERE user_id = ?').bind(userId),
      c.env.DB.prepare('DELETE FROM scheduled_scans WHERE user_id = ?').bind(userId),
      c.env.DB.prepare('DELETE FROM webhooks WHERE user_id = ?').bind(userId),
      c.env.DB.prepare(
        "DELETE FROM system_config WHERE key LIKE ?",
      ).bind(`%:${userId}`),
      c.env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId),
    ]);
  } catch (err) {
    console.error(`[ACCOUNT_DELETE] D1 batch delete failed for user ${userId}:`, err);
    return c.json({ error: 'internal_error', message: 'Account deletion failed' }, 500);
  }

  // Clear session
  await c.env.SESSIONS_KV.delete(`session:${jti}`);

  return c.json(
    { message: 'Account deleted' },
    200,
    { 'Set-Cookie': 'jwp_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0' },
  );
});

export default user;
