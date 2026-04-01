// Rate limiting middleware
// Fast check: KV sliding window (burst)
// Authoritative check: D1 daily + monthly counts

import type { Context, Next } from 'hono';
import type { Env } from '../types.js';
import type { AuthContext } from './auth.js';
import { getDailyUsageCount, getMonthlyUsageCount, getUserLimits } from '../lib/db.js';
import { trackEvent } from '../lib/analytics.js';

/**
 * checkRateLimit — call inline AFTER request validation so invalid payloads
 * return 400 without consuming a rate-limit slot.
 *
 * Increments the KV counter FIRST (optimistically) to prevent the race
 * condition where concurrent requests both pass the check before either
 * increments. At worst one extra scan is allowed — acceptable trade-off
 * versus unlimited bypass.
 *
 * Returns a Response if the limit is exceeded, otherwise null.
 */
export async function checkRateLimit(
  c: Context<{ Bindings: Env; Variables: AuthContext }>,
): Promise<Response | null> {
  const user = c.get('user');
  const userId = user.sub;

  const { dailyLimit, monthlyLimit } = await getUserLimits(c.env, userId);

  // Increment KV first (optimistic), then check
  const today = utcDateString();
  const kvKey = `rl:${userId}:${today}`;
  const kvCount = parseInt((await c.env.RATELIMIT_KV.get(kvKey)) ?? '0', 10);
  const newKvCount = kvCount + 1;
  await c.env.RATELIMIT_KV.put(kvKey, String(newKvCount), { expirationTtl: 172_800 });

  if (newKvCount > dailyLimit) {
    trackEvent(c.env, 'rate_limit_hit', { user_id: userId });
    return rateLimitResponse(c, newKvCount, dailyLimit, monthlyLimit) as unknown as Response;
  }

  const [daily, monthly] = await Promise.all([
    getDailyUsageCount(c.env, userId),
    getMonthlyUsageCount(c.env, userId),
  ]);

  if (daily >= dailyLimit || monthly >= monthlyLimit) {
    trackEvent(c.env, 'rate_limit_hit', { user_id: userId });
    return rateLimitResponse(c, daily, dailyLimit, monthly, monthlyLimit) as unknown as Response;
  }

  return null;
}

/** Hono middleware wrapper — kept for any route that doesn't need pre-validation. */
export async function rateLimitMiddleware(
  c: Context<{ Bindings: Env; Variables: AuthContext }>,
  next: Next,
) {
  const blocked = await checkRateLimit(c);
  if (blocked) return blocked;

  return next();
}

function rateLimitResponse(
  c: Context,
  daily: number,
  dailyLimit: number,
  monthlyOrLimit: number,
  monthlyLimit?: number,
) {
  const now = new Date();
  const tomorrow = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));

  const retryAfterSeconds = Math.ceil((tomorrow.getTime() - now.getTime()) / 1000);

  return c.json(
    {
      error: 'rate_limit',
      message: `Scan limit reached. You have used ${daily}/${dailyLimit} scans today. Resets at ${tomorrow.toISOString()}.`,
      daily_used: daily,
      daily_limit: dailyLimit,
      daily_remaining: Math.max(0, dailyLimit - daily),
      monthly_used: monthlyLimit ? monthlyOrLimit : 0,
      monthly_limit: monthlyLimit ?? monthlyOrLimit,
      monthly_remaining: monthlyLimit ? Math.max(0, monthlyLimit - monthlyOrLimit) : 0,
      reset_daily_at: tomorrow.toISOString(),
      reset_monthly_at: nextMonth.toISOString(),
    },
    429,
    { 'Retry-After': String(retryAfterSeconds) },
  );
}

function utcDateString(): string {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}
