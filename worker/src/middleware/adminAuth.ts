// Admin authentication middleware — verifies admin session token from cookie

import type { Context, Next } from 'hono';
import type { Env } from '../types.js';

const COOKIE_NAME = 'jwp_admin_session';
const SESSION_PREFIX = 'admin_session:';
const SESSION_TTL = 60 * 60 * 24; // 24 hours

export async function adminAuthMiddleware(
  c: Context<{ Bindings: Env }>,
  next: Next,
) {
  const token = getCookieValue(c.req.raw.headers.get('Cookie') ?? '', COOKIE_NAME);

  if (!token) {
    return c.json({ error: 'unauthorized', message: 'Admin authentication required' }, 401);
  }

  const valid = await c.env.SESSIONS_KV.get(`${SESSION_PREFIX}${token}`);
  if (valid !== 'admin') {
    return c.json({ error: 'unauthorized', message: 'Invalid or expired admin session' }, 401);
  }

  return next();
}

export async function createAdminSession(env: Env): Promise<string> {
  const token = generateToken(48);
  await env.SESSIONS_KV.put(`${SESSION_PREFIX}${token}`, 'admin', {
    expirationTtl: SESSION_TTL,
  });
  return token;
}

export function adminSessionCookie(token: string): string {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${SESSION_TTL}`;
}

export function clearAdminSessionCookie(): string {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`;
}

function getCookieValue(cookieHeader: string, name: string): string {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}

function generateToken(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map((b) => chars[b % chars.length]).join('');
}
