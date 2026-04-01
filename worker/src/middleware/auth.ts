// JWT auth middleware — attaches verified user to context
// Also supports API key auth via Bearer jwp_live_... tokens

import type { Context, Next } from 'hono';
import type { Env, JWTPayload } from '../types.js';
import { verifyJWT } from '../lib/jwt.js';
import { sha256Hex } from '../lib/crypto.js';
import { getApiKeyByHash, touchApiKey, getUserById } from '../lib/db.js';

export type AuthContext = { user: JWTPayload };

export async function authMiddleware(c: Context<{ Bindings: Env; Variables: AuthContext }>, next: Next) {
  const header = c.req.header('Authorization') ?? '';
  const cookie = getCookieValue(c.req.raw.headers.get('Cookie') ?? '', 'jwp_session');

  // ── API key path: Bearer jwp_live_... ─────────────────────────────────
  if (header.startsWith('Bearer jwp_live_')) {
    const rawKey = header.slice(7);
    const keyHash = await sha256Hex(rawKey);
    const apiKey = await getApiKeyByHash(c.env, keyHash);

    if (!apiKey) {
      return c.json({ error: 'unauthorized', message: 'Invalid API key' }, 401);
    }

    const userRow = await getUserById(c.env, apiKey.user_id);
    if (!userRow || userRow.is_active === 0) {
      return c.json({ error: 'unauthorized', message: 'Account not active' }, 401);
    }

    // Update last_used_at asynchronously
    touchApiKey(c.env, apiKey.id).catch(console.error);

    c.set('user', {
      sub: userRow.id,
      email: userRow.email,
      jti: `apikey:${apiKey.id}`,
      iat: 0,
      exp: 0,
    });
    return next();
  }

  // ── JWT / session-cookie path ──────────────────────────────────────────
  const token = header.startsWith('Bearer ') ? header.slice(7) : cookie;

  if (!token) {
    return c.json({ error: 'unauthorized', message: 'Authentication required' }, 401);
  }

  const payload = await verifyJWT(token, c.env.JWT_SECRET);
  if (!payload) {
    return c.json({ error: 'unauthorized', message: 'Invalid or expired token' }, 401);
  }

  // Check session is still valid in KV (supports logout / revocation)
  const sessionUserId = await c.env.SESSIONS_KV.get(`session:${payload.jti}`);
  if (!sessionUserId || sessionUserId !== payload.sub) {
    return c.json({ error: 'unauthorized', message: 'Session revoked' }, 401);
  }

  c.set('user', payload);
  return next();
}

function getCookieValue(cookieHeader: string, name: string): string {
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : '';
}
