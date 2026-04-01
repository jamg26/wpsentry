// Security headers middleware

import type { Context, Next } from 'hono';
import type { Env } from '../types.js';

export async function securityHeaders(c: Context<{ Bindings: Env }>, next: Next) {
  await next();
  const res = c.res;
  res.headers.set('X-Content-Type-Options', 'nosniff');
  res.headers.set('X-Frame-Options', 'DENY');
  res.headers.set('X-XSS-Protection', '0'); // Prefer CSP
  res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.headers.set('Content-Security-Policy', "default-src 'none'");
  if (c.env.ENVIRONMENT === 'production') {
    res.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
}

/**
 * CSRF protection via Origin verification (OWASP recommended).
 * Skips GET/HEAD/OPTIONS and bearer-token auth (not vulnerable to CSRF).
 * Required because cookies use SameSite=None for cross-origin auth.
 */
export async function csrfProtection(c: Context<{ Bindings: Env }>, next: Next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
    return next();
  }

  // Bearer token auth is not vulnerable to CSRF
  const authHeader = c.req.header('Authorization') ?? '';
  if (authHeader.startsWith('Bearer ')) {
    return next();
  }

  const expectedOrigin = c.env.CORS_ORIGIN;
  if (!expectedOrigin || expectedOrigin === '*') return next();

  const allowedOrigins = expectedOrigin.split(',').map(o => o.trim());
  const origin = c.req.header('Origin') ?? '';
  if (origin && allowedOrigins.includes(origin)) return next();

  // Fallback to Referer header
  const referer = c.req.header('Referer') ?? '';
  if (referer) {
    try {
      if (allowedOrigins.includes(new URL(referer).origin)) return next();
    } catch { /* invalid referer */ }
  }

  return c.json({ error: 'forbidden', message: 'CSRF validation failed' }, 403);
}

export function corsHeaders(origin: string) {
  return async (c: Context<{ Bindings: Env }>, next: Next) => {
    const reqOrigin = c.req.header('Origin') ?? '';
    // Support comma-separated list of allowed origins
    const allowed = origin === '*' || origin.split(',').map(o => o.trim()).includes(reqOrigin);

    if (c.req.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': allowed ? reqOrigin : '',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Allow-Credentials': 'true',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    await next();

    if (allowed) {
      c.res.headers.set('Access-Control-Allow-Origin', reqOrigin);
      c.res.headers.set('Access-Control-Allow-Credentials', 'true');
      c.res.headers.set('Vary', 'Origin');
    }
    return;
  };
}
