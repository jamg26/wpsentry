// Auth routes: POST /auth/signup, POST /auth/login, POST /auth/logout

import { Hono } from 'hono';
import type { Env } from '../types.js';
import { hashPassword, verifyPassword, generateId } from '../lib/crypto.js';
import { signJWT } from '../lib/jwt.js';
import { createUser, getUserByEmail, updateLastLogin, verifyUserEmail } from '../lib/db.js';
import { trackEvent } from '../lib/analytics.js';
import type { AuthContext } from '../middleware/auth.js';
import { authMiddleware } from '../middleware/auth.js';
import { sendEmail } from '../lib/email.js';
import { welcomeEmail, verifyEmailTemplate } from '../lib/emailTemplates.js';

const auth = new Hono<{ Bindings: Env; Variables: AuthContext }>();

const JWT_TTL_SECONDS = 60 * 60 * 24; // 24 hours

// HIGH-01: Lazy dummy hash — computed once on first login request, cached for reuse.
// Using top-level await for 100K PBKDF2 iterations exceeds Workers' startup CPU budget.
let _dummyHash: string | null = null;
async function getDummyHash(): Promise<string> {
  if (!_dummyHash) {
    _dummyHash = await hashPassword('dummy-constant-time-placeholder-1234567890');
  }
  return _dummyHash;
}

// ── IP-based rate limit helper ────────────────────────────────────────────
async function ipRateLimit(
  env: Env,
  key: string,
  maxAttempts: number,
  windowSeconds: number,
): Promise<{ blocked: boolean; retryAfter: number }> {
  const current = parseInt((await env.RATELIMIT_KV.get(key)) ?? '0', 10);
  const newCount = current + 1;
  await env.RATELIMIT_KV.put(key, String(newCount), { expirationTtl: windowSeconds });
  if (newCount > maxAttempts) {
    return { blocked: true, retryAfter: windowSeconds };
  }
  return { blocked: false, retryAfter: 0 };
}

// ── POST /auth/signup ─────────────────────────────────────────────────────
auth.post('/signup', async (c) => {
  // HIGH-02: Only trust CF-Connecting-IP. X-Forwarded-For is user-controlled
  // and can be spoofed to bypass rate limiting.
  const ip = c.req.header('CF-Connecting-IP') ?? (c.env.ENVIRONMENT !== 'production' ? 'dev-local' : null);
  if (!ip) return c.json({ error: 'Cannot verify client IP' }, 400);
  const signupMax = parseInt((await c.env.DB.prepare("SELECT value FROM system_config WHERE key='AUTH_SIGNUP_MAX_ATTEMPTS'").first<{ value: string }>())?.value ?? '5', 10);
  const signupWindow = parseInt((await c.env.DB.prepare("SELECT value FROM system_config WHERE key='AUTH_SIGNUP_WINDOW_SECONDS'").first<{ value: string }>())?.value ?? '3600', 10);
  const rl = await ipRateLimit(c.env, `auth_signup_ip:${ip}`, signupMax, signupWindow);
  if (rl.blocked) {
    return c.json(
      { error: 'Too many attempts', retryAfter: rl.retryAfter },
      429,
      { 'Retry-After': String(rl.retryAfter) },
    );
  }

  const body = await c.req.json().catch(() => ({})) as { email?: string; password?: string; agreed_to_terms?: boolean; full_name?: string };
  const email = (body.email ?? '').toLowerCase().trim();
  const password = body.password ?? '';
  const fullName = (body.full_name ?? '').trim() || null;

  if (!body.agreed_to_terms) {
    return c.json({ error: 'You must agree to the Terms of Service to create an account.' }, 400);
  }

  if (!isValidEmail(email)) {
    return c.json({ error: 'validation', message: 'Invalid email address' }, 400);
  }
  if (password.length < 8) {
    return c.json({ error: 'validation', message: 'Password must be at least 8 characters' }, 400);
  }

  const existing = await getUserByEmail(c.env, email);
  if (existing) {
    return c.json({ error: 'conflict', message: 'Email already registered' }, 409);
  }

  const userId = generateId();
  const passwordHash = await hashPassword(password);
  const verifyToken = crypto.randomUUID();
  await createUser(c.env, userId, email, passwordHash, Date.now(), '2026-04-01', verifyToken, fullName ?? undefined);

  const token = await issueSession(c.env, userId, email);
  trackEvent(c.env, 'auth_signup', { user_id: userId });

  // waitUntil keeps the worker alive after the response is sent (CF Workers requirement)
  const { subject, html, text } = verifyEmailTemplate({ email, verifyToken });
  c.executionCtx.waitUntil(sendEmail(c.env, { to: email, subject, html, text }));

  return c.json(
    { message: 'Account created', user: { id: userId, email } },
    201,
    { 'Set-Cookie': sessionCookie(token) },
  );
});

// ── POST /auth/login ──────────────────────────────────────────────────────
auth.post('/login', async (c) => {
  // HIGH-02: Only trust CF-Connecting-IP (same as signup)
  const ip = c.req.header('CF-Connecting-IP') ?? (c.env.ENVIRONMENT !== 'production' ? 'dev-local' : null);
  if (!ip) return c.json({ error: 'Cannot verify client IP' }, 400);
  const loginMax = parseInt((await c.env.DB.prepare("SELECT value FROM system_config WHERE key='AUTH_LOGIN_MAX_ATTEMPTS'").first<{ value: string }>())?.value ?? '10', 10);
  const loginWindow = parseInt((await c.env.DB.prepare("SELECT value FROM system_config WHERE key='AUTH_LOGIN_WINDOW_SECONDS'").first<{ value: string }>())?.value ?? '900', 10);
  const rl = await ipRateLimit(c.env, `auth_login_ip:${ip}`, loginMax, loginWindow);
  if (rl.blocked) {
    return c.json(
      { error: 'Too many attempts', retryAfter: rl.retryAfter },
      429,
      { 'Retry-After': String(rl.retryAfter) },
    );
  }

  const body = await c.req.json().catch(() => ({})) as { email?: string; password?: string };
  const email = (body.email ?? '').toLowerCase().trim();
  const password = body.password ?? '';

  const user = await getUserByEmail(c.env, email);
  // HIGH-01: Always run verifyPassword regardless of whether user exists.
  // Using a dummy hash when the user is not found equalizes timing and prevents
  // user enumeration via response time differences.
  const hashToCompare = (user && user.is_active) ? user.password_hash : await getDummyHash();
  const valid = await verifyPassword(password, hashToCompare);
  if (!user || !user.is_active || !valid) {
    return c.json({ error: 'auth', message: 'Invalid email or password' }, 401);
  }

  await updateLastLogin(c.env, user.id);
  const token = await issueSession(c.env, user.id, user.email);
  trackEvent(c.env, 'auth_login', { user_id: user.id });

  return c.json(
    { message: 'Logged in', user: { id: user.id, email: user.email } },
    200,
    { 'Set-Cookie': sessionCookie(token) },
  );
});

// ── GET /auth/verify — public email verification endpoint ─────────────────
auth.get('/verify', async (c) => {
  const token = c.req.query('token') ?? '';
  if (!token) return c.redirect('https://wpsentry.link/verify-email?error=invalid');

  const result = await verifyUserEmail(c.env, token);
  if (!result.success) {
    return c.redirect('https://wpsentry.link/verify-email?error=invalid');
  }

  // Send welcome email now that email is verified
  const { subject, html, text } = welcomeEmail(result.email!);
  c.executionCtx.waitUntil(sendEmail(c.env, { to: result.email!, subject, html, text }));

  trackEvent(c.env, 'email_verified', { email: result.email });

  return c.redirect('https://wpsentry.link/verify-email?success=1');
});

// ── POST /auth/logout ─────────────────────────────────────────────────────
auth.post('/logout', authMiddleware, async (c) => {
  const user = c.get('user');
  await c.env.SESSIONS_KV.delete(`session:${user.jti}`);
  return c.json(
    { message: 'Logged out' },
    200,
    { 'Set-Cookie': clearCookie() },
  );
});

// ── Helpers ───────────────────────────────────────────────────────────────

async function issueSession(env: Env, userId: string, email: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jti = generateId();
  const token = await signJWT(
    { sub: userId, email, jti, iat: now, exp: now + JWT_TTL_SECONDS },
    env.JWT_SECRET,
  );
  await env.SESSIONS_KV.put(`session:${jti}`, userId, { expirationTtl: JWT_TTL_SECONDS });
  return token;
}

function sessionCookie(token: string): string {
  return `jwp_session=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${JWT_TTL_SECONDS}`;
}

function clearCookie(): string {
  return 'jwp_session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0';
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

export default auth;
