// Webhook routes: GET/POST/DELETE /user/webhooks

import { Hono } from 'hono';
import type { Env, WebhookRow } from '../types.js';
import type { AuthContext } from '../middleware/auth.js';
import { listWebhooks, createWebhook, deleteWebhook } from '../lib/db.js';
import { generateId } from '../lib/crypto.js';

const VALID_EVENTS = ['scan.completed', 'critical.found'];

const webhooks = new Hono<{ Bindings: Env; Variables: AuthContext }>();

// ── GET /user/webhooks ────────────────────────────────────────────────────
webhooks.get('/', async (c) => {
  const { sub: userId } = c.get('user');
  const rows = await listWebhooks(c.env, userId);
  return c.json({ webhooks: rows.map(formatRow) });
});

// ── POST /user/webhooks ───────────────────────────────────────────────────
webhooks.post('/', async (c) => {
  const { sub: userId } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as {
    url?: string;
    events?: string[];
  };

  const url = (body.url ?? '').trim();
  if (!url) return c.json({ error: 'validation', message: 'url is required' }, 400);

  // Basic URL validation
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return c.json({ error: 'validation', message: 'Webhook URL must use http or https' }, 400);
    }
  } catch {
    return c.json({ error: 'validation', message: 'Invalid webhook URL' }, 400);
  }

  const events = Array.isArray(body.events) && body.events.length > 0
    ? body.events.filter((e) => VALID_EVENTS.includes(e))
    : VALID_EVENTS;

  if (events.length === 0) {
    return c.json({ error: 'validation', message: `events must include at least one of: ${VALID_EVENTS.join(', ')}` }, 400);
  }

  // Limit: max 10 webhooks
  const existing = await listWebhooks(c.env, userId);
  if (existing.length >= 10) {
    return c.json({ error: 'limit', message: 'Maximum of 10 webhooks allowed per account' }, 400);
  }

  const id = generateId();
  const secret = generateId(32); // shared signing secret
  await createWebhook(c.env, id, userId, url, secret, events.join(','));

  const row = await listWebhooks(c.env, userId).then((rows) => rows.find((r) => r.id === id));
  return c.json({ ...formatRow(row!), secret }, 201);
});

// ── DELETE /user/webhooks/:id ─────────────────────────────────────────────
webhooks.delete('/:id', async (c) => {
  const { sub: userId } = c.get('user');
  const deleted = await deleteWebhook(c.env, c.req.param('id'), userId);
  if (!deleted) return c.json({ error: 'not_found', message: 'Webhook not found' }, 404);
  return c.json({ message: 'Webhook deleted' });
});

function formatRow(row: WebhookRow) {
  return {
    id: row.id,
    url: row.url,
    events: row.events.split(','),
    enabled: row.enabled === 1,
    created_at: new Date(row.created_at).toISOString(),
  };
}

export default webhooks;
