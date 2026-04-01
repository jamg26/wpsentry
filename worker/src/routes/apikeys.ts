// API key routes: GET/POST/DELETE /user/api-keys

import { Hono } from 'hono';
import type { Env } from '../types.js';
import type { AuthContext } from '../middleware/auth.js';
import { listApiKeys, createApiKey, deleteApiKey, getUserById } from '../lib/db.js';
import { generateId, generateApiKey, sha256Hex } from '../lib/crypto.js';
import { sendEmail } from '../lib/email.js';
import { apiKeyCreatedEmail } from '../lib/emailTemplates.js';

const apiKeys = new Hono<{ Bindings: Env; Variables: AuthContext }>();

// ── GET /user/api-keys ────────────────────────────────────────────────────
apiKeys.get('/', async (c) => {
  const { sub: userId } = c.get('user');
  const keys = await listApiKeys(c.env, userId);
  return c.json({
    api_keys: keys.map((k) => ({
      id: k.id,
      name: k.name,
      key_prefix: k.key_prefix,
      last_used_at: k.last_used_at ? new Date(k.last_used_at).toISOString() : null,
      created_at: new Date(k.created_at).toISOString(),
      enabled: k.enabled === 1,
    })),
  });
});

// ── POST /user/api-keys ───────────────────────────────────────────────────
apiKeys.post('/', async (c) => {
  const { sub: userId } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as { name?: string };
  const name = (body.name ?? '').trim();
  if (!name) return c.json({ error: 'validation', message: 'name is required' }, 400);

  // Check limit: max 10 API keys per user
  const existing = await listApiKeys(c.env, userId);
  if (existing.length >= 10) {
    return c.json({ error: 'limit', message: 'Maximum of 10 API keys allowed per account' }, 400);
  }

  const rawKey = generateApiKey();
  const keyHash = await sha256Hex(rawKey);
  const keyPrefix = rawKey.slice(0, 17); // jwp_live_ + 8 chars

  const id = generateId();
  await createApiKey(c.env, id, userId, name, keyHash, keyPrefix);

  // Send API key creation notification (fire-and-forget)
  const userRow = await getUserById(c.env, userId);
  if (userRow) {
    const { subject, html, text } = apiKeyCreatedEmail({ email: userRow.email, keyPreview: rawKey.slice(0, 8) });
    sendEmail(c.env, { to: userRow.email, subject, html, text }).catch(console.error);
  }

  return c.json({
    id,
    name,
    key: rawKey,         // shown ONCE — client must save it
    key_prefix: keyPrefix,
    created_at: new Date().toISOString(),
  }, 201);
});

// ── DELETE /user/api-keys/:id ─────────────────────────────────────────────
apiKeys.delete('/:id', async (c) => {
  const { sub: userId } = c.get('user');
  const deleted = await deleteApiKey(c.env, c.req.param('id'), userId);
  if (!deleted) return c.json({ error: 'not_found', message: 'API key not found' }, 404);
  return c.json({ message: 'API key deleted' });
});

export default apiKeys;
