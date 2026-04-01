// Scheduled scans routes: GET/POST /scans/schedule, PUT/DELETE /scans/schedule/:id

import { Hono } from 'hono';
import type { Env } from '../types.js';
import type { AuthContext } from '../middleware/auth.js';
import {
  listScheduledScans,
  createScheduledScan,
  getScheduledScanById,
  updateScheduledScan,
  deleteScheduledScan,
} from '../lib/db.js';
import { generateId } from '../lib/crypto.js';

const schedule = new Hono<{ Bindings: Env; Variables: AuthContext }>();

export function computeNextRun(scheduleCron: string, fromMs = Date.now()): number {
  switch (scheduleCron) {
    case 'daily':   return fromMs + 24 * 60 * 60 * 1000;
    case 'weekly':  return fromMs + 7 * 24 * 60 * 60 * 1000;
    case 'monthly': return fromMs + 30 * 24 * 60 * 60 * 1000;
    default:        return fromMs + 24 * 60 * 60 * 1000;
  }
}

// ── GET /scans/schedule ───────────────────────────────────────────────────
schedule.get('/', async (c) => {
  const { sub: userId } = c.get('user');
  const rows = await listScheduledScans(c.env, userId);
  return c.json({ scheduled_scans: rows.map(formatRow) });
});

// ── POST /scans/schedule ──────────────────────────────────────────────────
schedule.post('/', async (c) => {
  const { sub: userId } = c.get('user');
  const body = await c.req.json().catch(() => ({})) as {
    url?: string;
    schedule_cron?: string;
  };

  const url = (body.url ?? '').trim();
  const cron = body.schedule_cron ?? 'daily';

  if (!url) return c.json({ error: 'validation', message: 'url is required' }, 400);
  if (!['daily', 'weekly', 'monthly'].includes(cron)) {
    return c.json({ error: 'validation', message: 'schedule_cron must be daily, weekly, or monthly' }, 400);
  }

  const id = generateId();
  const nextRunAt = computeNextRun(cron);
  await createScheduledScan(c.env, id, userId, url, cron, nextRunAt);

  const row = await getScheduledScanById(c.env, id, userId);
  return c.json(formatRow(row!), 201);
});

// ── PUT /scans/schedule/:id ───────────────────────────────────────────────
schedule.put('/:id', async (c) => {
  const { sub: userId } = c.get('user');
  const id = c.req.param('id');
  const body = await c.req.json().catch(() => ({})) as {
    url?: string;
    schedule_cron?: string;
    enabled?: boolean;
  };

  const existing = await getScheduledScanById(c.env, id, userId);
  if (!existing) return c.json({ error: 'not_found', message: 'Scheduled scan not found' }, 404);

  const updates: Parameters<typeof updateScheduledScan>[3] = {};
  if (body.url !== undefined) updates.url = body.url.trim();
  if (body.schedule_cron !== undefined) {
    if (!['daily', 'weekly', 'monthly'].includes(body.schedule_cron)) {
      return c.json({ error: 'validation', message: 'Invalid schedule_cron' }, 400);
    }
    updates.schedule_cron = body.schedule_cron;
    updates.next_run_at = computeNextRun(body.schedule_cron);
  }
  if (body.enabled !== undefined) updates.enabled = body.enabled ? 1 : 0;

  await updateScheduledScan(c.env, id, userId, updates);
  const row = await getScheduledScanById(c.env, id, userId);
  return c.json(formatRow(row!));
});

// ── DELETE /scans/schedule/:id ────────────────────────────────────────────
schedule.delete('/:id', async (c) => {
  const { sub: userId } = c.get('user');
  const deleted = await deleteScheduledScan(c.env, c.req.param('id'), userId);
  if (!deleted) return c.json({ error: 'not_found', message: 'Scheduled scan not found' }, 404);
  return c.json({ message: 'Scheduled scan deleted' });
});

function formatRow(row: NonNullable<Awaited<ReturnType<typeof getScheduledScanById>>>) {
  return {
    id: row.id,
    url: row.url,
    schedule_cron: row.schedule_cron,
    next_run_at: new Date(row.next_run_at).toISOString(),
    last_run_at: row.last_run_at ? new Date(row.last_run_at).toISOString() : null,
    enabled: row.enabled === 1,
    created_at: new Date(row.created_at).toISOString(),
  };
}

export default schedule;
