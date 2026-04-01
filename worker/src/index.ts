// JWP Worker — main entry point
// Routes: /auth/*, /user/*, /scans/*, /admin/*, /public/*
// Queue consumer: handles async scan jobs

import { Hono } from 'hono';
import type { Env, ScanJobMessage } from './types.js';
import type { AuthContext } from './middleware/auth.js';
import { authMiddleware } from './middleware/auth.js';
import { securityHeaders, corsHeaders, csrfProtection } from './middleware/security.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/user.js';
import scanRoutes from './routes/scans.js';
import adminRoutes from './routes/admin.js';
import publicRoutes from './routes/public.js';
import { handleScanJob, handleScanJobError } from './scanner/engine.js';
import { getDueScheduledScans, updateScheduledScan } from './lib/db.js';
import { generateId } from './lib/crypto.js';
import { computeNextRun } from './routes/schedule.js';

const app = new Hono<{ Bindings: Env; Variables: AuthContext }>();

// ── Global middleware ─────────────────────────────────────────────────────
app.use('*', securityHeaders);
app.use('*', async (c, next) => {
  // CRIT-02: Fail closed on missing CORS_ORIGIN — fall back to localhost only in development
  const origin = c.env.CORS_ORIGIN ?? (c.env.ENVIRONMENT === 'development' ? 'http://localhost:5173' : null);
  if (!origin) return c.json({ error: 'Server misconfiguration: CORS_ORIGIN not set' }, 500);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return corsHeaders(origin)(c as any, next);
});
app.use('*', csrfProtection);

// ── Health check ──────────────────────────────────────────────────────────
app.get('/health', (c) => c.json({ status: 'ok', version: '3.0.0' }));

// ── Public routes (no auth) ───────────────────────────────────────────────
app.route('/auth', authRoutes);
app.route('/public', publicRoutes);

// ── Admin routes (self-protecting via adminAuth middleware) ────────────
app.route('/admin', adminRoutes);

// ── Protected routes ──────────────────────────────────────────────────────
app.use('/user/*', authMiddleware);
app.use('/scans/*', authMiddleware);

app.route('/user', userRoutes);
app.route('/scans', scanRoutes);

// ── 404 fallback ──────────────────────────────────────────────────────────
app.notFound((c) => c.json({ error: 'not_found', message: 'Route not found' }, 404));

// ── Global error handler ──────────────────────────────────────────────────
app.onError((err, c) => {
  const isProd = c.env.ENVIRONMENT === 'production';
  console.error('[JWP Worker Error]', err);
  return c.json(
    {
      error: 'internal_error',
      message: isProd ? 'An unexpected error occurred' : err.message,
    },
    500,
  );
});

// ── Worker + Queue consumer export ────────────────────────────────────────
export default {
  // HTTP fetch handler
  fetch: app.fetch,

  // Queue consumer — processes scan jobs
  async queue(batch: MessageBatch<ScanJobMessage>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      try {
        await handleScanJob(msg.body, env);
        msg.ack();
      } catch (err) {
        console.error('[JWP Queue Error] scan_id:', msg.body.scan_id, err);
        try {
          await handleScanJobError(msg.body, env, err);
          msg.ack(); // Scan marked failed in D1 — no need to retry
        } catch (innerErr) {
          console.error('[JWP Queue Error] handleScanJobError failed, will retry:', innerErr);
          msg.retry(); // D1 may be temporarily unavailable — retry the whole thing
        }
      }
    }
  },

  // Cron: recover scans stuck in "running" after a worker restart
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    // 1. Recover stuck scans
    const timeoutMs = 20 * 60 * 1000; // 20 minutes
    const cutoff = Date.now() - timeoutMs;
    const result = await env.DB.prepare(
      `UPDATE scans SET status = 'failed', error_message = ?, completed_at = ?
       WHERE status = 'running' AND started_at < ?`,
    ).bind('Scan timed out — worker may have restarted', Date.now(), cutoff).run();
    if (result.meta.changes > 0) {
      console.log(`[Cron] Recovered ${result.meta.changes} stuck running scans`);
    }

    // 2. Trigger due scheduled scans
    const dueScans = await getDueScheduledScans(env);
    for (const scheduled of dueScans) {
      try {
        const scanId = generateId();
        const message: ScanJobMessage = {
          scan_id: scanId,
          user_id: scheduled.user_id,
          target: scheduled.url,
          modules: null,
        };

        // Insert scan record
        await env.DB.prepare(
          `INSERT INTO scans (id, user_id, target, status, created_at) VALUES (?, ?, ?, 'queued', ?)`,
        ).bind(scanId, scheduled.user_id, scheduled.url, Date.now()).run();

        await env.SCAN_QUEUE.send(message);

        // Update next_run_at and last_run_at
        await updateScheduledScan(env, scheduled.id, scheduled.user_id, {
          last_run_at: Date.now(),
          next_run_at: computeNextRun(scheduled.schedule_cron),
        });

        console.log(`[Cron] Triggered scheduled scan ${scanId} for ${scheduled.url}`);
      } catch (err) {
        console.error(`[Cron] Failed to trigger scheduled scan ${scheduled.id}:`, err);
      }
    }
  },
};
