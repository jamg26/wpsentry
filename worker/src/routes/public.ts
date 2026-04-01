// Public scan routes — no authentication required
// GET /public/scans/:token — returns a publicly shared scan report

import { Hono } from 'hono';
import type { Env, ScanRow } from '../types.js';

const pub = new Hono<{ Bindings: Env }>();

pub.get('/scans/:token', async (c) => {
  const token = c.req.param('token');

  const scan = await c.env.DB.prepare(
    'SELECT * FROM scans WHERE public_token = ? AND is_public = 1',
  ).bind(token).first<ScanRow>();

  if (!scan) {
    return c.json({ error: 'not_found', message: 'Public scan not found or link has been revoked' }, 404);
  }

  const response: Record<string, unknown> = {
    id: scan.id,
    target: scan.target,
    status: scan.status,
    created_at: new Date(scan.created_at).toISOString(),
    started_at: scan.started_at ? new Date(scan.started_at).toISOString() : null,
    completed_at: scan.completed_at ? new Date(scan.completed_at).toISOString() : null,
    findings_count: scan.findings_count,
    by_severity: {
      critical: scan.critical_count,
      high: scan.high_count,
      medium: scan.medium_count,
      low: scan.low_count,
      info: scan.info_count,
    },
    tags: scan.tags ? scan.tags.split(',').filter(Boolean) : [],
  };

  if (scan.status === 'completed' && scan.report_key) {
    const obj = await c.env.REPORTS_R2.get(scan.report_key);
    if (obj) {
      response.report = await obj.json();
    }
  }

  return c.json(response);
});

export default pub;
