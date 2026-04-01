// Scan routes: POST /scans, GET /scans, GET /scans/:id, DELETE /scans/:id
// Also: schedule, compare, share, tags

import { Hono } from 'hono';
import type { Env, ScanJobMessage, ScanRow } from '../types.js';
import type { AuthContext } from '../middleware/auth.js';
import { checkRateLimit } from '../middleware/rateLimit.js';
import { createScan, getScanById, listScans, deleteScan, logUsage, getDailyUsageCount, getMonthlyUsageCount, getUserLimits } from '../lib/db.js';
import { generateId } from '../lib/crypto.js';
import { trackEvent } from '../lib/analytics.js';
import scheduleRoutes from './schedule.js';

const MODULE_COUNT = 122;

const scans = new Hono<{ Bindings: Env; Variables: AuthContext }>();

// ── Mount schedule sub-router (must be before /:id routes) ───────────────
scans.route('/schedule', scheduleRoutes);

// ── GET /scans/compare?a=id&b=id ─────────────────────────────────────────
scans.get('/compare', async (c) => {
  const user = c.get('user');
  const aId = c.req.query('a') ?? '';
  const bId = c.req.query('b') ?? '';

  if (!aId || !bId) {
    return c.json({ error: 'validation', message: 'Both a and b scan IDs are required' }, 400);
  }

  const [scanA, scanB] = await Promise.all([
    getScanById(c.env, aId, user.sub),
    getScanById(c.env, bId, user.sub),
  ]);

  if (!scanA) return c.json({ error: 'not_found', message: `Scan ${aId} not found` }, 404);
  if (!scanB) return c.json({ error: 'not_found', message: `Scan ${bId} not found` }, 404);

  const [reportAObj, reportBObj] = await Promise.all([
    scanA.report_key ? c.env.REPORTS_R2.get(scanA.report_key) : null,
    scanB.report_key ? c.env.REPORTS_R2.get(scanB.report_key) : null,
  ]);

  const reportA = reportAObj ? await reportAObj.json<{ findings?: Array<{ type: string; url: string; severity: string; description: string }> }>() : null;
  const reportB = reportBObj ? await reportBObj.json<{ findings?: Array<{ type: string; url: string; severity: string; description: string }> }>() : null;

  const findingsA = reportA?.findings ?? [];
  const findingsB = reportB?.findings ?? [];

  // Key for deduplication: type + url (normalized)
  const keyOf = (f: { type: string; url: string }) => `${f.type}::${f.url.toLowerCase()}`;
  const setA = new Map(findingsA.map((f) => [keyOf(f), f]));
  const setB = new Map(findingsB.map((f) => [keyOf(f), f]));

  const new_findings = findingsB.filter((f) => !setA.has(keyOf(f)));
  const fixed_findings = findingsA.filter((f) => !setB.has(keyOf(f)));
  const unchanged_findings = findingsA.filter((f) => setB.has(keyOf(f)));

  return c.json({
    scan_a: formatScan(scanA),
    scan_b: formatScan(scanB),
    new_findings,
    fixed_findings,
    unchanged_findings,
    summary: {
      new: new_findings.length,
      fixed: fixed_findings.length,
      unchanged: unchanged_findings.length,
    },
  });
});

// ── POST /scans — create + enqueue ───────────────────────────────────────
scans.post('/', async (c) => {
  const user = c.get('user');
  const body = await c.req.json().catch(() => ({})) as { target?: string; modules?: number[]; tags?: string[]; authorization_confirmed?: boolean };

  // Validate URL BEFORE the rate-limit check so invalid payloads return 400
  // without consuming a daily scan slot.
  const target = normalizeUrl(body.target ?? '');
  if (!target) {
    return c.json({ error: 'validation', message: 'Invalid or missing target URL' }, 400);
  }

  // Require explicit authorization confirmation for every scan
  if (body.authorization_confirmed !== true) {
    return c.json({
      error: 'authorization_required',
      message: 'You must confirm you have authorization to scan this target. Set authorization_confirmed: true in your request.',
    }, 400);
  }

  // Block unverified users from scanning
  const userRow = await c.env.DB.prepare('SELECT is_verified FROM users WHERE id = ?')
    .bind(user.sub).first<{ is_verified: number }>();
  if (!userRow?.is_verified) {
    return c.json({
      error: 'email_not_verified',
      message: 'Please verify your email address before scanning. Check your inbox or resend the verification email from Settings.',
    }, 403);
  }

  // SSRF protection: block private/reserved IP addresses and internal hostnames
  if (isPrivateTarget(target)) {
    return c.json({ error: 'validation', message: 'Cannot scan private or reserved IP addresses' }, 400);
  }

  // Rate-limit check (KV fast path + D1 authoritative — also increments KV)
  const rlBlocked = await checkRateLimit(c);
  if (rlBlocked) return rlBlocked;

  // Concurrent scan guard: max 2 active scans per user to prevent queue starvation
  const inFlight = await c.env.DB
    .prepare("SELECT COUNT(*) as cnt FROM scans WHERE user_id = ? AND status IN ('queued','running')")
    .bind(user.sub)
    .first<{ cnt: number }>();
  if ((inFlight?.cnt ?? 0) >= 2) {
    return c.json({ error: 'conflict', message: 'You already have 2 scans in progress. Wait for them to complete before starting a new one.' }, 429);
  }

  const modules = Array.isArray(body.modules) && body.modules.length > 0
    ? body.modules.filter((m) => Number.isInteger(m) && m >= 1 && m <= MODULE_COUNT)
    : null;

  const tags = Array.isArray(body.tags) && body.tags.length > 0
    ? body.tags.map((t) => String(t).trim().slice(0, 50)).filter(Boolean).join(',')
    : null;

  const scanId = generateId();
  const authIp = c.req.header('CF-Connecting-IP') ?? 'unknown';
  await createScan(c.env, scanId, user.sub, target, modules, Date.now(), authIp);

  if (tags) {
    await c.env.DB.prepare('UPDATE scans SET tags = ? WHERE id = ?').bind(tags, scanId).run();
  }

  await logUsage(c.env, user.sub, 'scan', scanId);

  const message: ScanJobMessage = {
    scan_id: scanId,
    user_id: user.sub,
    target,
    modules,
  };
  await c.env.SCAN_QUEUE.send(message);

  trackEvent(c.env, 'scan_created', {
    user_id: user.sub,
    scan_id: scanId,
    target_domain: extractDomain(target),
    module_count: modules?.length ?? MODULE_COUNT,
  });

  return c.json({ id: scanId, status: 'queued', target, tags: tags ? tags.split(',') : [], created_at: new Date().toISOString() }, 202);
});

// ── GET /scans — list history ─────────────────────────────────────────────
scans.get('/', async (c) => {
  const user = c.get('user');
  const limit = Math.min(parseInt(c.req.query('limit') ?? '20', 10), 100);
  const offset = parseInt(c.req.query('offset') ?? '0', 10);
  const tagFilter = c.req.query('tag') ?? '';

  const [rows, { dailyLimit, monthlyLimit }, daily, monthly] = await Promise.all([
    listScans(c.env, user.sub, limit, offset),
    getUserLimits(c.env, user.sub),
    getDailyUsageCount(c.env, user.sub),
    getMonthlyUsageCount(c.env, user.sub),
  ]);

  const filtered = tagFilter
    ? rows.filter((s) => s.tags && s.tags.split(',').includes(tagFilter))
    : rows;

  return c.json({
    scans: filtered.map(formatScan),
    pagination: { limit, offset },
    usage: {
      daily_used: daily,
      daily_limit: dailyLimit,
      monthly_used: monthly,
      monthly_limit: monthlyLimit,
    },
  });
});

// ── GET /scans/:id/progress — live progress from KV ──────────────────────
scans.get('/:id/progress', async (c) => {
  const user = c.get('user');
  const scanId = c.req.param('id');

  const scan = await getScanById(c.env, scanId, user.sub);
  if (!scan) return c.json({ error: 'not_found', message: 'Scan not found' }, 404);

  const raw = await c.env.SESSIONS_KV.get(`scan_progress:${scanId}`);
  if (!raw) {
    const modulesSelected: number[] | null = (() => {
      try { return scan.modules_selected ? JSON.parse(scan.modules_selected) : null; } catch { return null; }
    })();
    const total = modulesSelected ? modulesSelected.length : 122;
    return c.json({
      scan_id: scanId,
      total,
      completed: scan.status === 'completed' ? total : scan.status === 'queued' ? 0 : null,
      current_module: null,
      events: [],
      status: scan.status,
      updated_at: scan.started_at ?? scan.created_at,
    });
  }

  // CRIT-03: Wrap JSON.parse in try/catch to prevent 500 on corrupt KV data
  let progress: unknown = null;
  try {
    progress = raw ? JSON.parse(raw) : null;
  } catch {
    progress = null;
  }
  if (!progress) {
    const modulesSelected2: number[] | null = (() => {
      try { return scan.modules_selected ? JSON.parse(scan.modules_selected) : null; } catch { return null; }
    })();
    const total = modulesSelected2 ? modulesSelected2.length : 122;
    return c.json({
      scan_id: scanId,
      total,
      completed: scan.status === 'completed' ? total : scan.status === 'queued' ? 0 : null,
      current_module: null,
      events: [],
      status: scan.status,
      updated_at: scan.started_at ?? scan.created_at,
    });
  }
  return c.json({ ...(progress as Record<string, unknown>), status: scan.status });
});

// ── GET /scans/:id — status + summary ────────────────────────────────────
scans.get('/:id', async (c) => {
  const user = c.get('user');
  const scan = await getScanById(c.env, c.req.param('id'), user.sub);
  if (!scan) return c.json({ error: 'not_found', message: 'Scan not found' }, 404);

  const response: Record<string, unknown> = formatScan(scan);

  // If completed, include the full report from R2
  if (scan.status === 'completed' && scan.report_key) {
    const obj = await c.env.REPORTS_R2.get(scan.report_key);
    if (obj) {
      response.report = await obj.json();
    }
  }

  return c.json(response);
});

// ── PUT /scans/:id/tags — update tags ────────────────────────────────────
scans.put('/:id/tags', async (c) => {
  const user = c.get('user');
  const scan = await getScanById(c.env, c.req.param('id'), user.sub);
  if (!scan) return c.json({ error: 'not_found', message: 'Scan not found' }, 404);

  const body = await c.req.json().catch(() => ({})) as { tags?: string[] };
  const tags = Array.isArray(body.tags)
    ? body.tags.map((t) => String(t).trim().slice(0, 50)).filter(Boolean).join(',')
    : '';

  await c.env.DB.prepare('UPDATE scans SET tags = ? WHERE id = ? AND user_id = ?')
    .bind(tags || null, scan.id, user.sub).run();

  return c.json({ id: scan.id, tags: tags ? tags.split(',') : [] });
});

// ── POST /scans/:id/share — generate public token ─────────────────────────
scans.post('/:id/share', async (c) => {
  const user = c.get('user');
  const scan = await getScanById(c.env, c.req.param('id'), user.sub);
  if (!scan) return c.json({ error: 'not_found', message: 'Scan not found' }, 404);

  if (scan.status !== 'completed') {
    return c.json({ error: 'conflict', message: 'Only completed scans can be shared' }, 409);
  }

  const token = scan.public_token ?? generateId(32);
  await c.env.DB.prepare('UPDATE scans SET is_public = 1, public_token = ? WHERE id = ? AND user_id = ?')
    .bind(token, scan.id, user.sub).run();

  const origin = c.env.CORS_ORIGIN ?? 'https://wpsentry.link';
  return c.json({
    token,
    public_url: `${origin}/public/scans/${token}`,
    api_url: `/public/scans/${token}`,
  });
});

// ── DELETE /scans/:id/share — revoke public access ────────────────────────
scans.delete('/:id/share', async (c) => {
  const user = c.get('user');
  const scan = await getScanById(c.env, c.req.param('id'), user.sub);
  if (!scan) return c.json({ error: 'not_found', message: 'Scan not found' }, 404);

  await c.env.DB.prepare('UPDATE scans SET is_public = 0, public_token = NULL WHERE id = ? AND user_id = ?')
    .bind(scan.id, user.sub).run();

  return c.json({ message: 'Public access revoked' });
});

// ── DELETE /scans/:id ─────────────────────────────────────────────────────
scans.delete('/:id', async (c) => {
  const user = c.get('user');
  const scan = await getScanById(c.env, c.req.param('id'), user.sub);
  if (!scan) return c.json({ error: 'not_found', message: 'Scan not found' }, 404);

  if (scan.status === 'running' || scan.status === 'queued') {
    return c.json({ error: 'conflict', message: 'Cannot delete a scan that is still running' }, 409);
  }

  // Remove R2 report
  if (scan.report_key) {
    await c.env.REPORTS_R2.delete(scan.report_key);
  }

  await deleteScan(c.env, scan.id, user.sub);
  return c.json({ message: 'Scan deleted' });
});

// ── Helpers ───────────────────────────────────────────────────────────────

function formatScan(scan: ScanRow) {
  return {
    id: scan.id,
    target: scan.target,
    status: scan.status,
    modules_selected: scan.modules_selected ? (() => { try { return JSON.parse(scan.modules_selected!); } catch { return null; } })() : null,
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
    error_message: scan.error_message ?? null,
    tags: scan.tags ? scan.tags.split(',').filter(Boolean) : [],
    is_public: scan.is_public === 1,
    public_token: scan.is_public === 1 ? scan.public_token : null,
  };
}

function normalizeUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(withProto);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    if (!url.hostname.includes('.')) return ''; // require a TLD
    return url.origin;
  } catch {
    return '';
  }
}

function extractDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

/** Block private/reserved IP addresses and internal hostnames (SSRF protection). */
function isPrivateTarget(url: string): boolean {
  try {
    const hostname = new URL(url).hostname.toLowerCase();

    // Localhost variants
    if (hostname === 'localhost' || hostname === '[::1]') return true;

    // Internal TLDs
    if (hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname.endsWith('.localhost')) return true;

    // Strip IPv6 brackets for numeric checks
    const bare = hostname.startsWith('[') ? hostname.slice(1, -1) : hostname;

    // IPv6 reserved ranges
    if (bare === '::1') return true;
    if (/^f[cd][0-9a-f]{2}:/i.test(bare)) return true;   // fc00::/7 (ULA)
    if (/^fe80:/i.test(bare)) return true;                 // link-local

    // IPv4 private/reserved ranges
    const ipv4Match = bare.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipv4Match) {
      const [, aStr, bStr] = ipv4Match;
      const a = Number(aStr);
      const b = Number(bStr);
      if (a === 127) return true;                     // 127.0.0.0/8
      if (a === 10) return true;                      // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
      if (a === 192 && b === 168) return true;        // 192.168.0.0/16
      if (a === 169 && b === 254) return true;        // 169.254.0.0/16
      if (a === 0) return true;                       // 0.0.0.0/8
    }

    return false;
  } catch {
    return true; // Fail closed on parse errors
  }
}

// ── POST /scans/:id/report-fp — report a false positive finding ──────────
scans.post('/:id/report-fp', async (c) => {
  const { user_id } = c.get('auth') as AuthContext;
  const scan_id = c.req.param('id');

  // Verify scan belongs to user
  const scan = await c.env.DB.prepare('SELECT id FROM scans WHERE id = ? AND user_id = ?')
    .bind(scan_id, user_id).first<{ id: string }>();
  if (!scan) return c.json({ error: 'Scan not found' }, 404);

  const body = await c.req.json().catch(() => ({})) as {
    finding_type?: string;
    finding_url?: string;
    finding_severity?: string;
    reason?: string;
  };

  if (!body.finding_type || !body.finding_url || !body.finding_severity) {
    return c.json({ error: 'finding_type, finding_url and finding_severity are required' }, 400);
  }

  const id = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO false_positive_reports (id, scan_id, user_id, finding_type, finding_url, finding_severity, reason, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch())`
  ).bind(id, scan_id, user_id, body.finding_type, body.finding_url, body.finding_severity, body.reason ?? null).run();

  return c.json({ success: true, id });
});

export default scans;
