// Queue consumer — scans are executed here
// Each message carries a ScanJobMessage; consumer runs selected modules in parallel,
// writes results to D1 + R2, and updates scan status throughout.

import type { Env, ScanJobMessage, ScanReport } from '../types.js';
import type { ModuleResult, Finding, ScanState } from './types.js';
import { updateScanStatus, getWebhooksByUserAndEvent } from '../lib/db.js';
import { hmacSha256Hex } from '../lib/crypto.js';
import { trackEvent } from '../lib/analytics.js';
import { sendEmail } from '../lib/email.js';
import { scanCompleteEmail, criticalAlertEmail } from '../lib/emailTemplates.js';
import { fetchURL } from './utils.js';
import { MODULES } from './modules/index.js';
import { enhanceRemediationsWithAI } from '../lib/ai-remediation.js';

interface ScanProgressEvent {
  module: string;
  status: 'ok' | 'error';
  findings: number;
  duration_ms: number;
  ts: number;
}

interface ScanProgress {
  scan_id: string;
  total: number;
  completed: number;
  current_module: string | null;
  events: ScanProgressEvent[];
  updated_at: number;
}

async function writeProgress(
  env: Env,
  scan_id: string,
  total: number,
  completed: number,
  current_module: string | null,
  events: ScanProgressEvent[],
): Promise<void> {
  const progress: ScanProgress = { scan_id, total, completed, current_module, events, updated_at: Date.now() };
  await env.SESSIONS_KV.put(`scan_progress:${scan_id}`, JSON.stringify(progress), { expirationTtl: 3600 });
}

export async function handleScanJob(message: ScanJobMessage, env: Env): Promise<void> {
  const { scan_id, user_id, target, modules: moduleIds } = message;
  const startMs = Date.now();

  await updateScanStatus(env, scan_id, 'running', { started_at: Date.now() });

  const selectedModules = moduleIds
    ? MODULES.filter((m) => moduleIds.includes(m.id))
    : MODULES;

  // Shared scan state with reachability + response body cache to reduce redundant requests
  // and eliminate contradictory "unreachable" findings across modules
  const scanState: ScanState = {
    reachabilityCache: new Map<string, { status: number; timestamp: number }>(),
    responseCache: new Map<string, { status: number; body: string; headers: Record<string, string>; timestamp: number }>(),
  };

  // Pre-fetch common paths: populate reachabilityCache (all) and responseCache (body-needed paths).
  // Fetch bodies for WP-specific paths too so we can validate content, not just status codes.
  const HEAD_ONLY = new Set(['/wp-admin/']);
  const commonPaths = ['/', '/wp-login.php', '/wp-admin/', '/wp-json/', '/robots.txt'];
  await Promise.all(commonPaths.map(async (path) => {
    const url = target + path;
    const useHead = HEAD_ONLY.has(path);
    const res = await fetchURL(url, { method: useHead ? 'HEAD' : 'GET', timeoutMs: 5000 });
    const status = res?.status ?? 0;
    scanState.reachabilityCache!.set(url, { status, timestamp: Date.now() });
    if (!useHead && res) {
      const body = await res.text().catch(() => '');
      const headers: Record<string, string> = {};
      res.headers.forEach((v: string, k: string) => { headers[k] = v; });
      scanState.responseCache!.set(url, { status, body, headers, timestamp: Date.now() });
    }
  }));

  // Detect WordPress by checking actual content, not just HTTP status codes.
  // SPAs (e.g. Cloudflare Pages) return 200 for all paths — a 200 alone is not proof of WordPress.
  const homeEntry = scanState.responseCache?.get(target + '/');
  const homeBody = homeEntry?.body ?? '';
  const wpLoginBody = scanState.responseCache?.get(target + '/wp-login.php')?.body ?? '';
  const wpJsonBody = scanState.responseCache?.get(target + '/wp-json/')?.body ?? '';

  const isWordPress = (
    // Real WP asset URLs embedded in page source — highly reliable
    homeBody.includes('wp-content/') ||
    homeBody.includes('wp-includes/') ||
    // WP login page contains this form ID — reliable, SPAs won't have it
    wpLoginBody.includes('id="loginform"') ||
    wpLoginBody.includes('name="log"') ||
    // WP REST API root returns JSON with "name"/"url"/"namespaces" — check it's actually JSON
    (wpJsonBody.trimStart().startsWith('{') && wpJsonBody.includes('"namespaces"')) ||
    // X-Powered-By or link headers from WP server
    (homeEntry?.headers?.['x-powered-by'] ?? '').toLowerCase().includes('wordpress') ||
    (homeEntry?.headers?.['link'] ?? '').includes('wp-json')
  );
  scanState.isWordPress = isWordPress;

  // For non-WordPress sites, skip WP-specific modules to prevent false positives.
  // Any module with requiresWordPress === false is generic and always runs.
  // All current modules default to undefined which is treated as WP-specific.
  const modulesToRun = isWordPress
    ? selectedModules
    : selectedModules.filter(m => m.requiresWordPress === false);

  const results: ModuleResult[] = [];
  const progressEvents: ScanProgressEvent[] = [];
  const PARALLEL_BATCH = 12; // run up to 12 modules concurrently (~60% wall-clock reduction vs 4)
  const MODULE_TIMEOUT_MS = 25_000; // hard cap per module regardless of how many fetches it makes

  // CRIT-04: Create one AbortController per module so the timeout can cancel
  // in-flight fetches inside the module (prevents orphaned CPU-burning requests).
  const runWithTimeout = (m: (typeof MODULES)[number], t: string): Promise<ModuleResult> => {
    const ac = new AbortController();
    const moduleState: ScanState = { ...scanState, signal: ac.signal };
    const timeout = new Promise<ModuleResult>((_, reject) =>
      setTimeout(
        () => { ac.abort(); reject(new Error(`Module timeout after ${MODULE_TIMEOUT_MS}ms`)); },
        MODULE_TIMEOUT_MS,
      ),
    );
    return Promise.race([m.run(t, moduleState), timeout]);
  };

  writeProgress(env, scan_id, modulesToRun.length, 0, modulesToRun[0]?.name ?? null, []).catch(console.error);

  for (let i = 0; i < modulesToRun.length; i += PARALLEL_BATCH) {
    const batch = modulesToRun.slice(i, i + PARALLEL_BATCH);
    const batchResults = await Promise.allSettled(
      batch.map((m) => runWithTimeout(m, target)),
    );
    for (let j = 0; j < batchResults.length; j++) {
      const r = batchResults[j];
      const moduleName = batch[j].name;
      if (r.status === 'fulfilled') {
        const result = r.value as ModuleResult;
        results.push(result);
        progressEvents.push({ module: moduleName, status: 'ok', findings: result.findings.length, duration_ms: result.duration_ms, ts: Date.now() });
      } else {
        results.push({ module: moduleName, target, vulnerable: false, findings: [], errors: [String(r.reason)], duration_ms: 0 });
        progressEvents.push({ module: moduleName, status: 'error', findings: 0, duration_ms: 0, ts: Date.now() });
      }
    }
    const completed = Math.min(i + PARALLEL_BATCH, modulesToRun.length);
    const nextBatch = modulesToRun.slice(i + PARALLEL_BATCH, i + PARALLEL_BATCH * 2);
    writeProgress(env, scan_id, selectedModules.length, completed, nextBatch[0]?.name ?? null, progressEvents).catch(console.error);
  }

  // For non-WordPress sites, prepend a synthetic INFO result explaining the skip.
  if (!isWordPress) {
    const homeStatus = scanState.reachabilityCache?.get(target + '/')?.status ?? 0;
    const wpLoginStatus = scanState.reachabilityCache?.get(target + '/wp-login.php')?.status ?? 0;
    const wpJsonStatus = scanState.reachabilityCache?.get(target + '/wp-json/')?.status ?? 0;

    const isUnreachable = homeStatus === 0;
    const isHttp = target.startsWith('http://');
    const isBlocked = [homeStatus, wpLoginStatus, wpJsonStatus].some((s) => s === 403 || s === 401);

    let type: string;
    let description: string;
    let remediation: string;

    if (isUnreachable) {
      type = 'site_unreachable';
      description = 'The target site is not responding or could not be reached. All modules were skipped.';
      remediation = isHttp
        ? 'The site may have redirected to HTTPS. Try scanning with https:// instead. Ensure the URL is correct and the server is online.'
        : 'Ensure the URL is correct and the server is publicly accessible. Check DNS resolution and firewall rules.';
    } else if (isBlocked) {
      type = 'scanner_blocked';
      description = `The scanner was blocked by the target server (HTTP ${[homeStatus, wpLoginStatus, wpJsonStatus].find((s) => s === 403 || s === 401)}). WordPress-specific modules were skipped.`;
      remediation = "A security plugin or WAF (e.g. Wordfence, Cloudflare) is blocking the scanner's requests. Temporarily whitelist the scanner IP, or use a browser-based check to confirm WordPress is installed.";
    } else if (isHttp) {
      type = 'http_redirect';
      description = 'WordPress was not detected. The site uses HTTP — it may redirect to HTTPS where WordPress markup would be present.';
      remediation = 'Try scanning with https:// instead. If the site is WordPress, ensure wp-login.php and /wp-json/ are publicly accessible.';
    } else {
      type = 'not_wordpress';
      description = 'This site does not appear to be running WordPress. WordPress-specific security modules were skipped. Only generic web security checks were performed.';
      remediation = 'If this site is WordPress, ensure wp-login.php and /wp-json/ are accessible and the homepage includes WordPress markup.';
    }

    const wpNotDetectedResult: ModuleResult = {
      module: 'wp_detection',
      target,
      vulnerable: false,
      findings: [{ type, severity: 'INFO', url: target, description, remediation }],
      errors: [],
      duration_ms: 0,
    };
    results.unshift(wpNotDetectedResult);
  }

  const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const rawFindings: Finding[] = results
    .flatMap((r) => r.findings)
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  const deduped = deduplicateFindings(rawFindings, results);
  const allFindings = await enhanceRemediationsWithAI(deduped, env.OLLAMA_API_KEY);
  const summary = buildSummary(results, allFindings);

  // Build full report — include deduped findings at top level so clients don't need to
  // re-aggregate from per-module results (which are pre-dedup and would give wrong counts).
  const report: ScanReport = {
    scan_id,
    target,
    created_at: new Date(startMs).toISOString(),
    completed_at: new Date().toISOString(),
    modules_run: results.length,
    modules_selected: moduleIds,
    findings: allFindings,
    results,
    summary,
  };

  // Write to R2
  const reportKey = `scans/${user_id}/${scan_id}.json`;
  await env.REPORTS_R2.put(reportKey, JSON.stringify(report, null, 2), {
    httpMetadata: { contentType: 'application/json' },
  });

  // Update D1
  await updateScanStatus(env, scan_id, 'completed', {
    completed_at: Date.now(),
    findings_count: summary.total_findings,
    critical_count: summary.by_severity.CRITICAL,
    high_count: summary.by_severity.HIGH,
    medium_count: summary.by_severity.MEDIUM,
    low_count: summary.by_severity.LOW,
    info_count: summary.by_severity.INFO,
    report_key: reportKey,
  });

  trackEvent(env, 'scan_completed', {
    user_id,
    scan_id,
    target_domain: extractDomain(target),
    module_count: results.length,
    findings_count: summary.total_findings,
    duration_ms: Date.now() - startMs,
    status: 'completed',
  });

  // Fire webhooks (fire-and-forget, don't block scan completion)
  fireWebhooks(env, user_id, {
    event: 'scan.completed',
    scan_id,
    target,
    status: 'completed',
    findings_count: summary.total_findings,
    critical_count: summary.by_severity.CRITICAL,
    completed_at: new Date().toISOString(),
  }).catch(console.error);

  // Fire critical webhook separately if there are critical findings
  if (summary.by_severity.CRITICAL > 0) {
    fireWebhooks(env, user_id, {
      event: 'critical.found',
      scan_id,
      target,
      critical_count: summary.by_severity.CRITICAL,
      completed_at: new Date().toISOString(),
    }).catch(console.error);
  }

  // Send email notifications based on user preferences.
  // Each email has its own try/catch so a failure in one never prevents the other.
  let userRow: { email: string; notification_prefs: string | null } | null = null;
  let prefs: { scan_complete?: boolean; critical_found?: boolean } = { scan_complete: true, critical_found: true };
  try {
    userRow = await env.DB.prepare('SELECT email, notification_prefs FROM users WHERE id = ?')
      .bind(user_id).first<{ email: string; notification_prefs: string | null }>();
    if (userRow?.notification_prefs) {
      prefs = JSON.parse(userRow.notification_prefs);
    }
  } catch (dbErr) {
    console.error('[email] Failed to fetch user for notifications:', dbErr);
  }

  if (userRow) {
    const durationMs = Date.now() - startMs;
    const durationStr = durationMs > 60000
      ? `${Math.floor(durationMs / 60000)}m ${Math.floor((durationMs % 60000) / 1000)}s`
      : `${Math.floor(durationMs / 1000)}s`;

    try {
      if (prefs.scan_complete !== false) {
        const { subject, html, text } = scanCompleteEmail({
          email: userRow.email,
          target,
          scanId: scan_id,
          totalFindings: summary.total_findings,
          criticalCount: summary.by_severity.CRITICAL ?? 0,
          highCount: summary.by_severity.HIGH ?? 0,
          mediumCount: summary.by_severity.MEDIUM ?? 0,
          duration: durationStr,
        });
        await sendEmail(env, { to: userRow.email, subject, html, text });
      }
    } catch (e) {
      console.error('[email] scan_complete send failed:', e);
    }

    try {
      if (prefs.critical_found !== false && (summary.by_severity.CRITICAL ?? 0) > 0) {
        const criticalFindings = allFindings
          .filter((f) => f.severity === 'CRITICAL')
          .slice(0, 5)
          .map((f) => ({ type: f.type, url: f.url, description: f.description }));
        const { subject, html, text } = criticalAlertEmail({
          email: userRow.email,
          target,
          scanId: scan_id,
          criticalCount: summary.by_severity.CRITICAL,
          findings: criticalFindings,
        });
        await sendEmail(env, { to: userRow.email, subject, html, text });
      }
    } catch (e) {
      console.error('[email] critical_found send failed:', e);
    }
  }
}

export async function handleScanJobError(
  message: ScanJobMessage,
  env: Env,
  error: unknown,
): Promise<void> {
  await updateScanStatus(env, message.scan_id, 'failed', {
    completed_at: Date.now(),
    error_message: String(error).slice(0, 500),
  });
  trackEvent(env, 'scan_failed', {
    user_id: message.user_id,
    scan_id: message.scan_id,
    error: String(error).slice(0, 200),
  });
}

function deduplicateFindings(findings: Finding[], results: ModuleResult[]): Finding[] {
  const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

  // HIGH-07: Key the dedup map by stable string (not object identity) so lookups
  // survive object spread/copy operations used later in the dedup logic.
  const findingKey = (f: Finding): string => `${f.type}::${f.url}::${(f.evidence ?? '').slice(0, 50)}`;
  const findingToModule = new Map<string, string>();
  for (const r of results) {
    for (const f of r.findings) {
      findingToModule.set(findingKey(f), r.module);
    }
  }

  // Normalize URL for grouping (strip trailing slash, lowercase)
  function normalizeUrl(url: string): string {
    try {
      const u = new URL(url);
      return (u.origin + u.pathname.replace(/\/+$/, '') + u.search).toLowerCase();
    } catch {
      return url.toLowerCase().replace(/\/+$/, '');
    }
  }

  // Categorize findings into dedup groups
  function dedupCategory(f: Finding): string {
    const t = f.type.toLowerCase();
    const u = f.url.toLowerCase();

    // debug.log — any module reporting on debug.log file
    if (t.includes('debug_log') || t.includes('error_log') || u.includes('debug.log')) return 'debug_log';

    // user / account enumeration — all user discovery and login-enumeration types
    if (
      t.includes('user_exposed') || t.includes('user_enum') || t.includes('user_email') ||
      t.includes('user_data') || t.includes('author_username') || t.includes('user_oembed') ||
      t.includes('login_user_enum') || t.includes('login_username_enum') ||
      t.includes('lostpass_email_enum') ||
      u.includes('/wp-json/wp/v2/users')
    ) return 'user_enum';

    // wp-cron — any finding about wp-cron.php regardless of type
    if (u.includes('wp-cron.php') || t.includes('wpcron') || t === 'cron_accessible' || t === 'wp_cron') return 'wpcron';

    // rate limiting — merge rate-limit findings even if module names differ
    if (t.includes('rate_limit') || t.includes('no_rate_limit') || t.includes('rate_limit_absent')) return 'rate_limiting';

    // WordPress emoji — all emoji-related findings describe the same underlying configuration
    if (t.includes('wp_emoji') || t.includes('emoji_dns') || t.includes('emoji_version')) return 'emoji';

    // server header — SERVER_HEADER_SERVER from any module at the same URL
    if (t === 'server_header_server' || (t.startsWith('server_header') && (t.endsWith('_server') || t === 'server_header_server'))) return 'server_header';

    // X-Frame-Options / clickjacking — all framing-related findings
    if (t.includes('clickjacking') || t.includes('frame_option') || t.includes('missing_frame')) return 'xframe';

    // Cookie SameSite — two modules report the same underlying issue with different type names
    if (t.includes('samesite') || t.includes('same_site')) return 'cookie_samesite';

    // Return the type itself for other findings
    return t;
  }

  // Categories where the issue is site-wide — one finding per site regardless of which URL triggered it
  const SITE_WIDE_CATEGORIES = new Set([
    'user_enum', 'user_enumeration',
    'debug_log',
    'wpcron', 'wp_cron', 'cron_accessible',
    'rate_limiting', 'no_rate_limiting', 'rate_limit_absent',
    'emoji',
    'server_header',
  ]);

  // Group by dedup key: site-wide categories collapse to one per site; others key on URL + category
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const category = dedupCategory(f);
    const key = SITE_WIDE_CATEGORIES.has(category)
      ? `site||${category}`
      : `${normalizeUrl(f.url)}||${category}`;
    const group = groups.get(key) ?? [];
    group.push(f);
    groups.set(key, group);
  }

  const deduped: Finding[] = [];
  for (const [, group] of groups) {
    if (group.length === 1) {
      deduped.push(group[0]);
      continue;
    }

    // For user enumeration: merge all per-user findings into ONE finding
    const category = dedupCategory(group[0]);
    if (category === 'user_enum') {
      // Sort by severity, then description length
      group.sort((a, b) => {
        const sevDiff = (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5);
        if (sevDiff !== 0) return sevDiff;
        return (b.description.length) - (a.description.length);
      });
      const best = { ...group[0] };
      const otherModules = group
        .slice(1)
        .map(f => findingToModule.get(findingKey(f)))
        .filter((m): m is string => !!m);
      const uniqueModules = [...new Set(otherModules)];
      if (uniqueModules.length > 0) {
        best.evidence = (best.evidence ?? '') + `\nAlso detected by: ${uniqueModules.join(', ')}`;
      }
      deduped.push(best);
      continue;
    }

    // General dedup: keep highest severity, most detailed description, most replication steps
    group.sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5);
      if (sevDiff !== 0) return sevDiff;
      const stepsA = a.replication_steps?.length ?? 0;
      const stepsB = b.replication_steps?.length ?? 0;
      if (stepsB !== stepsA) return stepsB - stepsA;
      return (b.description.length) - (a.description.length);
    });
    const best = { ...group[0] };
    const otherModules = group
      .slice(1)
      .map(f => findingToModule.get(findingKey(f)))
      .filter((m): m is string => !!m);
    const uniqueModules = [...new Set(otherModules)];
    if (uniqueModules.length > 0) {
      best.evidence = (best.evidence ?? '') + `\nAlso detected by: ${uniqueModules.join(', ')}`;
    }
    deduped.push(best);
  }

  // Re-sort by severity
  deduped.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5));

  // Secondary dedup pass: same type + same evidence at different URLs → merge into one finding.
  // This handles cases like FEED_EMAIL_DISCLOSURE where the same email is found in multiple feed URLs.
  const evidenceGroups = new Map<string, Finding[]>();
  for (const f of deduped) {
    const ev = (f.evidence ?? '').trim();
    if (!ev) continue;
    const key = `${f.type.toLowerCase()}|||${ev}`;
    const group = evidenceGroups.get(key) ?? [];
    group.push(f);
    evidenceGroups.set(key, group);
  }
  const mergedSet = new Set<Finding>();
  const extraFindings: Finding[] = [];
  for (const [, group] of evidenceGroups) {
    if (group.length < 2) continue;
    const best = { ...group[0] };
    const otherUrls = group.slice(1).map((f) => f.url);
    best.evidence = (best.evidence ?? '') + `\nAlso found at: ${otherUrls.join(', ')}`;
    for (const f of group) mergedSet.add(f);
    extraFindings.push(best);
  }
  const finalFindings = deduped.filter((f) => !mergedSet.has(f)).concat(extraFindings);
  finalFindings.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5));
  return finalFindings;
}

function buildSummary(results: ModuleResult[], findings: Finding[]) {
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return {
    total_modules: results.length,
    vulnerable: results.filter((r) => r.vulnerable).length,
    clean: results.filter((r) => !r.vulnerable).length,
    total_findings: findings.length,
    by_severity: bySeverity,
  };
}

function extractDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

async function fireWebhooks(env: Env, userId: string, payload: Record<string, unknown>): Promise<void> {
  const event = payload.event as string;
  const hooks = await getWebhooksByUserAndEvent(env, userId, event);
  if (hooks.length === 0) return;

  const body = JSON.stringify(payload);
  await Promise.allSettled(
    hooks.map(async (hook) => {
      const signature = await hmacSha256Hex(hook.secret, body);
      await fetch(hook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-JWP-Signature': `sha256=${signature}`,
          'X-JWP-Event': event,
          'User-Agent': 'WPSentry-Webhook/1.0',
        },
        body,
        // @ts-ignore — Cloudflare Workers specific: limit redirect follows
        redirect: 'follow',
      }).catch(console.error);
    }),
  );
}
