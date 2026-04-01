// Scanner HTTP utility helpers (mirrors modules/utils.py)

import type { Finding, ModuleResult, Severity, ScanState } from './types.js';

const DEFAULT_TIMEOUT_MS = 2_000;

export const HEADERS = {
  'User-Agent': 'WPSentry/3.0 (+https://wpsentry.link/report-abuse; abuse@wpsentry.link)',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.5',
};

export async function fetchURL(
  url: string,
  options: RequestInit & { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<Response | null> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, signal: externalSignal, ...init } = options;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    // Propagate external abort (e.g., module-level AbortController from engine timeout)
    const onExternalAbort = () => controller.abort();
    externalSignal?.addEventListener('abort', onExternalAbort);
    const res = await fetch(url, {
      ...init,
      headers: { ...HEADERS, ...(init.headers as Record<string, string> ?? {}) },
      signal: controller.signal,
      redirect: init.redirect ?? 'follow',
    });
    clearTimeout(timer);
    externalSignal?.removeEventListener('abort', onExternalAbort);
    // Eagerly read the body to free the TCP connection immediately and avoid
    // "stalled HTTP response" deadlocks when many requests run in parallel.
    const bodyText = await res.text().catch(() => '');
    return new Response(bodyText, { status: res.status, statusText: res.statusText, headers: res.headers });
  } catch {
    return null;
  }
}

export async function getText(url: string): Promise<string> {
  const res = await fetchURL(url);
  if (!res) return '';
  try { return await res.text(); } catch { return ''; }
}

export async function getJSON<T = unknown>(url: string): Promise<T | null> {
  const res = await fetchURL(url);
  if (!res) return null;
  try { return await res.json() as T; } catch { return null; }
}

export function finding(
  type: string,
  severity: Severity,
  url: string,
  description: string,
  opts: Partial<Finding> = {},
): Finding {
  return { type, severity, url, description, ...opts };
}

export function moduleResult(
  name: string,
  target: string,
  findings: Finding[],
  errors: string[],
  startMs: number,
): ModuleResult {
  return {
    module: name,
    target,
    vulnerable: findings.some((f) => ['CRITICAL', 'HIGH', 'MEDIUM'].includes(f.severity)),
    findings,
    errors,
    duration_ms: Date.now() - startMs,
  };
}

/** Normalise target: strip trailing slash, ensure https:// */
export function normalizeTarget(target: string): string {
  return target.replace(/\/+$/, '');
}

/** Check if a response body contains any of the patterns */
export function containsAny(body: string, patterns: (string | RegExp)[]): boolean {
  return patterns.some((p) =>
    typeof p === 'string' ? body.includes(p) : p.test(body),
  );
}

/** Extract WordPress version from HTML */
export function extractWPVersion(html: string): string | null {
  const m =
    html.match(/meta name="generator" content="WordPress ([0-9.]+)"/i) ??
    html.match(/\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
  return m ? m[1] : null;
}

export function extractDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

/**
 * Return a cached response for `url` if one exists in `state.responseCache` and is < 60s old.
 * Falls back to a live fetchURL() call when the cache misses.
 * Use this in modules that re-fetch URLs already pre-fetched by the engine (homepage, robots.txt, etc.)
 * to avoid redundant network round-trips.
 */
export async function getCachedResponse(
  url: string,
  state?: ScanState,
  options: RequestInit & { timeoutMs?: number } = {},
): Promise<Response | null> {
  const cached = state?.responseCache?.get(url);
  if (cached && Date.now() - cached.timestamp < 60_000) {
    return new Response(cached.body, { status: cached.status, headers: cached.headers });
  }
  return fetchURL(url, options);
}

export async function parallelProbe<T>(
  items: T[],
  fn: (item: T) => Promise<unknown>,
  concurrency = 15,
): Promise<void> {
  const queue = [...items];
  async function worker() {
    while (queue.length > 0) {
      const item = queue.shift();
      if (item !== undefined) await fn(item).catch(() => {});
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
}
