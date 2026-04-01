import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget} from '../utils.js';

const MODULE_NAME = 'Cache Poisoning';

/** Three-tier cache status: cached (definitely stored), ambiguous, or uncached (definitely not stored) */
function getCacheStatus(headers: Headers): 'cached' | 'ambiguous' | 'uncached' {
  const cfCache = headers.get('cf-cache-status')?.toUpperCase();
  if (cfCache === 'HIT' || cfCache === 'STALE') return 'cached';
  if (cfCache === 'DYNAMIC' || cfCache === 'BYPASS' || cfCache === 'EXPIRED') return 'uncached';

  const cc = headers.get('cache-control') ?? '';
  if (/no-store|no-cache|private/.test(cc)) return 'uncached';
  if (/max-age=0/.test(cc)) return 'ambiguous';

  return 'ambiguous';
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const baseUrl = `${target}/`;

  try {
    // Test 1: X-Forwarded-Host reflection
    const attackerHost = 'evil.attacker.com';
    const xfhRes = await fetchURL(baseUrl, {
      headers: { 'X-Forwarded-Host': attackerHost },
    });
    if (xfhRes) {
      const body = await xfhRes.text();
      const reflected = body.includes(attackerHost);
      const locationPoisoned = (xfhRes.headers.get('Location') ?? '').includes(attackerHost);
      const linkPoisoned = (xfhRes.headers.get('Link') ?? '').includes(attackerHost);
      if (reflected || locationPoisoned || linkPoisoned) {
        const evidenceLocation = reflected ? 'body' : locationPoisoned ? 'Location header' : 'Link header';
        const cacheStatus = getCacheStatus(xfhRes.headers);
        if (cacheStatus === 'uncached') {
          // Definitively not cached — poisoning is not exploitable; skip finding
        } else {
          const severity = cacheStatus === 'cached' ? 'HIGH' as const : 'MEDIUM' as const;
          const cacheNote = cacheStatus === 'cached' ? '' : ' (response may or may not be cached — verify exploitability)';
          findings.push(finding(
            'cache_poisoning', severity, baseUrl,
            `X-Forwarded-Host header value '${attackerHost}' is reflected in the response (${evidenceLocation}).${cacheNote} If cached, all users may be served attacker-controlled content.`,
            {
              replication_steps: [
                `curl -s -H "X-Forwarded-Host: ${attackerHost}" "${baseUrl}" | grep -i "${attackerHost}"`,
                `curl -sI -H "X-Forwarded-Host: ${attackerHost}" "${baseUrl}" | grep -i "location\\|link"`,
                '# If cached, subsequent requests without header may also receive poisoned content',
              ],
              remediation: 'Strip or validate X-Forwarded-Host at the load balancer/CDN. Ensure cache keys include Host header.',
              evidence: `Attacker host reflected in ${evidenceLocation}`,
            },
          ));
        }
      }
    }

    // Test 2: X-Forwarded-Scheme structural reflection (avoid false positives)
    const xfsRes = await fetchURL(baseUrl, {
      headers: { 'X-Forwarded-Scheme': 'javascript' },
    });
    if (xfsRes) {
      const body = await xfsRes.text();
      const structuralReflect = /(?:href|src|action|content)\s*=\s*["']javascript:\/\//i.test(body);
      const locationReflect = (xfsRes.headers.get('Location') ?? '').includes('javascript');
      if (structuralReflect || locationReflect) {
        const cacheStatus2 = getCacheStatus(xfsRes.headers);
        if (cacheStatus2 === 'uncached') {
          // Definitively not cached — poisoning is not exploitable; skip finding
        } else {
          const severity2 = cacheStatus2 === 'cached' ? 'HIGH' as const : 'MEDIUM' as const;
          const cacheNote2 = cacheStatus2 === 'cached' ? '' : ' (response may or may not be cached — verify exploitability)';
          findings.push(finding(
            'cache_poisoning', severity2, baseUrl,
            `X-Forwarded-Scheme: javascript reflected in a URL-bearing response attribute.${cacheNote2} May enable XSS via cache poisoning.`,
            {
              replication_steps: [
                `curl -s -H "X-Forwarded-Scheme: javascript" "${baseUrl}" | grep -iP "(href|src|action)\\s*=\\s*[\"']javascript://"`,
              ],
              remediation: 'Validate and whitelist X-Forwarded-Scheme values (http/https only).',
              evidence: "'javascript://' reflected in URL-bearing attribute",
            },
          ));
        }
      }
    }

    // Test 3: X-Original-URL bypass to wp-admin
    const xouRes = await fetchURL(baseUrl, {
      headers: { 'X-Original-URL': '/wp-admin/' },
    });
    if (xouRes && xouRes.status === 200) {
      const body = await xouRes.text();
      // Require actual admin DOM elements — 'wp-admin/admin' alone matches admin-ajax.php on any WP site
      const hasAdminContent =
        body.includes('id="wpbody"') ||
        body.includes('id="adminmenuwrap"') ||
        body.includes('id="wpadminbar"') ||
        body.includes('class="wp-admin"') ||
        (body.includes('wp-admin') && body.includes('adminmenu'));
      if (xouRes.url.includes('wp-admin') || hasAdminContent) {
        const cacheStatus3 = getCacheStatus(xouRes.headers);
        if (cacheStatus3 === 'uncached') {
          // Definitively not cached — skip finding
        } else {
          const severity3 = cacheStatus3 === 'cached' ? 'HIGH' as const : 'MEDIUM' as const;
          const cacheNote3 = cacheStatus3 === 'cached' ? '' : ' (response may or may not be cached — verify exploitability)';
          findings.push(finding(
            'cache_poisoning', severity3, baseUrl,
            `X-Original-URL header allowed access to /wp-admin/ (HTTP 200).${cacheNote3} This may bypass WAF or access control rules.`,
            {
              replication_steps: [
                `curl -s -H "X-Original-URL: /wp-admin/" "${baseUrl}" | grep -i "dashboard\\|wp-admin"`,
              ],
              remediation: 'Strip X-Original-URL/X-Rewrite-URL headers at the proxy layer.',
              evidence: `HTTP ${xouRes.status} with X-Original-URL: /wp-admin/`,
            },
          ));
        }
      }
    }

    // Test 4: X-Rewrite-URL bypass
    const xruRes = await fetchURL(baseUrl, {
      headers: { 'X-Rewrite-URL': '/wp-admin/' },
    });
    if (xruRes && xruRes.status === 200) {
      const body = await xruRes.text();
      // Require actual admin DOM elements — 'wp-admin/admin' alone matches admin-ajax.php on any WP site
      const hasAdminContent =
        body.includes('id="wpbody"') ||
        body.includes('id="adminmenuwrap"') ||
        body.includes('id="wpadminbar"') ||
        body.includes('class="wp-admin"') ||
        (body.includes('wp-admin') && body.includes('adminmenu'));
      if (hasAdminContent) {
        const cacheStatus4 = getCacheStatus(xruRes.headers);
        if (cacheStatus4 === 'uncached') {
          // Definitively not cached — skip finding
        } else {
          const severity4 = cacheStatus4 === 'cached' ? 'HIGH' as const : 'MEDIUM' as const;
          const cacheNote4 = cacheStatus4 === 'cached' ? '' : ' (response may or may not be cached — verify exploitability)';
          findings.push(finding(
            'cache_poisoning', severity4, baseUrl,
            `X-Rewrite-URL header allowed access to protected path /wp-admin/.${cacheNote4}`,
            {
              replication_steps: [
                `curl -s -H "X-Rewrite-URL: /wp-admin/" "${baseUrl}"`,
              ],
              remediation: 'Remove X-Rewrite-URL header handling or restrict to trusted proxies.',
              evidence: `HTTP ${xruRes.status} with X-Rewrite-URL: /wp-admin/`,
            },
          ));
        }
      }
    }

    // Test 5 & 6: Cache headers analysis + cache buster + poison confirmation
    const cacheBuster = Math.random().toString(16).slice(2, 10);
    const cachedUrl = `${baseUrl}?cb=${cacheBuster}`;
    const [r1, r2] = await Promise.all([
      fetchURL(baseUrl),
      fetchURL(cachedUrl),
    ]);

    if (r1) {
      const cacheHeaders: Record<string, string> = {};
      for (const hdr of ['X-Cache', 'CF-Cache-Status', 'Age', 'Vary', 'Cache-Control']) {
        const val = r1.headers.get(hdr);
        if (val) cacheHeaders[hdr] = val;
      }
      if (Object.keys(cacheHeaders).length > 0) {
        const cacheStatusNote = cacheHeaders['CF-Cache-Status'] ? ` CF-Cache-Status: ${cacheHeaders['CF-Cache-Status']}.` : '';
        findings.push(finding(
          'CDN_CACHING_ACTIVE', 'INFO', baseUrl,
          `CDN caching is active.${cacheStatusNote} Ensure sensitive endpoints use Cache-Control: no-store.`,
          {
            replication_steps: [
              `curl -sI "${baseUrl}" | grep -iE "x-cache|cf-cache|age|vary|cache-control"`,
              `curl -sI "${cachedUrl}" | grep -iE "x-cache|cf-cache|age|vary|cache-control"`,
              '# Compare Age header — if > 0 on ?cb= URL, cache does not key on query string',
            ],
            remediation: 'Ensure cache keys include Host, Vary, and relevant security headers. Purge cache after any configuration change.',
            evidence: `Cache headers: ${JSON.stringify(cacheHeaders)}; CF-Cache-Status: ${cacheHeaders['CF-Cache-Status'] ?? 'absent'}`,
          },
        ));
      }

      // Poison confirmation: only if cache HIT detected
      const xCacheHit = (r1.headers.get('X-Cache') ?? '').toLowerCase();
      const cfStatus = (r1.headers.get('CF-Cache-Status') ?? '').toLowerCase();
      if (xCacheHit.includes('hit') || cfStatus.includes('hit')) {
        const marker = `strix-${Math.random().toString(16).slice(2, 8)}`;
        const rPoison = await fetchURL(baseUrl, {
          headers: { 'X-Forwarded-Host': `${marker}.attacker.com` },
        });
        if (rPoison) {
          const poisonBody = await rPoison.text();
          if (poisonBody.includes(marker)) {
            const rCheck = await fetchURL(baseUrl);
            if (rCheck) {
              const checkBody = await rCheck.text();
              if (checkBody.includes(marker)) {
                findings.push(finding(
                  'cache_poisoning', 'HIGH', baseUrl,
                  `Cache poisoning confirmed: marker '${marker}' injected via X-Forwarded-Host and found in subsequent uncached response.`,
                  {
                    replication_steps: [
                      `curl -s -H "X-Forwarded-Host: ${marker}.attacker.com" "${baseUrl}"`,
                      `curl -s "${baseUrl}" | grep "${marker}"`,
                      '# If marker appears in second request = cache poisoned',
                    ],
                    remediation: 'Immediately purge cache and fix cache key configuration.',
                    evidence: `Marker ${marker} persisted in cached response`,
                  },
                ));
              }
            }
          }
        }
      }
    }
    void r2; // fetched to compare cache behaviour; headers already inspected on r1
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
