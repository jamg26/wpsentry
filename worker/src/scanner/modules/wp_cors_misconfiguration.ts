import type { Finding, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'CORS Misconfiguration (Enhanced)';

const TEST_ORIGINS = [
  { origin: 'https://evil.com',  type: 'arbitrary' },
  { origin: 'null',              type: 'null_origin' },
];

const TEST_ENDPOINTS = [
  '/',
  '/wp-json/',
  '/wp-json/wp/v2/users',
  '/wp-json/wp/v2/posts',
  '/wp-admin/admin-ajax.php',
];

function buildDynamicOrigins(target: string): Array<{ origin: string; type: string }> {
  try {
    const { hostname } = new URL(target);
    return [
      { origin: `https://${hostname}.evil.com`, type: 'suffix_bypass' },
      { origin: `https://evil.${hostname}`,     type: 'prefix_bypass' },
      { origin: `http://${hostname}`,           type: 'http_downgrade' },
    ];
  } catch { return []; }
}

export async function run(target: string, _state?: ScanState) {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const dynamicOrigins = buildDynamicOrigins(target);
    const allOrigins = [...TEST_ORIGINS, ...dynamicOrigins];

    // Flatten endpoint × origin combos and run in parallel batches
    type Combo = { url: string; endpoint: string; origin: string; type: string };
    const combos: Combo[] = TEST_ENDPOINTS.flatMap(ep =>
      allOrigins.map(o => ({ url: target + ep, endpoint: ep, origin: o.origin, type: o.type })),
    );

    // Track which endpoints already have a finding (skip remaining origins for that endpoint)
    const found = new Set<string>();
    const CONCURRENCY = 12;

    for (let i = 0; i < combos.length; i += CONCURRENCY) {
      const batch = combos.slice(i, i + CONCURRENCY).filter(c => !found.has(c.endpoint));
      if (batch.length === 0) continue;

      await Promise.allSettled(batch.map(async ({ url, endpoint, origin, type }) => {
        if (found.has(endpoint)) return;
        try {
          const res = await fetchURL(url, {
            method: 'GET',
            headers: { Origin: origin },
            timeoutMs: 3_000,
            redirect: 'follow',
          });
          if (!res) return;

          const acao = res.headers.get('Access-Control-Allow-Origin') ?? '';
          const acac = res.headers.get('Access-Control-Allow-Credentials') ?? '';
          if (!acao || found.has(endpoint)) return;

          if (acao === '*' && acac.toLowerCase() === 'true') {
            found.add(endpoint);
            findings.push(finding('CORS_WILDCARD_WITH_CREDENTIALS', 'CRITICAL', url,
              `CORS wildcard (*) with credentials — all cookies/auth tokens exposed to any origin`,
              { evidence: `ACAO="*" ACAC="true" endpoint="${endpoint}"`,
                remediation: 'Never combine Access-Control-Allow-Origin: * with credentials. Whitelist specific origins.' }));
          } else if (acao === origin && acac.toLowerCase() === 'true' && type === 'arbitrary') {
            found.add(endpoint);
            findings.push(finding('CORS_REFLECTED_WITH_CREDENTIALS', 'CRITICAL', url,
              `CORS reflects arbitrary origin '${origin}' with credentials — cross-origin credential theft possible`,
              { evidence: `ACAO="${acao}" ACAC="${acac}" endpoint="${endpoint}"`,
                remediation: 'Validate Origin against strict allowlist before reflecting. Never reflect arbitrary origins with credentials.' }));
          } else if ((acao === 'null' || acao === origin) && origin === 'null' && acac.toLowerCase() === 'true') {
            found.add(endpoint);
            findings.push(finding('CORS_NULL_ORIGIN_CREDENTIALS', 'HIGH', url,
              `CORS allows null origin with credentials — sandboxed iframe attack vector`,
              { evidence: `ACAO="${acao}" ACAC="${acac}" endpoint="${endpoint}"`,
                remediation: 'Never allow null origin with credentials. null origin is used by sandboxed iframes.' }));
          } else if (acao === origin && type === 'arbitrary') {
            found.add(endpoint);
            findings.push(finding('CORS_REFLECTED_NO_CREDENTIALS', 'MEDIUM', url,
              `CORS reflects arbitrary origin '${origin}' — unauthenticated cross-origin requests allowed`,
              { evidence: `ACAO="${acao}" endpoint="${endpoint}"`,
                remediation: 'Validate Origin header against an explicit allowlist.' }));
          } else if (acao === origin && (type === 'suffix_bypass' || type === 'prefix_bypass')) {
            found.add(endpoint);
            findings.push(finding('CORS_ORIGIN_BYPASS', 'HIGH', url,
              `CORS origin validation bypass via ${type} — '${origin}' accepted`,
              { evidence: `ACAO="${acao}" bypass_type="${type}" endpoint="${endpoint}"`,
                remediation: 'Use strict equality (===) for Origin validation, not startsWith/endsWith.' }));
          }
        } catch { /* timeout or network error — skip */ }
      }));
    }

    // OPTIONS preflight check on REST endpoints only
    const restEndpoints = TEST_ENDPOINTS.filter(ep => ep.startsWith('/wp-json/'));
    await Promise.allSettled(restEndpoints.map(async ep => {
      if (found.has(ep)) return;
      try {
        const res = await fetchURL(target + ep, {
          method: 'OPTIONS',
          headers: { Origin: 'https://evil.com', 'Access-Control-Request-Method': 'GET' },
          timeoutMs: 3_000,
        });
        if (!res) return;
        const acao = res.headers.get('Access-Control-Allow-Origin') ?? '';
        if (acao === '*' && !findings.some(f => f.url === target + ep && f.type === 'CORS_REST_WILDCARD')) {
          findings.push(finding('CORS_REST_WILDCARD', 'MEDIUM', target + ep,
            `WordPress REST API has CORS wildcard (*) — any origin can read REST API data`,
            { evidence: `ACAO="*" endpoint="${ep}" method="OPTIONS"`,
              remediation: 'Restrict REST API CORS to trusted origins with add_filter("rest_allowed_cors_headers", ...).' }));
        }
      } catch { /* skip */ }
    }));
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}

