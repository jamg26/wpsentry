import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'JavaScript Prototype Pollution';

// Test params to inject into GET requests
const GET_PROBE_PARAMS = [
  '__proto__[polluted]=jwpscanner1',
  'constructor[prototype][polluted]=jwpscanner1',
  '__proto__.polluted=jwpscanner1',
];

// REST API endpoints that accept JSON bodies
const REST_ENDPOINTS = [
  '/wp-json/wp/v2/comments',
  '/wp-json/wp/v2/posts',
  '/wp-json/wp/v2/users/me',
];

// JSON bodies that attempt prototype pollution
const JSON_PAYLOADS = [
  '{"__proto__":{"admin":true,"polluted":"jwpscanner1"}}',
  '{"constructor":{"prototype":{"admin":true,"polluted":"jwpscanner1"}}}',
  '[{"__proto__":{"polluted":"jwpscanner1"}}]',
];

// Unusual error patterns that indicate reflection or JS-side processing
const REFLECTION_INDICATORS = [
  'jwpscanner1',
  'polluted',
  'prototype',
  '__proto__',
  'constructor.prototype',
];

// Error patterns suggesting the payload caused unexpected behavior
const ERROR_INDICATORS = [
  'Cannot set property',
  'Cannot assign to read only',
  'prototype is read-only',
  'cyclic object value',
  'converting circular structure',
  'Maximum call stack',
  'too much recursion',
  'Internal Server Error',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const seen = new Set<string>();

    // GET-based pollution probes
    const getProbes: Array<[string, string]> = [];
    for (const param of GET_PROBE_PARAMS) {
      getProbes.push([`/?${param}`, param]);
      getProbes.push([`/?s=test&${param}`, `search:${param}`]);
    }

    await parallelProbe(getProbes, async ([path, label]) => {
      if (seen.has('GET')) return;
      const url = target + path;
      const res = await fetchURL(url, { timeoutMs: 4_000 });
      if (!res) return;

      const text = await res.text().catch(() => '');
      const reflected = REFLECTION_INDICATORS.find(ind => text.includes(ind) && ind !== 'prototype' && ind !== '__proto__');
      if (reflected && !seen.has('GET')) {
        seen.add('GET');
        findings.push(finding(
          'PROTOTYPE_POLLUTION_REFLECTED',
          'HIGH',
          url,
          `Prototype pollution indicator reflected in response via GET param: ${label}`,
          {
            evidence: `reflected="${reflected}" url="${url}"`,
            remediation: 'Sanitize object keys on server-side. Use Object.create(null) or freeze prototypes. Update Node.js/JavaScript dependencies.',
          },
        ));
      }
    }, 10);

    // REST API JSON body probes
    const restCombos: Array<[string, string]> = [];
    for (const endpoint of REST_ENDPOINTS) {
      for (const payload of JSON_PAYLOADS) {
        restCombos.push([endpoint, payload]);
      }
    }

    await parallelProbe(restCombos, async ([endpoint, payload]) => {
      if (seen.has(endpoint)) return;
      const url = target + endpoint;
      const res = await fetchURL(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        timeoutMs: 5_000,
      });
      if (!res) return;

      const text = await res.text().catch(() => '');
      const textLower = text.toLowerCase();

      // Check for reflection of injected property
      const reflected = REFLECTION_INDICATORS.find(ind =>
        ind === 'jwpscanner1' && text.includes(ind)
      );
      const errorTriggered = ERROR_INDICATORS.find(ind => textLower.includes(ind.toLowerCase()));

      if ((reflected || errorTriggered) && !seen.has(endpoint)) {
        seen.add(endpoint);
        const indicator = reflected ?? errorTriggered ?? 'unknown';
        findings.push(finding(
          'PROTOTYPE_POLLUTION_REST',
          'HIGH',
          url,
          `REST API endpoint may be vulnerable to prototype pollution. Indicator: '${indicator}'`,
          {
            evidence: `endpoint="${endpoint}" payload="${payload.slice(0, 80)}" indicator="${indicator}"`,
            remediation: 'Validate and sanitize JSON input server-side. Use JSON schema validation. Avoid recursive object merges on user-controlled data.',
          },
        ));
      }
    }, 15);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
