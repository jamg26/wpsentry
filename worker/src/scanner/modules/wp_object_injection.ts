import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget , parallelProbe } from '../utils.js';

const MODULE_NAME = 'PHP Object Injection';

const RAW_PAYLOADS = [
  'O:8:"stdClass":0:{}',
  'O:29:"Illuminate\\Support\\MessageBag":0:{}',
  'a:2:{i:0;O:8:"stdClass":0:{}i:1;O:8:"stdClass":0:{}}',
  'O:15:"WP_Fatal_Error_":0:{}',
];

// Each entry: [raw payload, base64-encoded payload]
const PAYLOADS: [string, string][] = RAW_PAYLOADS.map((p) => [p, btoa(p)]);

const ERROR_INDICATORS = [
  'Fatal error',
  'Uncaught exception',
  'unserialize()',
  'Object of class',
  '__wakeup',
  '__destruct',
];

const TEST_PARAMS = ['page_id', 'p', 'cat', 'tag', 'attachment_id'];
const TEST_COOKIES = ['wordpress_logged_in', 'wp_postpass', 'comment_author'];

function buildFinding(
  url: string, rawPayload: string, b64Payload: string, via: string, indicator: string, status: number,
): Finding {
  const isCookie = via.toLowerCase().includes('cookie');
  const cookieName = isCookie ? via.split("'")[1] ?? 'wp-cookie' : '';
  return finding(
    'object_injection', 'CRITICAL', url,
    `Possible PHP Object Injection via ${via}. ` +
    `Serialized payload triggered indicator: '${indicator}' (HTTP ${status}).`,
    {
      replication_steps: [
        `# Inject via ${via}`,
        `# Raw payload: ${rawPayload}`,
        `# Base64 encoded: ${b64Payload}`,
        isCookie
          ? `curl -s "${url.split('?')[0]}" \\`
          : `curl -s "${url}" \\`,
        isCookie
          ? `  -b "${cookieName}=${b64Payload}"`
          : '  # (payload in URL param)',
        'Observe 500 error or PHP exception indicating unserialize() hit.',
      ],
      remediation:
        'Never pass user-controlled data to unserialize(). ' +
        'Use JSON encode/decode instead. ' +
        'Implement an object whitelist if unserialize is unavoidable.',
      evidence: `HTTP ${status} — indicator: '${indicator}'`,
    },
  );
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Flatten params × payloads to avoid sequential inner loop
    const paramCombos = TEST_PARAMS.flatMap((param) =>
      PAYLOADS.map(([rawPayload, b64Payload]) => [param, rawPayload, b64Payload] as const),
    );
    await parallelProbe(paramCombos, async ([param, rawPayload, b64Payload]) => {
      const url = `${target}/?${param}=${encodeURIComponent(rawPayload)}`;
      try {
        const res = await fetchURL(url, { timeoutMs: 10000 });
        if (!res) return;
        let body = '';
        try { body = await res.text(); } catch { return; }
        const indicator = ERROR_INDICATORS.find((i) => body.includes(i));
        if (indicator) {
          findings.push(buildFinding(url, rawPayload, b64Payload, `GET param '${param}'`, indicator, res.status));
        }
      } catch { /* continue */ }
    }, 20);

    // Flatten cookies × payloads to avoid sequential inner loop
    const cookieCombos = TEST_COOKIES.flatMap((cookieName) =>
      PAYLOADS.map(([rawPayload, b64Payload]) => [cookieName, rawPayload, b64Payload] as const),
    );
    await parallelProbe(cookieCombos, async ([cookieName, rawPayload, b64Payload]) => {
      try {
        const res = await fetchURL(`${target}/`, {
          headers: { Cookie: `${cookieName}=${b64Payload}` },
          timeoutMs: 10000,
        });
        if (!res) return;
        let body = '';
        try { body = await res.text(); } catch { return; }
        const indicator = ERROR_INDICATORS.find((i) => body.includes(i));
        if (indicator) {
          findings.push(buildFinding(
            `${target}/`, rawPayload, b64Payload, `cookie '${cookieName}'`, indicator, res.status,
          ));
        }
      } catch { /* continue */ }
    }, 12);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
