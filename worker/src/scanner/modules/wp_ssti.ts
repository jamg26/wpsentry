import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Server-Side Template Injection (SSTI)';

// High-entropy expected values to avoid false positives.
// "60481729" (7777*7777) is unique enough to confirm actual evaluation.
const SSTI_PAYLOADS: [string, string][] = [
  ['{{7777*7777}}',    '60481729'],   // Jinja2 / Twig arithmetic
  ['${7777*7777}',     '60481729'],   // FreeMarker / Velocity
  ['<%= 7777*7777 %>', '60481729'],   // ERB
  ['{{config}}',       '<Config {'],  // Flask/Jinja2 config object
  ['#{7777*7777}',     '60481729'],   // Ruby ERB
];

const TEST_PARAMS = ['s', 'q', 'search', 'query'];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Flatten params × payloads to avoid sequential inner loop
    const paramPayloadCombos = TEST_PARAMS.flatMap((param) =>
      SSTI_PAYLOADS.map(([payload, expected]) => [param, payload, expected] as const),
    );
    await parallelProbe(paramPayloadCombos, async ([param, payload, expected]) => {
      const url = `${target}/?${param}=${encodeURIComponent(payload)}`;
      try {
        const res = await fetchURL(url);
        if (!res) return;
        let body = '';
        try { body = await res.text(); } catch { return; }
        if (body.includes(expected)) {
          findings.push(finding(
            'ssti', 'CRITICAL', url,
            `SSTI detected via GET parameter '${param}'. Payload '${payload}' evaluated to '${expected}'.`,
            {
              replication_steps: [
                `curl -s "${url}"`,
                `# Look for '${expected}' in the response body.`,
                `# If present, the template engine evaluated '${payload}'.`,
              ],
              remediation:
                'Never pass user input directly to template engines. ' +
                'Sanitize and escape all input. Use a sandboxed template environment.',
              evidence: `Payload '${payload}' → '${expected}' reflected in body.`,
            },
          ));
        }
      } catch { /* continue */ }
    }, 20);

    // Test SSTI via REST API post title (only top 2 payloads to stay within budget)
    const restUrl = `${target}/wp-json/wp/v2/posts`;
    await parallelProbe(SSTI_PAYLOADS.slice(0, 2), async ([payload, expected]) => {
      try {
        const res = await fetchURL(restUrl, {
          method: 'POST',
          body: JSON.stringify({ title: payload, content: 'SSTI test', status: 'draft' }),
          headers: { 'Content-Type': 'application/json' },
        });
        if (!res) return;
        if (res.status === 200 || res.status === 201) {
          let body = '';
          try { body = await res.text(); } catch { return; }
          if (body.includes(expected)) {
            findings.push(finding(
              'ssti', 'CRITICAL', restUrl,
              `SSTI detected via WP REST API post title. Payload '${payload}' evaluated to '${expected}'.`,
              {
                replication_steps: [
                  `curl -s -X POST "${restUrl}" \\`,
                  '  -H "Content-Type: application/json" \\',
                  `  -d '{"title": "${payload}", "content": "test", "status": "draft"}'`,
                  `# Look for '${expected}' in JSON response.`,
                ],
                remediation:
                  'Sanitize user-supplied content before passing to template engines. ' +
                  'Review REST API write access controls.',
                evidence: `REST API evaluated '${payload}' → '${expected}'.`,
              },
            ));
          }
        }
      } catch { /* continue */ }
    }, 2);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
