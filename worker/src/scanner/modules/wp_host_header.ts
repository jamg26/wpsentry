import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Host Header Injection';

const EVIL_HOST = 'evil.attacker.com';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  let realHost = '';
  try { realHost = new URL(target).host; } catch { realHost = target; }

  const injectHeaders: Record<string, string> = {
    'Host':               EVIL_HOST,
    'X-Forwarded-Host':   EVIL_HOST,
    'X-Forwarded-Server': EVIL_HOST,
    'X-Host':             EVIL_HOST,
  };

  try {
    type TestConfig = [string, Record<string, string>, string];
    const tests: TestConfig[] = [
      [`${target}/`, injectHeaders, 'homepage'],
      [`${target}/wp-login.php?action=lostpassword`, injectHeaders, 'password-reset'],
      [`${target}/`, { 'Host': realHost, 'X-Forwarded-Host': EVIL_HOST }, 'x-forwarded-host only'],
    ];

    await parallelProbe(tests, async ([url, headers, label]) => {
      try {
        const res = await fetchURL(url, { headers });
        if (!res) return;
        const body = await res.text();
        const loc = res.headers.get('Location') ?? '';
        const reflectedBody = body.includes(EVIL_HOST);
        const reflectedLoc = loc.includes(EVIL_HOST);

        if (reflectedBody || reflectedLoc) {
          const where = reflectedLoc ? 'Location header' : 'response body';
          findings.push(finding(
            'host_header_injection', 'HIGH', url,
            `Host header '${EVIL_HOST}' reflected in ${where} (${label}). ` +
            'Attackers can poison password-reset links or cache entries.',
            {
              replication_steps: [
                `curl -sk -H "Host: ${EVIL_HOST}" \\`,
                `     -H "X-Forwarded-Host: ${EVIL_HOST}" \\`,
                `     "${url}" -D-`,
                `# Observe '${EVIL_HOST}' reflected in ${where}.`,
              ],
              remediation:
                'Whitelist allowed Host header values in WordPress and web server config. ' +
                'In wp-config.php set WP_HOME and WP_SITEURL explicitly. ' +
                'Configure Apache/Nginx to reject requests with unexpected Host headers.',
              evidence: `Reflected in ${where} (${label}).`,
            },
          ));
        }
      } catch { /* continue */ }
    }, 3);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
