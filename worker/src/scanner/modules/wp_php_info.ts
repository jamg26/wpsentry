import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'phpinfo() Exposure Scanner';

const PHPINFO_PATHS = [
  '/phpinfo.php',
  '/info.php',
  '/php_info.php',
  '/test.php',
  '/i.php',
  '/pi.php',
  '/php.php',
  '/temp.php',
  '/old.php',
  '/_phpinfo.php',
  '/wp-content/phpinfo.php',
  '/wp-includes/phpinfo.php',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(PHPINFO_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      // Must contain actual phpinfo() output, not just any PHP page
      if (body.includes('<title>phpinfo()</title>') || body.includes('PHP Version') && body.includes('PHP License')) {
        const versionMatch = body.match(/<h1[^>]*>PHP Version ([0-9.]+)<\/h1>/i);
        const phpVersion = versionMatch ? versionMatch[1] : 'unknown';

        findings.push(finding('PHPINFO_EXPOSED', 'HIGH', url,
          `phpinfo() page exposed at ${path} — PHP version ${phpVersion}`, {
            evidence: `phpinfo() output accessible, PHP ${phpVersion}`,
            replication_steps: [
              `Navigate to ${url}`,
              'Full PHP configuration including loaded modules, environment variables, and server paths is visible',
            ],
            remediation: `Delete the phpinfo file at ${path}. Never leave phpinfo() scripts on production servers.`,
          }));

        // Check for sensitive info in phpinfo
        if (body.includes('DOCUMENT_ROOT') || body.includes('SERVER_ADMIN')) {
          findings.push(finding('PHPINFO_SENSITIVE_DATA', 'HIGH', url,
            'phpinfo() exposes server paths, admin email, and environment variables', {
              evidence: 'DOCUMENT_ROOT and SERVER_ADMIN visible in phpinfo output',
              replication_steps: [
                `Visit ${url}`,
                'Search for DOCUMENT_ROOT, SERVER_ADMIN, database connection variables',
              ],
              remediation: 'Remove the phpinfo file immediately. Sensitive server configuration is fully exposed.',
            }));
        }
      }
    }, 6);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
