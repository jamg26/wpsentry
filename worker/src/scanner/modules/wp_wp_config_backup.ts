import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'wp-config.php Backup Scanner';

const CONFIG_BACKUP_PATHS = [
  '/wp-config.php.bak',
  '/wp-config.php.old',
  '/wp-config.php.orig',
  '/wp-config.php.save',
  '/wp-config.php.swp',
  '/wp-config.php.swo',
  '/wp-config.php~',
  '/wp-config.php.txt',
  '/wp-config.php.dist',
  '/wp-config.php.html',
  '/wp-config.bak',
  '/wp-config.old',
  '/wp-config.txt',
  '/wp-config.php.backup',
  '/wp-config-backup.php',
  '/wp-config-sample.php',
  '/.wp-config.php.swp',
  '/wp-config.php.1',
  '/wp-config.php.2',
  '/wp-config copy.php',
];

const CONFIG_INDICATORS = [
  'DB_NAME',
  'DB_USER',
  'DB_PASSWORD',
  'DB_HOST',
  'table_prefix',
  'AUTH_KEY',
  'SECURE_AUTH_KEY',
  'LOGGED_IN_KEY',
  'NONCE_KEY',
  'ABSPATH',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(CONFIG_BACKUP_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      if (body.length < 50) return;

      // Count how many config indicators are present
      const matchCount = CONFIG_INDICATORS.filter(ind => body.includes(ind)).length;

      if (matchCount >= 3) {
        // Strong match — this is definitely a wp-config backup
        const hasPassword = body.includes('DB_PASSWORD') &&
          (body.match(/DB_PASSWORD['"]\s*,\s*['"]([^'"]+)['"]/) !== null);

        findings.push(finding('WP_CONFIG_BACKUP_EXPOSED', 'CRITICAL', url,
          `wp-config.php backup file exposed at ${path} — database credentials visible`, {
            evidence: `${matchCount} WordPress configuration constants found in ${path}${hasPassword ? ' including DB_PASSWORD' : ''}`,
            replication_steps: [
              `Fetch ${url}`,
              'File contains WordPress database credentials and authentication keys',
              'An attacker can use these credentials to access the database directly',
            ],
            remediation: `Delete ${path} immediately. Never store config backups in the web root. Block .bak, .old, .orig, .save file extensions in server configuration.`,
          }));
      } else if (matchCount >= 1) {
        // Partial match — could be a config file
        findings.push(finding('WP_CONFIG_BACKUP_PARTIAL', 'HIGH', url,
          `Possible wp-config backup at ${path} — contains WordPress configuration data`, {
            evidence: `${matchCount} WordPress configuration indicator(s) found`,
            replication_steps: [
              `Fetch ${url}`,
              'Check for WordPress configuration constants',
            ],
            remediation: `Investigate and delete ${path} if it contains sensitive configuration data.`,
          }));
      }
    }, 10);

    // Also check wp-config-sample.php for information disclosure
    const sampleUrl = `${target}/wp-config-sample.php`;
    const sampleRes = await fetchURL(sampleUrl);
    if (sampleRes && sampleRes.status === 200) {
      const sampleBody = await sampleRes.text();
      if (sampleBody.includes('DB_NAME') && sampleBody.includes('database_name_here')) {
        findings.push(finding('WP_CONFIG_SAMPLE_PRESENT', 'LOW', sampleUrl,
          'wp-config-sample.php is accessible — confirms WordPress installation', {
            evidence: 'Sample configuration file is accessible',
            replication_steps: [`Fetch ${sampleUrl}`, 'Observe default configuration template'],
            remediation: 'Delete wp-config-sample.php from the web root after installation.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
