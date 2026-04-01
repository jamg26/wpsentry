import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Database Prefix Exposure';

const DB_ERROR_PATTERNS = [
  /table '[a-zA-Z0-9_]*?wp_/i,
  /\bwp_options\b/i,
  /\bwp_users\b/i,
  /\bwp_posts\b/i,
  /\bwp_postmeta\b/i,
  /\bwp_usermeta\b/i,
  /\bwp_comments\b/i,
  /\bwp_terms\b/i,
  /\bwp_term_taxonomy\b/i,
  /\bwp_term_relationships\b/i,
];

const CUSTOM_PREFIX_PATTERN = /table '([a-zA-Z0-9_]+?)_options'/i;

const PROBE_PATHS = [
  '/?p=99999999',
  '/wp-admin/admin-ajax.php?action=test',
  '/?s=%27',
  '/?author=99999',
  '/wp-content/debug.log',
  '/?rest_route=/wp/v2/posts&status=invalid',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    let prefixFound = false;
    await parallelProbe(PROBE_PATHS, async (path) => {
      if (prefixFound) return;
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res) return;
      const body = await res.text();

      // Check for default wp_ prefix in SQL errors
      for (const pattern of DB_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          prefixFound = true;
          findings.push(finding('DB_PREFIX_DEFAULT', 'LOW', url,
            'Default WordPress database table prefix "wp_" detected in error output', {
              evidence: `SQL error or debug output contains default "wp_" table references`,
              replication_steps: [
                `Visit ${url}`,
                'Examine page source for SQL error messages containing "wp_" table names',
              ],
              remediation: 'Change the WordPress database table prefix from the default "wp_" to a custom value in wp-config.php. Suppress SQL errors in production by setting WP_DEBUG to false.',
            }));
          return;
        }
      }

      // Check for custom prefix exposure
      const customMatch = CUSTOM_PREFIX_PATTERN.exec(body);
      if (customMatch && customMatch[1] !== 'wp') {
        prefixFound = true;
        findings.push(finding('DB_PREFIX_EXPOSED', 'MEDIUM', url,
          `Custom database table prefix "${customMatch[1]}_" exposed in error output`, {
            evidence: `Table prefix "${customMatch[1]}_" found in SQL error`,
            replication_steps: [
              `Visit ${url}`,
              'Examine page source for SQL error messages exposing table prefix',
            ],
            remediation: 'Suppress SQL errors in production by setting WP_DEBUG to false and ensuring display_errors is off.',
          }));
      }
    }, 6);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
