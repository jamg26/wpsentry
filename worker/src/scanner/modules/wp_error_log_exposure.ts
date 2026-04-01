import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Error Log Exposure Scanner';

const LOG_PATHS = [
  '/wp-content/debug.log',
  '/wp-content/uploads/debug.log',
  '/debug.log',
  '/error_log',
  '/error.log',
  '/php_errors.log',
  '/wp-content/error.log',
  '/wp-content/php_errors.log',
  '/logs/error.log',
  '/logs/debug.log',
  '/wp-admin/error_log',
  '/wp-includes/error_log',
  '/.logs/error.log',
  '/wp-content/uploads/error.log',
];

const LOG_INDICATORS = [
  /PHP (?:Warning|Notice|Fatal error|Parse error|Deprecated)/i,
  /\[\d{2}-\w{3}-\d{4}/,
  /Stack trace:/i,
  /WordPress database error/i,
  /on line \d+/i,
  /Call Stack/i,
  /\[error\]/i,
  /\[warn\]/i,
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(LOG_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      // Must contain actual log content, not a generic page
      if (body.length < 50) return;

      const isLog = LOG_INDICATORS.some(p => p.test(body));
      if (!isLog) return;

      // Determine severity based on content — debug.log is CRITICAL
      const isDebugLog = path.includes('debug.log');
      let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' = isDebugLog ? 'CRITICAL' : 'MEDIUM';
      const sensitivePatterns = [
        /password/i,
        /DB_PASSWORD/i,
        /DB_USER/i,
        /secret/i,
        /api[_-]?key/i,
        /auth[_-]?token/i,
        /\/home\/[a-z]/i,
        /\/var\/www/i,
      ];

      const hasSensitive = sensitivePatterns.some(p => p.test(body));
      if (hasSensitive && severity !== 'CRITICAL') severity = 'HIGH';

      const sizeKB = Math.round(body.length / 1024);
      findings.push(finding('ERROR_LOG_EXPOSED', severity, url,
        `Error log exposed at ${path} (${sizeKB}KB)${hasSensitive ? ' — contains sensitive data' : ''}`, {
          evidence: `Log file accessible at ${url}, size: ${sizeKB}KB, contains PHP error/log entries`,
          replication_steps: [
            `Fetch ${url}`,
            `Observe ${sizeKB}KB of log data containing PHP errors and server paths`,
            ...(hasSensitive ? ['Log contains potentially sensitive information (paths, credentials, API keys)'] : []),
          ],
          remediation: `Delete or restrict access to ${path}. Add a deny rule in .htaccess for log files. Set WP_DEBUG_LOG to a non-web-accessible path.`,
        }));
    }, 7);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
