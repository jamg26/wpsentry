import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Debug & Information Disclosure';

// HIGH-09: Tightened patterns require PHP severity prefix to avoid matching
// blog post dates or other formatted content (e.g. "01-Jan-2024 on line 5").
const PHP_ERROR_LOG_PATTERN = /\[(0[1-9]|[12]\d|3[01])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{4} \d{2}:\d{2}:\d{2} UTC\] PHP (Fatal error|Warning|Notice|Deprecated|Parse error):/;
const PHP_LINE_PATTERN = /PHP (Fatal error|Warning|Notice) .+ on line \d+/;

const PHP_ERROR_PATTERNS = [
  /<b>Warning<\/b>:/i,
  /<b>Notice<\/b>:/i,
  /<b>Fatal error<\/b>:/i,
  /<b>Parse error<\/b>:/i,
  /Stack trace:/i,
  /Call Stack:/i,
  /on line <b>\d+<\/b>/i,
  /in <b>.*?<\/b> on line/i,
  /PHP Warning:/i,
  /PHP Notice:/i,
  /PHP Fatal error:/i,
];

const SENSITIVE_HEADERS: [string, string, Finding['severity']][] = [
  ['X-Powered-By',  'PHP version exposed via X-Powered-By header',           'LOW'],
  ['Server',        'Web server version exposed via Server header',            'LOW'],
  ['X-Generator',   'Generator header discloses CMS',                         'LOW'],
  ['X-Debug-Token', 'Symfony/debug token exposed',                            'MEDIUM'],
  ['X-Pingback',    'Pingback URL disclosed (XML-RPC endpoint hint)',          'LOW'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await Promise.allSettled([
      // 1. Homepage checks
      (async () => {
        const rHome = await fetchURL(`${target}/`);
        if (!rHome) return;
        let homeBody = '';
        try { homeBody = await rHome.text(); } catch { /**/ }
        for (const pattern of PHP_ERROR_PATTERNS) {
          if (pattern.test(homeBody)) {
            findings.push(finding('PHP_ERROR_EXPOSED', 'MEDIUM', `${target}/`,
              'PHP error/warning message visible in homepage source'));
            break;
          }
        }
        for (const [header, desc, severity] of SENSITIVE_HEADERS) {
          const val = rHome.headers.get(header) ?? '';
          if (!val) continue;
          if (header === 'Server') {
            const CDN_NAMES = ['cloudflare', 'fastly', 'akamai', 'varnish', 'sucuri', 'incapsula', 'imperva'];
            const isCDN = CDN_NAMES.some(cdn => val.toLowerCase().includes(cdn));
            const hasVersion = /\d+\.\d+/.test(val);
            if (isCDN && !hasVersion) continue; // skip generic CDN server headers
          }
          findings.push(finding('HEADER_INFO_LEAK', severity, `${target}/`,
            `${desc}: '${val}'`, { evidence: `header: ${header}; value: ${val}` }));
        }
      })(),
      // 2. debug.log files in parallel
      parallelProbe(['/wp-content/debug.log', '/wp-content/uploads/debug.log'], async (logPath) => {
        const r = await fetchURL(`${target}${logPath}`);
        if (!r || r.status !== 200) return;
        let body = '';
        try { body = await r.text(); } catch { /**/ }
        // HIGH-09: Verify content looks like a real PHP error log before flagging.
        // Prevents false positives from generic files that happen to be named debug.log.
        const isErrorLog = body.length > 20 && (PHP_ERROR_LOG_PATTERN.test(body) || PHP_LINE_PATTERN.test(body));
        if (isErrorLog) findings.push(finding('DEBUG_LOG_EXPOSED', 'CRITICAL', `${target}${logPath}`,
          `WordPress debug.log is publicly accessible (${body.length} bytes) — may contain stack traces, DB queries, file paths, and credentials`,
          { remediation: 'Delete debug.log from web root. Set WP_DEBUG_LOG to a non-web-accessible path. Add deny rules in .htaccess.' }));
      }),
      // 3. phpinfo scripts in parallel
      parallelProbe(['/phpinfo.php', '/info.php', '/php_info.php', '/test.php', '/check.php'], async (phpinfoPath) => {
        const r = await fetchURL(`${target}${phpinfoPath}`);
        if (!r || r.status !== 200) return;
        let body = '';
        try { body = await r.text(); } catch { /**/ }
        if (body.toLowerCase().includes('phpinfo()')) findings.push(finding('PHPINFO_EXPOSED', 'HIGH',
          `${target}${phpinfoPath}`, `phpinfo() output accessible at ${phpinfoPath}`));
      }),
      // 4. REST API settings + install page in parallel
      (async () => {
        const rJson = await fetchURL(`${target}/wp-json/wp/v2/settings`);
        if (rJson && rJson.status === 200) {
          try {
            const data = await rJson.json();
            if (typeof data === 'object' && data !== null && JSON.stringify(data).toLowerCase().includes('email')) {
              findings.push(finding('ADMIN_INFO_REST_API', 'MEDIUM', `${target}/wp-json/wp/v2/settings`,
                'Admin email/settings accessible via unauthenticated REST API call'));
            }
          } catch { /**/ }
        }
      })(),
      (async () => {
        const rInstall = await fetchURL(`${target}/wp-admin/install.php`);
        if (rInstall && rInstall.status === 200) {
          let body = '';
          try { body = await rInstall.text(); } catch { /**/ }
          if (body.includes('WordPress') && !body.toLowerCase().includes('already installed')) {
            findings.push(finding('INSTALL_SCRIPT_ACCESSIBLE', 'HIGH', `${target}/wp-admin/install.php`,
              'WordPress install script is accessible — site may be reinstallable'));
          }
        }
      })(),
    ]);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
