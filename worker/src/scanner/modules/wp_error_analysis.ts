import type { ModuleResult, ScanState } from '../types.js';
import type { Severity } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, HEADERS } from '../utils.js';

const MODULE_NAME = 'Error & Exception Analysis';

type ProbeMethod = 'GET' | 'POST';
type Probe = [string, ProbeMethod, Record<string, string> | string | null, string];

const ERROR_PROBES: Probe[] = [
  ['/?author=99999999',                  'GET',  null,   'author ID overflow'],
  ['/?p=99999999',                       'GET',  null,   'post ID overflow'],
  ['/?page_id=99999999',                 'GET',  null,   'page ID overflow'],
  ['/?cat=99999999',                     'GET',  null,   'category ID overflow'],
  ['/?m=99999999',                       'GET',  null,   'date archive overflow'],
  ['/?s=<![CDATA[',                      'GET',  null,   'XML/CDATA in search'],
  ['/?s=\x00null',                       'GET',  null,   'null byte in search'],
  ['/wp-json/wp/v2/posts/99999999',      'GET',  null,   'non-existent post ID via REST'],
  ['/wp-json/wp/v2/pages/0',             'GET',  null,   'zero ID via REST'],
  ['/wp-json/',                          'GET',  null,   'REST API root (error headers)'],
  ['/wp-login.php',                      'POST', { log: 'A'.repeat(500), pwd: 'x', 'wp-submit': 'Log In', testcookie: '1' }, 'long username POST'],
  ['/wp-admin/admin-ajax.php',           'POST', { action: 'A'.repeat(200) }, 'long action name'],
  ['/xmlrpc.php',                        'POST', '<?xml version="1.0"?><methodCall><methodName>INVALID</methodName></methodCall>', 'invalid xmlrpc method'],
  ['/wp-cron.php?doing_wp_cron=INVALID', 'GET',  null,   'invalid cron token'],
];

type ErrorPattern = [RegExp, string, Severity];

const PHP_ERROR_PATTERNS: ErrorPattern[] = [
  [/<b>(?:Fatal error|Parse error|Warning|Notice)<\/b>:\s*(.{0,200})/i,        'PHP error disclosed',    'HIGH'],
  [/(?:Fatal error|Parse error):\s+(.{0,200})\s+in\s+(\/[^\s<]+)\s+on line/i, 'PHP error with path',    'HIGH'],
  [/Stack trace:\s*#\d+/i,                                                      'PHP stack trace',        'HIGH'],
  [/(?:include_path|open_basedir|display_errors)\s*=/i,                         'PHP config exposed',     'HIGH'],
  [/\/(?:var\/www|srv|home|usr\/local)\/\S+\.php/,                              'PHP file path leaked',   'HIGH'],
  [/WordPress database error/i,                                                  'WP database error',      'HIGH'],
  [/You have an error in your SQL syntax/i,                                      'SQL error in 500',       'HIGH'],
  [/Table '[^']+' doesn't exist/i,                                               'DB table name leaked',   'HIGH'],
  [/(?:DB_NAME|DB_USER|DB_HOST)\s*=/,                                            'DB credential leaked',   'CRITICAL'],
  [/define\s*\(\s*['"](?:DB_|AUTH_KEY|SECURE_AUTH)/,                            'wp-config constant leaked', 'CRITICAL'],
  [/wp-content\/plugins\/([^/\s"'<>]+)\/([^/\s"'<>]+\.php)/,                   'Plugin PHP path leaked', 'HIGH'],
  [/Xdebug/,                                                                     'Xdebug enabled',         'MEDIUM'],
  [/WP_DEBUG.*true/i,                                                            'WP_DEBUG=true active',   'MEDIUM'],
];

const SERVER_ERROR_HEADERS = [
  'X-Powered-By', 'Server', 'X-Generator', 'X-PHP-Version',
  'X-WordPress-Cache', 'X-AspNet-Version',
];

function analyseErrorResponse(
  status: number,
  text: string,
  url: string,
  probeDesc: string,
  findings: ReturnType<typeof finding>[],
): void {
  for (const [pattern, name, severity] of PHP_ERROR_PATTERNS) {
    const m = pattern.exec(text);
    if (m) {
      const snippet = m[0].slice(0, 150);
      const sev: Severity = name.includes('credential') || name.includes('wp-config') ? 'CRITICAL' : severity;
      findings.push(finding(
        `PHP_ERROR_DISCLOSED_${name.toUpperCase().replace(/[^A-Z0-9]/g, '_').slice(0, 25)}`,
        sev, url,
        `PHP/WP error exposed via '${probeDesc}': ${name} — ${snippet.slice(0, 80)}`,
        {
          replication_steps: [
            `curl -s "${url}"`,
            `Observe: ${snippet.slice(0, 120)}`,
            'Disable WP_DEBUG and PHP error display on production sites.',
          ],
          evidence: JSON.stringify({ error_type: name, snippet, http_status: status }),
        },
      ));
      return; // one finding per probe
    }
  }

  if (status === 500) {
    findings.push(finding(
      'UNEXPECTED_500_ERROR', 'LOW', url,
      `HTTP 500 error triggered via '${probeDesc}' — may indicate injectable parameter or unhandled exception`,
      {
        replication_steps: [
          `curl -sI "${url}"`,
          'HTTP 500 returned — server-side exception triggered.',
          'Investigate parameter for SQL injection or other input handling issues.',
        ],
        evidence: JSON.stringify({ probe: probeDesc, http_status: 500 }),
      },
    ));
  }
}

async function checkErrorHeaders(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const res = await fetchURL(base + '/');
  if (!res) return;
  for (const header of SERVER_ERROR_HEADERS) {
    const val = res.headers.get(header.toLowerCase()) ?? res.headers.get(header) ?? '';
    if (!val) continue;
    // For the Server header: skip known CDN/proxy names (no actionable version info),
    // flag as LOW only when a version number is present (e.g. Apache/2.4, nginx/1.18).
    if (header === 'Server') {
      const lval = val.toLowerCase();
      const knownCdns = ['cloudflare', 'fastly', 'akamai', 'varnish', 'sucuri', 'incapsula'];
      const isCdnOnly = knownCdns.some(cdn => lval.includes(cdn)) && !/\d+\.\d+/.test(val);
      if (isCdnOnly) continue; // CDN name without version — skip entirely
      if (!/\d+\.\d+/.test(val)) {
        // Generic server name without version — INFO only
        findings.push(finding(
          `SERVER_HEADER_${header.toUpperCase().replace(/-/g, '_')}`, 'INFO', base + '/',
          `Response header '${header}: ${val}' discloses server technology (no version — informational only)`,
          {
            replication_steps: [
              `curl -sI "${base}/" | grep -i '${header}'`,
              `Value: ${val}`,
              'Generic server name without version number — low risk.',
            ],
            evidence: JSON.stringify({ header, value: val }),
          },
        ));
        continue;
      }
      // Version number present — LOW
      findings.push(finding(
        `SERVER_HEADER_${header.toUpperCase().replace(/-/g, '_')}`, 'LOW', base + '/',
        `Response header '${header}: ${val}' discloses server version`,
        {
          replication_steps: [
            `curl -sI "${base}/" | grep -i '${header}'`,
            `Value: ${val}`,
            'Suppress server version headers in web server config.',
          ],
          evidence: JSON.stringify({ header, value: val }),
        },
      ));
      continue;
    }
    // For all other info-leaking headers (X-Powered-By, X-PHP-Version, etc.) — always LOW
    findings.push(finding(
      `SERVER_HEADER_${header.toUpperCase().replace(/-/g, '_')}`, 'LOW', base + '/',
      `Response header '${header}: ${val}' discloses server technology/version`,
      {
        replication_steps: [
          `curl -sI "${base}/" | grep -i '${header}'`,
          `Value: ${val}`,
          'Suppress server version headers in web server config.',
        ],
        evidence: JSON.stringify({ header, value: val }),
      },
    ));
  }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await checkErrorHeaders(target, findings);

    for (const [path, method, body, desc] of ERROR_PROBES) {
      const url = path.startsWith('http') ? path : target + path;
      try {
        let res: Response | null = null;

        if (method === 'GET') {
          res = await fetchURL(url);
        } else if (typeof body === 'string') {
          // Raw body (e.g. XML for xmlrpc)
          res = await fetchURL(url, {
            method: 'POST',
            body,
            headers: { ...HEADERS, 'Content-Type': 'text/xml' },
          });
        } else if (body && typeof body === 'object') {
          res = await fetchURL(url, {
            method: 'POST',
            body: new URLSearchParams(body as Record<string, string>).toString(),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
        }

        if (!res) continue;
        let text = '';
        try { text = await res.text(); } catch { continue; }
        analyseErrorResponse(res.status, text, url, desc, findings);
      } catch { /* ignore per-probe errors */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
