import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Sensitive File Exposure';

// [path, indicator, severity, description]
const SENSITIVE_FILES: Array<[string, string, string, string]> = [
  ['/wp-config.php',                'DB_PASSWORD',       'CRITICAL', 'WordPress config with DB credentials'],
  ['/wp-config.php.bak',            'DB_PASSWORD',       'CRITICAL', 'WordPress config backup'],
  ['/wp-config.php.old',            'DB_PASSWORD',       'CRITICAL', 'WordPress config old backup'],
  ['/wp-config.php~',               'DB_',               'CRITICAL', 'WordPress config editor temp file'],
  ['/wp-config-sample.php',         'database_name_here','INFO',     'WP sample config (may expose structure)'],
  // debug.log entries removed — handled more thoroughly by wp_debug_info module
  ['/error_log',                    '',                  'MEDIUM',   'PHP error_log exposed'],
  ['/php_errorlog',                 '',                  'MEDIUM',   'PHP error log exposed'],
  ['/.env',                         '',                  'CRITICAL', '.env file exposed (may contain API keys/passwords)'],
  ['/.env.local',                   '',                  'CRITICAL', '.env.local file exposed'],
  ['/.env.production',              '',                  'CRITICAL', '.env.production file exposed'],
  ['/.git/config',                  '[core]',            'HIGH',     'Git repository config exposed'],
  ['/.git/HEAD',                    'ref:',              'HIGH',     'Git HEAD file exposed'],
  ['/.svn/entries',                 '',                  'HIGH',     'SVN entries file exposed'],
  ['/wp-admin/install.php',         'WordPress',         'MEDIUM',   'Install script accessible'],
  ['/wp-admin/upgrade.php',         'WordPress',         'MEDIUM',   'Upgrade script accessible'],
  ['/wp-includes/install.php',      '',                  'MEDIUM',   'Install script in wp-includes'],
  ['/readme.html',                  'WordPress',         'LOW',      'readme.html discloses WP version'],
  ['/license.txt',                  'WordPress',         'LOW',      'license.txt present (version fingerprint)'],
  ['/backup.sql',                   '',                  'CRITICAL', 'SQL backup file exposed'],
  ['/database.sql',                 '',                  'CRITICAL', 'Database SQL dump exposed'],
  ['/db.sql',                       '',                  'CRITICAL', 'Database SQL dump exposed'],
  ['/wordpress.sql',                '',                  'CRITICAL', 'WordPress SQL dump exposed'],
  ['/phpinfo.php',                  'phpinfo',           'HIGH',     'phpinfo() script exposed'],
  ['/info.php',                     'phpinfo',           'HIGH',     'phpinfo() script exposed'],
  ['/test.php',                     '',                  'LOW',      'test.php present'],
  ['/.htaccess',                    'RewriteEngine',     'LOW',      '.htaccess exposed (rewrite rules visible)'],
  ['/xmlrpc.php',                   'XML-RPC',           'MEDIUM',   'xmlrpc.php accessible (see xmlrpc module)'],
  ['/wp-cron.php',                  '',                  'LOW',      'wp-cron.php directly accessible'],
  ['/wp-json/',                     'routes',            'LOW',      'WP REST API root exposed'],
  ['/wp-config.txt',                'DB_',               'CRITICAL', 'WordPress config as .txt exposed'],
  ['/wp-config.bak',                'DB_',               'CRITICAL', 'WordPress config .bak exposed'],
  ['/wp-content/uploads/.htaccess', '',                  'LOW',      '.htaccess missing in uploads (allows PHP exec)'],
  ['/.DS_Store',                    '',                  'LOW',      '.DS_Store file exposed (macOS metadata)'],
  ['/wp-content/uploads/wpforms/',  '',                  'LOW',      'WPForms upload directory exposed'],
  ['/sitemap.xml',                  'wordpress',         'LOW',      'Sitemap exposes post structure'],
  ['/wp-sitemap.xml',               '',                  'LOW',      'WordPress native sitemap exposed'],
  ['/server-status',                'Apache',            'HIGH',     'Apache mod_status exposed'],
  ['/.well-known/security.txt',     '',                  'INFO',     'security.txt present (good practice)'],
];

const INSTALL_PATHS = new Set(['/wp-admin/install.php', '/wp-admin/upgrade.php', '/wp-includes/install.php']);
const ENV_PATHS = new Set(['/.env', '/.env.local', '/.env.production']);

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(SENSITIVE_FILES, async ([path, indicator, severity, desc]) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url, { redirect: 'manual' });
      if (!res || res.status !== 200) return;

      const body = await res.text();

      if (indicator && !body.toLowerCase().includes(indicator.toLowerCase())) return;

      if (INSTALL_PATHS.has(path)) {
        const lower = body.toLowerCase();
        if (
          lower.includes('already installed') ||
          lower.includes('already up-to-date') ||
          lower.includes('no update required')
        ) return;
      }

      if (ENV_PATHS.has(path)) {
        const ct = (res.headers.get('content-type') ?? '').toLowerCase();
        const isHtml = ct.includes('text/html') || body.trimStart().match(/^<(!|html)/i) !== null;
        const hasKv = body.includes('=') && !isHtml;
        if (!hasKv) return;
      }

      findings.push(finding(
        'SENSITIVE_FILE_EXPOSED',
        severity as Parameters<typeof finding>[1],
        url,
        `${desc} at ${path}`,
      ));
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
