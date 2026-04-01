import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Backup File Discovery';

// [path, contentIndicator, severity]
const BACKUP_TARGETS: Array<[string, string, string]> = [
  ['/backup.sql',              'INSERT INTO', 'CRITICAL'],
  ['/database.sql',            'INSERT INTO', 'CRITICAL'],
  ['/db.sql',                  'INSERT INTO', 'CRITICAL'],
  ['/dump.sql',                'INSERT INTO', 'CRITICAL'],
  ['/wordpress.sql',           'INSERT INTO', 'CRITICAL'],
  ['/wp.sql',                  'INSERT INTO', 'CRITICAL'],
  ['/site.sql',                'INSERT INTO', 'CRITICAL'],
  ['/mysql.sql',               'INSERT INTO', 'CRITICAL'],
  ['/export.sql',              'INSERT INTO', 'CRITICAL'],
  ['/backup.zip',              '',            'CRITICAL'],
  ['/backup.tar.gz',           '',            'CRITICAL'],
  ['/backup.tar',              '',            'CRITICAL'],
  ['/wordpress.zip',           '',            'CRITICAL'],
  ['/wp-content.zip',          '',            'CRITICAL'],
  ['/site.zip',                '',            'CRITICAL'],
  ['/www.zip',                 '',            'CRITICAL'],
  ['/html.zip',                '',            'CRITICAL'],
  ['/public_html.zip',         '',            'CRITICAL'],
  ['/web.zip',                 '',            'CRITICAL'],
  ['/wp-content/backup-db/',   '',            'HIGH'],
  ['/wp-content/backups/',     '',            'HIGH'],
  ['/wp-content/updraft/',     '',            'HIGH'],
  ['/wp-content/ai1wm-backups/','',           'HIGH'],
  ['/wp-content/wpallimport/', '',            'HIGH'],
  ['/wp-content/uploads/backup.sql',   'INSERT INTO', 'CRITICAL'],
  ['/wp-content/uploads/database.sql', 'INSERT INTO', 'CRITICAL'],
  ['/wp-config.php.bak',       'DB_',         'CRITICAL'],
  ['/wp-config.php.orig',      'DB_',         'CRITICAL'],
  ['/wp-config.php.save',      'DB_',         'CRITICAL'],
  ['/wp-config.php_bak',       'DB_',         'CRITICAL'],
  ['/old/',                    '',            'MEDIUM'],
  ['/backup/',                 '',            'MEDIUM'],
  ['/bak/',                    '',            'MEDIUM'],
  ['/_backup/',                '',            'MEDIUM'],
];

const LISTING_HINTS = [
  'index of /', 'directory listing', '[dir]', '[parentdir]',
  'parent directory', '<title>index of',
];

const BINARY_EXTS = ['.zip', '.tar.gz', '.tar', '.gz'];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(BACKUP_TARGETS, async ([path, indicator, severity]) => {
      // Exclude debug.log — handled by dedicated debug/error log modules
      if (path.includes('debug.log')) return;
      const url = `${target}${path}`;
      const res = await fetchURL(url, { redirect: 'manual' });
      if (!res) return;

      let hit = false;

      if (res.status === 200) {
        const isBinary = BINARY_EXTS.some(ext => path.endsWith(ext));
        const ct = (res.headers.get('content-type') ?? '').toLowerCase();
        const isHtml = ct.includes('text/html');

        if (indicator) {
          const body = await res.text();
          if (body.toLowerCase().includes(indicator.toLowerCase())) hit = true;
        } else if (isBinary) {
          if (!isHtml) {
            const cl = parseInt(res.headers.get('content-length') ?? '0', 10);
            if (cl > 100 || ct.includes('application/') || ct.includes('octet-stream')) hit = true;
          }
        } else if (path.endsWith('/')) {
          const body = await res.text();
          const lower = body.toLowerCase();
          if (!isHtml && LISTING_HINTS.some(h => lower.includes(h))) hit = true;
        } else {
          if (!isHtml) {
            const cl = parseInt(res.headers.get('content-length') ?? '0', 10);
            if (cl > 50) {
              hit = true;
            } else {
              const body = await res.text();
              if (body.length > 50 && !body.trimStart().match(/^<(!|html)/i)) hit = true;
            }
          }
        }
      }

      if (hit) {
        findings.push(finding(
          'BACKUP_FILE_FOUND',
          severity as Parameters<typeof finding>[1],
          url,
          `Backup/dump file accessible: ${path} (HTTP ${res.status})`,
          { remediation: 'Remove backup files from the web root. Store backups outside the public directory.' },
        ));
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
