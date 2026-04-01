import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Database Dump Exposure Scanner';

const DUMP_PATHS = [
  '/dump.sql',
  '/database.sql',
  '/backup.sql',
  '/db.sql',
  '/data.sql',
  '/wp.sql',
  '/wordpress.sql',
  '/site.sql',
  '/export.sql',
  '/mysql.sql',
  '/dump.sql.gz',
  '/backup.sql.gz',
  '/db.sql.gz',
  '/database.sql.gz',
  '/dump.sql.bz2',
  '/backup.sql.bz2',
  '/db.sql.zip',
  '/backup.sql.zip',
  '/wp-content/backup.sql',
  '/wp-content/dump.sql',
  '/wp-content/uploads/dump.sql',
  '/wp-content/mysql.sql',
  '/backups/database.sql',
  '/backups/dump.sql',
];

const SQL_INDICATORS = [
  /^-- MySQL dump/mi,
  /^-- MariaDB dump/mi,
  /^CREATE TABLE/mi,
  /^INSERT INTO/mi,
  /^DROP TABLE/mi,
  /^-- Dumping data for table/mi,
  /^-- Table structure for table/mi,
  /wp_options/i,
  /wp_users/i,
  /wp_posts/i,
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(DUMP_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      if (body.length < 100) return;

      // Check for compressed files by looking at first bytes
      if (path.endsWith('.gz') || path.endsWith('.bz2') || path.endsWith('.zip')) {
        // For compressed files, just the fact that we got a 200 with substantial content is concerning
        const contentType = res.headers.get('content-type') ?? '';
        if (contentType.includes('octet-stream') || contentType.includes('gzip') ||
            contentType.includes('zip') || contentType.includes('x-bzip') || body.length > 1000) {
          findings.push(finding('DATABASE_DUMP_COMPRESSED', 'CRITICAL', url,
            `Compressed database dump accessible at ${path} (${Math.round(body.length / 1024)}KB)`, {
              evidence: `Compressed file at ${url}, Content-Type: ${contentType}, size: ${body.length} bytes`,
              replication_steps: [
                `Download ${url}`,
                'Decompress the file',
                'Database dump likely contains user credentials and personal data',
              ],
              remediation: `Delete ${path} immediately. Never store database dumps in web-accessible directories.`,
            }));
        }
        return;
      }

      // Check for SQL dump indicators
      const isSqlDump = SQL_INDICATORS.some(p => p.test(body));
      if (isSqlDump) {
        const hasCredentials = /\bpassword\b/i.test(body) || /user_pass/i.test(body);
        findings.push(finding('DATABASE_DUMP_EXPOSED', 'CRITICAL', url,
          `SQL database dump accessible at ${path}${hasCredentials ? ' — contains password hashes' : ''}`, {
            evidence: `SQL dump file at ${url}, size: ${Math.round(body.length / 1024)}KB`,
            replication_steps: [
              `Fetch ${url}`,
              'Observe SQL dump with CREATE TABLE/INSERT INTO statements',
              ...(hasCredentials ? ['Dump contains user password hashes'] : []),
            ],
            remediation: `Delete ${path} immediately. Never store database backups in web-accessible locations. Use secure off-site backup storage.`,
          }));
      }
    }, 8);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
