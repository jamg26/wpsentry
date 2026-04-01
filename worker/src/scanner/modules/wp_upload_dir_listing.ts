import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Upload Directory Listing Scanner';

const UPLOAD_PATHS = [
  '/wp-content/uploads/',
  '/wp-content/uploads/2024/',
  '/wp-content/uploads/2025/',
  '/wp-content/uploads/2023/',
  '/wp-content/uploads/woocommerce_uploads/',
  '/wp-content/uploads/wpforms/',
  '/wp-content/uploads/gravity_forms/',
  '/wp-content/uploads/backups/',
  '/wp-content/uploads/backup/',
  '/wp-content/uploads/elementor/',
  '/wp-content/uploads/sites/',
];

const SENSITIVE_EXTENSIONS = [
  '.sql', '.sql.gz', '.sql.zip',
  '.bak', '.old', '.orig',
  '.csv', '.xls', '.xlsx',
  '.doc', '.docx', '.pdf',
  '.zip', '.tar', '.tar.gz',
  '.json', '.xml',
  '.log', '.txt',
  '.php', '.php.bak',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(UPLOAD_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      // Check for directory listing
      const isDirListing = body.includes('Index of') ||
                          body.includes('<title>Directory listing') ||
                          (body.includes('<pre>') && body.includes('</pre>') && body.includes('<a href='));

      if (!isDirListing) return;

      findings.push(finding('UPLOAD_DIR_LISTING', 'MEDIUM', url,
        `Directory listing enabled for ${path}`, {
          evidence: 'Upload directory shows file listing when accessed directly',
          replication_steps: [
            `Navigate to ${url}`,
            'Observe directory listing of uploaded files',
          ],
          remediation: 'Disable directory listing by adding "Options -Indexes" to .htaccess or "autoindex off" to nginx config.',
        }));

      // Check for sensitive files in listing
      const sensitiveFiles: string[] = [];
      for (const ext of SENSITIVE_EXTENSIONS) {
        const extRegex = new RegExp(`href="[^"]*\\${ext}"`, 'gi');
        const matches = body.match(extRegex);
        if (matches) {
          for (const match of matches) {
            const fileMatch = match.match(/href="([^"]+)"/);
            if (fileMatch) sensitiveFiles.push(fileMatch[1]);
          }
        }
      }

      if (sensitiveFiles.length > 0) {
        const severity = sensitiveFiles.some(f => f.match(/\.(sql|php|bak|csv|xls)/i)) ? 'HIGH' as const : 'MEDIUM' as const;
        findings.push(finding('UPLOAD_SENSITIVE_FILES', severity, url,
          `${sensitiveFiles.length} potentially sensitive file(s) found in upload directory: ${sensitiveFiles.slice(0, 5).join(', ')}`, {
            evidence: `Sensitive files: ${sensitiveFiles.slice(0, 10).join(', ')}`,
            replication_steps: [
              `Navigate to ${url}`,
              'Identify files with sensitive extensions (.sql, .bak, .csv, .php, etc.)',
            ],
            remediation: 'Remove sensitive files from the uploads directory. Restrict file types that can be accessed. Add deny rules for sensitive extensions.',
          }));
      }

      // Check for PHP files in uploads (potential backdoor/webshell)
      const phpFiles = body.match(/href="[^"]*\.php"/gi);
      if (phpFiles && phpFiles.length > 0) {
        findings.push(finding('UPLOAD_PHP_FILES', 'HIGH', url,
          `PHP files found in uploads directory — possible backdoor or webshell`, {
            evidence: `${phpFiles.length} PHP file(s) found in ${path}`,
            replication_steps: [
              `Navigate to ${url}`,
              'Locate PHP files in the directory listing',
              'PHP files in upload directories are a common indicator of compromise',
            ],
            remediation: 'Investigate PHP files in the uploads directory immediately. Remove any unauthorized files. Add .htaccess rules to prevent PHP execution in uploads: "php_flag engine off".',
          }));
      }
    }, 5);

    // Check for direct file access patterns (without directory listing)
    const testFiles = [
      '/wp-content/uploads/woocommerce_uploads/.htaccess',
      '/wp-content/uploads/gravity_forms/.htaccess',
    ];

    await parallelProbe(testFiles, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      if (body.includes('deny from all') || body.includes('Require all denied')) {
        // Good — protected
        return;
      }
      if (body.length > 10) {
        findings.push(finding('UPLOAD_HTACCESS_EXPOSED', 'LOW', url,
          `.htaccess in uploads directory is readable — may reveal protection rules`, {
            evidence: `.htaccess at ${path} is accessible`,
            replication_steps: [`Fetch ${url}`],
            remediation: 'Ensure .htaccess files are not directly accessible via web server.',
          }));
      }
    }, 2);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
