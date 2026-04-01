import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Web Shell Indicators';

// Common webshell paths in wp-content/uploads and admin areas
const WEBSHELL_PATHS = [
  '/wp-content/uploads/shell.php',
  '/wp-content/uploads/wp.php',
  '/wp-content/uploads/cmd.php',
  '/wp-content/uploads/c99.php',
  '/wp-content/uploads/r57.php',
  '/wp-content/uploads/b374k.php',
  '/wp-content/uploads/wso.php',
  '/wp-content/uploads/alfa.php',
  '/wp-content/uploads/indoxploit.php',
  '/wp-content/uploads/web.php',
  '/wp-content/uploads/1.php',
  '/wp-content/uploads/tmp.php',
  '/wp-content/uploads/upload.php',
  '/wp-admin/css/colors.php',
  '/wp-admin/js/wp.php',
  '/wp-includes/class-wp-term-query.php.php',
  // Year/month upload paths
  '/wp-content/uploads/2024/01/shell.php',
  '/wp-content/uploads/2023/shell.php',
  '/wp-content/uploads/images/shell.php',
  // Common upload subdirectory shells
  '/wp-content/uploads/cache/shell.php',
  '/wp-content/uploads/woocommerce_uploads/shell.php',
  // Backdoored plugin paths
  '/wp-content/plugins/akismet/shell.php',
  '/wp-content/plugins/contact-form-7/shell.php',
  '/wp-content/themes/twentytwenty/shell.php',
  '/wp-content/themes/twentytwentyone/shell.php',
  '/wp-content/themes/twentytwentytwo/shell.php',
  '/wp-content/themes/twentytwentythree/shell.php',
  '/wp-content/themes/twentytwentyfour/shell.php',
];

// Webshell content indicators in response body
const WEBSHELL_CONTENT_PATTERNS: RegExp[] = [
  /eval\s*\(\s*base64_decode\s*\(/i,
  /eval\s*\(\s*gzinflate\s*\(/i,
  /eval\s*\(\s*str_rot13\s*\(/i,
  /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
  /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
  /passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
  /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
  /preg_replace\s*\(['"]\/.+\/e['"]/i,
  /assert\s*\(\s*(base64_decode|\$_(GET|POST))/i,
  /b374k/i,
  /c99shell/i,
  /r57shell/i,
  /wso shell/i,
  /FilesMan/i,
  /IndoXploit/i,
  // B374k webshell marker
  /defined\s*\(\s*['"]B374K['"]\s*\)/i,
  // C99 marker
  /\$auth_pass\s*=/i,
  // WSO webshell
  /\$sF\s*=\s*"[^"]{10,}/,
];

// Indicators that a page is a webshell login form rather than 404
const WEBSHELL_LOGIN_PATTERNS = [
  'webshell',
  'web shell',
  'file manager',
  'command execution',
  'cmd=',
  'system(',
  'password protection',
  'Shell v',
  'FilesMan',
  'IndoXploit',
  'b374k',
  'c99',
  'r57',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Get baseline 404 response length
    const notFoundRes = await fetchURL(target + '/wp-content/uploads/nonexistent-file-xyz123.php', { timeoutMs: 3_000 });
    const notFoundStatus = notFoundRes?.status ?? 404;
    const notFoundBody = notFoundRes ? await notFoundRes.text().catch(() => '') : '';

    await parallelProbe(WEBSHELL_PATHS, async (path) => {
      const url = target + path;
      const res = await fetchURL(url, { timeoutMs: 4_000 });
      if (!res) return;

      // Skip if same status as 404 baseline
      if (res.status === 404 || res.status === 403 || res.status === 410) return;

      const body = await res.text().catch(() => '');
      if (!body) return;

      // Check for webshell content patterns
      const contentMatch = WEBSHELL_CONTENT_PATTERNS.find(p => p.test(body));
      if (contentMatch) {
        findings.push(finding(
          'WEBSHELL_CONTENT_DETECTED',
          'CRITICAL',
          url,
          `Web shell detected at ${path} — malicious code pattern found in response`,
          {
            evidence: `status=${res.status} pattern="${contentMatch.toString().slice(0, 60)}" body_prefix="${body.slice(0, 150)}"`,
            remediation: 'IMMEDIATELY remove the file and all uploads. Audit server for additional backdoors. Restore from clean backup. Change all credentials.',
          },
        ));
        return;
      }

      // Check for webshell login page
      const bodyLower = body.toLowerCase();
      const loginInd = WEBSHELL_LOGIN_PATTERNS.find(ind => bodyLower.includes(ind.toLowerCase()));
      if (loginInd && res.status === 200) {
        findings.push(finding(
          'WEBSHELL_LOGIN_PAGE',
          'CRITICAL',
          url,
          `Possible web shell login page detected at ${path} — indicator: '${loginInd}'`,
          {
            evidence: `status=${res.status} indicator="${loginInd}" body_prefix="${body.slice(0, 200)}"`,
            remediation: 'IMMEDIATELY investigate and remove. Treat as active compromise. Rotate all credentials and re-audit the server.',
          },
        ));
        return;
      }

      // .php file accessible in uploads but content seems benign — still suspicious
      if (res.status === 200 && path.includes('/uploads/') && path.endsWith('.php')) {
        // Only flag if body is non-trivial (not just whitespace/empty)
        if (body.trim().length > 0 && body.length !== notFoundBody.length) {
          findings.push(finding(
            'PHP_FILE_IN_UPLOADS',
            'HIGH',
            url,
            `PHP file accessible in wp-content/uploads — uploads directory should never serve PHP`,
            {
              evidence: `status=${res.status} size=${body.length} path="${path}"`,
              remediation: 'Add "php_flag engine off" or equivalent to uploads .htaccess. Use server-level PHP execution blocking for uploads directory.',
            },
          ));
        }
      }
    }, 20);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
