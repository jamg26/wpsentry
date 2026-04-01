import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Session Fixation Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const loginUrl = `${target}/wp-login.php`;

    // Fetch login page and examine session cookie behavior
    const res = await fetchURL(loginUrl);
    if (!res) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();

    // Extract all Set-Cookie headers
    const cookies: string[] = [];
    const rawHeaders = res.headers;
    const setCookie = rawHeaders.get('set-cookie') ?? '';
    if (setCookie) cookies.push(setCookie);

    // Check for wordpress_test_cookie
    const hasTestCookie = body.includes('wordpress_test_cookie') || setCookie.includes('wordpress_test_cookie');

    // Check for PHPSESSID (indicates custom session handling)
    if (setCookie.includes('PHPSESSID')) {
      // Check if PHPSESSID is accepted from URL parameter
      const fixationUrl = `${target}/wp-login.php?PHPSESSID=fixation_test_12345`;
      const fixRes = await fetchURL(fixationUrl);
      if (fixRes) {
        const fixCookies = fixRes.headers.get('set-cookie') ?? '';
        if (fixCookies.includes('fixation_test_12345')) {
          findings.push(finding('SESSION_FIXATION', 'HIGH', loginUrl,
            'Session fixation vulnerability — PHPSESSID from URL parameter is accepted', {
              evidence: 'Server accepted externally supplied PHPSESSID value',
              replication_steps: [
                `Visit ${fixationUrl}`,
                'Check Set-Cookie header for PHPSESSID containing the injected value',
                'The server adopts the attacker-supplied session ID',
              ],
              remediation: 'Configure PHP to use session.use_only_cookies=1 and session.use_strict_mode=1. Regenerate session IDs on authentication.',
            }));
        }
      }
    }

    // Check cookie security attributes on login page response
    if (setCookie) {
      const cookieParts = setCookie.toLowerCase();

      if (!cookieParts.includes('httponly')) {
        findings.push(finding('SESSION_COOKIE_NO_HTTPONLY', 'MEDIUM', loginUrl,
          'Session cookies on login page lack HttpOnly flag — vulnerable to XSS-based session theft', {
            evidence: `Set-Cookie header missing HttpOnly: ${setCookie.substring(0, 100)}`,
            replication_steps: [
              `Fetch ${loginUrl}`,
              'Examine Set-Cookie response headers',
              'Verify HttpOnly flag is missing',
            ],
            remediation: 'Ensure all session cookies include the HttpOnly flag via PHP configuration or WordPress security plugins.',
          }));
      }

      // Check for SameSite attribute
      if (!cookieParts.includes('samesite')) {
        findings.push(finding('SESSION_COOKIE_NO_SAMESITE', 'LOW', loginUrl,
          'Session cookies lack SameSite attribute — may be vulnerable to CSRF attacks', {
            evidence: `Set-Cookie header missing SameSite: ${setCookie.substring(0, 100)}`,
            replication_steps: [
              `Fetch ${loginUrl}`,
              'Examine Set-Cookie headers for SameSite attribute',
            ],
            remediation: 'Set SameSite=Lax or SameSite=Strict on all cookies.',
          }));
      }
    }

    // Check if login page is served over HTTP (session hijacking risk)
    if (target.startsWith('http://')) {
      if (hasTestCookie || setCookie) {
        findings.push(finding('SESSION_OVER_HTTP', 'HIGH', loginUrl,
          'Login page serves session cookies over unencrypted HTTP — session hijacking risk', {
            evidence: 'Login page accessed via HTTP sets cookies without Secure flag',
            replication_steps: [
              `Visit ${loginUrl} over HTTP`,
              'Observe cookies being set without encryption',
            ],
            remediation: 'Enforce HTTPS for the entire site, especially login and admin pages. Set FORCE_SSL_ADMIN to true in wp-config.php.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
