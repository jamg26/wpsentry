import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Logout Security Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check if logout URL is accessible and properly uses nonces
    const loginUrl = `${target}/wp-login.php`;
    const loginRes = await fetchURL(loginUrl);
    if (!loginRes) return moduleResult(MODULE_NAME, target, findings, errors, start);
    void await loginRes.text();

    // Check logout URL structure in the login page
    // Check if wp-login.php?action=logout without nonce does anything
    const logoutUrl = `${target}/wp-login.php?action=logout`;
    const logoutRes = await fetchURL(logoutUrl);
    if (logoutRes) {
      const logoutBody = await logoutRes.text();

      // If logout proceeds without a nonce, it's a CSRF risk
      if (logoutRes.status === 200 && !logoutBody.includes('_wpnonce') &&
          !logoutBody.includes('Are you sure') && !logoutBody.includes('confirm')) {
        findings.push(finding('LOGOUT_NO_NONCE', 'LOW', logoutUrl,
          'Logout does not require nonce confirmation — may be vulnerable to CSRF logout attacks', {
            evidence: 'wp-login.php?action=logout does not require nonce verification',
            replication_steps: [
              `Visit ${logoutUrl}`,
              'Observe logout proceeds without CSRF token verification',
              'An attacker could log users out via cross-site request',
            ],
            remediation: 'WordPress should prompt for nonce confirmation on logout. Ensure WordPress is updated and no plugins are bypassing the logout nonce check.',
          }));
      }

      // Good sign: WordPress asks for confirmation
      if (logoutBody.includes('Are you sure') || logoutBody.includes('confirm') || logoutBody.includes('_wpnonce')) {
        findings.push(finding('LOGOUT_NONCE_PRESENT', 'INFO', logoutUrl,
          'Logout requires nonce/confirmation — CSRF-protected', {
            evidence: 'Logout page asks for confirmation before proceeding',
            replication_steps: [
              `Visit ${logoutUrl} without a valid nonce`,
              'Observe confirmation prompt',
            ],
            remediation: 'No action needed — this is correct behavior.',
          }));
      }
    }

    // Check if session cookies are set with appropriate expiration
    const setCookie = loginRes.headers.get('set-cookie') ?? '';
    if (setCookie) {
      // Check for overly long cookie expiration
      const maxAgeMatch = setCookie.match(/max-age=(\d+)/i);
      const expiresMatch = setCookie.match(/expires=([^;,]+)/i);

      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        const daysValid = maxAge / 86400;
        if (daysValid > 14) {
          findings.push(finding('SESSION_LONG_EXPIRY', 'LOW', loginUrl,
            `Session cookie has long expiration: ${Math.round(daysValid)} days — increases session hijacking window`, {
              evidence: `Cookie max-age=${maxAge} (${Math.round(daysValid)} days)`,
              replication_steps: [
                `Fetch ${loginUrl}`,
                'Check Set-Cookie max-age value',
              ],
              remediation: 'Reduce session cookie lifetime to 24-48 hours for admin sessions. Configure AUTH_COOKIE_EXPIRATION in wp-config.php.',
            }));
        }
      } else if (expiresMatch) {
        try {
          const expiryDate = new Date(expiresMatch[1]);
          const now = new Date();
          const daysUntilExpiry = (expiryDate.getTime() - now.getTime()) / (86400 * 1000);
          if (daysUntilExpiry > 14) {
            findings.push(finding('SESSION_LONG_EXPIRY', 'LOW', loginUrl,
              `Session cookie expires in ${Math.round(daysUntilExpiry)} days — increases session hijacking window`, {
                evidence: `Cookie expires: ${expiresMatch[1]}`,
                replication_steps: [
                  `Fetch ${loginUrl}`,
                  'Check Set-Cookie Expires value',
                ],
                remediation: 'Reduce session cookie lifetime. Configure AUTH_COOKIE_EXPIRATION in wp-config.php.',
              }));
          }
        } catch { /* invalid date */ }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
