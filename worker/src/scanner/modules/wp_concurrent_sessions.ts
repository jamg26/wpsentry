import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Concurrent Sessions Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check for session management plugins
    const sessionPlugins = [
      'loggedin',
      'limit-login-attempts-reloaded',
      'wp-session-manager',
      'inactive-logout',
      'all-in-one-wp-security-and-firewall',
    ];

    let hasSessionPlugin = false;
    for (const slug of sessionPlugins) {
      const readmeUrl = `${target}/wp-content/plugins/${slug}/readme.txt`;
      const res = await fetchURL(readmeUrl);
      if (res && res.status === 200) {
        const body = await res.text();
        if (body.includes('===') || body.includes('Stable tag')) {
          hasSessionPlugin = true;
          break;
        }
      }
    }

    if (!hasSessionPlugin) {
      // Check if WordPress default session handling is in place
      // WordPress by default allows unlimited concurrent sessions
      const loginUrl = `${target}/wp-login.php`;
      const loginRes = await fetchURL(loginUrl);
      if (loginRes && loginRes.status === 200) {
        const body = await loginRes.text();
        if (body.includes('wp-login') || body.includes('loginform')) {
          findings.push(finding('NO_SESSION_LIMIT', 'LOW', loginUrl,
            'No concurrent session limiting detected — WordPress default allows unlimited simultaneous logins', {
              evidence: 'No session management plugin detected; WordPress allows unlimited concurrent sessions by default',
              replication_steps: [
                'Log in from multiple devices/browsers simultaneously',
                'All sessions remain active with no warnings or logouts',
                'WordPress Profile page shows sessions but does not enforce limits',
              ],
              remediation: 'Install a session management plugin to limit concurrent logins. Consider plugins like "Loggedin" or use WordPress\'s built-in session management with custom limits.',
            }));
        }
      }
    }

    // Check for session timeout indicators
    const adminUrl = `${target}/wp-admin/`;
    const adminRes = await fetchURL(adminUrl);
    if (adminRes) {
      // If we get a redirect to login, check for session timeout in URL
      const location = adminRes.headers.get('location') ?? '';
      if (location.includes('reauth=1')) {
        findings.push(finding('SESSION_REAUTH', 'INFO', adminUrl,
          'WordPress session re-authentication is active (reauth=1 in redirect)', {
            evidence: `Redirect includes reauth=1: ${location}`,
            replication_steps: [
              `Access ${adminUrl} without authentication`,
              'Check redirect URL for reauth parameter',
            ],
            remediation: 'This is a positive security control. Ensure session timeouts are configured appropriately.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
