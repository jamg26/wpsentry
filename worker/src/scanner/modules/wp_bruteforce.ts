import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'WordPress Login Brute Force';

const TOP_USERNAMES = ['admin', 'administrator', 'user', 'root', 'editor'];
const TOP_PASSWORDS = ['admin', 'password', '123456', 'welcome', 'admin123'];

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const loginUrl = `${target}/wp-login.php`;

    // Use cached reachability data when available to avoid a redundant fetch
    const cachedReach = state?.reachabilityCache?.get(loginUrl);
    if (cachedReach && (cachedReach.status === 0 || cachedReach.status >= 400)) {
      findings.push(finding(
        'LOGIN_PAGE_UNREACHABLE', 'INFO', loginUrl,
        'wp-login.php unreachable — login page may be blocked, renamed, or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Reachability check
    const rLogin = await fetchURL(loginUrl);
    if (!rLogin) {
      findings.push(finding(
        'LOGIN_PAGE_UNREACHABLE', 'INFO', loginUrl,
        'wp-login.php unreachable — login page may be blocked, renamed, or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    let loginBody = '';
    try { loginBody = await rLogin.text(); } catch { /* ignore */ }
    if (!loginBody.includes('user_login') && !loginBody.toLowerCase().includes('wp-login')) {
      findings.push(finding(
        'LOGIN_PAGE_NOT_WP', 'INFO', loginUrl,
        'wp-login.php does not appear to be a WordPress login page',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Extract nonce if present
    let nonceVal: string | null = null;
    const m = loginBody.match(/name="_wpnonce"\s+value="([^"]+)"/);
    if (m) nonceVal = m[1];

    // Top 5 × 5 = 25 combos max
    const credCombos: [string, string][] = TOP_USERNAMES.flatMap((u) =>
      TOP_PASSWORDS.map((p) => [u, p] as [string, string]),
    );
    let found = false;

    await parallelProbe(credCombos, async ([username, password]) => {
      if (found) return;
      try {
        const data: Record<string, string> = {
          log:         username,
          pwd:         password,
          'wp-submit': 'Log In',
          redirect_to: `${target}/wp-admin`,
          testcookie:  '1',
        };
        if (nonceVal) data['_wpnonce'] = nonceVal;

        const res = await fetchURL(loginUrl, {
          method:  'POST',
          body:    new URLSearchParams(data),
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer':      loginUrl,
          },
          redirect: 'manual',
        });

        if (!res) return;

        // 302 redirect to wp-admin with wordpress_logged_in cookie = valid credentials
        const location = res.headers.get('Location') ?? '';
        const cookies = res.headers.get('set-cookie') ?? '';
        if (res.status === 302 && location.includes('/wp-admin') && cookies.includes('wordpress_logged_in')) {
          found = true;
          findings.push(finding(
            'VALID_CREDENTIALS_FOUND',
            'CRITICAL',
            loginUrl,
            `Valid credentials found: ${username}:${'*'.repeat(password.length)}`,
            { evidence: `username: ${username}; password: ****` },
          ));
        }
      } catch { /* skip individual failures gracefully */ }
    }, 10);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
