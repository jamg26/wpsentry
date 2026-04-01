import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, containsAny, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Login Brute-Force Protection Check';

const SECURITY_PLUGINS: [string, string][] = [
  ['wordfence',                        '/wp-content/plugins/wordfence/'],
  ['all-in-one-wp-security',           '/wp-content/plugins/all-in-one-wp-security-and-firewall/'],
  ['sucuri-scanner',                   '/wp-content/plugins/sucuri-scanner/'],
  ['limit-login-attempts-reloaded',    '/wp-content/plugins/limit-login-attempts-reloaded/'],
  ['loginizer',                        '/wp-content/plugins/loginizer/'],
  ['wp-cerber',                        '/wp-content/plugins/wp-cerber/'],
  ['two-factor',                       '/wp-content/plugins/two-factor/'],
  ['google-authenticator',             '/wp-content/plugins/google-authenticator/'],
  ['shield-security',                  '/wp-content/plugins/wp-simple-firewall/'],
];

const CAPTCHA_PATTERNS = [
  'g-recaptcha', 'recaptcha', 'hcaptcha', 'turnstile',
  'captcha', 'cf-turnstile', 'cf_turnstile',
];

const LOCKOUT_KEYWORDS = ['locked', 'too many', 'temporarily blocked', 'slow down', 'limit'];

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];
  const login = `${target}/wp-login.php`;

  try {
    // Use cached reachability data — if login page is known unreachable, skip all checks
    const cachedReach = state?.reachabilityCache?.get(login);
    if (cachedReach && (cachedReach.status === 0 || cachedReach.status >= 400)) {
      findings.push(finding(
        'LOGIN_PAGE_UNREACHABLE', 'INFO', login,
        'wp-login.php unreachable — brute-force protection checks skipped',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Check 1: Rate limiting — 10 rapid GET requests (all parallel)
    const rateLimitResults = await Promise.allSettled(
      Array.from({ length: 10 }, () => fetchURL(login))
    );
    const blocked = rateLimitResults.some(r =>
      r.status === 'fulfilled' && r.value && (
        r.value.status === 429 || r.value.status === 503 || r.value.status === 403 ||
        r.value.headers.get('Retry-After') !== null ||
        r.value.headers.get('X-RateLimit-Limit') !== null ||
        r.value.headers.get('X-RateLimit-Remaining') !== null
      )
    );

    if (!blocked) {
      findings.push(finding(
        'NO_RATE_LIMITING', 'HIGH', login,
        'Login page has no rate limiting — 10 rapid requests went unblocked',
        {
          replication_steps: [
            `for i in $(seq 1 10); do curl -sI "${login}" | grep HTTP; done`,
            'Observe: all 10 requests return 200 (no 429 Too Many Requests).',
            'Fix: install Limit Login Attempts Reloaded or enable Cloudflare rate limiting.',
          ],
        },
      ));
    }

    // Check 2: Account lockout — 5 failed logins in parallel
    const lockoutResults = await Promise.allSettled(
      Array.from({ length: 5 }, (_, i) => {
        const body = new URLSearchParams({
          log: 'admin',
          pwd: `wrong_password_${i}_jwp_test`,
          'wp-submit': 'Log In',
          redirect_to: '/wp-admin/',
          testcookie: '1',
        });
        return fetchURL(login, {
          method: 'POST', body: body.toString(),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
      })
    );

    // CRIT-05: Replace Promise.any() with Promise.allSettled() analysis.
    // Promise.any() was inverted — it resolved on the first non-error (which could be
    // the lockout response itself), giving wrong results.
    // Require at least 2 of 5 responses to show lockout indicators.
    const responses = lockoutResults
      .filter(r => r.status === 'fulfilled' && r.value !== null)
      .map(r => (r as PromiseFulfilledResult<Response | null>).value!);

    let lockoutCount = 0;
    for (const res of responses) {
      const text = await res.text().catch(() => '');
      if (
        res.status === 429 || res.status === 403 ||
        res.headers.get('Retry-After') !== null ||
        containsAny(text.toLowerCase(), LOCKOUT_KEYWORDS)
      ) {
        lockoutCount++;
      }
    }
    const lockoutDetected = lockoutCount >= 2;

    if (!lockoutDetected) {
      findings.push(finding(
        'NO_ACCOUNT_LOCKOUT', 'HIGH', login,
        'Account not locked after 5 consecutive failed login attempts',
        {
          replication_steps: [
            `for i in $(seq 1 5); do curl -s -X POST "${login}" -d 'log=admin&pwd=wrong$i&wp-submit=Log+In&testcookie=1'; done`,
            'Observe: no lockout message or 403 after repeated failures.',
            'Fix: install Loginizer or Limit Login Attempts Reloaded plugin.',
          ],
        },
      ));
    }

    // Check 3: CAPTCHA on login form
    const captchaRes = await fetchURL(login);
    if (captchaRes && captchaRes.status === 200) {
      const captchaText = await captchaRes.text();
      if (!containsAny(captchaText.toLowerCase(), CAPTCHA_PATTERNS)) {
        findings.push(finding(
          'NO_CAPTCHA_ON_LOGIN', 'MEDIUM', login,
          'No CAPTCHA detected on login form — automated brute-force unimpeded',
          {
            replication_steps: [
              `curl -s "${login}" | grep -iE 'captcha|recaptcha|hcaptcha'`,
              'Observe: no CAPTCHA field in response.',
              'Automated tools can submit login form at full speed.',
              'Fix: enable Google reCAPTCHA via Wordfence or a dedicated CAPTCHA plugin.',
            ],
          },
        ));
      }
    }

    // Check 4: Security plugin presence
    const detectedPlugins: string[] = [];
    await parallelProbe(SECURITY_PLUGINS, async ([name, path]) => {
      const res = await fetchURL(target + path);
      if (res && (res.status === 200 || res.status === 403)) {
        detectedPlugins.push(name);
      }
    });

    if (detectedPlugins.length === 0) {
      findings.push(finding(
        'NO_SECURITY_PLUGIN', 'MEDIUM', target,
        'No WordPress security plugin detected — no WAF/login protection layer',
        {
          replication_steps: [
            `curl -sI "${target}/wp-content/plugins/wordfence/" (and others)`,
            'All return 404 — no recognised security plugin installed.',
            'Recommended: install Wordfence, Sucuri, or All-In-One WP Security.',
          ],
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
