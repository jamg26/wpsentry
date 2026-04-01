import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Application Passwords';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  // Test 1: Application Passwords feature detection
  try {
    const meUrl = `${target}/wp-json/wp/v2/users/me`;
    const emptyCreds = btoa(':');
    const r = await fetchURL(meUrl, { headers: { Authorization: `Basic ${emptyCreds}` } });

    let appPassActive = false;
    let wwwAuthHeader = '';
    if (r) {
      wwwAuthHeader = r.headers.get('WWW-Authenticate') ?? '';
      let respCode = '';
      try {
        const data = await r.json() as Record<string, unknown>;
        respCode = String(data.code ?? '');
      } catch { /* ignore */ }

      if (wwwAuthHeader.toLowerCase().includes('application-passwords') || respCode.includes('rest_not_logged_in')) {
        appPassActive = true;
      }
    }

    const altUrl = `${target}/?rest_route=/wp/v2/users/me`;
    const r2 = await fetchURL(altUrl);
    if (r2) {
      const wwwAuth2 = r2.headers.get('WWW-Authenticate') ?? '';
      if (wwwAuth2.includes('Basic realm="WordPress"')) appPassActive = true;
    }

    if (appPassActive) {
      findings.push(finding(
        'APP_PASSWORDS_ACTIVE',
        'INFO',
        meUrl,
        'Application Passwords feature is active — test for weak credential creation and enumeration',
        {
          replication_steps: [
            `curl -sI "${meUrl}" -H 'Authorization: Basic Og=='`,
            'Observe WWW-Authenticate or rest_not_logged_in confirming App Passwords support.',
          ],
          remediation: 'Audit Application Passwords via Dashboard > Users > Application Passwords. Remove unused or overly broad passwords.',
          evidence: `WWW-Authenticate: ${wwwAuthHeader || 'rest_not_logged_in in response'}`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 2: App password creation endpoint access control
  try {
    const appPassUrl = `${target}/wp-json/wp/v2/users/1/application-passwords`;
    const r = await fetchURL(appPassUrl, { redirect: 'manual' });
    if (r) {
      if (r.status === 200) {
        findings.push(finding(
          'APP_PASSWORDS_ENDPOINT_OPEN',
          'CRITICAL',
          appPassUrl,
          'Application Passwords endpoint accessible without authentication — allows enumeration or creation of app passwords',
          {
            replication_steps: [
              `curl -s "${appPassUrl}"`,
              'Observe HTTP 200 with application password list — no auth required.',
              `curl -s -X POST "${appPassUrl}" -H 'Content-Type: application/json' -d '{"name":"malicious_app"}'`,
              'Attempt to create a new application password without credentials.',
            ],
            remediation: "Immediately restrict the application-passwords endpoint to authenticated users. Update WordPress core. Consider disabling Application Passwords via add_filter('wp_is_application_passwords_available', '__return_false').",
            evidence: `HTTP ${r.status} returned without authentication`,
          },
        ));
      } else if (r.status === 401) {
        findings.push(finding(
          'APP_PASSWORDS_AUTH_REQUIRED',
          'INFO',
          appPassUrl,
          'Application Passwords endpoint properly requires authentication',
          {
            replication_steps: [
              `curl -sI "${appPassUrl}"`,
              'Observe HTTP 401 — endpoint correctly requires authentication.',
            ],
            remediation: 'No action required — endpoint is properly secured.',
            evidence: `HTTP ${r.status} (authentication required)`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 3: Weak basic auth credentials
  const privateUrl = `${target}/wp-json/wp/v2/posts?status=private`;
  const weakCreds: [string, string][] = [
    ['admin', 'admin'],
    ['admin', 'password'],
    ['admin', '123456'],
  ];
  try {
    await parallelProbe(weakCreds, async ([username, password]) => {
      const creds = btoa(`${username}:${password}`);
      const r = await fetchURL(privateUrl, {
        headers: { Authorization: `Basic ${creds}` },
        redirect: 'manual',
      });
      if (!r) return;
      // A 3xx redirect means the request was not processed — inconclusive, not vulnerable
      if (r.status >= 300 && r.status < 400) return;
      if (r.status === 200) {
        try {
          const data = await r.json() as unknown;
          // Only flag CRITICAL if: actual array with items AND no WP error code field
          if (Array.isArray(data) && data.length > 0) {
            const hasErrorCode = (data as Record<string, unknown>[]).some(
              (item) => typeof item === 'object' && item !== null && 'code' in item,
            );
            // If any post has status==='publish', the redirect stripped the ?status=private filter
            const hasPublishedPost = (data as Record<string, unknown>[]).some(
              (item) => typeof item === 'object' && item !== null && (item as Record<string, unknown>)['status'] === 'publish',
            );
            if (!hasErrorCode && !hasPublishedPost) {
              findings.push(finding(
                'APP_PASSWORDS_WEAK_CREDS',
                'CRITICAL',
                privateUrl,
                `Weak Application Password accepted — trivially guessable credentials grant API access (username: ${username})`,
                {
                  replication_steps: [
                    `curl -s "${privateUrl}" -H 'Authorization: Basic ${creds}'`,
                    `Observe HTTP 200 with private posts — ${username}:${password} is valid.`,
                    'Use these credentials to access all REST API endpoints as this user.',
                  ],
                  remediation: 'Immediately change the WordPress admin password. Revoke all Application Passwords and regenerate with strong credentials.',
                  evidence: `Credentials '${username}:${password}' returned ${(data as unknown[]).length} private post(s)`,
                },
              ));
              // Found - no need to test more
            }
          }
        } catch { /* ignore */ }
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  // Test 4: Revocation endpoint check
  try {
    const revokeUrl = `${target}/wp-json/wp/v2/users/me/application-passwords`;
    const r = await fetchURL(revokeUrl);
    if (r && [200, 401, 403].includes(r.status)) {
      findings.push(finding(
        'APP_PASSWORDS_REVOCATION_ENDPOINT',
        'INFO',
        revokeUrl,
        'Application Passwords revocation endpoint exists — audit and rotate app passwords regularly',
        {
          replication_steps: [
            `curl -sI "${revokeUrl}"`,
            'Authenticate and GET this endpoint to list all active application passwords.',
            `DELETE ${revokeUrl}/<uuid>  — revoke individual password.`,
            `DELETE ${revokeUrl}          — revoke all passwords at once.`,
          ],
          remediation: 'Regularly audit Application Passwords via Dashboard > Users > Profile. Revoke unused passwords and implement a rotation policy.',
          evidence: `Endpoint returned HTTP ${r.status}`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 5: Namespace enumeration
  try {
    const apiRoot = `${target}/wp-json`;
    const r = await fetchURL(apiRoot);
    if (r?.status === 200) {
      try {
        const data = await r.json() as Record<string, unknown>;
        const routes = (data.routes as Record<string, unknown>) ?? {};
        const appPassRoutes = Object.keys(routes).filter((route) =>
          route.toLowerCase().includes('application-password'),
        );
        if (appPassRoutes.length > 0) {
          findings.push(finding(
            'APP_PASSWORDS_ROUTES_FOUND',
            'INFO',
            apiRoot,
            `Application Password routes enumerated from REST API root — ${appPassRoutes.length} route(s) found`,
            {
              replication_steps: [
                `curl -s "${apiRoot}" | python3 -m json.tool | grep -i application-password`,
                `Observe ${appPassRoutes.length} application-password route(s).`,
                "Review each route's methods and required capabilities.",
              ],
              remediation: "If Application Passwords are not needed, disable with: add_filter('wp_is_application_passwords_available', '__return_false');",
              evidence: `Routes: ${JSON.stringify(appPassRoutes.slice(0, 5))}`,
            },
          ));
        }
      } catch { /* ignore */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
