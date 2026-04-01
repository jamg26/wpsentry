import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'OAuth Vulnerability Scanner';

const OAUTH_ENDPOINTS = [
  '/wp-json/oauth1/',
  '/wp-json/oauth2/',
  '/oauth/authorize',
  '/oauth/token',
  '/wp-json/miniorange/oauth/',
  '/wp-json/wc-auth/v1/authorize',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    let oauthDetected = false;

    await parallelProbe(OAUTH_ENDPOINTS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || (res.status !== 200 && res.status !== 302 && res.status !== 400 && res.status !== 401)) return;
      const body = await res.text();

      // Check for OAuth endpoint presence
      if (body.includes('oauth') || body.includes('authorize') || body.includes('access_token') ||
          body.includes('client_id') || res.status === 400) {
        oauthDetected = true;

        findings.push(finding('OAUTH_ENDPOINT_DETECTED', 'INFO', url,
          `OAuth endpoint detected at ${path}`, {
            evidence: `OAuth-related endpoint returned status ${res.status}`,
            replication_steps: [`Fetch ${url}`, 'Observe OAuth endpoint response'],
            remediation: 'Ensure OAuth implementation follows security best practices.',
          }));
      }
    }, 6);

    if (!oauthDetected) return moduleResult(MODULE_NAME, target, findings, errors, start);

    // Test for redirect_uri manipulation
    const redirectTests = [
      '/wp-json/oauth1/authorize?redirect_uri=https://evil.example.com/callback',
      '/oauth/authorize?client_id=test&redirect_uri=https://evil.example.com/callback&response_type=code',
    ];

    await parallelProbe(redirectTests, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res) return;
      const body = await res.text();
      const location = res.headers.get('location') ?? '';

      // Check if arbitrary redirect_uri is accepted
      if (location.includes('evil.example.com') ||
          (res.status === 302 && location.includes('evil'))) {
        findings.push(finding('OAUTH_REDIRECT_BYPASS', 'HIGH', url,
          'OAuth redirect_uri validation is missing — attacker can steal authorization codes', {
            evidence: `OAuth redirect to evil.example.com was accepted: ${location}`,
            replication_steps: [
              `Fetch ${url}`,
              'OAuth server redirects to the attacker-controlled redirect_uri',
              'Authorization code is sent to attacker\'s server',
            ],
            remediation: 'Implement strict redirect_uri validation. Only allow pre-registered callback URLs. Follow RFC 6749 Section 3.1.2.',
          }));
      }

      // Check if redirect_uri appears in the page (potential for manipulation)
      if (body.includes('evil.example.com') && body.includes('redirect')) {
        findings.push(finding('OAUTH_REDIRECT_REFLECTED', 'MEDIUM', url,
          'OAuth redirect_uri is reflected in the response — potential for XSS or open redirect', {
            evidence: 'Arbitrary redirect_uri value is reflected in response body',
            replication_steps: [
              `Fetch ${url}`,
              'Observe redirect_uri value in response',
            ],
            remediation: 'Sanitize and validate redirect_uri before including it in any response output.',
          }));
      }
    }, 2);

    // Check WooCommerce auth endpoint for open redirect
    const wcAuthUrl = `${target}/wc-auth/v1/authorize?app_name=test&scope=read&user_id=1&return_url=https://evil.example.com&callback_url=https://evil.example.com/cb`;
    const wcRes = await fetchURL(wcAuthUrl);
    if (wcRes && (wcRes.status === 200 || wcRes.status === 302)) {
      const wcBody = await wcRes.text();
      const wcLocation = wcRes.headers.get('location') ?? '';
      if (wcBody.includes('evil.example.com') || wcLocation.includes('evil.example.com')) {
        findings.push(finding('WC_AUTH_REDIRECT_BYPASS', 'MEDIUM', wcAuthUrl,
          'WooCommerce REST API auth endpoint accepts arbitrary callback URLs', {
            evidence: 'Arbitrary callback_url/return_url accepted in WooCommerce auth flow',
            replication_steps: [
              `Fetch ${wcAuthUrl}`,
              'Observe that evil.example.com is accepted as callback',
            ],
            remediation: 'Validate callback and return URLs against a whitelist in WooCommerce settings.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
