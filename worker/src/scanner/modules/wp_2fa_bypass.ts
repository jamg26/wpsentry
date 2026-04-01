import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = '2FA Bypass Detection';

const TWO_FA_PLUGINS = [
  { slug: 'two-factor-authentication', name: 'Two Factor Authentication' },
  { slug: 'wordfence', name: 'Wordfence (2FA)' },
  { slug: 'google-authenticator', name: 'Google Authenticator' },
  { slug: 'duo-wordpress', name: 'Duo Two-Factor' },
  { slug: 'two-factor', name: 'Two Factor' },
  { slug: 'miniorange-2-factor-authentication', name: 'miniOrange 2FA' },
  { slug: 'wp-2fa', name: 'WP 2FA' },
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    let has2fa = false;

    // Check if any 2FA plugin is installed
    await parallelProbe(TWO_FA_PLUGINS, async (plugin) => {
      const readmeUrl = `${target}/wp-content/plugins/${plugin.slug}/readme.txt`;
      const res = await fetchURL(readmeUrl);
      if (res && res.status === 200) {
        const body = await res.text();
        if (body.includes('===') || body.includes('Stable tag')) {
          has2fa = true;
        }
      }
    }, 7);

    if (!has2fa) {
      // No 2FA detected — report it
      findings.push(finding('NO_2FA_DETECTED', 'INFO', `${target}/wp-login.php`,
        'No two-factor authentication plugin detected — admin accounts rely solely on passwords', {
          evidence: 'None of the common 2FA plugins were detected in wp-content/plugins/',
          replication_steps: [
            `Check ${target}/wp-content/plugins/ for 2FA plugin directories`,
            'None of the common 2FA plugins (Wordfence, WP 2FA, Google Authenticator, etc.) were found',
          ],
          remediation: 'Install and configure a two-factor authentication plugin for all admin and editor accounts.',
        }));
    }

    // Check if XML-RPC bypasses 2FA (XML-RPC doesn't enforce 2FA by default)
    const xmlrpcUrl = `${target}/xmlrpc.php`;
    const xmlrpcRes = await fetchURL(xmlrpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'text/xml' },
      body: `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`,
    });
    if (xmlrpcRes && xmlrpcRes.status === 200) {
      const xmlBody = await xmlrpcRes.text();
      if (xmlBody.includes('wp.getUsersBlogs') || xmlBody.includes('wp.getPost')) {
        findings.push(finding('XMLRPC_2FA_BYPASS', 'HIGH', xmlrpcUrl,
          'XML-RPC is enabled and may bypass two-factor authentication — allows password-only login', {
            evidence: 'XML-RPC accepts authentication methods (wp.getUsersBlogs) that typically bypass 2FA',
            replication_steps: [
              `Send XML-RPC system.listMethods call to ${xmlrpcUrl}`,
              'Observe that wp.getUsersBlogs and other auth methods are available',
              'These methods authenticate with username/password only, bypassing 2FA',
            ],
            remediation: 'Disable XML-RPC or ensure your 2FA plugin intercepts XML-RPC authentication. Add a filter on authenticate hook or block XML-RPC entirely.',
          }));
      }
    }

    // Check if REST API application passwords bypass 2FA
    const appPassUrl = `${target}/wp-json/wp/v2/users/me`;
    const appPassRes = await fetchURL(appPassUrl);
    if (appPassRes && appPassRes.status !== 401 && appPassRes.status !== 403) {
      const appBody = await appPassRes.text();
      if (appBody.includes('"id"') && appBody.includes('"name"')) {
        findings.push(finding('REST_API_2FA_BYPASS', 'MEDIUM', appPassUrl,
          'REST API returns user data without authentication — 2FA may be bypassable via API', {
            evidence: 'wp/v2/users/me returns user data without credentials',
            replication_steps: [
              `Fetch ${appPassUrl}`,
              'Observe user data returned without authentication',
            ],
            remediation: 'Ensure REST API endpoints require authentication and that application passwords also enforce 2FA.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
