import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Multisite Misconfiguration';

const NETWORK_ADMIN_PATHS = ['/network/admin/', '/wp-admin/network/'];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // Test 1: wp-signup.php — open registration
    const signupUrl = `${target}/wp-signup.php`;
    const signupRes = await fetchURL(signupUrl);
    if (signupRes && signupRes.status === 200) {
      const body = await signupRes.text();
      const bodyLower = body.toLowerCase();
      if (bodyLower.includes('register') || bodyLower.includes('sign up')) {
        findings.push(finding(
          'multisite_open_registration', 'HIGH', signupUrl,
          'WordPress Multisite signup page (wp-signup.php) is publicly accessible. Anyone can register a new sub-site, potentially for spam or abuse.',
          {
            replication_steps: [
              `curl -s -o /dev/null -w "%{http_code}" "${signupUrl}"`,
              `curl -s "${signupUrl}" | grep -i "register\\|sign up\\|blogname"`,
            ],
            remediation: "Disable open registration: Network Admin → Settings → Registration Settings → set 'Allow new registrations' to 'No'.",
            evidence: `HTTP ${signupRes.status} — signup form accessible`,
          },
        ));
      } else {
        findings.push(finding(
          'multisite_open_registration', 'LOW', signupUrl,
          'wp-signup.php is accessible (HTTP 200). Verify registration is restricted.',
          {
            replication_steps: [`curl -s "${signupUrl}"`],
            remediation: 'Restrict wp-signup.php if public registration is not required.',
            evidence: `HTTP ${signupRes.status}`,
          },
        ));
      }
    }

    // Test 2: wp-activate.php accessible
    const activateUrl = `${target}/wp-activate.php`;
    const activateRes = await fetchURL(activateUrl);
    if (activateRes && activateRes.status === 200) {
      findings.push(finding(
        'multisite_open_registration', 'MEDIUM', activateUrl,
        'WordPress Multisite activation endpoint (wp-activate.php) is publicly accessible. If registration keys are weak or predictable, accounts can be activated without authorization.',
        {
          replication_steps: [
            `curl -s -o /dev/null -w "%{http_code}" "${activateUrl}"`,
            `curl -s "${activateUrl}?key=TESTKEY123"`,
          ],
          remediation: 'Block direct access to wp-activate.php via .htaccess or nginx if not needed.',
          evidence: `HTTP ${activateRes.status}`,
        },
      ));
    }

    // Test 3: REST API sites listing
    const sitesUrl = `${target}/wp-json/wp/v2/sites`;
    const sites = await getJSON<unknown[]>(sitesUrl);
    if (Array.isArray(sites) && sites.length > 0) {
      findings.push(finding(
        'multisite_network_exposed', 'MEDIUM', sitesUrl,
        `WordPress Multisite REST API /wp/v2/sites endpoint lists ${sites.length} site(s) without authentication.`,
        {
          replication_steps: [
            `curl -s "${sitesUrl}" | python3 -m json.tool`,
          ],
          remediation: 'Restrict sites endpoint to authenticated network admins.',
          evidence: `${sites.length} sites returned at ${sitesUrl}`,
        },
      ));
    }

    // Test 4: Site context switching via ?site= and ?blog=
    // First fetch the baseline homepage to compare against
    const baselineRes = await fetchURL(`${target}/`);
    const baselineTitle = baselineRes ? (await baselineRes.text()).match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() : null;

    for (const param of ['site', 'blog']) {
      for (const siteId of [2, 3, 4]) {
        const switchUrl = `${target}/?${param}=${siteId}`;
        const switchRes = await fetchURL(switchUrl);
        if (!switchRes || switchRes.status !== 200) continue;

        const switchBody = await switchRes.text();
        const switchTitle = switchBody.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim();

        // Only flag if the page title actually changed (proving a different site context)
        // and the title isn't just an error page
        if (baselineTitle && switchTitle && switchTitle !== baselineTitle &&
            !switchTitle.toLowerCase().includes('not found') &&
            !switchTitle.toLowerCase().includes('error')) {
          findings.push(finding(
            'multisite_network_exposed', 'MEDIUM', switchUrl,
            `?${param}=${siteId} parameter loaded a different site context (title changed). Site switching via query parameter may be enabled.`,
            {
              replication_steps: [
                `curl -sI "${switchUrl}"`,
                `curl -s "${switchUrl}" | grep -i "<title>"`,
                `Compare with: curl -s "${target}/" | grep -i "<title>"`,
              ],
              remediation: 'Disable unauthenticated site context switching.',
              evidence: `Baseline title: "${baselineTitle}" → Switched title: "${switchTitle}"`,
            },
          ));
          break;
        }
      }
    }

    // Test 5: Multisite context headers in response
    const mainRes = await fetchURL(`${target}/`);
    if (mainRes) {
      const contextHeaders: Record<string, string> = {};
      mainRes.headers.forEach((v, k) => {
        const kl = k.toLowerCase();
        if (kl.includes('x-site') || kl.includes('x-blog') || kl.includes('x-network') || kl.includes('x-multisite')) {
          contextHeaders[k] = v;
        }
      });
      if (Object.keys(contextHeaders).length > 0) {
        findings.push(finding(
          'multisite_network_exposed', 'MEDIUM', `${target}/`,
          `Multisite-related headers detected in response: ${JSON.stringify(contextHeaders)}`,
          {
            replication_steps: [`curl -sI "${target}/" | grep -iE "x-site|x-blog|x-network"`],
            remediation: 'Strip internal multisite headers from public HTTP responses.',
            evidence: JSON.stringify(contextHeaders),
          },
        ));
      }
    }

    // Test 6: Network admin paths accessible
    await parallelProbe(NETWORK_ADMIN_PATHS, async (path) => {
      const adminUrl = `${target}${path}`;
      const adminRes = await fetchURL(adminUrl);
      if (adminRes && adminRes.status === 200) {
        const body = await adminRes.text();
        const bodyLower = body.toLowerCase();
        if ((bodyLower.includes('<div id="wpbody"') || bodyLower.includes('<body class="wp-admin"')) &&
            (bodyLower.includes('network') || adminRes.url.includes('admin'))) {
          findings.push(finding(
            'multisite_network_exposed', 'HIGH', adminUrl,
            `WordPress Multisite network admin path ${path} is accessible (HTTP 200).`,
            {
              replication_steps: [
                `curl -s -o /dev/null -w "%{http_code}" "${adminUrl}"`,
                `curl -s "${adminUrl}" | grep -i "network\\|super admin"`,
              ],
              remediation: 'Restrict network admin to authenticated super admins only.',
              evidence: `HTTP ${adminRes.status} from ${adminUrl}`,
            },
          ));
        }
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
