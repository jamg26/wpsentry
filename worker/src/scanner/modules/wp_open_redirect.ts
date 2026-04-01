import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Open Redirect Check';

const EVIL_DOMAIN = 'https://evil-strix-test.example.com';

const REDIRECT_PARAMS: [string, string][] = [
  ['/?redirect_to={payload}',                                        'redirect_to'],
  ['/?return={payload}',                                             'return'],
  ['/?url={payload}',                                                'url'],
  ['/?next={payload}',                                               'next'],
  ['/?redir={payload}',                                              'redir'],
  ['/?destination={payload}',                                        'destination'],
  ['/?goto={payload}',                                               'goto'],
  ['/wp-login.php?redirect_to={payload}',                            'wp_login_redirect'],
  ['/wp-login.php?loggedout=true&redirect_to={payload}',             'wp_login_loggedout'],
  ['/wp-admin/admin-ajax.php?action=logout&redirect_to={payload}',   'ajax_logout_redirect'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const encodedDomain = encodeURIComponent(EVIL_DOMAIN);

    await parallelProbe(REDIRECT_PARAMS, async ([tmpl, label]) => {
      const url = target + tmpl.replace('{payload}', encodedDomain);
      const res = await fetchURL(url, { redirect: 'manual' });
      if (!res) return;

      const location = res.headers.get('Location') ?? '';
      if ([301, 302, 303, 307, 308].includes(res.status) && location.includes(EVIL_DOMAIN)) {
        findings.push(finding(
          'OPEN_REDIRECT',
          'MEDIUM',
          url,
          `Open redirect via '${label}' — redirects to arbitrary external URL`,
          {
            replication_steps: [
              `curl -sI "${url}"`,
              `Observe: Location header points to ${EVIL_DOMAIN}`,
              'Craft phishing URL: send this link to a victim to harvest credentials.',
              `PoC: ${url}`,
            ],
            evidence: `param: ${label}; location: ${location}`,
          },
        ));
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
