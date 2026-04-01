import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Staging Environment Detection';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const res = await fetchURL(`${target}/`);
    if (!res || res.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();
    const headers = res.headers;

    // Check hostname for staging indicators
    const hostname = new URL(target).hostname;
    const stagingPatterns = [
      /^staging\./i, /^stage\./i, /^dev\./i, /^test\./i, /^uat\./i,
      /^qa\./i, /^preview\./i, /^preprod\./i, /^beta\./i,
      /\.staging\./i, /\.dev\./i, /\.test\./i, /\.local$/i,
      /-staging\./i, /-dev\./i, /-test\./i,
    ];

    const isStagingDomain = stagingPatterns.some(p => p.test(hostname));

    // Check for staging indicators in page content
    // Check headers for staging indicators
    const debugHeaders = [
      'X-Debug-Token',
      'X-Debug-Token-Link',
      'X-Powered-By',
    ];

    let isStaging = isStagingDomain;
    const evidence: string[] = [];

    if (isStagingDomain) {
      evidence.push(`Hostname "${hostname}" matches staging pattern`);
    }

    for (const header of debugHeaders) {
      const val = headers.get(header);
      if (val && (val.includes('debug') || val.includes('dev'))) {
        isStaging = true;
        evidence.push(`Header ${header}: ${val}`);
      }
    }

    // Check for WP_DEBUG output in page
    if (body.includes('WP_DEBUG') || body.includes('SCRIPT_DEBUG')) {
      isStaging = true;
      evidence.push('Debug constants detected in page output');
    }

    // Check for robots.txt blocking everything (common on staging)
    const robotsRes = await fetchURL(`${target}/robots.txt`);
    if (robotsRes && robotsRes.status === 200) {
      const robotsBody = await robotsRes.text();
      if (robotsBody.includes('Disallow: /') && !robotsBody.includes('Allow:') &&
          robotsBody.match(/Disallow:\s*\/\s*$/m)) {
        evidence.push('robots.txt blocks all crawlers (Disallow: /)');
        isStaging = true;
      }
    }

    // Check for noindex meta tag
    if (body.includes('noindex') && body.includes('nofollow')) {
      evidence.push('Page has noindex,nofollow meta tag');
    }

    // Check for Basic Auth prompt (common on staging)
    if (headers.get('www-authenticate')) {
      evidence.push('Basic authentication is required');
      isStaging = true;
    }

    if (isStaging && evidence.length > 0) {
      findings.push(finding('STAGING_ENV_EXPOSED', 'MEDIUM', `${target}/`,
        `Site appears to be a staging/development environment exposed to the public`, {
          evidence: evidence.join('; '),
          replication_steps: [
            `Visit ${target}/`,
            ...evidence.map(e => `Indicator: ${e}`),
          ],
          remediation: 'Restrict staging environments behind VPN, IP whitelist, or Basic Authentication. Ensure staging sites are not indexed by search engines and not linked from production.',
        }));
    }

    // Check for PHP error display (common on staging, dangerous on production)
    const phpErrors = [
      /<b>Warning<\/b>:/i,
      /<b>Notice<\/b>:/i,
      /<b>Deprecated<\/b>:/i,
      /PHP Warning:/i,
      /PHP Notice:/i,
    ];

    for (const pattern of phpErrors) {
      if (pattern.test(body)) {
        findings.push(finding('PHP_ERRORS_DISPLAYED', 'MEDIUM', `${target}/`,
          'PHP errors/warnings are displayed on the page — indicates debug mode or misconfiguration', {
            evidence: 'PHP error/warning messages visible in page source',
            replication_steps: [
              `Visit ${target}/`,
              'View page source for PHP error messages',
            ],
            remediation: 'Set display_errors=Off and WP_DEBUG_DISPLAY=false in production. Log errors to a file instead.',
          }));
        break;
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
