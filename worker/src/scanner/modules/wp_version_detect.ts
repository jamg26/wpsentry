import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getCachedResponse, finding, moduleResult, normalizeTarget , parallelProbe } from '../utils.js';

const MODULE_NAME = 'WordPress Version Detection';

const PATTERNS: Array<[RegExp, string]> = [
  [/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress ([0-9.]+)/i, 'meta generator tag'],
  [/<generator>https?:\/\/wordpress\.org\/\?v=([0-9.]+)<\/generator>/i, 'RSS/Atom feed'],
  [/wp-emoji-release\.min\.js\?ver=([0-9.]+)/i, 'emoji script (WP ver)'],
  [/wp-includes\/css\/dashicons\.min\.css\?ver=([0-9.]+)/i, 'dashicons CSS (WP ver)'],
  [/wp-includes\/js\/wp-embed\.min\.js\?ver=([0-9.]+)/i, 'wp-embed JS (WP ver)'],
  [/wp-login\.php.*ver=([0-9.]+)/i, 'login page asset ver'],
  [/Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i, 'readme.html'],
];

const SKIP_ASSET_PATTERNS = [
  /jquery\.min\.js/i,
  /jquery-migrate/i,
  /jquery\/ui\//i,
  /react\.min\.js/i,
  /lodash\.min\.js/i,
];

const PROBE_PATHS: Array<[string, string]> = [
  ['', 'homepage'],
  ['/feed/', 'RSS feed'],
  ['/readme.html', 'readme file'],
  ['/wp-login.php', 'login page'],
  ['/wp-links-opml.php', 'OPML export'],
  ['/wp-includes/version.php', 'version.php'],
];

const WP_EOL_MAJOR_MINOR = new Set([
  '3.0', '3.1', '3.2', '3.3', '3.4', '3.5', '3.6', '3.7', '3.8', '3.9',
  '4.0', '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9',
  '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9',
  '6.0', '6.1', '6.2',
]);

const VERSION_PHP_RE = /\$wp_version\s*=\s*['"]([0-9.]+)['"]/;

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  function checkEol(version: string): void {
    const majorMinor = version.split('.').slice(0, 2).join('.');
    if (WP_EOL_MAJOR_MINOR.has(majorMinor)) {
      findings.push(finding(
        'WP_VERSION_EOL', 'HIGH', target,
        `WordPress ${version} is end-of-life (EOL) — no longer receives security updates`,
        { evidence: version, remediation: "Remove the generator meta tag: remove_action('wp_head', 'wp_generator'). Update WordPress to the latest supported version." },
      ));
    }
  }

  try {
    let found = false;
    await parallelProbe(PROBE_PATHS, async ([path]) => {
      // Use response cache for the homepage to avoid a redundant round-trip
      const res = path === ''
        ? await getCachedResponse(target + '/', state)
        : await fetchURL(`${target}${path}`);
      if (!res || ![200, 301, 302].includes(res.status)) return;
      if (found) return;

      const body = await res.text();

      if (path === '/wp-includes/version.php') {
        const m = VERSION_PHP_RE.exec(body);
        if (m) {
          const version = m[1];
          found = true;
          findings.push(finding(
            'VERSION_DISCLOSED', 'LOW', `${target}${path}`,
            `WordPress ${version} detected via wp-includes/version.php`,
            { evidence: version, remediation: "Remove the generator meta tag: remove_action('wp_head', 'wp_generator');" },
          ));
          checkEol(version);
          return;
        }
        return;
      }

      for (const [pattern, method] of PATTERNS) {
        const m = pattern.exec(body);
        if (!m) continue;
        if (SKIP_ASSET_PATTERNS.some(p => p.test(m[0]))) continue;
        const version = m[1];
        found = true;
        findings.push(finding(
          'VERSION_DISCLOSED', 'LOW', `${target}${path}`,
          `WordPress ${version} detected via ${method}`,
          { evidence: version, remediation: "Remove the generator meta tag: remove_action('wp_head', 'wp_generator');" },
        ));
        checkEol(version);
        return;
      }
    });

    if (found) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Confirm WP without version
    const loginRes = await fetchURL(`${target}/wp-login.php`);
    if (loginRes) {
      const loginBody = await loginRes.text();
      if (loginBody.includes('user_login') || loginBody.toLowerCase().includes('wp-login')) {
        findings.push(finding(
          'WP_DETECTED_VERSION_HIDDEN', 'INFO', `${target}/wp-login.php`,
          'WordPress detected but version is hardened/hidden',
        ));
      } else {
        findings.push(finding(
          'WP_NOT_CONFIRMED', 'INFO', target,
          'Could not confirm a WordPress installation at this target — endpoint may be blocked or non-existent',
        ));
      }
    } else {
      findings.push(finding(
        'WP_NOT_CONFIRMED', 'INFO', target,
        'Could not confirm a WordPress installation at this target — endpoint may be blocked or non-existent',
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
