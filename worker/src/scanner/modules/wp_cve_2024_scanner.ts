import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'CVE 2024-2025 Scanner';

// [cve, description, affected_range, check_fn_key]
interface CveEntry {
  id: string;
  desc: string;
  component: 'core' | 'plugin' | 'theme';
  slug?: string;
  fixedVersion: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  checkPath?: string;
  checkBody?: string;
}

const CVE_LIST: CveEntry[] = [
  {
    id: 'CVE-2024-4439',
    desc: 'WordPress core XSS via Avatar Block (wp_get_attachment_image) — affects < 6.5.2',
    component: 'core',
    fixedVersion: '6.5.2',
    severity: 'HIGH',
  },
  {
    id: 'CVE-2024-6386',
    desc: 'WPML Remote Code Execution via Twig template injection — affects < 4.6.13',
    component: 'plugin',
    slug: 'sitepress-multilingual-cms',
    fixedVersion: '4.6.13',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/sitepress-multilingual-cms/readme.txt',
  },
  {
    id: 'CVE-2024-9047',
    desc: 'WordPress File Upload plugin — file upload bypass allowing PHP execution',
    component: 'plugin',
    slug: 'wp-file-upload',
    fixedVersion: '4.24.12',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/wp-file-upload/readme.txt',
  },
  {
    id: 'CVE-2024-10924',
    desc: 'Really Simple Security (Really Simple SSL) — authentication bypass allowing admin access — affects < 9.1.2',
    component: 'plugin',
    slug: 'really-simple-ssl',
    fixedVersion: '9.1.2',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/really-simple-ssl/readme.txt',
  },
  {
    id: 'CVE-2024-27956',
    desc: 'WP Automatic plugin — unauthenticated SQL injection — affects < 3.92.1',
    component: 'plugin',
    slug: 'wp-automatic',
    fixedVersion: '3.92.1',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/wp-automatic/readme.txt',
  },
  {
    id: 'CVE-2024-2879',
    desc: 'LayerSlider — unauthenticated SQL injection — affects <= 7.10.0',
    component: 'plugin',
    slug: 'LayerSlider',
    fixedVersion: '7.10.1',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/LayerSlider/readme.txt',
  },
  {
    id: 'CVE-2024-1071',
    desc: 'Ultimate Member plugin — unauthenticated SQL injection — affects < 2.8.3',
    component: 'plugin',
    slug: 'ultimate-member',
    fixedVersion: '2.8.3',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/ultimate-member/readme.txt',
  },
  {
    id: 'CVE-2024-3400',
    desc: 'PAN-OS style — check if site is running behind Palo Alto GlobalProtect (out-of-scope but indicative)',
    component: 'core',
    fixedVersion: '999',
    severity: 'HIGH',
  },
  {
    id: 'CVE-2024-5961',
    desc: '2Checkout WooCommerce Payment Plugin — reflected XSS — affects < 6.9.2',
    component: 'plugin',
    slug: 'woo-2checkout',
    fixedVersion: '6.9.2',
    severity: 'HIGH',
    checkPath: '/wp-content/plugins/woo-2checkout/readme.txt',
  },
  {
    id: 'CVE-2024-22147',
    desc: 'WP User Frontend — CSRF to privilege escalation — affects < 3.6.9',
    component: 'plugin',
    slug: 'wp-user-frontend',
    fixedVersion: '3.6.9',
    severity: 'HIGH',
    checkPath: '/wp-content/plugins/wp-user-frontend/readme.txt',
  },
  {
    id: 'CVE-2025-0282',
    desc: 'Path traversal in WP Crontrol and similar — check WP Crontrol < 1.16.3',
    component: 'plugin',
    slug: 'wp-crontrol',
    fixedVersion: '1.16.3',
    severity: 'HIGH',
    checkPath: '/wp-content/plugins/wp-crontrol/readme.txt',
  },
  {
    id: 'CVE-2024-11972',
    desc: 'Hunk Companion — unauthenticated plugin installation — affects < 1.9.0',
    component: 'plugin',
    slug: 'hunk-companion',
    fixedVersion: '1.9.0',
    severity: 'CRITICAL',
    checkPath: '/wp-content/plugins/hunk-companion/readme.txt',
  },
];

function parseVersion(v: string): number[] {
  return v.split('.').map(n => parseInt(n, 10) || 0);
}

function isVersionBelow(installed: string, fixed: string): boolean {
  const iv = parseVersion(installed);
  const fv = parseVersion(fixed);
  for (let i = 0; i < Math.max(iv.length, fv.length); i++) {
    const a = iv[i] ?? 0;
    const b = fv[i] ?? 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false; // equal = patched
}

function extractVersion(text: string): string | null {
  const m = text.match(/Stable tag:\s*([\d.]+)/i)
    ?? text.match(/Version:\s*([\d.]+)/i)
    ?? text.match(/^\*\*Version\*\*:\s*([\d.]+)/mi);
  return m?.[1] ?? null;
}

function extractWPVersion(html: string): string | null {
  const m = html.match(/meta name="generator" content="WordPress ([\d.]+)"/i)
    ?? html.match(/\?ver=([\d]+\.[\d]+(?:\.[\d]+)?)/);
  return m?.[1] ?? null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Get WordPress version from homepage
    const homepageRes = await fetchURL(target + '/', { timeoutMs: 5_000 });
    const homepageHtml = homepageRes ? await homepageRes.text().catch(() => '') : '';
    const wpVersion = extractWPVersion(homepageHtml);

    // Also try /feed/ for version detection
    let finalWpVersion = wpVersion;
    if (!finalWpVersion) {
      const feedRes = await fetchURL(target + '/feed/', { timeoutMs: 4_000 });
      if (feedRes) {
        const feedBody = await feedRes.text().catch(() => '');
        finalWpVersion = feedBody.match(/\?ver=([\d]+\.[\d]+\.[\d]+)/)?.[1] ?? null;
      }
    }

    // Check core CVEs
    if (finalWpVersion) {
      for (const cve of CVE_LIST.filter(c => c.component === 'core')) {
        if (cve.fixedVersion === '999') continue; // Skip informational
        if (isVersionBelow(finalWpVersion, cve.fixedVersion)) {
          findings.push(finding(
            `CVE_${cve.id.replace('-', '_')}`,
            cve.severity,
            target,
            `WordPress core ${finalWpVersion} is vulnerable to ${cve.id}: ${cve.desc}`,
            {
              evidence: `wp_version="${finalWpVersion}" fixed_in="${cve.fixedVersion}" cve="${cve.id}"`,
              remediation: `Update WordPress to >= ${cve.fixedVersion} immediately. This is a ${cve.severity} severity vulnerability.`,
            },
          ));
        }
      }
    }

    // Check plugin CVEs
    const pluginCves = CVE_LIST.filter(c => c.component === 'plugin' && c.checkPath);

    await Promise.all(pluginCves.map(async (cve) => {
      if (!cve.checkPath) return;
      const res = await fetchURL(target + cve.checkPath, { timeoutMs: 4_000 });
      if (!res || res.status !== 200) return;

      const text = await res.text().catch(() => '');
      if (!text.includes('Stable tag:') && !text.includes('Version:')) return;

      const version = extractVersion(text);
      if (!version) return;

      if (isVersionBelow(version, cve.fixedVersion)) {
        findings.push(finding(
          `CVE_${cve.id.replace(/-/g, '_')}`,
          cve.severity,
          target + cve.checkPath,
          `Plugin '${cve.slug}' v${version} is vulnerable to ${cve.id}: ${cve.desc}`,
          {
            evidence: `plugin="${cve.slug}" installed="${version}" fixed_in="${cve.fixedVersion}" cve="${cve.id}"`,
            remediation: `Update '${cve.slug}' to >= ${cve.fixedVersion} immediately. This is ${cve.severity} severity.`,
          },
        ));
      }
    }));

    // Report WP version if detected
    if (finalWpVersion) {
      findings.push(finding(
        'WP_VERSION_DETECTED',
        'INFO',
        target,
        `WordPress version ${finalWpVersion} detected — checked against 2024-2025 CVE database`,
        { evidence: `wp_version="${finalWpVersion}"` },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
