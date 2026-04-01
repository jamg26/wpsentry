import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Yoast SEO Vulnerability Scanner';

type VulnCheck = { cve: string; desc: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; patched: string };

const YOAST_VULNS: VulnCheck[] = [
  { cve: 'CVE-2023-40680', desc: 'Reflected XSS in admin panel', severity: 'MEDIUM', patched: '21.1' },
  { cve: 'CVE-2024-4041', desc: 'Reflected XSS via breadcrumbs', severity: 'MEDIUM', patched: '22.6' },
  { cve: 'CVE-2023-25367', desc: 'SQL Injection in admin', severity: 'HIGH', patched: '20.3' },
  { cve: 'CVE-2021-25118', desc: 'Authenticated Stored XSS', severity: 'MEDIUM', patched: '17.3' },
  { cve: 'CVE-2024-24706', desc: 'Server-Side Request Forgery', severity: 'HIGH', patched: '22.0' },
];

function versionLessThan(a: string, b: string): boolean {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] ?? 0) < (pb[i] ?? 0)) return true;
    if ((pa[i] ?? 0) > (pb[i] ?? 0)) return false;
  }
  return false;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Try both yoast plugin slugs
    const slugs = ['wordpress-seo', 'wordpress-seo-premium'];
    let version: string | null = null;
    let detectedSlug = '';

    for (const slug of slugs) {
      const readmeUrl = `${target}/wp-content/plugins/${slug}/readme.txt`;
      const res = await fetchURL(readmeUrl);
      if (res && res.status === 200) {
        const body = await res.text();
        const m = body.match(/Stable tag:\s*([0-9.]+)/i) ?? body.match(/Version:\s*([0-9.]+)/i);
        if (m) {
          version = m[1];
          detectedSlug = slug;
          break;
        }
      }
    }

    // Also try detecting from page source
    if (!version) {
      const homeRes = await fetchURL(`${target}/`);
      if (homeRes && homeRes.status === 200) {
        const html = await homeRes.text();
        // Yoast adds a comment in HTML
        const yoastComment = html.match(/Yoast SEO plugin[^-]*- ([0-9.]+)/i) ??
                            html.match(/yoast-seo.*?ver=([0-9.]+)/i);
        if (yoastComment) {
          version = yoastComment[1];
          detectedSlug = 'wordpress-seo';
        }
      }
    }

    if (!version) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const readmeUrl = `${target}/wp-content/plugins/${detectedSlug}/readme.txt`;
    for (const vuln of YOAST_VULNS) {
      if (versionLessThan(version, vuln.patched)) {
        findings.push(finding('YOAST_CVE', vuln.severity, readmeUrl,
          `Yoast SEO v${version} is vulnerable: ${vuln.cve} — ${vuln.desc} (patched in ${vuln.patched})`, {
            evidence: `Detected version: ${version}, Patched version: ${vuln.patched}`,
            replication_steps: [
              `Check ${readmeUrl} or page source for Yoast version`,
              `Look up ${vuln.cve} for exploit details`,
            ],
            remediation: `Update Yoast SEO to version ${vuln.patched} or later`,
          }));
      }
    }

    // Check for Yoast SEO sitemap (info leak)
    const sitemapUrl = `${target}/sitemap_index.xml`;
    const sitemapRes = await fetchURL(sitemapUrl);
    if (sitemapRes && sitemapRes.status === 200) {
      const sitemapBody = await sitemapRes.text();
      if (sitemapBody.includes('Yoast SEO') || sitemapBody.includes('yoast')) {
        findings.push(finding('YOAST_SITEMAP_FINGERPRINT', 'INFO', sitemapUrl,
          `Yoast SEO sitemap detected (v${version}) — confirms plugin presence and version`, {
            evidence: 'Sitemap XML contains Yoast SEO references',
            replication_steps: [`Fetch ${sitemapUrl}`, 'Check for Yoast references'],
            remediation: 'Consider removing Yoast SEO credits from sitemap output.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
