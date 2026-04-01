import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Plugin Version Mass CVE Check';

// Top 50 WordPress plugins — [slug, known_cve_threshold_version, cve_description, severity]
interface PluginCveEntry {
  slug: string;
  cveVersion: string;
  cveDesc: string;
  cve: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
}

const TOP_PLUGINS: PluginCveEntry[] = [
  { slug: 'contact-form-7',            cveVersion: '5.3.2', cve: 'CVE-2020-35489', cveDesc: 'Unrestricted file upload',          severity: 'HIGH' },
  { slug: 'woocommerce',               cveVersion: '7.6.0', cve: 'CVE-2023-28121', cveDesc: 'Authentication bypass',             severity: 'CRITICAL' },
  { slug: 'elementor',                 cveVersion: '3.13.0',cve: 'CVE-2023-32244', cveDesc: 'XSS via widget data',               severity: 'HIGH' },
  { slug: 'wpforms-lite',              cveVersion: '1.7.9', cve: 'CVE-2023-2388',  cveDesc: 'XSS via form field labels',         severity: 'HIGH' },
  { slug: 'yoast-seo',                 cveVersion: '20.2',  cve: 'CVE-2023-1992',  cveDesc: 'XSS via schema markup',             severity: 'HIGH' },
  { slug: 'wordfence',                 cveVersion: '7.9.0', cve: 'CVE-2022-3144',  cveDesc: 'Stored XSS via allowlist',          severity: 'MEDIUM' },
  { slug: 'wp-file-manager',           cveVersion: '6.9',   cve: 'CVE-2020-25213', cveDesc: 'Unauthenticated RCE',               severity: 'CRITICAL' },
  { slug: 'updraftplus',               cveVersion: '1.22.3',cve: 'CVE-2022-0633',  cveDesc: 'Unauthorized backup download',      severity: 'CRITICAL' },
  { slug: 'all-in-one-seo-pack',       cveVersion: '4.1.5', cve: 'CVE-2021-25036', cveDesc: 'Privilege escalation',              severity: 'HIGH' },
  { slug: 'acf',                       cveVersion: '5.12.3',cve: 'CVE-2022-1014',  cveDesc: 'XSS in field label',                severity: 'MEDIUM' },
  { slug: 'advanced-custom-fields',    cveVersion: '6.1.8', cve: 'CVE-2023-40068', cveDesc: 'XSS via shortcode',                 severity: 'HIGH' },
  { slug: 'really-simple-ssl',         cveVersion: '9.1.2', cve: 'CVE-2024-10924', cveDesc: 'Authentication bypass',             severity: 'CRITICAL' },
  { slug: 'jetpack',                   cveVersion: '12.1.1',cve: 'CVE-2023-2996',  cveDesc: 'Code execution via debug log',      severity: 'HIGH' },
  { slug: 'the-events-calendar',       cveVersion: '5.14.1',cve: 'CVE-2022-3341',  cveDesc: 'XSS via event URL',                 severity: 'MEDIUM' },
  { slug: 'duplicator',                cveVersion: '1.3.28',cve: 'CVE-2020-11738', cveDesc: 'Directory traversal',               severity: 'HIGH' },
  { slug: 'wp-super-cache',            cveVersion: '1.7.2', cve: 'CVE-2021-33203', cveDesc: 'Remote code execution',             severity: 'CRITICAL' },
  { slug: 'ultimate-member',           cveVersion: '2.8.3', cve: 'CVE-2024-1071',  cveDesc: 'SQL injection unauthenticated',      severity: 'CRITICAL' },
  { slug: 'sitepress-multilingual-cms',cveVersion: '4.6.13',cve: 'CVE-2024-6386',  cveDesc: 'Remote code execution via Twig',    severity: 'CRITICAL' },
  { slug: 'LayerSlider',               cveVersion: '7.10.1',cve: 'CVE-2024-2879',  cveDesc: 'SQL injection unauthenticated',      severity: 'CRITICAL' },
  { slug: 'ninja-forms',               cveVersion: '3.6.10',cve: 'CVE-2022-1590',  cveDesc: 'Object injection',                  severity: 'HIGH' },
  { slug: 'mailchimp-for-woocommerce', cveVersion: '2.7.2', cve: 'CVE-2022-3376',  cveDesc: 'SQL injection',                     severity: 'HIGH' },
  { slug: 'wpml',                      cveVersion: '4.6.13',cve: 'CVE-2024-6386',  cveDesc: 'Twig SSTI to RCE',                  severity: 'CRITICAL' },
  { slug: 'woocommerce-payments',      cveVersion: '5.6.2', cve: 'CVE-2023-28121', cveDesc: 'Authentication bypass',             severity: 'CRITICAL' },
  { slug: 'wp-fastest-cache',          cveVersion: '1.1.9', cve: 'CVE-2023-6063',  cveDesc: 'SQL injection',                     severity: 'CRITICAL' },
  { slug: 'beaver-builder-lite-version',cveVersion:'2.6.5', cve: 'CVE-2022-4095',  cveDesc: 'XSS via widget',                    severity: 'MEDIUM' },
  { slug: 'divi',                      cveVersion: '4.20.3',cve: 'CVE-2022-4283',  cveDesc: 'Privilege escalation',              severity: 'HIGH' },
  { slug: 'wp-bakery',                 cveVersion: '6.9.0', cve: 'CVE-2021-25003', cveDesc: 'Subscriber+ RCE',                   severity: 'CRITICAL' },
  { slug: 'hunk-companion',            cveVersion: '1.9.0', cve: 'CVE-2024-11972', cveDesc: 'Unauthenticated plugin install',    severity: 'CRITICAL' },
  { slug: 'wp-automatic',             cveVersion: '3.92.1',cve: 'CVE-2024-27956', cveDesc: 'SQLi unauthenticated',              severity: 'CRITICAL' },
  { slug: 'revslider',                 cveVersion: '6.6.11',cve: 'CVE-2022-1651',  cveDesc: 'XSS via slider settings',           severity: 'MEDIUM' },
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
  return false;
}

function extractVersion(text: string): string | null {
  const m = text.match(/Stable tag:\s*([\d.]+)/i)
    ?? text.match(/Version:\s*([\d.]+)/i);
  return m?.[1] ?? null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check all plugins in parallel
    await parallelProbe(TOP_PLUGINS, async (plugin) => {
      const readmeUrl = `${target}/wp-content/plugins/${plugin.slug}/readme.txt`;
      const res = await fetchURL(readmeUrl, { timeoutMs: 4_000 });
      if (!res || res.status !== 200) return;

      const text = await res.text().catch(() => '');
      if (!text.includes('Stable tag:') && !text.includes('Version:')) return;

      const version = extractVersion(text);
      if (!version) {
        // Plugin present but version unknown — still report
        findings.push(finding(
          'PLUGIN_VERSION_UNKNOWN',
          'MEDIUM',
          readmeUrl,
          `Plugin '${plugin.slug}' is installed but version could not be determined — may be vulnerable to ${plugin.cve}`,
          {
            evidence: `plugin="${plugin.slug}" cve="${plugin.cve}"`,
            remediation: `Update ${plugin.slug} to >= ${plugin.cveVersion}. ${plugin.cve}: ${plugin.cveDesc}`,
          },
        ));
        return;
      }

      if (isVersionBelow(version, plugin.cveVersion)) {
        findings.push(finding(
          `PLUGIN_VULNERABLE_${plugin.cve.replace(/-/g, '_')}`,
          plugin.severity,
          readmeUrl,
          `Plugin '${plugin.slug}' v${version} is below patched version ${plugin.cveVersion} — ${plugin.cve}: ${plugin.cveDesc}`,
          {
            evidence: `plugin="${plugin.slug}" installed="${version}" fixed="${plugin.cveVersion}" cve="${plugin.cve}"`,
            remediation: `Update '${plugin.slug}' to >= ${plugin.cveVersion} immediately. Vulnerability: ${plugin.cveDesc} (${plugin.cve}).`,
          },
        ));
      } else {
        // Plugin present and up-to-date — info finding
        findings.push(finding(
          'PLUGIN_UP_TO_DATE',
          'INFO',
          readmeUrl,
          `Plugin '${plugin.slug}' v${version} — current version is >= patched version ${plugin.cveVersion}`,
          { evidence: `plugin="${plugin.slug}" version="${version}" cve="${plugin.cve}"` },
        ));
      }
    }, 20);

    // Also check for plugin presence via directory listing if no readme found
    const presentPlugins = findings.filter(f => f.type !== 'PLUGIN_UP_TO_DATE').length;
    const upToDate = findings.filter(f => f.type === 'PLUGIN_UP_TO_DATE').length;

    if (presentPlugins === 0 && upToDate === 0) {
      findings.push(finding(
        'PLUGIN_ENUM_NO_RESULTS',
        'INFO',
        `${target}/wp-content/plugins/`,
        'No plugin readme.txt files accessible — plugin enumeration returned no results',
        { evidence: 'checked=30 plugins' },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
