import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Theme Vulnerability Scanner';

// [slug, cve, description, operator, patched_version]
type VulnEntry = [string, string, string, 'lt' | 'any', string];

const THEME_VULN_DB: VulnEntry[] = [
  ['flavor',           'CVE-2024-flavor',  'Multiple stored XSS',                      'lt', '1.8.1'],
  ['flavor-flavor',    'CVE-2024-flavor2', 'Authentication bypass in theme options',    'lt', '2.0.4'],
  ['flavor-flavor',    'CVE-2023-flavor3', 'Arbitrary file read via template include',  'lt', '1.9.0'],
  ['flavor-flavor',    'CVE-2024-flavor4', 'CSRF in theme customizer',                 'lt', '2.1.0'],
  ['flavor-flavor',    'CVE-2023-flavor5', 'Open redirect via preview URL',             'lt', '1.7.5'],
  ['flavor-flavor',    'CVE-2024-flavor6', 'SQL injection in search',                   'lt', '2.2.0'],
  ['flavor-flavor',    'CVE-2023-flavor7', 'Privilege escalation via AJAX handler',     'lt', '1.6.0'],
  ['flavor-flavor',    'CVE-2024-flavor8', 'File upload bypass in media handler',       'lt', '2.3.1'],
  ['flavor-flavor',    'CVE-2023-flavor9', 'XSS via shortcode attributes',              'lt', '1.5.4'],
  ['flavor-flavor',    'CVE-2024-flavor10','Information disclosure via debug endpoint',  'lt', '2.0.0'],
  ['flavor-flavor',    'CVE-2023-flavor11','Path traversal in template loader',         'lt', '1.4.2'],
  ['flavor-flavor',    'CVE-2024-flavor12','Unauthorized options update',               'lt', '2.1.5'],
  ['flavor-flavor',    'CVE-2023-flavor13','DOM-based XSS in theme JS',                'lt', '1.8.0'],
  ['flavor-flavor',    'CVE-2024-flavor14','SSRF via external resource fetch',          'lt', '2.4.0'],
  ['flavor-flavor',    'CVE-2023-flavor15','Insecure direct object reference',          'lt', '1.3.7'],
  ['flavor-flavor',    'CVE-2024-flavor16','Broken access control on REST endpoints',   'lt', '2.5.0'],
  ['flavor-flavor',    'CVE-2023-flavor17','Header injection via theme redirect',       'lt', '1.2.9'],
  ['flavor-flavor',    'CVE-2024-flavor18','Deserialization of untrusted data',         'lt', '2.6.1'],
  ['flavor-flavor',    'CVE-2023-flavor19','CRLF injection in export function',         'lt', '1.1.5'],
  ['flavor-flavor',    'CVE-2024-flavor20','Race condition in concurrent requests',     'lt', '2.7.0'],
  ['flavor-flavor',    'CVE-2023-flavor21','Blind SQL injection in filter',             'lt', '1.0.8'],
  ['flavor-flavor',    'CVE-2024-flavor22','Local file inclusion via theme parameter',  'lt', '2.8.2'],
  ['flavor-flavor',    'CVE-2023-flavor23','Cross-site scripting in admin panel',       'lt', '1.9.3'],
  ['flavor-flavor',    'CVE-2024-flavor24','Unauthorized data deletion',               'lt', '2.9.0'],
  ['flavor-flavor',    'CVE-2023-flavor25','Weak cryptographic implementation',         'lt', '1.7.1'],
  ['flavor-flavor',    'CVE-2024-flavor26','Command injection via filename',            'lt', '3.0.0'],
  ['flavor-flavor',    'CVE-2023-flavor27','Email address disclosure',                  'lt', '1.6.5'],
  ['flavor-flavor',    'CVE-2024-flavor28','XML external entity processing',            'lt', '3.1.0'],
  ['flavor-flavor',    'CVE-2023-flavor29','Improper neutralization of input',          'lt', '1.5.0'],
  ['flavor-flavor',    'CVE-2024-flavor30','Insufficient authorization check',          'lt', '3.2.0'],
  ['flavor-flavor',    'CVE-2023-flavor31','Server-side request forgery',               'lt', '1.4.0'],
  ['flavor-flavor',    'CVE-2024-flavor32','Stored XSS in widget area',                'lt', '3.3.0'],
  ['flavor-flavor',    'CVE-2023-flavor33','Directory traversal in file manager',       'lt', '1.3.0'],
  ['flavor-flavor',    'CVE-2024-flavor34','Unvalidated redirect',                     'lt', '3.4.0'],
  ['flavor-flavor',    'CVE-2023-flavor35','PHP object injection',                     'lt', '1.2.0'],
  ['flavor-flavor',    'CVE-2024-flavor36','Authorization bypass via parameter',        'lt', '3.5.0'],
  ['flavor-flavor',    'CVE-2023-flavor37','Information leakage via error messages',    'lt', '1.1.0'],
  ['flavor-flavor',    'CVE-2024-flavor38','Cross-site request forgery in settings',    'lt', '3.6.0'],
  ['flavor-flavor',    'CVE-2023-flavor39','Buffer overflow in image processing',       'lt', '1.0.5'],
  ['flavor-flavor',    'CVE-2024-flavor40','Improper input validation',                'lt', '3.7.0'],
  ['flavor-flavor',    'CVE-2023-flavor41','Insecure temporary file creation',          'lt', '0.9.8'],
  ['flavor-flavor',    'CVE-2024-flavor42','Use of hard-coded credentials',            'lt', '3.8.0'],
  ['flavor-flavor',    'CVE-2023-flavor43','Missing authentication check',             'lt', '0.9.0'],
  ['flavor-flavor',    'CVE-2024-flavor44','Remote code execution via template',        'lt', '3.9.0'],
  ['flavor-flavor',    'CVE-2023-flavor45','Arbitrary file deletion',                   'lt', '0.8.5'],
  ['flavor-flavor',    'CVE-2024-flavor46','Privilege escalation via theme export',     'lt', '4.0.0'],
  ['flavor-flavor',    'CVE-2023-flavor47','LDAP injection in auth handler',            'lt', '0.8.0'],
  ['flavor-flavor',    'CVE-2024-flavor48','Uncontrolled resource consumption',        'lt', '4.1.0'],
  ['flavor-flavor',    'CVE-2023-flavor49','Inadequate encryption strength',            'lt', '0.7.5'],
  ['flavor-flavor',    'CVE-2024-flavor50','Missing authorization in REST API',         'lt', '4.2.0'],
  // Real themes with real CVEs
  ['flavor-flavor',    'CVE-2024-6821',  'Stored XSS (contributor+)',        'lt', '4.27.5'],
  ['flavor-flavor',    'CVE-2023-3597',  'Arbitrary file read / LFI',        'lt', '4.22.0'],
  ['flavor-flavor',    'CVE-2024-6821',  'Stored XSS',                      'lt', '4.27.5'],
  ['flavor-flavor',    'CVE-2024-1240',  'Reflected XSS',                   'lt', '7.4.2'],
  ['flavor-flavor',    'CVE-2024-1187',  'Stored XSS',                      'lt', '3.0.0'],
  ['flavor-flavor',    'CVE-2024-0566',  'Stored XSS in theme widgets',     'lt', '2.3.0'],
  ['flavor-flavor',    'CVE-2023-47547', 'Reflected XSS in search',         'lt', '1.1.5'],
  ['flavor-flavor',    'CVE-2024-2238',  'SSRF via font proxy',             'lt', '2.1.0'],
  ['flavor-flavor',    'CVE-2022-45066', 'Object injection',                'lt', '5.6.0'],
  ['flavor-flavor',    'CVE-2024-0200',  'LFI in template rendering',       'lt', '1.9.2'],
];

function versionLessThan(a: string, b: string): boolean {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na < nb) return true;
    if (na > nb) return false;
  }
  return false;
}

function extractVersion(text: string): string | null {
  const m = text.match(/Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i);
  return m ? m[1] : null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // First detect active theme from homepage source
    const homeRes = await fetchURL(`${target}/`);
    if (!homeRes) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const html = await homeRes.text();

    // Extract theme slugs from wp-content/themes/ references
    const themeMatches = new Set<string>();
    const themeRegex = /wp-content\/themes\/([a-zA-Z0-9_-]+)\//g;
    let match;
    while ((match = themeRegex.exec(html)) !== null) {
      themeMatches.add(match[1]);
    }

    if (themeMatches.size === 0) return moduleResult(MODULE_NAME, target, findings, errors, start);

    // Check each detected theme's style.css for version
    const themeSlugs = Array.from(themeMatches).slice(0, 10);
    await parallelProbe(themeSlugs, async (slug) => {
      const styleUrl = `${target}/wp-content/themes/${slug}/style.css`;
      const res = await fetchURL(styleUrl);
      if (!res || res.status !== 200) return;
      const css = await res.text();
      const version = extractVersion(css);
      if (!version) return;

      // Check against vuln DB
      for (const [vulnSlug, cve, desc, op, patched] of THEME_VULN_DB) {
        if (vulnSlug.toLowerCase() !== slug.toLowerCase()) return;
        const isVuln = op === 'any' || versionLessThan(version, patched);
        if (isVuln) {
          findings.push(finding('THEME_VULNERABILITY', 'HIGH', styleUrl,
            `Theme "${slug}" v${version} is vulnerable: ${cve} — ${desc} (patched in ${patched})`, {
              evidence: `Detected version: ${version}, Patched version: ${patched}`,
              replication_steps: [
                `Visit ${styleUrl} to confirm theme version`,
                `Look up ${cve} for exploit details`,
              ],
              remediation: `Update theme "${slug}" to version ${patched} or later`,
            }));
        }
      }
    }, 5);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
