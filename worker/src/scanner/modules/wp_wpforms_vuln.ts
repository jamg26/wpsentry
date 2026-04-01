import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'WPForms Vulnerability Scanner';

type VulnCheck = { cve: string; desc: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; patched: string };

const WPFORMS_VULNS: VulnCheck[] = [
  { cve: 'CVE-2023-2986', desc: 'Authentication Bypass via Stripe payment', severity: 'CRITICAL', patched: '1.8.3' },
  { cve: 'CVE-2024-2887', desc: 'Reflected XSS', severity: 'MEDIUM', patched: '1.8.8' },
  { cve: 'CVE-2024-5765', desc: 'Unauthorized Form Submission', severity: 'MEDIUM', patched: '1.8.9' },
  { cve: 'CVE-2023-3654', desc: 'Stored XSS via form fields', severity: 'MEDIUM', patched: '1.8.3.2' },
  { cve: 'CVE-2022-3574', desc: 'CSV Injection in form exports', severity: 'MEDIUM', patched: '1.7.8' },
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
    const slugs = ['wpforms-lite', 'wpforms'];
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

    if (!version) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const readmeUrl = `${target}/wp-content/plugins/${detectedSlug}/readme.txt`;
    for (const vuln of WPFORMS_VULNS) {
      if (versionLessThan(version, vuln.patched)) {
        findings.push(finding('WPFORMS_CVE', vuln.severity, readmeUrl,
          `WPForms v${version} is vulnerable: ${vuln.cve} — ${vuln.desc} (patched in ${vuln.patched})`, {
            evidence: `Detected version: ${version}, Patched version: ${vuln.patched}`,
            replication_steps: [
              `Fetch ${readmeUrl} and check "Stable tag"`,
              `Look up ${vuln.cve} for exploit details`,
            ],
            remediation: `Update WPForms to version ${vuln.patched} or later`,
          }));
      }
    }

    // Check for file upload forms without CSRF protection
    const homeRes = await fetchURL(`${target}/`);
    if (homeRes && homeRes.status === 200) {
      const html = await homeRes.text();
      if (html.includes('wpforms') && html.includes('type="file"')) {
        findings.push(finding('WPFORMS_FILE_UPLOAD', 'INFO', `${target}/`,
          'WPForms file upload field detected on public page', {
            evidence: 'Page contains WPForms form with file upload field',
            replication_steps: [
              `Visit ${target}/`,
              'Locate form with file upload capability',
            ],
            remediation: 'Ensure file upload forms have proper file type restrictions and size limits configured in WPForms settings.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
