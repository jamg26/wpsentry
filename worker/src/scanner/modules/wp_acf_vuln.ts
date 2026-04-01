import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'ACF Vulnerability Scanner';

type VulnCheck = { cve: string; desc: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; patched: string };

const ACF_VULNS: VulnCheck[] = [
  { cve: 'CVE-2023-30777', desc: 'Reflected XSS (subscriber+)', severity: 'HIGH', patched: '6.1.6' },
  { cve: 'CVE-2024-1532', desc: 'Stored XSS via custom field', severity: 'MEDIUM', patched: '6.2.5' },
  { cve: 'CVE-2023-4220', desc: 'Arbitrary file read via export', severity: 'HIGH', patched: '6.2.0' },
  { cve: 'CVE-2022-40696', desc: 'Reflected XSS in admin', severity: 'MEDIUM', patched: '5.12.4' },
  { cve: 'CVE-2023-1196', desc: 'PHP Object Injection', severity: 'HIGH', patched: '6.1.0' },
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
    // Check both free and pro versions
    const slugs = ['advanced-custom-fields', 'advanced-custom-fields-pro'];
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
    for (const vuln of ACF_VULNS) {
      if (versionLessThan(version, vuln.patched)) {
        findings.push(finding('ACF_CVE', vuln.severity, readmeUrl,
          `Advanced Custom Fields v${version} is vulnerable: ${vuln.cve} — ${vuln.desc} (patched in ${vuln.patched})`, {
            evidence: `Detected version: ${version}, Patched version: ${vuln.patched}`,
            replication_steps: [
              `Fetch ${readmeUrl} and check "Stable tag"`,
              `Look up ${vuln.cve} for exploit details`,
            ],
            remediation: `Update Advanced Custom Fields to version ${vuln.patched} or later`,
          }));
      }
    }

    // Check for ACF REST API exposure
    const acfRestUrl = `${target}/wp-json/acf/v3/posts`;
    const acfRes = await fetchURL(acfRestUrl);
    if (acfRes && acfRes.status === 200) {
      const body = await acfRes.text();
      if (body.length > 20 && !body.includes('rest_no_route')) {
        findings.push(finding('ACF_REST_EXPOSED', 'MEDIUM', acfRestUrl,
          'ACF REST API endpoint is publicly accessible — custom field data may be exposed', {
            evidence: `ACF REST API returned ${body.length} bytes of data`,
            replication_steps: [`Fetch ${acfRestUrl}`, 'Observe custom field data in response'],
            remediation: 'Restrict ACF REST API access to authenticated users in ACF settings.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
