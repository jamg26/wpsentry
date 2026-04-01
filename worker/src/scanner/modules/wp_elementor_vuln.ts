import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Elementor Vulnerability Scanner';

// [cve, description, severity, check_type, patched_version]
type VulnCheck = {
  cve: string;
  desc: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  patched: string;
};

const ELEMENTOR_VULNS: VulnCheck[] = [
  { cve: 'CVE-2023-48777', desc: 'Arbitrary File Upload leading to RCE', severity: 'CRITICAL', patched: '3.18.2' },
  { cve: 'CVE-2024-2117', desc: 'Reflected XSS via URL parameter', severity: 'MEDIUM', patched: '3.20.0' },
  { cve: 'CVE-2024-0506', desc: 'Privilege Escalation via template import', severity: 'HIGH', patched: '3.18.4' },
  { cve: 'CVE-2023-47504', desc: 'Stored XSS in widgets', severity: 'MEDIUM', patched: '3.17.4' },
  { cve: 'CVE-2023-0133', desc: 'DOM-based XSS in frontend editor', severity: 'MEDIUM', patched: '3.10.0' },
  { cve: 'CVE-2022-29455', desc: 'Reflected DOM XSS', severity: 'HIGH', patched: '3.5.6' },
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

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check if Elementor is installed
    const readmeUrl = `${target}/wp-content/plugins/elementor/readme.txt`;
    const readmeRes = await fetchURL(readmeUrl);
    if (!readmeRes || readmeRes.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const readmeBody = await readmeRes.text();
    if (!readmeBody.includes('Elementor') && !readmeBody.includes('elementor')) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Extract version from readme
    const versionMatch = readmeBody.match(/Stable tag:\s*([0-9.]+)/i) ??
                         readmeBody.match(/Version:\s*([0-9.]+)/i);
    const version = versionMatch ? versionMatch[1] : null;

    if (version) {
      for (const vuln of ELEMENTOR_VULNS) {
        if (versionLessThan(version, vuln.patched)) {
          findings.push(finding('ELEMENTOR_CVE', vuln.severity, readmeUrl,
            `Elementor v${version} is vulnerable: ${vuln.cve} — ${vuln.desc} (patched in ${vuln.patched})`, {
              evidence: `Detected Elementor version: ${version}, Patched version: ${vuln.patched}`,
              replication_steps: [
                `Fetch ${readmeUrl} and check "Stable tag" for version`,
                `Look up ${vuln.cve} for exploit details`,
              ],
              remediation: `Update Elementor to version ${vuln.patched} or later`,
            }));
        }
      }
    }

    // Check Elementor-specific endpoints
    await parallelProbe([
      '/wp-json/elementor/v1/system-info',
      '/wp-content/plugins/elementor/assets/js/editor.js',
    ], async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      if (path.includes('system-info') && body.length > 50 && !body.includes('rest_forbidden')) {
        findings.push(finding('ELEMENTOR_SYSINFO_EXPOSED', 'MEDIUM', url,
          'Elementor system-info endpoint is publicly accessible — leaks server configuration', {
            evidence: `System info endpoint returned ${body.length} bytes`,
            replication_steps: [`Fetch ${url}`, 'Observe system configuration data'],
            remediation: 'Restrict the Elementor system-info REST endpoint to administrators only.',
          }));
      }
    }, 2);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
