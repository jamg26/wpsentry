import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'All in One SEO Vulnerability Scanner';

type VulnCheck = { cve: string; desc: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; patched: string };

const AIOSEO_VULNS: VulnCheck[] = [
  { cve: 'CVE-2021-25036', desc: 'SQL Injection (subscriber+)', severity: 'CRITICAL', patched: '4.1.5.3' },
  { cve: 'CVE-2021-25037', desc: 'Privilege Escalation to admin', severity: 'CRITICAL', patched: '4.1.5.3' },
  { cve: 'CVE-2023-0586', desc: 'Stored XSS via SEO meta', severity: 'MEDIUM', patched: '4.3.0' },
  { cve: 'CVE-2024-1071', desc: 'SQL Injection via REST API', severity: 'HIGH', patched: '4.5.4' },
  { cve: 'CVE-2023-6156', desc: 'Reflected XSS in sitemap', severity: 'MEDIUM', patched: '4.4.8' },
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
    const readmeUrl = `${target}/wp-content/plugins/all-in-one-seo-pack/readme.txt`;
    const res = await fetchURL(readmeUrl);
    if (!res || res.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();

    if (!body.includes('All in One SEO') && !body.includes('all-in-one-seo')) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    const m = body.match(/Stable tag:\s*([0-9.]+)/i) ?? body.match(/Version:\s*([0-9.]+)/i);
    const version = m ? m[1] : null;

    if (version) {
      for (const vuln of AIOSEO_VULNS) {
        if (versionLessThan(version, vuln.patched)) {
          findings.push(finding('AIOSEO_CVE', vuln.severity, readmeUrl,
            `All in One SEO v${version} is vulnerable: ${vuln.cve} — ${vuln.desc} (patched in ${vuln.patched})`, {
              evidence: `Detected version: ${version}, Patched version: ${vuln.patched}`,
              replication_steps: [
                `Fetch ${readmeUrl} and check "Stable tag"`,
                `Look up ${vuln.cve} for exploit details`,
              ],
              remediation: `Update All in One SEO to version ${vuln.patched} or later`,
            }));
        }
      }
    }

    // Check for AIOSEO REST API endpoints
    const aioseoRestUrl = `${target}/wp-json/aioseo/v1/`;
    const restRes = await fetchURL(aioseoRestUrl);
    if (restRes && restRes.status === 200) {
      const restBody = await restRes.text();
      if (restBody.length > 50 && !restBody.includes('rest_no_route') && !restBody.includes('rest_forbidden')) {
        findings.push(finding('AIOSEO_REST_EXPOSED', 'MEDIUM', aioseoRestUrl,
          'All in One SEO REST API is publicly accessible', {
            evidence: `AIOSEO REST API returned ${restBody.length} bytes`,
            replication_steps: [`Fetch ${aioseoRestUrl}`, 'Observe API response'],
            remediation: 'Restrict AIOSEO REST endpoints to authenticated users.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
