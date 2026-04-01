import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'UpdraftPlus Vulnerability Scanner';

type VulnCheck = { cve: string; desc: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; patched: string };

const UPDRAFT_VULNS: VulnCheck[] = [
  { cve: 'CVE-2022-0633', desc: 'Unauthorized Backup Download (subscriber+)', severity: 'HIGH', patched: '1.22.3' },
  { cve: 'CVE-2023-32960', desc: 'Sensitive Data Exposure', severity: 'MEDIUM', patched: '1.23.11' },
  { cve: 'CVE-2022-2572', desc: 'SSRF via backup destination', severity: 'HIGH', patched: '1.22.24' },
  { cve: 'CVE-2021-25022', desc: 'Reflected XSS', severity: 'MEDIUM', patched: '1.16.69' },
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
    const readmeUrl = `${target}/wp-content/plugins/updraftplus/readme.txt`;
    const res = await fetchURL(readmeUrl);
    if (!res || res.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();
    if (!body.includes('UpdraftPlus') && !body.includes('updraft')) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    const m = body.match(/Stable tag:\s*([0-9.]+)/i) ?? body.match(/Version:\s*([0-9.]+)/i);
    const version = m ? m[1] : null;

    if (version) {
      for (const vuln of UPDRAFT_VULNS) {
        if (versionLessThan(version, vuln.patched)) {
          findings.push(finding('UPDRAFTPLUS_CVE', vuln.severity, readmeUrl,
            `UpdraftPlus v${version} is vulnerable: ${vuln.cve} — ${vuln.desc} (patched in ${vuln.patched})`, {
              evidence: `Detected version: ${version}, Patched version: ${vuln.patched}`,
              replication_steps: [
                `Fetch ${readmeUrl} and check "Stable tag"`,
                `Look up ${vuln.cve} for exploit details`,
              ],
              remediation: `Update UpdraftPlus to version ${vuln.patched} or later`,
            }));
        }
      }
    }

    // Check for exposed backup files
    const backupPaths = [
      '/wp-content/updraft/',
      '/wp-content/backups/',
      '/wp-content/updraft-backups/',
    ];

    await parallelProbe(backupPaths, async (path) => {
      const url = `${target}${path}`;
      const dirRes = await fetchURL(url);
      if (!dirRes || dirRes.status !== 200) return;
      const dirBody = await dirRes.text();

      if (dirBody.includes('Index of') || dirBody.includes('.zip') || dirBody.includes('.gz') ||
          dirBody.includes('backup_') || dirBody.includes('.sql')) {
        findings.push(finding('UPDRAFT_BACKUPS_EXPOSED', 'CRITICAL', url,
          `UpdraftPlus backup directory is publicly accessible at ${path}`, {
            evidence: `Directory listing or backup files accessible at ${url}`,
            replication_steps: [
              `Navigate to ${url}`,
              'Observe backup files that can be downloaded',
              'Backups may contain database dumps with credentials and user data',
            ],
            remediation: 'Block public access to the backup directory via .htaccess. Configure UpdraftPlus to store backups in a secure remote location (S3, Google Drive, etc.).',
          }));
      }
    }, 3);

    // Check for UpdraftPlus AJAX endpoints
    const ajaxUrl = `${target}/wp-admin/admin-ajax.php?action=updraft_download_backup`;
    const ajaxRes = await fetchURL(ajaxUrl);
    if (ajaxRes && ajaxRes.status === 200) {
      const ajaxBody = await ajaxRes.text();
      if (!ajaxBody.includes('error') && !ajaxBody.includes('not_logged_in') && ajaxBody.length > 10) {
        findings.push(finding('UPDRAFT_AJAX_EXPOSED', 'HIGH', ajaxUrl,
          'UpdraftPlus backup download AJAX endpoint accessible without proper authentication', {
            evidence: `AJAX endpoint returned response without authentication error`,
            replication_steps: [`Fetch ${ajaxUrl}`, 'Check if backup data is returned'],
            remediation: 'Update UpdraftPlus to the latest version. The download endpoint should require admin authentication.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
