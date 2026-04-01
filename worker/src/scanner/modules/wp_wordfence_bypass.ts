import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Wordfence WAF Bypass Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check if Wordfence is present
    let wordfenceDetected = false;
    let version: string | null = null;

    const readmeRes = await fetchURL(`${target}/wp-content/plugins/wordfence/readme.txt`);
    if (readmeRes && readmeRes.status === 200) {
      const body = await readmeRes.text();
      if (body.includes('Wordfence') || body.includes('wordfence')) {
        wordfenceDetected = true;
        const m = body.match(/Stable tag:\s*([0-9.]+)/i);
        if (m) version = m[1];
      }
    }

    if (!wordfenceDetected) return moduleResult(MODULE_NAME, target, findings, errors, start);

    // Check for exposed Wordfence logs
    const wflogsUrl = `${target}/wp-content/wflogs/`;
    const wflogsRes = await fetchURL(wflogsUrl);
    if (wflogsRes && wflogsRes.status === 200) {
      const body = await wflogsRes.text();
      if (body.includes('Index of') || body.includes('ips.php') || body.includes('config.php')) {
        findings.push(finding('WORDFENCE_LOGS_EXPOSED', 'HIGH', wflogsUrl,
          'Wordfence logs directory is publicly accessible — may expose IP addresses and security events', {
            evidence: `Directory listing or files accessible at ${wflogsUrl}`,
            replication_steps: [
              `Navigate to ${wflogsUrl}`,
              'Observe directory listing with Wordfence log files',
            ],
            remediation: 'Block public access to /wp-content/wflogs/ via .htaccess or nginx configuration.',
          }));
      }
    }

    // Check specific Wordfence log files
    await parallelProbe([
      '/wp-content/wflogs/ips.php',
      '/wp-content/wflogs/config.php',
      '/wp-content/wflogs/config-synced.php',
      '/wp-content/wflogs/attack-data.php',
    ], async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();
      // These files should start with <?php exit; to prevent access
      if (body.length > 50 && !body.startsWith('<?php exit')) {
        findings.push(finding('WORDFENCE_CONFIG_EXPOSED', 'HIGH', url,
          `Wordfence configuration file exposed: ${path}`, {
            evidence: `File accessible and not protected by PHP exit guard`,
            replication_steps: [`Fetch ${url}`, 'Observe configuration data'],
            remediation: 'Ensure Wordfence files have the <?php exit; guard and are not directly downloadable.',
          }));
      }
    }, 4);

    // Test WAF bypass techniques (benign test patterns only)
    const bypassTests: Array<{ path: string; desc: string }> = [
      { path: '/?s=<script>alert(1)</script>', desc: 'basic XSS payload' },
      { path: '/?s=%3Cscript%3Ealert(1)%3C/script%3E', desc: 'URL-encoded XSS' },
      { path: "/?s=' OR 1=1--", desc: 'basic SQL injection' },
    ];

    await parallelProbe(bypassTests, async (test) => {
      const url = `${target}${test.path}`;
      const res = await fetchURL(url);
      if (!res) return;
      const body = await res.text();

      // Check if WAF blocked the request (403 or Wordfence block page)
      if (res.status === 403 || body.includes('wordfence') || body.includes('blocked')) {
        // WAF is working — good
        return;
      }

      // If the payload made it through and is reflected
      if (res.status === 200 && body.includes('<script>alert(1)</script>')) {
        findings.push(finding('WORDFENCE_WAF_BYPASS', 'HIGH', url,
          `Wordfence WAF did not block ${test.desc} — payload reflected in response`, {
            evidence: `Payload "${test.desc}" was not blocked and is reflected in response`,
            replication_steps: [
              `Visit ${url}`,
              'Observe that the WAF did not intercept the malicious input',
            ],
            remediation: 'Enable Wordfence WAF in Extended Protection mode. Ensure WAF rules are up to date.',
          }));
      }
    }, 3);

    // Version check for known Wordfence vulns
    if (version) {
      const pa = version.split('.').map(Number);
      // CVE-2022-3912: Open Redirect in Wordfence < 7.7.0
      if (pa[0] < 7 || (pa[0] === 7 && (pa[1] ?? 0) < 7)) {
        findings.push(finding('WORDFENCE_CVE', 'MEDIUM',
          `${target}/wp-content/plugins/wordfence/readme.txt`,
          `Wordfence v${version} is vulnerable: CVE-2022-3912 — Open Redirect (patched in 7.7.0)`, {
            evidence: `Detected version: ${version}`,
            replication_steps: ['Check Wordfence readme.txt for version', 'Compare against CVE-2022-3912'],
            remediation: 'Update Wordfence to version 7.7.0 or later.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
