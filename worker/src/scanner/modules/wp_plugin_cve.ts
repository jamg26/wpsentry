import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Plugin CVE Scanner';

// [slug, cve, description, operator, patched_version]
type DbEntry = [string, string, string, 'lt' | 'any', string];

const PLUGIN_DB: DbEntry[] = [
  ['elementor',                'CVE-2023-48777', 'RCE',                                         'lt',  '3.18.2'],
  ['wpforms',                  'CVE-2023-2986',  'Auth bypass',                                  'lt',  '1.8.3'],
  ['advanced-custom-fields',   'CVE-2023-30777', 'Reflected XSS',                               'lt',  '6.1.6'],
  ['yoast-seo',                'CVE-2023-4733',  'SQLi',                                        'lt',  '21.1'],
  ['wordfence',                'CVE-2022-3912',  'Open Redirect',                               'lt',  '7.7.0'],
  ['all-in-one-seo-pack',      'CVE-2021-25036', 'SQLi',                                        'any', ''],
  ['ultimate-member',          'CVE-2023-3460',  'SQLi / Auth bypass',                          'lt',  '2.6.7'],
  ['gravityforms',             'CVE-2023-28782', 'SQLi',                                        'any', ''],
  ['ninja-forms',              'CVE-2021-34656', 'Code injection',                              'lt',  '3.4.34'],
  ['wp-super-cache',           'CVE-2021-24209', 'Authenticated XSS',                           'lt',  '1.7.3'],
  ['duplicator',               'CVE-2020-11738', 'Path traversal',                              'lt',  '1.3.28'],
  ['wp-fastest-cache',         'CVE-2023-6063',  'SQLi',                                        'lt',  '1.2.2'],
  ['simple-membership',        'CVE-2023-3459',  'Auth bypass',                                 'any', ''],
  ['loginizer',                'CVE-2020-27615', 'SQLi',                                        'lt',  '1.6.4'],
  ['mail-masta',               'CVE-2016-10956', 'LFI',                                         'any', ''],
  ['dzs-video-gallery',        'CVE-2016-4000',  'SQLi',                                        'any', ''],
  ['adsense-manager',          'CVE-2016-10986', 'LFI',                                         'any', ''],
  ['relevanssi',               'CVE-2020-11028', 'SSRF',                                        'lt',  '4.14.8'],
  ['w3-total-cache',           'CVE-2021-24587', 'SSRF',                                        'lt',  '2.1.4'],
  ['wp-statistics',            'CVE-2023-1045',  'SQLi',                                        'lt',  '13.2.9'],
  ['learnpress',               'CVE-2022-45808', 'SQLi',                                        'lt',  '4.1.7'],
  ['buddypress',               'CVE-2021-21389', 'Privilege escalation',                        'lt',  '7.2.1'],
  ['paid-memberships-pro',     'CVE-2023-23575', 'SQLi',                                        'any', ''],
  ['give',                     'CVE-2022-2559',  'SQLi',                                        'lt',  '2.20.2'],
  ['amelia',                   'CVE-2022-0265',  'SQLi',                                        'lt',  '1.0.48'],
  ['booked',                   'CVE-2015-7377',  'XSS + SQLi',                                  'any', ''],
  ['wp-google-maps',           'CVE-2019-10692', 'SQLi',                                        'lt',  '7.11.18'],
  ['popup-builder',            'CVE-2023-6114',  'SQLi',                                        'lt',  '4.2.3'],
  ['slimstat-analytics',       'CVE-2022-3996',  'SQLi',                                        'lt',  '4.9.3.3'],
  ['wp-fastest-cache-premium', 'CVE-2023-6065',  'Auth bypass',                                 'any', ''],
  ['really-simple-ssl',        'CVE-2024-10924', 'CRITICAL Auth Bypass (unauth admin login)',   'lt',  '9.1.2'],
  ['Divi',                     'CVE-2024-6821',  'Stored XSS (contributor+)',                   'lt',  '4.27.5'],
  ['Divi',                     'CVE-2023-3597',  'Arbitrary File Read / LFI',                   'lt',  '4.22.0'],
  ['contact-form-7',           'CVE-2023-6449',  'Unrestricted File Upload',                    'lt',  '5.8.4'],
  ['contact-form-7',           'CVE-2020-35489', 'Unrestricted File Upload',                    'lt',  '5.3.2'],
  ['updraftplus',              'CVE-2023-32960', 'Sensitive Data Exposure',                     'lt',  '1.23.11'],
  ['updraftplus',              'CVE-2022-2572',  'SSRF via backup destination',                 'lt',  '1.22.24'],
  ['wp-optimize',              'CVE-2023-5958',  'Reflected XSS',                               'lt',  '3.2.22'],
  ['divi-builder',             'CVE-2024-6821',  'Stored XSS',                                  'lt',  '4.27.5'],
  ['Extra',                    'CVE-2024-6821',  'Stored XSS',                                  'lt',  '4.27.5'],
  ['honeypot',                 'CVE-2022-3352',  'Auth bypass in login honeypot',               'lt',  '2.3.1'],
  ['wpforms-lite',             'CVE-2024-2887',  'Reflected XSS',                               'lt',  '1.8.8'],
  ['rank-math-seo',            'CVE-2023-32600', 'SSRF via schema markup',                      'lt',  '1.0.214'],
  ['litespeed-cache',          'CVE-2024-28000', 'Privilege Escalation (unauth admin)',         'lt',  '6.4.1'],
  ['jetpack',                  'CVE-2023-2996',  'Cross-Site Request Forgery',                  'lt',  '12.1.1'],
];

const THEME_DB: DbEntry[] = [
  ['Divi',          'CVE-2024-6821',  'Stored XSS (contributor+)',         'lt', '4.27.5'],
  ['Divi',          'CVE-2023-3597',  'Arbitrary File Read / LFI',         'lt', '4.22.0'],
  ['Extra',         'CVE-2024-6821',  'Stored XSS',                        'lt', '4.27.5'],
  ['enfold',        'CVE-2023-1018',  'Reflected XSS',                     'lt', '5.6.4'],
  ['flatsome',      'CVE-2024-24409', 'Reflected XSS',                     'lt', '3.16.8'],
  ['astra',         'CVE-2022-4285',  'Broken Access Control',             'lt', '3.9.4'],
  ['generatepress', 'CVE-2022-2034',  'XSS via theme options',             'lt', '3.1.3'],
  ['avada',         'CVE-2021-24347', 'SQLi in form handler',              'lt', '7.3.0'],
  ['betheme',       'CVE-2021-34626', 'Stored XSS',                        'lt', '21.9.8'],
  ['porto',         'CVE-2022-0660',  'Auth bypass via theme options',     'lt', '6.0.5'],
];

function parseVersion(text: string): string {
  for (const line of text.split('\n')) {
    const m = line.match(/(?:Stable tag|Version)\s*:\s*([\d.]+)/i);
    if (m) return m[1];
  }
  return '';
}

function versionTuple(ver: string): number[] {
  try {
    return ver.split('.').map(Number);
  } catch {
    return [0];
  }
}

function versionLt(a: string, b: string): boolean {
  const ta = versionTuple(a);
  const tb = versionTuple(b);
  const len = Math.max(ta.length, tb.length);
  for (let i = 0; i < len; i++) {
    const ai = ta[i] ?? 0;
    const bi = tb[i] ?? 0;
    if (ai < bi) return true;
    if (ai > bi) return false;
  }
  return false;
}

function isVulnerable(runningVer: string, operator: 'lt' | 'any', patchedVer: string): boolean {
  if (operator === 'any') return true;
  if (operator === 'lt' && runningVer && patchedVer) return versionLt(runningVer, patchedVer);
  return false;
}

async function scanItems(
  base: string,
  db: DbEntry[],
  assetType: 'plugin' | 'theme',
  findings: ReturnType<typeof finding>[],
  errors: string[],
): Promise<void> {
  const seen = new Set<string>();

  await parallelProbe(db, async ([slug, cve, vulnType, operator, patchedVer]) => {
    let readmeUrl = `${base}/wp-content/${assetType}s/${slug}/readme.txt`;
    let responseText = '';
    let gotResponse = false;

    try {
      const res = await fetchURL(readmeUrl);
      if (res && res.status === 200) {
        responseText = await res.text();
        gotResponse = true;
      } else if (assetType === 'theme') {
        const styleUrl = `${base}/wp-content/themes/${slug}/style.css`;
        const res2 = await fetchURL(styleUrl);
        if (res2 && res2.status === 200) {
          responseText = await res2.text();
          readmeUrl = styleUrl;
          gotResponse = true;
        }
      }
    } catch (e) {
      errors.push(String(e));
    }

    if (!gotResponse) return;

    const runningVer = parseVersion(responseText);
    const vulnerable = isVulnerable(runningVer, operator, patchedVer);
    const key = `${slug}::${cve}`;

    if (!vulnerable) {
      return;
    }

    if (seen.has(key)) return;
    seen.add(key);

    const verNote = (runningVer && patchedVer)
      ? `Running version: ${runningVer}. Patched version: ${patchedVer}.`
      : `Running version: ${runningVer || 'unknown'}. Any version is affected.`;

    findings.push(finding(`${assetType}_known_cve`, 'HIGH', readmeUrl,
      `${assetType.charAt(0).toUpperCase() + assetType.slice(1)} '${slug}' is vulnerable to ${cve} (${vulnType}). ${verNote}`,
      {
        replication_steps: [
          `curl -s "${readmeUrl}" | grep -E "Stable tag|Version"`,
          `# Version: ${runningVer || 'unknown'} — vulnerable to ${cve}.`,
          `# Reference: https://wpscan.com/vulnerability/ (search ${cve})`,
          `# Patched version: ${patchedVer || 'N/A — all versions affected'}`,
        ],
        remediation:
          `Update '${slug}' to version ${patchedVer || 'latest'} or higher. ` +
          `If no patch is available, deactivate and remove the ${assetType} immediately. ` +
          `Review ${cve} for further exploitation details.`,
        evidence: JSON.stringify({ running: runningVer, patched: patchedVer, cvss_score: 8.8, cve_refs: [cve] }),
      },
    ));
  });
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await scanItems(target, PLUGIN_DB, 'plugin', findings, errors);
    await scanItems(target, THEME_DB,  'theme',  findings, errors);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
