import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Remote File Inclusion (RFI) Probe';

// Encode like Python's quote(s, safe="%/:.")
function quoteSafe(s: string, safe: string): string {
  return s.split('').map(c => {
    if (safe.includes(c) || /[A-Za-z0-9\-_~]/.test(c)) return c;
    return encodeURIComponent(c);
  }).join('');
}

const RFI_PAYLOADS = [
  'http://127.0.0.1/',
  'http://127.0.0.1:80/',
  'http://0.0.0.0/',
  'http://169.254.169.254/',
  'expect://id',
  'php://input',
  'php://filter/read=convert.base64-encode/resource=index.php',
];

const RFI_INDICATORS = [
  'failed to open stream',
  'include() [function.include]',
  'require() [function.require]',
  'warning: include',
  'warning: require',
  'no such file or directory',
  'url file-access is disabled',
  'allow_url_include',
  'ami-id',
];

const VULNERABLE_PARAMS: [string, string][] = [
  ['/?file={payload}',     'file_param'],
  ['/?page={payload}',     'page_param'],
  ['/?include={payload}',  'include_param'],
  ['/?inc={payload}',      'inc_param'],
  ['/?module={payload}',   'module_param'],
  ['/?template={payload}', 'template_param'],
  ['/?load={payload}',     'load_param'],
  ['/?url={payload}',      'url_param'],
  ['/wp-content/plugins/wp-symposium/server/file_upload_form.php?ref={payload}',
    'wp_symposium'],
  ['/wp-content/plugins/mac-dock-gallery/macwidgets.php?url={payload}',
    'mac_dock_gallery'],
  ['/wp-content/plugins/n-media-website-contact-form-with-file-upload/admin/image.php?url={payload}',
    'nmedia_contact'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Flatten [param, payload] combos — all run in parallel
    const combos: [string, string, string][] = [];
    for (const [endpointTemplate, label] of VULNERABLE_PARAMS) {
      for (const payload of RFI_PAYLOADS) {
        combos.push([endpointTemplate, label, payload]);
      }
    }
    await parallelProbe(combos, async ([endpointTemplate, label, payload]) => {
      const encoded = quoteSafe(payload, '%/:.');
      const url = target + endpointTemplate.replace('{payload}', encoded);
      const res = await fetchURL(url);
      if (!res) return;
      if (![200, 500].includes(res.status)) return;

      let body: string;
      try { body = await res.text(); } catch { return; }

      const encodedPayloadLower = encoded.toLowerCase();
      const rawPayloadLower = payload.toLowerCase();
      const sanitisedLines = body.split('\n').filter(line => {
        const ll = line.toLowerCase();
        return !ll.includes(encodedPayloadLower) && !ll.includes(rawPayloadLower);
      });
      const sanitisedText = sanitisedLines.join('\n').toLowerCase();

      for (const indicator of RFI_INDICATORS) {
        if (sanitisedText.includes(indicator.toLowerCase())) {
          findings.push(finding(
            'RFI_INDICATOR_TRIGGERED',
            'HIGH',
            url,
            `RFI indicator '${indicator}' triggered via '${label}' param`,
            { evidence: `payload: ${payload}; indicator: ${indicator}` },
          ));
          break;
        }
      }
    }, 30);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
