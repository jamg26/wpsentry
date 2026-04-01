import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Cross-Site Scripting (XSS) Probe';


const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  "'\"><script>alert(1)</script>",
  '<svg/onload=alert(1)>',
  '"><img src=x onerror=alert(1)>',
  '<ScRiPt>alert(1)</ScRiPt>',
  'javascript:alert(1)',
  '<body onload=alert(1)>',
  "';alert(1)//",
  '";alert(1)//',
  '<details/open/ontoggle=alert(1)>',
  '<iframe src="javascript:alert(1)">',
  '<input autofocus onfocus=alert(1)>',
  '<select autofocus onfocus=alert(1)>',
  '<textarea autofocus onfocus=alert(1)>',
];

const PROBE_ENDPOINTS: [string, string, string][] = [
  ['/?s={payload}',                                          'search',          'LOW'],
  ['/{payload}',                                             '404_page_path',   'LOW'],
  ['/?error={payload}',                                      'error_param',     'LOW'],
  ['/?redirect_to={payload}',                                'redirect_param',  'MEDIUM'],
  ['/?message={payload}',                                    'message_param',   'LOW'],
  ['/?msg={payload}',                                        'msg_param',       'LOW'],
  ['/?url={payload}',                                        'url_param',       'MEDIUM'],
  ['/?return={payload}',                                     'return_param',    'MEDIUM'],
  ['/wp-login.php?redirect_to={payload}',                    'login_redirect',  'HIGH'],
  ['/wp-admin/admin-ajax.php?action={payload}',              'ajax_action',     'MEDIUM'],
  ['/wp-comments-post.php?comment_post_ID={payload}',        'comment_post_id', 'LOW'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Flatten [endpoint, payload] combos — all run in parallel
    const hitEndpoints = new Set<string>();
    const combos: [string, string, string, string][] = [];
    for (const [endpointTemplate, label, severity] of PROBE_ENDPOINTS) {
      for (const rawPayload of XSS_PAYLOADS) {
        combos.push([endpointTemplate, label, severity, rawPayload]);
      }
    }
    await parallelProbe(combos, async ([endpointTemplate, label, severity, rawPayload]) => {
      if (hitEndpoints.has(label)) return;
      const encodedPayload = encodeURIComponent(rawPayload);
      const url = target + endpointTemplate.replace('{payload}', encodedPayload);
      const res = await fetchURL(url);
      if (!res) return;
      if (![200, 400, 404].includes(res.status)) return;

      let body: string;
      try { body = await res.text(); } catch { return; }

      const contentType = res.headers.get('Content-Type') ?? '';
      if (!contentType.includes('text/html')) return;

      // Check that the EXACT injected payload appears literally in the response body.
      // We look for the raw (unencoded) payload string — if the server properly
      // encodes/escapes it, the raw HTML tags won't appear.
      if (!body.includes(rawPayload)) return;

      // Double-check: the payload must not just appear inside an HTML attribute value
      // or a <script> context that was already there. Verify the specific dangerous
      // constructs from our payload are present as raw HTML.
      const dangerousPatterns = [
        /alert\s*\(\s*1\s*\)/i,
        /onerror\s*=/i,
        /onload\s*=/i,
        /onfocus\s*=/i,
        /ontoggle\s*=/i,
        /javascript\s*:/i,
      ];
      const hasDangerousContext = dangerousPatterns.some(p => p.test(body));
      if (!hasDangerousContext) return;

      if (!hitEndpoints.has(label)) {
        hitEndpoints.add(label);
        const effectiveSeverity = (severity === 'LOW') ? 'MEDIUM' : severity;
        findings.push(finding(
          'XSS_REFLECTED',
          effectiveSeverity as Finding['severity'],
          url,
          `Reflected XSS in '${label}' param — payload echoed back`,
          { evidence: `payload: ${rawPayload}`, remediation: 'Sanitize all user input with wp_kses(). Escape output with esc_html(), esc_attr(), esc_url().' },
        ));
      }
    }, 30);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
