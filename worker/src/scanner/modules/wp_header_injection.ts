import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'HTTP Response Header Injection';

// CRLF injection payloads
const CRLF_PAYLOADS = [
  '%0d%0aSet-Cookie:jwpinjected=1',
  '%0aSet-Cookie:jwpinjected=1',
  '%0d%0aX-Injected:jwpscanner',
  '%0aX-Injected:jwpscanner',
  '%0d%0a%0d%0a<html>injected</html>',
  // Double encoding
  '%250d%250aSet-Cookie:jwpinjected=1',
  // Unicode
  '%E5%98%8D%E5%98%8ASet-Cookie:jwpinjected=1',
  // Whitespace variants
  ' %0d%0aSet-Cookie:jwpinjected=1',
  '\r\nSet-Cookie:jwpinjected=1',
];

// Probe endpoints that likely handle redirects or echo headers
const PROBE_ENDPOINTS: Array<[string, string]> = [
  // Open redirect / Location-based injection
  ['/?redirect={payload}',                        'redirect_param'],
  ['/?redirect_to={payload}',                     'redirect_to_param'],
  ['/?return={payload}',                          'return_param'],
  ['/?return_url={payload}',                      'return_url_param'],
  ['/?next={payload}',                            'next_param'],
  ['/?url={payload}',                             'url_param'],
  ['/?goto={payload}',                            'goto_param'],
  ['/wp-login.php?redirect_to={payload}',         'wp_login_redirect'],
  // WooCommerce redirect
  ['/?wc_error={payload}',                        'wc_error_param'],
  ['/?add-to-cart=1&redirect={payload}',          'wc_add_to_cart_redirect'],
  // REST API that might set headers from input
  ['/wp-json/wp/v2/posts?context={payload}',      'rest_context_param'],
  // Custom post types
  ['/?post_type={payload}',                       'post_type_param'],
  ['/?lang={payload}',                            'lang_param'],
  ['/?wpml_lang={payload}',                       'wpml_lang_param'],
];

function checkInjectedHeader(headers: Headers): string | null {
  // Check for our injected header
  const injectedCookie = headers.get('Set-Cookie') ?? '';
  if (injectedCookie.includes('jwpinjected')) return 'Set-Cookie: jwpinjected header injected';

  const injectedHeader = headers.get('X-Injected') ?? '';
  if (injectedHeader.includes('jwpscanner')) return 'X-Injected header reflected';

  // Check Location header manipulation
  const location = headers.get('Location') ?? '';
  if (location.includes('jwpinjected') || location.includes('jwpscanner')) {
    return `Location header injected: ${location}`;
  }

  return null;
}

function checkBodyInjection(body: string): string | null {
  if (body.includes('jwpinjected=1') || body.includes('jwpscanner')) {
    return 'Injection payload reflected in body';
  }
  if (body.includes('<html>injected</html>')) {
    return 'HTML injection via CRLF in body';
  }
  return null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const seen = new Set<string>();

    const combos: Array<[string, string, string]> = [];
    for (const [endpointTemplate, label] of PROBE_ENDPOINTS) {
      for (const payload of CRLF_PAYLOADS.slice(0, 4)) {
        combos.push([endpointTemplate, label, payload]);
      }
    }

    await parallelProbe(combos, async ([endpointTemplate, label, payload]) => {
      if (seen.has(label)) return;

      const url = target + endpointTemplate.replace('{payload}', `https://example.com${payload}`);

      const res = await fetchURL(url, {
        timeoutMs: 4_000,
        redirect: 'manual', // Don't follow redirects so we can inspect Location header
      });
      if (!res) return;

      const headerInjection = checkInjectedHeader(res.headers);
      const body = await res.text().catch(() => '');
      const bodyInjection = checkBodyInjection(body);

      const injection = headerInjection ?? bodyInjection;
      if (!injection) return;

      if (!seen.has(label)) {
        seen.add(label);
        findings.push(finding(
          'HEADER_INJECTION_CRLF',
          'HIGH',
          url,
          `HTTP response header injection (CRLF) via '${label}' — ${injection}`,
          {
            evidence: `param="${label}" payload="${payload}" injection="${injection}" status=${res.status}`,
            remediation: 'Strip or reject \\r\\n characters from all input used in HTTP headers or redirects. Use wp_safe_redirect() instead of header() for redirects.',
          },
        ));
      }
    }, 15);

    // Test REST API endpoints for header injection
    const restCrlfTests: Array<[string, string]> = [
      ['/wp-json/wp/v2/posts', 'rest_post_search'],
      ['/wp-json/wp/v2/users', 'rest_user_search'],
    ];

    await parallelProbe(restCrlfTests, async ([endpoint, label]) => {
      if (seen.has(label)) return;

      for (const payload of CRLF_PAYLOADS.slice(0, 3)) {
        const url = `${target}${endpoint}?search=${payload}`;
        const res = await fetchURL(url, {
          timeoutMs: 4_000,
          redirect: 'manual',
        });
        if (!res) continue;

        const headerInjection = checkInjectedHeader(res.headers);
        if (headerInjection && !seen.has(label)) {
          seen.add(label);
          findings.push(finding(
            'HEADER_INJECTION_REST',
            'HIGH',
            url,
            `REST API header injection via '${label}' — ${headerInjection}`,
            {
              evidence: `endpoint="${endpoint}" payload="${payload}" injection="${headerInjection}"`,
              remediation: 'Sanitize all user input before using in HTTP response headers. WP REST API should never reflect raw input into headers.',
            },
          ));
          break;
        }
      }
    }, 5);

    // Test woocommerce checkout redirect for header injection
    const wcRedirectTests = [
      `${target}/?wc-ajax=checkout&redirect=${encodeURIComponent('https://example.com' + CRLF_PAYLOADS[0])}`,
    ];

    await parallelProbe(wcRedirectTests, async (url) => {
      const res = await fetchURL(url, { timeoutMs: 4_000, redirect: 'manual' });
      if (!res) return;

      const headerInjection = checkInjectedHeader(res.headers);
      if (headerInjection) {
        findings.push(finding(
          'HEADER_INJECTION_WOOCOMMERCE',
          'HIGH',
          url,
          `WooCommerce checkout header injection — ${headerInjection}`,
          {
            evidence: `injection="${headerInjection}" status=${res.status}`,
            remediation: 'Sanitize redirect URLs in WooCommerce. Use esc_url() and wp_safe_redirect() for all redirect outputs.',
          },
        ));
      }
    }, 2);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
