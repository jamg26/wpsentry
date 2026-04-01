import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'CSRF Protection Check';

const FORM_ENDPOINTS: [string, string, string[]][] = [
  ['/?p=1',                           'Comment form',       ['_wpnonce', 'comment_nonce']],
  ['/wp-login.php?action=lostpassword','Password reset form', ['_wpnonce']],
  ['/wp-admin/admin-ajax.php',        'Admin AJAX endpoint',['_wpnonce', 'nonce']],
];

const NONCE_PATTERNS = [
  /name=["']_wpnonce["']/i,
  /name=["']nonce["']/i,
  /name=["'][a-z_]+-nonce["']/i,
  /wp_nonce_field/i,
  /X-WP-Nonce/i,
  /wpnonce/i,
];

function hasNonce(html: string): boolean {
  return NONCE_PATTERNS.some(p => p.test(html));
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(FORM_ENDPOINTS, async ([path, formName]) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url, { redirect: 'manual' });
      if (!res || res.status !== 200) return;

      let body: string;
      try { body = await res.text(); } catch { return; }

      // Extract all <form>...</form> blocks
      const formRegex = /<form[^>]*>[\s\S]*?<\/form>/gi;
      const forms = body.match(formRegex) ?? [];

      for (const formHtml of forms) {
        if (!hasNonce(formHtml)) {
          const actionMatch = formHtml.match(/action=["']([^"']+)["']/i);
          const actionUrl = actionMatch ? actionMatch[1] : url;

          findings.push(finding(
            'CSRF_TOKEN_MISSING',
            'MEDIUM',
            url,
            `CSRF token absent in '${formName}' — form actions can be forged`,
            {
              replication_steps: [
                `curl -s "${url}" | grep -i 'form'`,
                'Observe: no _wpnonce or equivalent token in form.',
                `PoC: Create an HTML page with <form action='${actionUrl}' method='POST'>`,
                "Victim visiting the PoC page submits the form under their own session.",
                "Impact: attacker can reset passwords, post content, delete users.",
              ],
              evidence: `form_action: ${actionUrl}`,
            },
          ));
          break; // one per endpoint
        }
      }
    });

    // NOTE: The REST API GET /wp-json/wp/v2/posts is intentionally public.
    // A write endpoint accepting POST/PUT/DELETE without a valid nonce would
    // be a genuine CSRF risk, but cannot be confirmed via a read-only GET probe.
    // Skipping to avoid false positives on stock WordPress installations.
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
