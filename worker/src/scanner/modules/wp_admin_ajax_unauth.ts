import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Unauthenticated admin-ajax.php Actions';

// Known unauthenticated (nopriv) AJAX actions that should require auth
// [action, description, expected_block]
const SENSITIVE_NOPRIV_ACTIONS: Array<[string, string, boolean]> = [
  // WordPress core — these should respond but in controlled ways
  ['upload-attachment',        'File attachment upload',                  true],
  ['query-attachments',        'Media library enumeration',               true],
  ['save-attachment',          'Attachment metadata save',                true],
  ['set-post-thumbnail',       'Post thumbnail setter',                   true],
  ['heartbeat',                'Heartbeat API (nopriv allowed)',          false],
  // Revolution Slider (Revslider) — CVE-2014-9734
  ['revslider_show_image',     'Revslider arbitrary file read',           true],
  ['revslider_ajax_action',    'Revslider admin action',                  true],
  // LayerSlider — CVE-2024-2879
  ['LayerSlider_Slider',       'LayerSlider admin panel',                 true],
  ['layerslider_data',         'LayerSlider data access',                 true],
  // WP All Import
  ['wp_all_import_upload',     'WP All Import file upload',               true],
  // Contact Form 7
  ['wpcf7-before-send-mail',   'CF7 mail hook',                          false],
  // Ninja Forms
  ['nf_ajax_submit',           'Ninja Forms submission',                  false],
  // Gravity Forms
  ['gf_upgrade',               'Gravity Forms upgrade action',            true],
  // WPBakery (Visual Composer)
  ['vc_frontend_load_template', 'WPBakery template loader',              true],
  // Elementor
  ['elementor_ajax',           'Elementor AJAX handler',                  true],
  // ACF
  ['acf/ajax/query_users',     'ACF user query',                         true],
  // Backup plugins
  ['duplicator_download',      'Duplicator backup download',              true],
  ['updraftplus_ajax',         'UpdraftPlus AJAX action',                 true],
  // WooCommerce
  ['woocommerce_get_sku',      'WooCommerce SKU data',                   false],
  ['wc_stripe_create_intent',  'WC Stripe payment intent creation',      true],
  // SEO plugins
  ['rank_math_rate',           'Rank Math rating',                       false],
  ['aiosp_import',             'All in One SEO import',                  true],
  // User-related
  ['get-user-by-email',        'User lookup by email',                    true],
  ['wp_ajax_nopriv_user_registration', 'User registration action',       false],
  // Misc
  ['send-link-to-editor',      'Send link to editor',                    true],
  ['wp-compression-test',      'Compression test (info)',                false],
];

// Response patterns indicating action was executed (not blocked)
const EXECUTION_INDICATORS = [
  '"success":true',
  '"success":"true"',
  '"status":"success"',
  '"result":"success"',
  '"data":{',
  '"url":',
  '"id":',
  // File path disclosure
  '/wp-content/',
  '/home/',
  // WP nonce
  '"nonce"',
  // Error from execution (not auth denial)
  'wp_die',
];

// Patterns indicating proper access control
const BLOCK_INDICATORS = [
  '-1',
  '0',
  '"success":false',
  'permission',
  'not allowed',
  'unauthorized',
  'nonce',
  'access denied',
  'insufficient permissions',
  'you do not have',
  'sorry',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const ajaxUrl = target + '/wp-admin/admin-ajax.php';

    // MED-FP-4: Allowlist of WordPress core AJAX actions that are intentionally
    // public or benign. These must never be flagged as vulnerabilities.
    const BENIGN_CORE_ACTIONS = new Set([
      'mce_load_script', 'heartbeat', 'fetch-list', 'ajax-tag-search',
      'wp-compression-test', 'get-community-events', 'dashboard-widgets',
    ]);

    // Verify ajax endpoint is accessible
    const pingRes = await fetchURL(ajaxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=heartbeat',
      timeoutMs: 4_000,
    });

    if (!pingRes || pingRes.status === 404) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    await parallelProbe(SENSITIVE_NOPRIV_ACTIONS, async ([action, description, shouldBlock]) => {
      if (!shouldBlock) return; // Only test actions that SHOULD be blocked
      if (BENIGN_CORE_ACTIONS.has(action)) return; // Skip known benign WordPress core actions

      const res = await fetchURL(ajaxUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=${encodeURIComponent(action)}`,
        timeoutMs: 4_000,
      });

      if (!res) return;

      const body = await res.text().catch(() => '');
      const bodyLower = body.toLowerCase();

      // -1 is standard "not allowed" for nopriv actions that need auth
      if (body.trim() === '-1' || body.trim() === '0') return;
      if (res.status === 403) return;

      const isBlocked = BLOCK_INDICATORS.some(ind => bodyLower.includes(ind));
      const isExecuted = EXECUTION_INDICATORS.some(ind => bodyLower.includes(ind.toLowerCase()));

      if (isExecuted && !isBlocked) {
        findings.push(finding(
          'ADMIN_AJAX_UNAUTH_ACCESS',
          'HIGH',
          `${ajaxUrl}?action=${action}`,
          `Unauthenticated access to sensitive admin-ajax action '${action}' (${description}) — response suggests execution`,
          {
            evidence: `action="${action}" status=${res.status} body="${body.slice(0, 150)}"`,
            remediation: `Add wp_ajax_nopriv_${action} handler that calls wp_die('-1', '', ['status' => 403]). Check plugin ${action} handler for missing capability checks.`,
          },
        ));
      } else if (!isBlocked && res.status === 200 && body.length > 2) {
        // Non-trivial response that isn't clearly blocked
        findings.push(finding(
          'ADMIN_AJAX_UNAUTH_POSSIBLE',
          'MEDIUM',
          `${ajaxUrl}?action=${action}`,
          `admin-ajax action '${action}' (${description}) returned non-empty response without auth — review manually`,
          {
            evidence: `action="${action}" status=${res.status} body_len=${body.length} body="${body.slice(0, 100)}"`,
            remediation: `Verify ${action} handler has proper nonce and capability checks.`,
          },
        ));
      }
    }, 20);

    // Special test: upload-attachment without auth
    const uploadRes = await fetchURL(ajaxUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=upload-attachment&_wpnonce=badenonce',
      timeoutMs: 4_000,
    });

    if (uploadRes && uploadRes.status !== 403) {
      const uploadBody = await uploadRes.text().catch(() => '');
      if (!uploadBody.includes('-1') && uploadBody.includes('"data"')) {
        findings.push(finding(
          'ADMIN_AJAX_UPLOAD_UNAUTH',
          'CRITICAL',
          ajaxUrl,
          'Unauthenticated file upload via admin-ajax.php upload-attachment action',
          {
            evidence: `status=${uploadRes.status} body="${uploadBody.slice(0, 150)}"`,
            remediation: 'Verify wp_ajax_nopriv handlers do not allow file uploads. Ensure all upload actions check user capabilities.',
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
