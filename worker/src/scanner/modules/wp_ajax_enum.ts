import type { ModuleResult, ScanState } from '../types.js';
import type { Severity } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Admin AJAX Action Enumeration';

type AjaxMethod = 'GET' | 'POST';
type AjaxAction = [string, AjaxMethod, Record<string, string>, string, Severity];

const AJAX_ACTIONS: AjaxAction[] = [
  // WordPress core
  ['heartbeat',                    'POST', { interval: '15' },         'Heartbeat API — exposes auth status and server time',                          'LOW'],
  ['get-tagcloud',                 'POST', {},                          'Tag cloud data',                                                               'LOW'],
  ['oembed-cache',                 'POST', { post_ID: '1' },           'oEmbed cache data',                                                            'LOW'],
  ['wp-remove-post-lock',          'POST', { post_ID: '1' },           'Post lock removal',                                                            'LOW'],
  // User/auth related
  ['um_activity',                  'POST', { action: 'um_activity' },  'Ultimate Member activity feed',                                                'MEDIUM'],
  ['um_get_members',               'POST', {},                          'Ultimate Member member list',                                                  'HIGH'],
  ['um_login',                     'POST', {},                          'Ultimate Member login endpoint',                                               'HIGH'],
  ['buddypress_activity',          'POST', {},                          'BuddyPress activity',                                                          'MEDIUM'],
  // File/media access
  ['query-attachments',            'POST', { 'query[post_parent]': '0' }, 'Media attachment query',                                                    'MEDIUM'],
  ['upload-attachment',            'POST', {},                          'File upload endpoint',                                                         'HIGH'],
  ['fetch-list',                   'GET',  {},                          'File list fetch',                                                              'MEDIUM'],
  // WooCommerce
  ['woocommerce_get_refreshed_fragments', 'POST', {},                  'WooCommerce cart fragments — may leak product/pricing',                         'LOW'],
  ['woocommerce_apply_coupon',     'POST', { coupon_code: 'TEST' },    'WooCommerce coupon apply',                                                     'LOW'],
  ['woocommerce_remove_coupon',    'POST', {},                          'WooCommerce coupon remove',                                                    'LOW'],
  ['woocommerce_checkout',         'POST', {},                          'WooCommerce checkout',                                                         'MEDIUM'],
  ['woocommerce_update_order_review', 'POST', {},                      'WooCommerce order review',                                                     'MEDIUM'],
  ['woocommerce_get_customer_location', 'GET', {},                     'WooCommerce customer location',                                                'LOW'],
  // Page builders
  ['vc_get_vc_grid_data',          'POST', { vc_post_id: '1', tag: 'vc_basic_grid', dataFilter: '', shortcodeAttrs: '' },
    'Visual Composer grid — known RCE/LFI vector (CVE-2015-4133)',                                                                                     'CRITICAL'],
  ['elementor_ajax',               'POST', { actions: '{}' },          'Elementor AJAX endpoint',                                                      'MEDIUM'],
  ['et_ajax',                      'POST', {},                          'Divi/Elegant Themes AJAX',                                                     'MEDIUM'],
  ['divi_switch_layout',           'POST', {},                          'Divi layout switch',                                                           'MEDIUM'],
  ['fl_builder_save_settings',     'POST', {},                          'Beaver Builder save settings',                                                 'MEDIUM'],
  // Contact/form plugins
  ['wpcf7_submit',                 'POST', {},                          'Contact Form 7 submit',                                                        'LOW'],
  ['gform_submit',                 'POST', {},                          'Gravity Forms submit',                                                         'LOW'],
  ['nf_ajax_submit',               'POST', {},                          'Ninja Forms AJAX submit',                                                      'LOW'],
  ['frm_entries_create',           'POST', {},                          'Formidable Forms create',                                                      'MEDIUM'],
  // SEO plugins
  ['wpseo_filter_dismiss_notification', 'GET', {},                     'Yoast SEO dismiss notice',                                                     'LOW'],
  ['rank_math_analytics_get_posts', 'GET', {},                         'Rank Math analytics post list',                                                'MEDIUM'],
  // Backup/migration
  ['updraftplus_backup',           'POST', {},                          'UpdraftPlus backup trigger',                                                   'HIGH'],
  ['updraft_download_backup',      'POST', {},                          'UpdraftPlus backup download',                                                  'CRITICAL'],
  ['wpallimport_preview_file',     'POST', {},                          'WP All Import file preview',                                                   'HIGH'],
  // Cache plugins
  ['w3tc_cdn_import_library',      'POST', {},                          'W3 Total Cache CDN import',                                                    'MEDIUM'],
  ['litespeed_purge_all',          'POST', {},                          'LiteSpeed cache purge',                                                        'LOW'],
  // Security plugins
  ['wordfence_ls_get_captcha_info', 'POST', {},                        'Wordfence captcha info',                                                       'LOW'],
  ['ithemes_sync_request_handler', 'POST', {},                          'iThemes Sync request handler',                                                 'HIGH'],
  // SSRF / inclusion risks
  ['revslider_ajax_action',        'POST', { client_action: 'revslider_update_plugin_fe' },
    'RevSlider AJAX — known LFI/RFI vector',                                                                                                           'HIGH'],
  ['LayerSlider_preview',          'POST', {},                          'LayerSlider preview',                                                          'MEDIUM'],
  ['mce_load_script',              'GET',  { plugin: '../../wp-config' }, 'TinyMCE script load — path traversal risk',                                'HIGH'],
  // User registration/profile
  ['wp_ajax_nopriv_bp_avatar_upload', 'POST', {},                      'BuddyPress avatar upload without auth',                                        'HIGH'],
  ['wpmu_dev_ajax',                'POST', {},                          'WPMU DEV AJAX',                                                                'MEDIUM'],
  ['mpp_media_upload',             'POST', {},                          'MediaPress media upload',                                                      'HIGH'],
  // Misc disclosure
  ['parse-embed',                  'POST', { shortcode: '[gallery]' }, 'Embed parser — may disclose server paths',                                     'LOW'],
  ['acf/fields/google_map/api',    'POST', {},                          'ACF Google Maps API key exposure',                                             'HIGH'],
  ['acf/validate_save_post',       'POST', {},                          'ACF save validation',                                                          'LOW'],
  ['wpml_set_language_by_cookie',  'POST', {},                          'WPML language switcher',                                                       'LOW'],
  ['wpes_search',                  'POST', { s: 'test' },              'WP eCommerce search',                                                          'LOW'],
  ['td_load_more_posts',           'POST', {},                          'TagDiv load more posts',                                                       'LOW'],
  ['woodmart_ajax_search',         'POST', { query: 'test' },          'WoodMart AJAX search',                                                         'LOW'],
  ['yith_wcwl_add_product',        'POST', { product_id: '1' },        'YITH Wishlist add product',                                                    'LOW'],
  ['woodmart_newsletter_subscribe', 'POST', { email: 'test@test.com' }, 'WoodMart newsletter',                                                         'LOW'],
  ['mailchimp_subscriber_popup',   'POST', {},                          'Mailchimp popup',                                                              'LOW'],
  ['wp_compress_files_search',     'POST', {},                          'Compress files search',                                                        'LOW'],
  ['wpforms_submit',               'POST', {},                          'WPForms submit',                                                               'LOW'],
  ['popupmaker-close',             'POST', {},                          'PopupMaker close',                                                             'LOW'],
  ['alo_easymail_send',            'POST', {},                          'ALO EasyMail send',                                                            'HIGH'],
  ['wysija_ajax',                  'POST', {},                          'WYSIJA newsletter AJAX',                                                       'MEDIUM'],
  ['mailoptin_forms_subscription', 'POST', {},                          'MailOptin subscription',                                                       'LOW'],
  ['newsletter_subscription',      'POST', { email: 'test@test.com' }, 'Newsletter plugin subscription',                                               'LOW'],
  ['super_socializer_twitter_connect', 'POST', {},                     'Super Socializer Twitter connect',                                             'MEDIUM'],
  ['ssba_save_share_counts',       'POST', {},                          'Simple Share Buttons share count',                                             'LOW'],
  ['monarch_share_count',          'POST', {},                          'Monarch social share count',                                                   'LOW'],
  ['wp_ulike_process',             'POST', { post_id: '1', type: 'post', button: 'like' }, 'WP ULike — like action',                                  'LOW'],
  ['berocket_ajax_load_posts',     'POST', {},                          'BeRocket AJAX load posts',                                                     'LOW'],
  ['ajax_pagination',              'POST', {},                          'Generic AJAX pagination',                                                      'LOW'],
  ['load_more_jobs',               'POST', {},                          'Jobs load more',                                                               'LOW'],
  ['the_ajax_hook',                'POST', {},                          'Generic WP hook',                                                              'LOW'],
];

function isMeaningfulResponse(status: number, text: string): boolean {
  if ([400, 403, 404, 405, 500].includes(status)) return false;
  const t = text.trim();
  if (['-1', '0', '', 'false', 'null', 'undefined'].includes(t)) return false;
  if (t.length < 3) return false;
  return true;
}

function assessResponse(
  action: string,
  _status: number,
  text: string,
  description: string,
  baseSeverity: Severity,
  ajaxUrl: string,
  findings: ReturnType<typeof finding>[],
): void {
  let severity = baseSeverity;

  let hasJson = false;
  try {
    JSON.parse(text);
    hasJson = true;
    // Size alone doesn't indicate sensitive data — let the checks below handle escalation
  } catch { /* not JSON */ }

  const hasEmail = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/.test(text);
  const hasPath  = /(?:\/var\/www|\/home\/|\/srv\/|C:\\\\)/.test(text);
  const hasKey   = /(?:api_key|secret|token|password)["\':=\s]+[\w\-]{8,}/i.test(text);
  const hasUrl   = /https?:\/\//.test(text);

  let extra: string;
  if (hasEmail || hasPath || hasKey) {
    severity = 'HIGH';
    extra = ' — sensitive data (email/path/key) in response';
  } else if (hasJson && text.length > 200) {
    extra = ` — returns ${text.length}B JSON data`;
  } else if (hasUrl) {
    extra = ' — returns URL data';
  } else {
    extra = ` — returns: ${text.slice(0, 60)}`;
  }

  const sanitizedAction = action.toUpperCase().replace(/[^A-Z0-9]/g, '_').slice(0, 30);
  findings.push(finding(
    `AJAX_ACTION_EXPOSED_${sanitizedAction}`, severity, ajaxUrl,
    `nopriv AJAX action '${action}' accessible without auth: ${description}${extra}`,
    {
      replication_steps: [
        `curl -s -X POST "${ajaxUrl}" -d 'action=${action}'`,
        `Observe response: ${text.slice(0, 100)}`,
        'This action executes without authentication — review for data exposure or side effects.',
      ],
      evidence: JSON.stringify({
        action,
        response_length: text.length,
        has_sensitive: hasEmail || hasPath || hasKey,
      }),
    },
  ));
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const ajaxUrl = `${target}/wp-admin/admin-ajax.php`;

  try {
    const probe = await fetchURL(ajaxUrl);
    if (!probe) {
      findings.push(finding(
        'AJAX_UNREACHABLE', 'INFO', ajaxUrl,
        'admin-ajax.php unreachable — endpoint may be blocked or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }
    if (probe.status === 404) {
      findings.push(finding(
        'AJAX_NOT_FOUND', 'INFO', ajaxUrl,
        'admin-ajax.php returns 404 — may be renamed or blocked',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    await parallelProbe(AJAX_ACTIONS, async ([action, method, data, description, severity]) => {
      try {
        const postData = { ...data, action };
        let res: Response | null;

        if (method === 'GET') {
          const params = new URLSearchParams(postData).toString();
          res = await fetchURL(`${ajaxUrl}?${params}`);
        } else {
          res = await fetchURL(ajaxUrl, {
            method: 'POST',
            body: new URLSearchParams(postData).toString(),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
        }

        if (!res) return;
        let text = '';
        try { text = await res.text(); } catch { return; }

        if (isMeaningfulResponse(res.status, text)) {
          assessResponse(action, res.status, text, description, severity, ajaxUrl, findings);
        }
      } catch { /* ignore per-action errors */ }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
