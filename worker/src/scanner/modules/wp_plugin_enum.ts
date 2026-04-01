import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getText, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'WordPress Plugin Enumeration';

const COMMON_PLUGINS = [
  'contact-form-7', 'woocommerce', 'yoast-seo', 'elementor',
  'classic-editor', 'wordfence', 'really-simple-ssl', 'updraftplus',
  'jetpack', 'akismet', 'all-in-one-seo-pack', 'duplicate-post',
  'redirection', 'wp-super-cache', 'w3-total-cache', 'litespeed-cache',
  'advanced-custom-fields', 'gravityforms', 'ninja-forms', 'mailchimp-for-wp',
  'wp-mail-smtp', 'tablepress', 'google-analytics-for-wordpress',
  'ithemes-security', 'limit-login-attempts-reloaded', 'revslider',
  'wp-file-manager', 'wp-statistics', 'wp-google-maps', 'easy-wp-smtp',
  'formidable', 'custom-post-type-ui', 'breadcrumb-navxt',
  'regenerate-thumbnails', 'user-role-editor', 'polylang',
  'all-in-one-wp-migration', 'login-lockdown', 'buddypress', 'bbpress',
  'the-events-calendar', 'newsletter', 'wp-fastest-cache', 'imagify',
  'smush', 'beaver-builder-plugin', 'divi-builder', 'wpforms-lite',
  'popup-maker', 'cookie-notice', 'gdpr-cookie-compliance',
  'wps-hide-login', 'loginizer', 'disable-comments',
  'enable-media-replace', 'file-manager-advanced',
  'wp-db-backup', 'wp-dbmanager', 'adminer',
  'wp-symposium', 'wp-shopping-cart', 'e-commerce',
  'tinymce-advanced', 'king-composer', 'kingcomposer',
  'wp-fastest-cache-premium', 'async-javascript',
  'optinmonster', 'sumo', 'pushassist', 'icegram',
  'social-warfare', 'monarch', 'shareaholic',
  'wp-seopress', 'rank-math', 'broken-link-checker',
  'rank-math-seo', 'astra-sites', 'wp-rocket', 'the-seo-framework',
  'mainwp-child', 'wp-migrate-db', 'duplicator-pro', 'wp-optimize',
  'shortpixel-image-optimiser', 'flying-pages', 'autoptimize',
  'wp-smushit', 'better-wp-security', 'wp-2fa', 'mycred',
  'paid-memberships-pro', 'learnpress', 'tutor', 'lifterlms',
];

const VERSION_RE = /Stable tag:\s*([0-9][^\s\r\n]*)/i;

async function detectVersion(base: string, slug: string): Promise<string | null> {
  const paths = [
    `/wp-content/plugins/${slug}/readme.txt`,
    `/wp-content/plugins/${slug}/README.txt`,
    `/wp-content/plugins/${slug}/CHANGELOG.txt`,
  ];
  const results = await Promise.allSettled(paths.map(p => getText(`${base}${p}`)));
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value.length > 10) {
      const m = VERSION_RE.exec(r.value);
      if (m) return m[1].trim();
    }
  }
  return null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // CRIT-06: Only confirm plugin presence when readme.txt returns HTTP 200 AND contains
    // canonical plugin content. Never infer plugin existence from 403 (WAF-protected sites
    // return 403 for ALL plugin directories, causing massive false positives).
    await parallelProbe(COMMON_PLUGINS, async (slug) => {
      const readmeUrl = `${target}/wp-content/plugins/${slug}/readme.txt`;
      const res = await fetchURL(readmeUrl);
      if (!res || res.status !== 200) return;
      const body = await res.text().catch(() => '');
      if (!body.includes('Plugin Name:') && !body.includes('Stable tag:') && !body.includes('Contributors:')) return;
      const versionMatch = VERSION_RE.exec(body);
      const version = versionMatch ? versionMatch[1].trim() : null;
      findings.push(finding(
        'PLUGIN_DETECTED',
        version ? 'MEDIUM' : 'LOW',
        readmeUrl,
        version
          ? `Plugin '${slug}' v${version} detected`
          : `Plugin '${slug}' detected (version unknown)`,
        { evidence: JSON.stringify({ slug, version: version ?? 'unknown' }), remediation: 'Keep plugins updated. Remove unused plugins. Use a security plugin to hide version info.' },
      ));
    }, 30);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
