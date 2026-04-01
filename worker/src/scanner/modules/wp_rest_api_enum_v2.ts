import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'REST API Deep Enumeration';

const CUSTOM_ENDPOINTS = [
  '/wp-json/wp/v2/types',
  '/wp-json/wp/v2/statuses',
  '/wp-json/wp/v2/taxonomies',
  '/wp-json/wp/v2/categories',
  '/wp-json/wp/v2/tags',
  '/wp-json/wp/v2/pages',
  '/wp-json/wp/v2/search?search=admin',
  '/wp-json/wp/v2/block-types',
  '/wp-json/wp/v2/block-renderer',
  '/wp-json/wp/v2/global-styles',
  '/wp-json/wp/v2/navigation',
  '/wp-json/wp/v2/templates',
  '/wp-json/wp/v2/template-parts',
  '/wp-json/wp/v2/pattern-directory/patterns',
  '/wp-json/wp/v2/menu-items',
  '/wp-json/wp/v2/menu-locations',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // First get the root index to discover all namespaces and routes
    const indexUrl = `${target}/wp-json/`;
    const indexRes = await fetchURL(indexUrl);
    if (!indexRes || indexRes.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const indexBody = await indexRes.text();
    let namespaces: string[] = [];

    try {
      const data = JSON.parse(indexBody);
      if (data.namespaces && Array.isArray(data.namespaces)) {
        namespaces = data.namespaces;
      }
    } catch { /* not JSON */ }

    // Report discovered namespaces beyond core WP
    const customNamespaces = namespaces.filter(ns =>
      !ns.startsWith('wp/') && ns !== 'oembed/1.0' && ns !== ''
    );

    if (customNamespaces.length > 0) {
      findings.push(finding('REST_CUSTOM_NAMESPACES', 'INFO', indexUrl,
        `${customNamespaces.length} custom REST API namespace(s) discovered: ${customNamespaces.slice(0, 10).join(', ')}`, {
          evidence: `Namespaces: ${customNamespaces.join(', ')}`,
          replication_steps: [
            `Fetch ${indexUrl}`,
            'Check "namespaces" array for non-core endpoints',
          ],
          remediation: 'Review custom REST API endpoints for proper authentication and authorization.',
        }));
    }

    // Check for custom post type endpoints
    const typesUrl = `${target}/wp-json/wp/v2/types`;
    const typesRes = await fetchURL(typesUrl);
    if (typesRes && typesRes.status === 200) {
      const typesBody = await typesRes.text();
      try {
        const types = JSON.parse(typesBody) as Record<string, { slug: string; rest_base?: string; name?: string }>;
        const customTypes = Object.values(types).filter(t =>
          !['post', 'page', 'attachment', 'wp_block', 'wp_template', 'wp_template_part',
            'wp_navigation', 'wp_font_family', 'wp_font_face', 'wp_global_styles'].includes(t.slug)
        );

        if (customTypes.length > 0) {
          const typeNames = customTypes.map(t => t.slug).slice(0, 10);
          findings.push(finding('REST_CUSTOM_POST_TYPES', 'LOW', typesUrl,
            `${customTypes.length} custom post type(s) exposed: ${typeNames.join(', ')}`, {
              evidence: `Custom post types: ${typeNames.join(', ')}`,
              replication_steps: [
                `Fetch ${typesUrl}`,
                'Look for non-default post types in response',
              ],
              remediation: 'Ensure custom post type REST endpoints have proper capability checks via show_in_rest and permission callbacks.',
            }));

          // Try to access each custom post type's content
          await parallelProbe(customTypes.slice(0, 5), async (cpt) => {
            const restBase = cpt.rest_base ?? cpt.slug;
            const cptUrl = `${target}/wp-json/wp/v2/${restBase}`;
            const cptRes = await fetchURL(cptUrl);
            if (!cptRes || cptRes.status !== 200) return;
            const cptBody = await cptRes.text();
            try {
              const items = JSON.parse(cptBody);
              if (Array.isArray(items) && items.length > 0) {
                findings.push(finding('REST_CPT_DATA_EXPOSED', 'MEDIUM', cptUrl,
                  `Custom post type "${cpt.slug}" has ${items.length} public item(s) accessible via REST API`, {
                    evidence: `${items.length} items of type "${cpt.slug}" returned`,
                    replication_steps: [`Fetch ${cptUrl}`, 'Observe custom post type content'],
                    remediation: `Review if "${cpt.slug}" content should be publicly accessible. Set appropriate permissions.`,
                  }));
              }
            } catch { /* not JSON */ }
          }, 5);
        }
      } catch { /* not JSON */ }
    }

    // Check standard endpoints for data exposure
    await parallelProbe(CUSTOM_ENDPOINTS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      if (body.length < 10) return;

      try {
        const data = JSON.parse(body);
        if (Array.isArray(data) && data.length > 0) {
          // Only flag non-obvious endpoints
          if (path.includes('search') || path.includes('block-types') || path.includes('navigation')) {
            findings.push(finding('REST_ENDPOINT_DATA', 'INFO', url,
              `REST API endpoint ${path.split('?')[0]} returns ${data.length} item(s)`, {
                evidence: `${data.length} items returned from ${path}`,
                replication_steps: [`Fetch ${url}`],
                remediation: 'Review if this endpoint should be publicly accessible.',
              }));
          }
        }
      } catch { /* not JSON */ }
    }, 8);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
