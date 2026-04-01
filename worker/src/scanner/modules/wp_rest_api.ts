import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'REST API Security Audit';

// [path, description, severity, jsonKey | null]
const SENSITIVE_ENDPOINTS: Array<[string, string, string, string | null]> = [
  ['/wp-json/wp/v2/users',               'User list exposed',              'HIGH',   null],
  ['/wp-json/wp/v2/settings',            'Site settings accessible',       'HIGH',   'title'],
  ['/wp-json/wp/v2/posts?status=draft',  'Draft posts accessible',         'MEDIUM', null],
  ['/wp-json/wp/v2/posts?status=private','Private posts accessible',       'MEDIUM', null],
  ['/wp-json/wp/v2/media',               'Media library exposed',          'LOW',    null],
  ['/wp-json/wp/v2/comments?status=spam','Spam comments exposed',          'LOW',    null],
  ['/wp-json/jwt-auth/v1/token',         'JWT auth endpoint exposed',      'MEDIUM', null],
  ['/wp-json/wp/v2/plugins',             'Plugin list exposed',            'HIGH',   null],
  ['/wp-json/wp/v2/themes',              'Theme list exposed',             'MEDIUM', null],
  ['/wp-json/',                          'API namespace disclosure',       'LOW',    'namespaces'],
  ['/wp-json/wp/v2/blocks',             'Block patterns exposed',          'LOW',    null],
  ['/wp-json/wp/v2/templates',           'Block templates accessible',     'MEDIUM', null],
  ['/wp-json/wp/v2/sidebars',            'Sidebar config exposed',         'LOW',    null],
  ['/wp-json/wp/v2/menus',               'Navigation menus exposed',       'LOW',    null],
  ['/wp-json/wc/v3/products',            'WooCommerce products API',       'MEDIUM', null],
  ['/wp-json/wc/v3/customers',           'WooCommerce customers API',      'HIGH',   null],
  ['/wp-json/wp/v2/application-passwords','App passwords API',             'HIGH',   null],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(SENSITIVE_ENDPOINTS, async ([path, desc, severity, jsonKey]) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;

      let data: unknown;
      try { data = await res.json(); } catch { data = null; }

      let exposed = false;
      let detail = '';

      if (jsonKey && typeof data === 'object' && data !== null && jsonKey in (data as object)) {
        exposed = true;
        if (jsonKey === 'namespaces') {
          const ns = (data as Record<string, unknown>)[jsonKey];
          detail = Array.isArray(ns) ? `namespaces: ${(ns as string[]).slice(0, 10).join(', ')}` : `key '${jsonKey}' present`;
        } else {
          detail = `key '${jsonKey}' present in response`;
        }
      } else if (jsonKey === null) {
        if (Array.isArray(data) && data.length > 0) {
          exposed = true; detail = `${data.length} items returned`;
        } else if (typeof data === 'object' && data !== null && 'namespaces' in (data as object)) {
          exposed = true;
          const ns = (data as Record<string, unknown>)['namespaces'];
          if (Array.isArray(ns)) detail = `namespaces: ${(ns as string[]).slice(0, 10).join(', ')}`;
        } else if (typeof data === 'object' && data !== null && Object.keys(data as object).length > 0) {
          exposed = true; detail = `${Object.keys(data as object).length} fields in response`;
        }
      }

      if (exposed) {
        findings.push(finding(
          'REST_API_DATA_EXPOSED',
          severity as Parameters<typeof finding>[1],
          url,
          detail ? `${desc} — ${detail}` : desc,
          { remediation: 'Restrict REST API access using the rest_authentication_errors filter or a plugin like Disable REST API.' },
        ));
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
