import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Broken Function Level Authorization';

// [path, description, method, severity, payload]
const REST_ADMIN_ENDPOINTS: [string, string, string, 'CRITICAL' | 'HIGH' | 'MEDIUM', Record<string, unknown> | null][] = [
  ['/wp-json/wp/v2/users',       'Create user (should require auth)',              'POST', 'HIGH',
   { username: 'bfla_test_probe', email: 'bfla@probe.invalid', password: 'Pr0be!2024' }],
  ['/wp-json/wp/v2/users/1',     'Edit admin user (should require auth)',          'POST', 'HIGH',
   { name: 'BFLA_PROBE' }],
  ['/wp-json/wp/v2/plugins',     'Install plugin (should require auth)',           'POST', 'HIGH',
   { slug: 'hello-dolly', status: 'active' }],
  ['/wp-json/wp/v2/settings',    'Write site settings (should require auth)',      'POST', 'CRITICAL',
   { title: 'BFLA_TEST' }],
  ['/wp-json/wp/v2/templates',   'Create block template (should require auth)',    'POST', 'MEDIUM',
   { slug: 'bfla-probe', content: '<!--BFLA-->' }],
  ['/wp-json/wp/v2/comments/1',  'Edit comment status (should require auth)',      'POST', 'MEDIUM',
   { status: 'approved' }],
  ['/wp-json/wp/v2/export',      'Data export endpoint (should require auth)',     'GET',  'MEDIUM', null],
  ['/wp-json/wp/v2/users/1/application-passwords',
   'Create app password for admin (should require auth)',                           'POST', 'CRITICAL',
   { name: 'bfla_probe' }],
];

const PRIVILEGED_AJAX: [string, string, 'CRITICAL' | 'HIGH' | 'MEDIUM'][] = [
  ['activate',            'Activate plugin',          'HIGH'],
  ['deactivate',          'Deactivate plugin',        'HIGH'],
  ['upgrade-plugin',      'Upgrade plugin',           'HIGH'],
  ['install-plugin',      'Install plugin',           'CRITICAL'],
  ['delete-plugin',       'Delete plugin',            'HIGH'],
  ['add-user',            'Add user',                 'HIGH'],
  ['create-user',         'Create user',              'HIGH'],
  ['update-user',         'Update user',              'HIGH'],
  ['trash-post',          'Trash post without auth',  'MEDIUM'],
  ['add_meta',            'Add post meta',            'MEDIUM'],
  ['reset-user-password', 'Reset user password',      'CRITICAL'],
];

const METHOD_OVERRIDE_HEADERS = ['X-HTTP-Method-Override', 'X-Method-Override', '_method'];

const WP_ERROR_CODES = new Set([
  'rest_forbidden', 'rest_cannot_create', 'rest_cannot_edit',
  'rest_not_logged_in', 'rest_user_cannot_create', 'rest_user_invalid_argument',
]);

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  // Check REST admin endpoints for BFLA
  await parallelProbe(REST_ADMIN_ENDPOINTS, async ([path, desc, method, severity, payload]) => {
    const url = `${target}${path}`;
    try {
      const r = method === 'GET'
        ? await fetchURL(url)
        : await fetchURL(url, {
            method: 'POST',
            body: JSON.stringify(payload),
            headers: { 'Content-Type': 'application/json' },
          });
      if (!r) return;

      if ([200, 201].includes(r.status)) {
        let data: Record<string, unknown> = {};
        try { data = await r.json() as Record<string, unknown>; } catch { /* ignore */ }
        if (WP_ERROR_CODES.has(String(data.code ?? ''))) return;

        findings.push(finding(
          'BFLA_REST_PRIVILEGED_ACTION',
          severity,
          url,
          `BFLA: ${desc} — HTTP ${r.status} without authentication`,
          {
            replication_steps: [
              `curl -s -X ${method} '${url}'` +
                (payload ? ` -H 'Content-Type: application/json' -d '${JSON.stringify(payload)}'` : ''),
              `Observe HTTP ${r.status} — privileged action performed without credentials.`,
              'Repeat with a low-privileged session cookie to confirm vertical privilege escalation.',
            ],
            evidence: JSON.stringify({ method, http_status: r.status }),
            remediation: 'Implement proper role-based access controls using WordPress capabilities system.',
          },
        ));
      } else if (r.status === 403 && method !== 'GET') {
        // Check verb-drift bypass via method-override headers
        for (const hdr of METHOD_OVERRIDE_HEADERS) {
          try {
            const r2 = await fetchURL(url, {
              method: 'POST',
              body: JSON.stringify(payload),
              headers: { 'Content-Type': 'application/json', [hdr]: 'GET' },
            });
            if (r2 && [200, 201].includes(r2.status)) {
              findings.push(finding(
                'BFLA_METHOD_OVERRIDE_BYPASS',
                severity,
                url,
                `BFLA method-override bypass: ${desc} via ${hdr} header`,
                {
                  replication_steps: [
                    `curl -s -X POST '${url}' -H '${hdr}: GET' -H 'Content-Type: application/json'`,
                    `Observe HTTP ${r2.status} — authorization check bypassed via method override.`,
                  ],
                  evidence: JSON.stringify({ bypass_header: hdr, http_status: r2.status }),
                  remediation: 'Implement proper role-based access controls using WordPress capabilities system.',
                },
              ));
              break;
            }
          } catch { /* ignore */ }
        }
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  // Check admin AJAX privilege escalation
  const ajaxUrl = `${target}/wp-admin/admin-ajax.php`;
  await parallelProbe(PRIVILEGED_AJAX, async ([action, desc, severity]) => {
    try {
      const r = await fetchURL(ajaxUrl, {
        method: 'POST',
        body: new URLSearchParams({ action }).toString(),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      if (!r) return;
      const body = (await r.text()).trim();
      if (['-1', '0', '', 'false', 'null'].includes(body)) return;
      if (r.status === 403) return;
      if (r.status === 200) {
        findings.push(finding(
          'BFLA_AJAX_PRIVILEGED_ACTION',
          severity,
          ajaxUrl,
          `BFLA: Admin AJAX action '${action}' (${desc}) returned non-empty response without auth`,
          {
            replication_steps: [
              `curl -s -X POST '${ajaxUrl}' -d 'action=${action}'`,
              `Observe non-empty/non-zero response (body: ${JSON.stringify(body.slice(0, 80))})`,
              'Investigate whether the action executes privileged operations.',
            ],
            evidence: JSON.stringify({ action, response_preview: body.slice(0, 200) }),
            remediation: 'Implement proper role-based access controls using WordPress capabilities system.',
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
