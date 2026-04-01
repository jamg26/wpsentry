import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'REST API Mass Assignment';

async function probeUserRoleEscalation(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const usersUrl = `${base}/wp-json/wp/v2/users`;
  try {
    const data = await getJSON<unknown[]>(usersUrl);
    if (!Array.isArray(data) || data.length === 0) return;

    const opts = await fetchURL(usersUrl, {
      headers: { 'X-HTTP-Method-Override': 'OPTIONS' },
    });
    if (!opts) return;

    const allowHeader = (opts.headers.get('allow') ?? '') +
                        (opts.headers.get('access-control-allow-methods') ?? '');

    if (/POST|PUT|PATCH/i.test(allowHeader)) {
      findings.push(finding(
        'REST_USER_WRITE_ALLOWED', 'CRITICAL', usersUrl,
        'REST API users endpoint allows write methods (POST/PUT) without credentials — potential role escalation vector',
        {
          replication_steps: [
            `curl -sI -X OPTIONS "${usersUrl}"`,
            'Observe Allow header includes POST or PUT methods.',
            `curl -s -X POST "${usersUrl}" -H 'Content-Type: application/json' -d '{"username":"attacker","email":"a@x.com","password":"pw","roles":["administrator"]}'`,
            'Attempt to create an admin user without authentication.',
          ],
          remediation: 'Ensure POST/PUT on /wp-json/wp/v2/users requires authentication. Disable REST API for unauthenticated users if not required publicly.',
          evidence: JSON.stringify({ allow: allowHeader }),
        },
      ));
    }
  } catch { /* ignore */ }
}

async function checkDraftPostExposure(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const draftUrl = `${base}/wp-json/wp/v2/posts?status=draft`;
  try {
    const res = await fetchURL(draftUrl);
    if (!res || res.status !== 200) return;
    let data: unknown;
    try { data = await res.json(); } catch { return; }
    if (!Array.isArray(data) || data.length === 0) return;

    findings.push(finding(
      'REST_DRAFT_POST_EXPOSURE', 'HIGH', draftUrl,
      'Unauthenticated access to draft/private posts via REST API mass assignment bypass',
      {
        replication_steps: [
          `curl -s "${draftUrl}" | python3 -m json.tool`,
          'Observe draft post content returned without authentication.',
          'Exposes unpublished content, internal plans, and potential secrets.',
        ],
        remediation: "Restrict REST API to authenticated users or disable draft/private post access via add_filter('rest_post_dispatch', ...).",
        evidence: JSON.stringify({ draft_count: (data as unknown[]).length }),
      },
    ));
  } catch { /* ignore */ }
}

async function checkContextEditFieldLeakage(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const editCtxUrl = `${base}/wp-json/wp/v2/users?context=edit`;
  try {
    const res = await fetchURL(editCtxUrl);
    if (!res || res.status !== 200) return;
    let data: unknown;
    try { data = await res.json(); } catch { return; }
    if (!Array.isArray(data) || data.length === 0) return;

    const first = data[0] as Record<string, unknown>;
    const leaked = ['capabilities', 'extra_capabilities', 'roles'].filter(f => f in first);
    if (leaked.length === 0) return;

    findings.push(finding(
      'REST_CONTEXT_EDIT_LEAK', 'HIGH', editCtxUrl,
      `REST API leaks user capabilities via context=edit parameter — fields exposed: ${leaked.join(', ')}`,
      {
        replication_steps: [
          `curl -s "${editCtxUrl}" | python3 -m json.tool`,
          `Observe fields present without authentication: ${leaked.join(', ')}`,
          'Role and capability data enables targeted privilege escalation.',
        ],
        remediation: 'Restrict context=edit to users with edit_users capability. Review REST API permission_callback in field registrations.',
        evidence: JSON.stringify({ leaked_fields: leaked }),
      },
    ));
  } catch { /* ignore */ }
}

async function checkPostMetaExposure(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const metaUrl = `${base}/wp-json/wp/v2/posts?context=edit`;
  try {
    const res = await fetchURL(metaUrl);
    if (!res || res.status !== 200) return;
    let data: unknown;
    try { data = await res.json(); } catch { return; }
    if (!Array.isArray(data) || data.length === 0) return;

    const first = data[0] as Record<string, unknown>;
    // Only flag _edit_lock/_edit_last (always sensitive), and meta only if non-empty
    const foundMeta = ['_edit_lock', '_edit_last'].filter(f => f in first);
    if ('meta' in first) {
      const meta = first['meta'];
      const hasContent = typeof meta === 'object' && meta !== null && Object.keys(meta).length > 0;
      if (hasContent) foundMeta.push('meta');
    }
    if (foundMeta.length === 0) return;

    findings.push(finding(
      'REST_POST_META_EXPOSURE', 'MEDIUM', metaUrl,
      `Unauthenticated access to internal post meta fields via REST API context=edit — fields: ${foundMeta.join(', ')}`,
      {
        replication_steps: [
          `curl -s "${metaUrl}" | python3 -m json.tool | grep -E '_edit_lock|_edit_last|"meta"'`,
          'Observe internal WordPress meta fields in unauthenticated response.',
        ],
        remediation: "Filter internal meta fields from unauthenticated REST responses. Use register_rest_field() with a proper permission_callback.",
        evidence: JSON.stringify({ meta_fields: foundMeta }),
      },
    ));
  } catch { /* ignore */ }
}

async function probeUserMetaInjection(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const user1Url = `${base}/wp-json/wp/v2/users/1?context=edit`;
  try {
    const res = await fetchURL(user1Url);
    if (!res || res.status !== 200) return;
    let data: unknown;
    try { data = await res.json(); } catch { return; }
    if (!data || typeof data !== 'object') return;

    const obj = data as Record<string, unknown>;
    const criticalFields = ['user_pass', 'session_tokens', '_capabilities'];
    const criticalFound = criticalFields.filter(f => f in obj);

    if (criticalFound.length > 0) {
      findings.push(finding(
        'REST_USER_SENSITIVE_DATA', 'CRITICAL', user1Url,
        `User capabilities/session data exposed via unauthenticated REST API — critical fields: ${criticalFound.join(', ')}`,
        {
          replication_steps: [
            `curl -s "${user1Url}" | python3 -m json.tool`,
            `Observe critical fields: ${criticalFound.join(', ')}`,
            'session_tokens enables direct session hijacking.',
          ],
          remediation: 'Immediately restrict context=edit to authenticated admin users. Audit all REST API field registrations for sensitive data.',
          evidence: JSON.stringify({ critical_fields: criticalFound }),
        },
      ));
    } else if ('capabilities' in obj) {
      findings.push(finding(
        'REST_USER_CAPABILITIES_LEAK', 'HIGH', user1Url,
        'User capabilities exposed via unauthenticated REST API context=edit — enables role mapping and targeted privilege escalation',
        {
          replication_steps: [
            `curl -s "${user1Url}" | python3 -m json.tool | grep -A5 'capabilities'`,
            'Observe user role/capability data returned without authentication.',
          ],
          remediation: 'Require authentication for context=edit on user endpoints.',
          evidence: 'capabilities field present in unauthenticated response for user ID 1',
        },
      ));
    }
  } catch { /* ignore */ }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await probeUserRoleEscalation(target, findings);
    await checkDraftPostExposure(target, findings);
    await checkContextEditFieldLeakage(target, findings);
    await checkPostMetaExposure(target, findings);
    await probeUserMetaInjection(target, findings);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
