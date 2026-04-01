import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'REST API Auth Bypass';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // User enumeration via REST API is covered by wp_user_enum module
    const usersUrl = `${target}/wp-json/wp/v2/users`;

    // Test 2: Draft post access without auth
    const draftsUrl = `${target}/wp-json/wp/v2/posts?status=draft`;
    const draftsRes = await fetchURL(draftsUrl, { redirect: 'manual' });
    const drafts = (draftsRes?.status === 200) ? await draftsRes.json().catch(() => null) as unknown : null;
    // Skip WP error responses (e.g. rest_invalid_param for unauthorized users)
    if (drafts && typeof drafts === 'object' && !Array.isArray(drafts) && 'code' in (drafts as Record<string, unknown>)) {
      // Error response means access is properly blocked — no finding
    } else if (Array.isArray(drafts) && drafts.length > 0) {
      // Verify returned posts actually have draft status (WP ignores status param for unauthed users)
      const actualDrafts = drafts.filter(
        (p): p is Record<string, unknown> =>
          typeof p === 'object' && p !== null && (p as Record<string, unknown>)['status'] === 'draft'
      );
      if (actualDrafts.length > 0) {
        findings.push(finding(
          'rest_api_draft_access', 'HIGH', draftsUrl,
          `Draft posts accessible without authentication: ${actualDrafts.length} draft post(s) exposed`,
          {
            replication_steps: [
              `curl -s '${target}/wp-json/wp/v2/posts?status=draft' | python3 -m json.tool`,
            ],
            remediation: 'Ensure REST API status-filtered queries require authentication.',
            evidence: `${actualDrafts.length} draft posts returned`,
          },
        ));
      }
    }

    // Test 3: Private post access without auth
    const privateUrl = `${target}/wp-json/wp/v2/posts?status=private`;
    const privateRes = await fetchURL(privateUrl, { redirect: 'manual' });
    const privateP = (privateRes?.status === 200) ? await privateRes.json().catch(() => null) as unknown : null;
    // Skip WP error responses (e.g. rest_invalid_param for unauthorized users)
    if (privateP && typeof privateP === 'object' && !Array.isArray(privateP) && 'code' in (privateP as Record<string, unknown>)) {
      // Error response means access is properly blocked — no finding
    } else if (Array.isArray(privateP) && privateP.length > 0) {
      // Verify returned posts actually have private status
      const actualPrivate = privateP.filter(
        (p): p is Record<string, unknown> =>
          typeof p === 'object' && p !== null && (p as Record<string, unknown>)['status'] === 'private'
      );
      if (actualPrivate.length > 0) {
        findings.push(finding(
          'rest_api_draft_access', 'HIGH', privateUrl,
          `Private posts accessible without authentication: ${actualPrivate.length} private post(s) exposed`,
          {
            replication_steps: [
              `curl -s '${target}/wp-json/wp/v2/posts?status=private' | python3 -m json.tool`,
            ],
            remediation: 'Update WordPress to a patched version and restrict REST API access.',
            evidence: `${actualPrivate.length} private posts returned`,
          },
        ));
      }
    }

    // Test 4: Unauthenticated POST — create post
    const postsUrl = `${target}/wp-json/wp/v2/posts`;
    const createRes = await fetchURL(postsUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'JWP-Test', status: 'draft' }),
      redirect: 'manual',
    });
    if (createRes && [200, 201].includes(createRes.status)) {
      const createBody = await createRes.json().catch(() => null) as Record<string, unknown> | null;
      // Only flag if the response is NOT a WP error object and DOES contain an id (post was actually created)
      const isErrorObj = createBody && typeof createBody === 'object' && 'code' in createBody;
      if (!isErrorObj && createBody && 'id' in createBody) {
        findings.push(finding(
          'rest_api_unauthenticated_write', 'CRITICAL', postsUrl,
          'Unauthenticated POST to /wp-json/wp/v2/posts succeeded — content can be created without login',
          {
            replication_steps: [
              `curl -s -X POST ${target}/wp-json/wp/v2/posts -H 'Content-Type: application/json' -d '{"title":"Test","status":"draft"}' | python3 -m json.tool`,
            ],
            remediation: 'Update WordPress immediately. REST API write operations must require authentication.',
            evidence: `HTTP ${createRes.status} on unauthenticated POST; id=${createBody['id']}`,
          },
        ));
      }
    }

    // Test 5: Unauthenticated PUT — edit post
    const editUrl = `${target}/wp-json/wp/v2/posts/1`;
    const editRes = await fetchURL(editUrl, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'JWP-Edit' }),
      redirect: 'manual',
    });
    if (editRes && [200, 201].includes(editRes.status)) {
      const editBody = await editRes.json().catch(() => null) as Record<string, unknown> | null;
      const isErrorObj = editBody && typeof editBody === 'object' && 'code' in editBody;
      if (!isErrorObj && editBody && 'id' in editBody) {
        findings.push(finding(
          'rest_api_unauthenticated_write', 'CRITICAL', editUrl,
          'Unauthenticated PUT to /wp-json/wp/v2/posts/1 succeeded — existing posts can be modified without auth',
          {
            replication_steps: [
              `curl -s -X PUT ${target}/wp-json/wp/v2/posts/1 -H 'Content-Type: application/json' -d '{"title":"Injected Title"}' | python3 -m json.tool`,
            ],
            remediation: 'Update WordPress. Restrict REST API write access to authenticated users.',
            evidence: `HTTP ${editRes.status} on unauthenticated PUT; id=${editBody['id']}`,
          },
        ));
      }
    }

    // Test 6: Unauthenticated DELETE
    const deleteUrl = `${target}/wp-json/wp/v2/posts/1`;
    const deleteRes = await fetchURL(deleteUrl, { method: 'DELETE', redirect: 'manual' });
    if (deleteRes && [200, 201].includes(deleteRes.status)) {
      const deleteBody = await deleteRes.json().catch(() => null) as Record<string, unknown> | null;
      const isErrorObj = deleteBody && typeof deleteBody === 'object' && 'code' in deleteBody;
      if (!isErrorObj && deleteBody && ('id' in deleteBody || 'deleted' in deleteBody)) {
        findings.push(finding(
          'rest_api_unauthenticated_write', 'CRITICAL', deleteUrl,
          'Unauthenticated DELETE to /wp-json/wp/v2/posts/1 succeeded — posts can be deleted without auth',
          {
            replication_steps: [
              `curl -s -X DELETE ${target}/wp-json/wp/v2/posts/1 | python3 -m json.tool`,
            ],
            remediation: 'Update WordPress. Restrict all REST API destructive operations to authenticated users.',
            evidence: `HTTP ${deleteRes.status} on unauthenticated DELETE`,
          },
        ));
      }
    }

    // Test 7: Settings endpoint without auth
    const settingsUrl = `${target}/wp-json/wp/v2/settings`;
    const settingsRes = await fetchURL(settingsUrl, { redirect: 'manual' });
    if (settingsRes && settingsRes.status === 200) {
      const settings = await settingsRes.json().catch(() => null) as Record<string, unknown> | null;
      // Skip WP error objects — a 'code' field means rest_forbidden/rest_cannot_read, not real settings
      if (settings && typeof settings === 'object' && !('code' in settings) && Object.keys(settings).length > 0) {
        findings.push(finding(
          'rest_api_settings_exposed', 'HIGH', settingsUrl,
          `WordPress settings endpoint accessible without authentication (${Object.keys(settings).length} setting(s) exposed)`,
          {
            replication_steps: [
              `curl -s ${target}/wp-json/wp/v2/settings | python3 -m json.tool`,
            ],
            remediation: 'Restrict /wp/v2/settings to administrators only (requires authentication by default in current WP).',
            evidence: `${Object.keys(settings).length} settings keys exposed`,
          },
        ));
      }
    }

    // Test 8: Plugins endpoint without auth
    const pluginsUrl = `${target}/wp-json/wp/v2/plugins`;
    const plugins = await getJSON<unknown[]>(pluginsUrl);
    if (Array.isArray(plugins) && plugins.length > 0) {
      findings.push(finding(
        'rest_api_settings_exposed', 'HIGH', pluginsUrl,
        `Plugin list exposed without authentication: ${plugins.length} plugin(s) visible`,
        {
          replication_steps: [
            `curl -s ${target}/wp-json/wp/v2/plugins | python3 -m json.tool | grep -E '"plugin"|"name"|"version"'`,
          ],
          remediation: 'Restrict /wp/v2/plugins endpoint to authenticated administrators.',
          evidence: `${plugins.length} plugins listed without auth`,
        },
      ));
    }

    // Test 9: JWT auth plugin detection — skipped.
    // A 400/403/405 on the JWT endpoint means it exists but is properly secured.
    // JWT detection is handled by the wp_jwt_auth module.

    // Test 10: Basic Auth with default credentials (admin:admin)
    // btoa('admin:admin') = 'YWRtaW46YWRtaW4='
    const basicCreds = btoa('admin:admin');
    const basicRes = await fetchURL(usersUrl, {
      headers: { Authorization: `Basic ${basicCreds}` },
    });
    if (basicRes?.status === 200) {
      const basicData = await basicRes.json().catch(() => null) as Array<Record<string, unknown>> | null;
      if (Array.isArray(basicData) && basicData.some(u => u['capabilities'])) {
        findings.push(finding(
          'rest_api_weak_auth', 'CRITICAL', usersUrl,
          'Default credentials admin:admin accepted via HTTP Basic Authentication on REST API',
          {
            replication_steps: [
              `curl -s -u admin:admin ${target}/wp-json/wp/v2/users | python3 -m json.tool`,
              `curl -s -H 'Authorization: Basic YWRtaW46YWRtaW4=' ${target}/wp-json/wp/v2/users | python3 -m json.tool`,
            ],
            remediation: 'Change default admin credentials immediately. Disable HTTP Basic Auth on REST API.',
            evidence: 'admin:admin accepted — capabilities field present in response',
          },
        ));
      }
    }

    // Test 11: Application Passwords endpoint
    const appPwUrl = `${target}/wp-json/wp/v2/users/1/application-passwords`;
    const appPwRes = await fetchURL(appPwUrl);
    if (appPwRes && appPwRes.status === 200) {
      findings.push(finding(
        'rest_api_app_passwords_exposed', 'MEDIUM', appPwUrl,
        `Application Passwords endpoint accessible (HTTP ${appPwRes.status}) — verify auth is enforced`,
        {
          replication_steps: [
            `curl -s '${appPwUrl}'`,
            'Observe: endpoint exists. If 200 returned, Application Passwords may be exposed.',
            'Application Passwords allow API access without the main password.',
          ],
          remediation: 'Ensure Application Passwords endpoint requires authentication. Update WordPress to latest version.',
          evidence: `HTTP ${appPwRes.status} at ${appPwUrl}`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
