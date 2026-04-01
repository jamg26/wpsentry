import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'WordPress User Enumeration';



async function tryRestApi(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-json/wp/v2/users`;
  const res = await fetchURL(url);
  if (!res) {
    findings.push(finding(
      'REST_API_UNREACHABLE', 'INFO', url,
      'REST API unreachable — endpoint may be blocked or non-existent',
    ));
    return;
  }

  if (res.status === 200) {
    try {
      const users = await res.json() as Array<{ name?: string; slug?: string; id?: number }>;
      if (Array.isArray(users) && users.length > 0) {
        const userList = users.map(u => ({
          name: u.name ?? u.slug ?? 'unknown',
          id: u.id ?? '?',
        }));
        const summary = userList.map(u => `${u.name} (id=${u.id})`).join(', ');
        findings.push(finding(
          'USER_EXPOSED_REST_API', 'LOW', url,
          `${users.length} user(s) exposed via REST API: ${summary}`,
          { evidence: JSON.stringify(userList), remediation: "Disable REST API user enumeration: add_filter('rest_endpoints', function($endpoints) { unset($endpoints['/wp/v2/users']); return $endpoints; });" },
        ));
      }
    } catch { /* ignore parse errors */ }
  } else if (res.status === 401) {
    findings.push(finding(
      'REST_API_AUTH_REQUIRED', 'INFO', url,
      'REST API /users endpoint requires authentication (good)',
    ));
    return;
  }

  // Paginated endpoint — merge any additional users into the existing finding
  const urlPaged = `${base}/wp-json/wp/v2/users?per_page=100`;
  const res2 = await fetchURL(urlPaged);
  if (res2 && res2.status === 200) {
    try {
      const users2 = await res2.json() as Array<{ name?: string; slug?: string; id?: number }>;
      if (Array.isArray(users2)) {
        const existingFinding = findings.find(f => f.type === 'USER_EXPOSED_REST_API');
        const existingIds = new Set<unknown>();
        if (existingFinding) {
          try {
            const parsed = JSON.parse(existingFinding.evidence ?? '[]') as Array<{ id: unknown }>;
            for (const u of parsed) existingIds.add(u.id);
          } catch { /* ignore */ }
        }
        const newUsers = users2
          .filter(u => !existingIds.has(u.id ?? '?'))
          .map(u => ({ name: u.name ?? u.slug ?? 'unknown', id: u.id ?? '?' }));
        if (newUsers.length > 0 && existingFinding) {
          const allUsers = [
            ...JSON.parse(existingFinding.evidence ?? '[]'),
            ...newUsers,
          ];
          existingFinding.evidence = JSON.stringify(allUsers);
          const summary = allUsers.map((u: { name: string; id: unknown }) => `${u.name} (id=${u.id})`).join(', ');
          existingFinding.description = `${allUsers.length} user(s) exposed via REST API: ${summary}`;
        } else if (newUsers.length > 0) {
          const summary = newUsers.map(u => `${u.name} (id=${u.id})`).join(', ');
          findings.push(finding(
            'USER_EXPOSED_REST_API', 'LOW', urlPaged,
            `${newUsers.length} user(s) exposed via paginated REST API: ${summary}`,
            { evidence: JSON.stringify(newUsers), remediation: "Disable REST API user enumeration: add_filter('rest_endpoints', function($endpoints) { unset($endpoints['/wp/v2/users']); return $endpoints; });" },
          ));
        }
      }
    } catch { /* ignore */ }
  }
}

async function tryAuthorArchives(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const ids = Array.from({ length: 10 }, (_, i) => i + 1);
  await parallelProbe(ids, async (uid) => {
    const url = `${base}/?author=${uid}`;
    const res = await fetchURL(url);
    if (!res) return;
    const finalUrl = res.url;
    if (finalUrl !== url && finalUrl.includes('/author/')) {
      const m = /\/author\/([^/?#]+)/.exec(finalUrl);
      const slug = m ? m[1] : 'unknown';
      findings.push(finding(
        'USER_EXPOSED_AUTHOR_ARCHIVE', 'LOW', url,
        `Author archive discloses username '${slug}' (id=${uid})`,
        { evidence: JSON.stringify({ slug, id: uid }), remediation: "Disable REST API user enumeration: add_filter('rest_endpoints', function($endpoints) { unset($endpoints['/wp/v2/users']); return $endpoints; });" },
      ));
    }
  });
}

async function tryLoginEnum(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-login.php`;
  const res = await fetchURL(url, {
    method: 'POST',
    body: new URLSearchParams({
      log: 'admin_strix_test_user_xyzzy',
      pwd: 'wrong_password_1234',
      'wp-submit': 'Log In',
      testcookie: '1',
    }),
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  if (res && res.status === 200) {
    const body = await res.text();
    if (body.toLowerCase().includes('invalid username')) {
      findings.push(finding(
        'LOGIN_USER_ENUM_POSSIBLE', 'LOW', url,
        "Login page reveals 'invalid username' — user enumeration possible",
      ));
    }
  }
}

async function tryOembed(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-json/oembed/1.0/embed?url=${encodeURIComponent(base)}&format=json`;
  const res = await fetchURL(url);
  if (!res || res.status !== 200) return;
  const body = await res.text();
  if (!body.includes('author_name')) return;
  try {
    const data = JSON.parse(body) as { author_name?: string };
    const author = data.author_name ?? 'unknown';
    findings.push(finding(
      'USER_OEMBED_DISCLOSURE', 'LOW', url,
      `oEmbed endpoint discloses author name: '${author}'`,
      { evidence: author },
    ));
  } catch {
    findings.push(finding(
      'USER_OEMBED_DISCLOSURE', 'LOW', url,
      "oEmbed endpoint discloses author name",
    ));
  }
}

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // Check cached reachability to skip probes for known-unreachable endpoints
    const restApiCached = state?.reachabilityCache?.get(`${target}/wp-json/`);
    const loginCached = state?.reachabilityCache?.get(`${target}/wp-login.php`);
    const restApiUnreachable = restApiCached && (restApiCached.status === 0 || restApiCached.status >= 400);
    const loginUnreachable = loginCached && (loginCached.status === 0 || loginCached.status >= 400);

    await Promise.allSettled([
      restApiUnreachable ? Promise.resolve() : tryRestApi(target, findings),
      tryAuthorArchives(target, findings),
      loginUnreachable ? Promise.resolve() : tryLoginEnum(target, findings),
      tryOembed(target, findings),
    ]);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
