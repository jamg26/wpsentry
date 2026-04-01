import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'REST API Content Injection';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // CVE-2017-1001000: Content injection via REST API
    // WordPress 4.7.0-4.7.1 allowed unauthenticated post modification via type juggling
    // The bug was in /wp-json/wp/v2/posts/<id> where passing id as string "1abc" bypassed auth

    // First, check if REST API is available
    const postsUrl = `${target}/wp-json/wp/v2/posts?per_page=1`;
    const postsRes = await fetchURL(postsUrl);
    if (!postsRes || postsRes.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const postsBody = await postsRes.text();
    let postId: number | null = null;

    try {
      const posts = JSON.parse(postsBody);
      if (Array.isArray(posts) && posts.length > 0 && posts[0].id) {
        postId = posts[0].id;
      }
    } catch { /* not JSON */ }

    if (postId === null) return moduleResult(MODULE_NAME, target, findings, errors, start);

    // Test CVE-2017-1001000 style type juggling (read-only test)
    // We append a string suffix to the ID to test if the API accepts it
    const typeJuggleUrl = `${target}/wp-json/wp/v2/posts/${postId}abc`;
    const juggleRes = await fetchURL(typeJuggleUrl);

    if (juggleRes && juggleRes.status === 200) {
      const juggleBody = await juggleRes.text();
      try {
        const data = JSON.parse(juggleBody);
        if (data && data.id === postId) {
          findings.push(finding('REST_TYPE_JUGGLING', 'CRITICAL', typeJuggleUrl,
            `REST API accepts type-juggled post ID (CVE-2017-1001000 style) — may allow unauthenticated content modification`, {
              evidence: `Request to /wp-json/wp/v2/posts/${postId}abc returned post ID ${postId}`,
              replication_steps: [
                `Fetch ${typeJuggleUrl}`,
                `API accepts "${postId}abc" as valid post ID ${postId}`,
                'This indicates vulnerable type juggling in REST API routing',
                'An attacker could send a POST/PUT request to modify content without authentication',
              ],
              remediation: 'Update WordPress immediately. This vulnerability was patched in WordPress 4.7.2. Check if the site is running WordPress 4.7.0 or 4.7.1.',
            }));
        }
      } catch { /* not JSON */ }
    }

    // Test for unauthenticated post creation attempt (safe - will be rejected on patched systems)
    const createUrl = `${target}/wp-json/wp/v2/posts`;
    const createRes = await fetchURL(createUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: 'security_test_probe_delete_me',
        status: 'draft',
      }),
    });

    if (createRes) {
      if (createRes.status === 201) {
        findings.push(finding('REST_UNAUTH_POST_CREATE', 'CRITICAL', createUrl,
          'REST API allows unauthenticated post creation — critical access control bypass', {
            evidence: `POST to ${createUrl} returned 201 Created without authentication`,
            replication_steps: [
              `Send POST to ${createUrl} with title and status fields`,
              'New post is created without authentication',
            ],
            remediation: 'This is a critical vulnerability. Update WordPress immediately. Check REST API permissions and authentication.',
          }));
      } else if (createRes.status !== 401 && createRes.status !== 403) {
        const createBody = await createRes.text();
        if (!createBody.includes('rest_cannot_create') && !createBody.includes('rest_forbidden')) {
          findings.push(finding('REST_POST_CREATE_UNEXPECTED', 'MEDIUM', createUrl,
            `Unexpected response to unauthenticated POST creation attempt: status ${createRes.status}`, {
              evidence: `POST request returned status ${createRes.status} instead of expected 401/403`,
              replication_steps: [
                `Send POST to ${createUrl}`,
                `Received unexpected status: ${createRes.status}`,
              ],
              remediation: 'Verify REST API post creation requires proper authentication and returns 401/403 for unauthenticated requests.',
            }));
        }
      }
    }

    // Test for content update via REST (GET with specific parameters that trigger content display)
    const singlePostUrl = `${target}/wp-json/wp/v2/posts/${postId}?context=edit`;
    const editRes = await fetchURL(singlePostUrl);
    if (editRes && editRes.status === 200) {
      const editBody = await editRes.text();
      try {
        const data = JSON.parse(editBody);
        if (data.content?.raw || data.title?.raw) {
          findings.push(finding('REST_EDIT_CONTEXT_EXPOSED', 'HIGH', singlePostUrl,
            'REST API returns raw/edit context data without authentication — unfiltered content visible', {
              evidence: 'context=edit returned raw post content (HTML unfiltered)',
              replication_steps: [
                `Fetch ${singlePostUrl}`,
                'Observe raw HTML content in response (normally restricted to editors)',
              ],
              remediation: 'Ensure context=edit requires at least editor-level authentication on REST API endpoints.',
            }));
        }
      } catch { /* not JSON */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
