import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget} from '../utils.js';

const MODULE_NAME = 'Nonce Weakness';

function extractNonces(html: string): Record<string, string> {
  const nonces: Record<string, string> = {};
  const patterns: Record<string, RegExp> = {
    login_nonce: /name=["']login_nonce["']\s+value=["']([a-f0-9]+)["']/i,
    wp_rest_nonce: /"nonce"\s*:\s*"([a-f0-9]+)"/,
    wpnonce: /name=["']_wpnonce["']\s+value=["']([a-f0-9]+)["']/i,
    comment_nonce: /name=["']_wp_unfiltered_html_comment_disabled["']\s+value=["']([a-f0-9]+)["']/i,
    ajax_nonce: /var\s+\w+\s*=\s*\{[^}]*"nonce"\s*:\s*"([a-f0-9]+)"/,
  };
  for (const [name, pat] of Object.entries(patterns)) {
    const m = html.match(pat);
    if (m) nonces[name] = m[1];
  }
  return nonces;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const ajaxUrl = `${target}/wp-admin/admin-ajax.php`;
  const loginUrl = `${target}/wp-login.php`;
  const usersUrl = `${target}/wp-json/wp/v2/users`;

  try {
    // Test 1: Unauthenticated nonce generation via AJAX
    const nonceGenRes = await fetchURL(`${ajaxUrl}?action=generate_nonce`);
    if (nonceGenRes && nonceGenRes.status === 200) {
      const body = (await nonceGenRes.text()).trim();
      if (/^[a-f0-9]{10}$/.test(body)) {
        findings.push(finding(
          'nonce_bypass', 'HIGH', `${ajaxUrl}?action=generate_nonce`,
          `Unauthenticated nonce generation: AJAX action 'generate_nonce' returned a valid nonce (${body}) without authentication.`,
          {
            replication_steps: [
              `curl -s "${ajaxUrl}?action=generate_nonce"`,
              '# If 10-char hex returned = nonces generated without auth',
            ],
            remediation: 'Restrict nonce generation actions to authenticated users. Use wp_verify_nonce() with capability checks.',
            evidence: `Nonce returned: ${body}`,
          },
        ));
      }
    }

    // Test 2: Extract nonces from login page and homepage
    const extractedNonces: Record<string, string> = {};
    const nonceSources: [string, string][] = [
      [loginUrl, 'login'],
      [`${target}/`, 'homepage'],
    ];
    for (const [url, sourceName] of nonceSources) {
      const res = await fetchURL(url);
      if (res && res.status === 200) {
        const html = await res.text();
        const found = extractNonces(html);
        if (Object.keys(found).length > 0) {
          Object.assign(extractedNonces, found);
          findings.push(finding(
            'missing_nonce', 'INFO', url,
            `Nonce value(s) found in ${sourceName} HTML: ${JSON.stringify(Object.keys(found))}. This is expected — confirm they are properly validated server-side.`,
            {
              replication_steps: [
                `curl -s "${url}" | grep -oP '(?<=nonce["\\'\\']:s*["\\'\\'])[a-f0-9]+'`,
                `curl -s "${url}" | grep -iE "nonce|_wpnonce"`,
              ],
              remediation: 'Ensure extracted nonces are used for one-time operation and validated.',
              evidence: `Found nonce keys: ${JSON.stringify(Object.keys(found))} in ${sourceName}`,
            },
          ));
        }
      }
    }

    // Test 3: Nonce reuse via heartbeat — send same nonce twice
    if (Object.keys(extractedNonces).length > 0) {
      const nonceVal = Object.values(extractedNonces)[0];
      const nonceName = Object.keys(extractedNonces)[0];
      const postBody = new URLSearchParams({ action: 'heartbeat', _nonce: nonceVal }).toString();
      const postOpts = {
        method: 'POST',
        body: postBody,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      };
      const [r1, r2] = await Promise.all([
        fetchURL(ajaxUrl, postOpts),
        fetchURL(ajaxUrl, postOpts),
      ]);
      const accepted: boolean[] = [];
      for (const res of [r1, r2]) {
        if (res) {
          const body = (await res.text()).trim();
          // admin-ajax returns "-1" or "0" for unauthenticated/rejected requests
          accepted.push(res.status === 200 && !['-1', '0', ''].includes(body));
        }
      }
      if (accepted.filter(Boolean).length === 2) {
        findings.push(finding(
          'nonce_reuse', 'MEDIUM', ajaxUrl,
          `Nonce '${nonceVal}' (${nonceName}) was accepted on two consecutive requests. WordPress nonces are valid for 24h by default — this may indicate a broad validity window.`,
          {
            replication_steps: [
              `NONCE="${nonceVal}"`,
              `curl -s -X POST "${ajaxUrl}" -d "action=heartbeat&_nonce=$NONCE"`,
              `curl -s -X POST "${ajaxUrl}" -d "action=heartbeat&_nonce=$NONCE"`,
              '# If both return non-empty JSON (not -1) = nonce accepted twice',
            ],
            remediation: 'For sensitive actions, implement single-use nonces. Reduce nonce_life for critical operations.',
            evidence: `Nonce ${nonceVal} accepted twice`,
          },
        ));
      }
    }

    // Test 4: Comment form nonce presence
    const postPageRes = await fetchURL(`${target}/?p=1`);
    if (postPageRes && postPageRes.status === 200) {
      const html = await postPageRes.text();
      const commentNoncePresent = /nonce|_wpnonce/i.test(html);
      const formPresent = /<form[^>]+comment/i.test(html);
      if (formPresent && !commentNoncePresent) {
        findings.push(finding(
          'missing_nonce', 'MEDIUM', `${target}/?p=1`,
          'Comment form found on post page without a detectable nonce field. Missing nonces enable CSRF attacks on comment submission.',
          {
            replication_steps: [
              `curl -s "${target}/?p=1" | grep -iE "nonce|_wpnonce"`,
              `curl -s "${target}/?p=1" | grep -i "<form"`,
              '# Absence of nonce in comment form = CSRF vulnerability',
            ],
            remediation: "Ensure wp_nonce_field() is included in comment forms. Use comment_form() which includes nonce by default.",
            evidence: 'Comment form present but no nonce field detected',
          },
        ));
      }
    }

    // Test 5: REST /users endpoint with invalid nonce
    // /wp/v2/users is public by default — only flag as nonce bypass if the invalid
    // nonce returns MORE data than a request without any nonce header.
    const [usersResNoNonce, usersResInvalidNonce] = await Promise.all([
      fetchURL(usersUrl),
      fetchURL(usersUrl, { headers: { 'X-WP-Nonce': 'invalid_nonce_12345' } }),
    ]);
    if (usersResNoNonce && usersResInvalidNonce) {
      if (usersResInvalidNonce.status === 200 && usersResNoNonce.status === 200) {
        try {
          const usersNoNonce = await usersResNoNonce.json() as unknown[];
          const usersInvalid = await usersResInvalidNonce.json() as unknown[];
          if (
            Array.isArray(usersInvalid) && Array.isArray(usersNoNonce) &&
            usersInvalid.length > 0 &&
            JSON.stringify(usersInvalid).length > JSON.stringify(usersNoNonce).length + 100
          ) {
            findings.push(finding(
              'nonce_bypass', 'HIGH', usersUrl,
              `REST /wp/v2/users endpoint returned more data with an invalid X-WP-Nonce than without one (${usersInvalid.length} vs ${usersNoNonce.length} users, or larger response). Nonce validation may be absent.`,
              {
                replication_steps: [
                  `curl -s "${usersUrl}" | wc -c`,
                  `curl -s -H "X-WP-Nonce: invalid_nonce_12345" "${usersUrl}" | wc -c`,
                  '# If second response is significantly larger = nonce not validated',
                ],
                remediation: 'Ensure nonce validation via wp_verify_nonce() on REST endpoints that return user data.',
                evidence: `Without nonce: ${usersNoNonce.length} users; with invalid nonce: ${usersInvalid.length} users`,
              },
            ));
          }
          // If both responses are the same size, the endpoint is simply public — not a nonce bypass
        } catch {
          // not JSON
        }
      } else if (usersResInvalidNonce.status === 403) {
        findings.push(finding(
          'nonce_bypass', 'INFO', usersUrl,
          'REST /wp/v2/users correctly rejected invalid X-WP-Nonce with HTTP 403.',
          {
            replication_steps: [
              `curl -sI -H "X-WP-Nonce: invalid_nonce_12345" "${usersUrl}"`,
            ],
            remediation: 'No action required — nonce validation is functioning.',
            evidence: 'HTTP 403 returned for invalid nonce',
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
