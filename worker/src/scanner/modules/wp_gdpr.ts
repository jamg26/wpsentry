import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'GDPR Privacy';

const AJAX_PATH    = '/wp-admin/admin-ajax.php';
const USERS_API    = '/wp-json/wp/v2/users';
const LOGIN_PATH   = '/wp-login.php';

function extractDomain(target: string): string {
  try {
    const url = new URL(target.startsWith('http') ? target : `https://${target}`);
    return url.hostname;
  } catch {
    return target.split('/')[0].split(':')[0];
  }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const domain = extractDomain(target);
  const adminEmail = `admin@${domain}`;
  const ajaxUrl = `${target}${AJAX_PATH}`;

  // Test 1: GDPR personal data export without auth
  try {
    const body = new URLSearchParams({
      'action': 'wp-privacy-export-personal-data',
      'email': adminEmail,
      'id': '1',
      'page': '1',
      'exporter': '1',
      '_wpnonce': 'test',
    }).toString();
    const res = await fetchURL(ajaxUrl, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (res && res.status === 200) {
      const text = await res.text();
      if (text.toLowerCase().includes('success')) {
        findings.push(finding('gdpr_data_export_unauth', 'HIGH', ajaxUrl,
          `GDPR personal data export endpoint accepted unauthenticated request for ${adminEmail}. ` +
          'This may allow an attacker to trigger data export emails.',
          {
            replication_steps: [
              `curl -s -X POST "${ajaxUrl}" ` +
              `-d "action=wp-privacy-export-personal-data&email=${adminEmail}` +
              '&id=1&page=1&exporter=1&_wpnonce=test"',
              "# Check if 'success':true returned without authentication",
            ],
            remediation:
              'Ensure export/erasure AJAX handlers require administrator capability. ' +
              'Validate nonce and user permissions.',
            evidence: JSON.stringify({ response_preview: text.slice(0, 300), cvss_score: 7.5, cve_refs: ['CVE-2019-9787'] }),
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 2: GDPR personal data erasure without auth
  try {
    const body = new URLSearchParams({
      'action': 'wp-privacy-erase-personal-data',
      'email': adminEmail,
      'id': '1',
      'page': '1',
      'eraser': '1',
      '_wpnonce': 'test',
    }).toString();
    const res = await fetchURL(ajaxUrl, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (res && res.status === 200) {
      const text = await res.text();
      if (text.toLowerCase().includes('success')) {
        findings.push(finding('gdpr_data_export_unauth', 'HIGH', ajaxUrl,
          `GDPR personal data erasure endpoint accepted unauthenticated request for ${adminEmail}.`,
          {
            replication_steps: [
              `curl -s -X POST "${ajaxUrl}" ` +
              `-d "action=wp-privacy-erase-personal-data&email=${adminEmail}` +
              '&id=1&page=1&eraser=1&_wpnonce=test"',
            ],
            remediation: 'Restrict erasure endpoint to authenticated admins only.',
            evidence: JSON.stringify({ response_preview: text.slice(0, 300), cvss_score: 7.5, cve_refs: ['CVE-2019-9787'] }),
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 3: REST API user email exposure (only flag if actual emails are found)
  try {
    const usersUrl = `${target}${USERS_API}`;
    const users = await getJSON<unknown[]>(usersUrl);
    if (users && Array.isArray(users)) {
      const allUsers = users.filter((u): u is Record<string, unknown> => typeof u === 'object' && u !== null);
      const exposedEmails = allUsers
        .map(u => String(u['email'] ?? ''))
        .filter(e => e.includes('@'));
      const exposedUsernames = allUsers
        .map(u => String(u['slug'] ?? u['name'] ?? ''))
        .filter(Boolean);

      if (exposedEmails.length > 0) {
        findings.push(finding('user_email_exposure', 'MEDIUM', usersUrl,
          `WordPress REST API exposes ${exposedEmails.length} email address(es): ${JSON.stringify(exposedEmails)}`,
          {
            replication_steps: [
              `curl -s "${usersUrl}" | python3 -m json.tool`,
              `curl -s "${usersUrl}" | grep -oP '"email":\\s*"[^"]+"'`,
            ],
            remediation:
              'Disable user enumeration: ' +
              "add_filter('rest_endpoints', fn($ep) => { " +
              "unset($ep['/wp/v2/users']); return $ep; }).",
            evidence: `${exposedEmails.length} emails found at ${usersUrl}`,
          },
        ));
      } else if (exposedUsernames.length > 0) {
        findings.push(finding('user_data_exposure', 'LOW', usersUrl,
          `WordPress REST API exposes ${exposedUsernames.length} username(s)/slug(s): ${JSON.stringify(exposedUsernames)}`,
          {
            replication_steps: [
              `curl -s "${usersUrl}" | python3 -m json.tool`,
              `curl -s "${usersUrl}" | grep -oP '"slug":\\s*"[^"]+"'`,
            ],
            remediation:
              'Disable user enumeration: ' +
              "add_filter('rest_endpoints', fn($ep) => { " +
              "unset($ep['/wp/v2/users']); return $ep; }).",
            evidence: `${exposedUsernames.length} usernames/slugs found at ${usersUrl}`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 4: Author archive enumeration
  const foundUsers: string[] = [];
  await parallelProbe(Array.from({ length: 5 }, (_, i) => i + 1), async (i) => {
    const authorUrl = `${target}/?author=${i}`;
    try {
      const res = await fetchURL(authorUrl);
      if (!res || res.status !== 200) return;
      const finalUrl = res.url ?? '';
      if (!finalUrl.includes('/author/')) return;
      const m = finalUrl.match(/\/author\/([^/"?]+)/);
      if (m) {
        const username = m[1];
        foundUsers.push(username);
        findings.push(finding('author_username_enumeration', 'LOW', authorUrl,
          `WordPress username '${username}' inferred via author redirect (?author=${i}).`,
          {
            replication_steps: [
              `curl -sI "${authorUrl}" | grep -i "location"`,
              `# Redirects to /author/${username}/ — username confirmed`,
            ],
            remediation: 'Redirect author archives or disable via SEO plugins.',
            evidence: `Redirected to ${finalUrl}`,
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  // Test 5: Password reset via discovered username
  if (foundUsers.length > 0) {
    const lostpwUrl = `${target}${LOGIN_PATH}?action=lostpassword`;
    await parallelProbe(foundUsers.slice(0, 2), async (username) => {
      try {
        const body = new URLSearchParams({
          'user_login': username,
          'redirect_to': '',
          'wp-submit': 'Get New Password',
        }).toString();
        const res = await fetchURL(lostpwUrl, {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        if (!res || (res.status !== 200 && res.status !== 302)) return;
        const text = (await res.text()).toLowerCase();
        if (text.includes('check your email') || text.includes('email has been sent')) {
          findings.push(finding('gdpr_data_export_unauth', 'LOW', lostpwUrl,
            `Password reset email triggered for user '${username}'. ` +
            'Combined with username enumeration, this enables targeted phishing.',
            {
              replication_steps: [
                `curl -s -X POST "${lostpwUrl}" ` +
                `-d "user_login=${username}&wp-submit=Get+New+Password"`,
                "# Observe 'Check your email' response = valid username confirmed",
              ],
              remediation:
                'Add CAPTCHA or rate-limiting to password reset. ' +
                'Do not confirm if account exists.',
              evidence: `Response contains password reset confirmation for ${username}`,
            },
          ));
        }
      } catch (e) {
        errors.push(String(e));
      }
    });
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
