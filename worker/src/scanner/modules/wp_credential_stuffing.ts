import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Credential Stuffing Amplifiers';

// Known valid usernames often found in WP (test via login oracle)
const TEST_USERNAMES = ['admin', 'administrator', 'user', 'editor', 'manager'];
const FAKE_PASSWORD = 'Wr0ng-P@$$w0rd-X99!';

// Different status/body patterns between valid vs invalid username on login failure
const VALID_USER_INDICATORS = [
  'incorrect password',
  'the password you entered',
  'wrong password',
  'lost your password',
  '<strong>error</strong>: the password you entered',
];
const INVALID_USER_INDICATORS = [
  'invalid username',
  'invalid email',
  'no account found',
  'username is not registered',
  'that email address is not registered',
  'there is no account with that username',
];




export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Test login oracle: do valid vs invalid usernames return different responses?
    const responses: Map<string, { body: string; status: number; elapsed: number }> = new Map();

    for (const username of ['admin', 'nonexistentuser99x']) {
      const t0 = Date.now();
      const res = await fetchURL(target + '/wp-login.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `log=${encodeURIComponent(username)}&pwd=${encodeURIComponent(FAKE_PASSWORD)}&wp-submit=Log+In&testcookie=1`,
        timeoutMs: 5_000,
        redirect: 'follow',
      });
      const elapsed = Date.now() - t0;
      if (res) {
        const body = await res.text().catch(() => '');
        responses.set(username, { body: body.toLowerCase(), status: res.status, elapsed });
      }
    }

    const adminResp = responses.get('admin');
    const fakeResp = responses.get('nonexistentuser99x');

    if (adminResp && fakeResp) {
      const adminHasValidInd = VALID_USER_INDICATORS.some(ind => adminResp.body.includes(ind));
      const fakeHasInvalidInd = INVALID_USER_INDICATORS.some(ind => fakeResp.body.includes(ind));
      const bodiesDiffer = adminResp.body !== fakeResp.body;

      if ((adminHasValidInd && fakeHasInvalidInd) || bodiesDiffer) {
        const indicator = adminHasValidInd
          ? `valid_user_msg="${VALID_USER_INDICATORS.find(i => adminResp.body.includes(i))}"`
          : 'different_response_bodies';
        findings.push(finding(
          'USERNAME_ORACLE_LOGIN',
          'HIGH',
          target + '/wp-login.php',
          `Login page reveals whether a username is valid — enables credential stuffing: ${indicator}`,
          {
            evidence: `admin_indicator="${adminHasValidInd}" fake_indicator="${fakeHasInvalidInd}" bodies_differ=${bodiesDiffer}`,
            remediation: 'Return generic "incorrect username or password" for all login failures. Use the "wp_hide_login_errors" hook.',
          },
        ));
      }

      // MED-FP-2: Raised timing threshold to 600ms and require N≥3 consistent results.
      // 300ms was too low — bcrypt is intentionally slow and any loaded PHP server can
      // exceed this threshold, causing false positives on non-vulnerable sites.
      const TIMING_THRESHOLD_MS = 600;
      const TIMING_ROUNDS = 3;
      const timingDiffs: number[] = [];
      for (let round = 0; round < TIMING_ROUNDS; round++) {
        const t1 = Date.now();
        await fetchURL(target + '/wp-login.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `log=admin&pwd=${encodeURIComponent(FAKE_PASSWORD)}&wp-submit=Log+In&testcookie=1`,
          timeoutMs: 5_000,
          redirect: 'follow',
        });
        const adminMs = Date.now() - t1;
        const t2 = Date.now();
        await fetchURL(target + '/wp-login.php', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `log=nonexistentuser99x&pwd=${encodeURIComponent(FAKE_PASSWORD)}&wp-submit=Log+In&testcookie=1`,
          timeoutMs: 5_000,
          redirect: 'follow',
        });
        const fakeMs = Date.now() - t2;
        timingDiffs.push(Math.abs(adminMs - fakeMs));
      }
      const timingHits = timingDiffs.filter(d => d > TIMING_THRESHOLD_MS).length;
      if (timingHits >= TIMING_ROUNDS) {
        findings.push(finding(
          'USERNAME_ORACLE_TIMING',
          'MEDIUM',
          target + '/wp-login.php',
          `Login response timing consistently differs by >${TIMING_THRESHOLD_MS}ms between valid/invalid username across ${timingHits}/${TIMING_ROUNDS} rounds — timing oracle for credential stuffing`,
          {
            evidence: `timing_diffs_ms=[${timingDiffs.join(',')}] threshold_ms=${TIMING_THRESHOLD_MS}`,
            remediation: 'Use constant-time comparison for authentication. Add artificial delay to equalize response times.',
          },
        ));
      }
    }

    // Note: /?wc-ajax=get_refreshed_fragments is a cart-refresh endpoint, not a login
    // endpoint. It always returns cart fragments JSON on WooCommerce sites, so checking
    // for "fragments" or "cart" in its response would fire on every WooCommerce install.
    // This endpoint does not expose credential stuffing primitives — removed.

    // Test application password creation rate limiting
    const appPassCreates: Array<{ status: number }> = [];
    for (let i = 0; i < 3; i++) {
      const res = await fetchURL(target + '/wp-json/wp/v2/users/1/application-passwords', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: `scanner_test_${i}` }),
        timeoutMs: 4_000,
      });
      if (res) appPassCreates.push({ status: res.status });
    }

    const appPassSuccess = appPassCreates.filter(r => r.status === 201 || r.status === 200).length;
    if (appPassSuccess > 0) {
      findings.push(finding(
        'APP_PASSWORD_UNAUTH',
        'CRITICAL',
        target + '/wp-json/wp/v2/users/1/application-passwords',
        `Application passwords can be created without authentication — ${appPassSuccess}/3 requests succeeded`,
        {
          evidence: `success_count=${appPassSuccess} statuses="${appPassCreates.map(r => r.status).join(',')}"`,
          remediation: 'Application passwords should require authentication. Update WordPress to >= 5.9 which includes improved app password security.',
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
