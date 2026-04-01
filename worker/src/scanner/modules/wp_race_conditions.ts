import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Race Condition Testing';

function formBody(data: Record<string, string>): string {
  return new URLSearchParams(data).toString();
}

function isSuccessResponse(status: number | null, text: string): boolean {
  if (status === null || status !== 200) return false;
  const t = text.toLowerCase();
  return !t.includes('error') && !t.includes('invalid') && !t.includes('expired');
}

async function testCouponRace(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const couponUrl = `${base}/?wc-ajax=apply_coupon`;

  for (const couponCode of ['FREESHIP', 'SAVE10']) {
    try {
      const requests = Array.from({ length: 5 }, () =>
        fetchURL(couponUrl, {
          method: 'POST',
          body: formBody({ coupon_code: couponCode }),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }).then(async res => {
          if (!res) return { status: null, text: '' };
          let text = '';
          try { text = await res.text(); } catch { /* ignore */ }
          return { status: res.status, text };
        }).catch(() => ({ status: null as null, text: '' })),
      );

      const results = await Promise.all(requests);
      const successCount = results.filter(r => isSuccessResponse(r.status, r.text)).length;

      if (successCount > 1) {
        findings.push(finding(
          'WOOCOMMERCE_COUPON_RACE', 'HIGH', couponUrl,
          `WooCommerce coupon may allow parallel double-redemption — ${successCount}/5 concurrent requests succeeded`,
          {
            replication_steps: [
              '# Fire 5 parallel POST requests simultaneously:',
              `for i in $(seq 1 5); do curl -s -X POST "${couponUrl}" -d 'coupon_code=${couponCode}' & done; wait`,
              'Observe that multiple requests return non-error responses.',
              'Indicates coupon validation lacks atomic database transactions.',
            ],
            remediation: 'Use SELECT ... FOR UPDATE to lock the coupon row before validation. Implement atomic transactions for all coupon redemption logic.',
            evidence: JSON.stringify({ success_count: successCount, total: 5, coupon_code: couponCode }),
          },
        ));
        break; // one finding is enough
      }
    } catch { /* ignore */ }
  }
}

async function testRegistrationRace(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const regUrl = `${base}/wp-login.php?action=register`;

  try {
    const requests = Array.from({ length: 5 }, (_, i) =>
      fetchURL(regUrl, {
        method: 'POST',
        body: formBody({
          user_login: `jwp_race_test_${i}`,
          user_email: `jwp_race_${i}@example.com`,
          'wp-submit': 'Register',
        }),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        redirect: 'manual',
      }).then(res => res?.status ?? null)
        .catch(() => null as null),
    );

    const statuses = await Promise.all(requests);
    const validStatuses = statuses.filter(s => s !== null) as number[];
    const success302  = validStatuses.filter(s => s === 302).length;
    const errorCount  = validStatuses.filter(s => s !== 302).length;

    if (success302 > 0 && errorCount > 0) {
      findings.push(finding(
        'REGISTRATION_RACE_CONDITION', 'MEDIUM', regUrl,
        `User registration race condition detected — responses vary under concurrent load (${success302} success, ${errorCount} errors)`,
        {
          replication_steps: [
            '# Fire 5 simultaneous registration requests:',
            `for i in $(seq 1 5); do curl -s -X POST "${regUrl}" -d 'user_login=jwp_race_$i&user_email=jwp_race_$i@example.com&wp-submit=Register' -o /dev/null -w '%{http_code}\\n' & done; wait`,
            'Observe mixed 302 and non-302 status codes indicating a race window.',
          ],
          remediation: 'Use database-level unique constraints and atomic user creation. Add a mutex or idempotency key to the registration flow.',
          evidence: JSON.stringify({ status_codes: validStatuses }),
        },
      ));
    }
  } catch { /* ignore */ }
}

async function testRestApiRateLimit(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const usersUrl = `${base}/wp-json/wp/v2/users`;

  try {
    const requests = Array.from({ length: 5 }, () =>
      fetchURL(usersUrl)
        .then(res => res?.status ?? null)
        .catch(() => null as null),
    );

    const statuses = await Promise.all(requests);
    const success200 = statuses.filter(s => s === 200).length;

    if (success200 === 5) {
      findings.push(finding(
        'REST_API_NO_RATE_LIMIT', 'INFO', usersUrl,
        'REST API users endpoint accessible — no rate limiting observed under concurrent load',
        {
          replication_steps: [
            `for i in $(seq 1 5); do curl -s -o /dev/null -w '%{http_code}\\n' "${usersUrl}" & done; wait`,
            'All 5 concurrent requests returned HTTP 200 — no throttling detected.',
          ],
          remediation: 'Implement rate limiting via a plugin (e.g. WP REST API Rate Limit) or at the server/WAF layer.',
          evidence: JSON.stringify({ success_count: success200, total: 5 }),
        },
      ));
    }
  } catch { /* ignore */ }
}

async function testPasswordResetRace(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const resetUrl = `${base}/wp-login.php?action=lostpassword`;

  try {
    const requests = Array.from({ length: 3 }, () =>
      fetchURL(resetUrl, {
        method: 'POST',
        body: formBody({ user_login: 'admin', 'wp-submit': 'Get New Password' }),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        redirect: 'manual',
      }).then(async res => {
        if (!res) return { status: null as null, text: '' };
        let text = '';
        try { text = await res.text(); } catch { /* ignore */ }
        return { status: res.status, text };
      }).catch(() => ({ status: null as null, text: '' })),
    );

    const results = await Promise.all(requests);
    // Only flag if multiple requests succeed (200/302) AND show token variation
    const successResults = results.filter(r => r.status !== null && [200, 302].includes(r.status));
    if (successResults.length >= 2) {
      // Extract reset tokens from response bodies
      const tokens = successResults
        .map(r => { const m = r.text.match(/key=([a-zA-Z0-9]+)/); return m ? m[1] : null; })
        .filter(Boolean);
      const uniqueTokens = new Set(tokens);
      if (uniqueTokens.size > 1) {
        findings.push(finding(
          'PASSWORD_RESET_RACE', 'MEDIUM', resetUrl,
          `Password reset race condition: ${uniqueTokens.size} different reset tokens generated from ${successResults.length} concurrent requests`,
          {
            replication_steps: [
              '# Fire 3 simultaneous password reset requests:',
              `for i in $(seq 1 3); do curl -s -X POST "${resetUrl}" -d 'user_login=admin&wp-submit=Get+New+Password' & done; wait`,
              'Observe different reset tokens — indicates non-atomic token generation.',
            ],
            remediation: 'Use atomic operations for reset token generation. Invalidate tokens on reuse and generate with cryptographically secure randomness.',
            evidence: JSON.stringify({ unique_tokens: uniqueTokens.size, total_success: successResults.length }),
          },
        ));
      }
    }
  } catch { /* ignore */ }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await testCouponRace(target, findings);
    await testRegistrationRace(target, findings);
    await testRestApiRateLimit(target, findings);
    await testPasswordResetRace(target, findings);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
