import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget , parallelProbe } from '../utils.js';

const MODULE_NAME = 'Password Reset Security';

const COMMON_USERNAMES = ['admin', 'administrator', 'user', 'editor', 'webmaster', 'test'];

const VALID_USER_SIGNALS = [
  'check your email', 'email has been sent', 'link has been sent',
  'please check your email', 'reset link', "we've sent", 'success',
];

const INVALID_USER_SIGNALS = [
  'no account', 'could not find', 'no user found',
  'invalid email', 'there is no user', 'error',
];

function formBody(data: Record<string, string>): string {
  return new URLSearchParams(data).toString();
}

async function testResetFormPresent(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<string | null> {
  const resetUrl = `${base}/wp-login.php?action=lostpassword`;
  const res = await fetchURL(resetUrl);
  if (!res || res.status !== 200) return null;

  let text = '';
  try { text = await res.text(); } catch { return null; }

  if (text.includes('user_login') || text.toLowerCase().includes('lostpassword')) {
    findings.push(finding(
      'PASSWORD_RESET_FORM_ACCESSIBLE', 'INFO', resetUrl,
      'Password reset form is publicly accessible — enumeration/poisoning attack surface exists',
      { replication_steps: [`curl -s "${resetUrl}" | grep -i 'form\\|input'`] },
    ));
    return `${base}/wp-login.php`;
  }
  return null;
}

async function testEmailEnumeration(
  _base: string,
  resetUrl: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const fakeBody = formBody({
    user_login: 'nonexistent_user_jwp_xyz_12345',
    redirect_to: '',
    'wp-submit': 'Get New Password',
  });

  const resFake = await fetchURL(resetUrl, {
    method: 'POST',
    body: fakeBody,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  if (!resFake) return;

  let fakeLower = '';
  try { fakeLower = (await resFake.text()).toLowerCase(); } catch { return; }

  const fakeIsInvalid = INVALID_USER_SIGNALS.some(s => fakeLower.includes(s));
  const fakeIsValid   = VALID_USER_SIGNALS.some(s => fakeLower.includes(s));

  await parallelProbe(COMMON_USERNAMES, async (username) => {
    const realBody = formBody({
      user_login: username,
      redirect_to: '',
      'wp-submit': 'Get New Password',
    });

    const resReal = await fetchURL(resetUrl, {
      method: 'POST',
      body: realBody,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (!resReal) return;

    let realLower = '';
    try { realLower = (await resReal.text()).toLowerCase(); } catch { return; }

    const realIsValid = VALID_USER_SIGNALS.some(s => realLower.includes(s));

    if (realIsValid && (fakeIsInvalid || !fakeIsValid)) {
      const confirmedSignal = VALID_USER_SIGNALS.find(s => realLower.includes(s)) ?? '';
      findings.push(finding(
        'PASSWORD_RESET_USER_ENUM', 'MEDIUM', resetUrl,
        `Password reset reveals valid username '${username}' via different response message`,
        {
          replication_steps: [
            `curl -s -X POST "${resetUrl}" -d 'user_login=nonexistent_xyz&wp-submit=Get+New+Password'`,
            `curl -s -X POST "${resetUrl}" -d 'user_login=${username}&wp-submit=Get+New+Password'`,
            'Compare responses — different messages confirm whether username exists.',
            `Message for valid user: '...${confirmedSignal}...'`,
          ],
          remediation: 'Return identical messages for valid and invalid users on password reset.',
          evidence: JSON.stringify({ confirmed_username: username }),
        },
      ));
    }
  });
}

async function testHostHeaderInjection(
  _base: string,
  resetUrl: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const attackerDomain = 'jwp-test-host-injection.evil.example.com';
  const res = await fetchURL(resetUrl, {
    method: 'POST',
    body: formBody({
      user_login: 'admin',
      redirect_to: '',
      'wp-submit': 'Get New Password',
    }),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Host: attackerDomain,
      'X-Forwarded-Host': attackerDomain,
      'X-Host': attackerDomain,
    },
  });
  if (!res) return;

  let text = '';
  try { text = await res.text(); } catch { return; }

  if (text.toLowerCase().includes(attackerDomain.toLowerCase())) {
    findings.push(finding(
      'PASSWORD_RESET_HOST_INJECTION', 'HIGH', resetUrl,
      'Password reset reflects injected Host header — reset link can be poisoned to attacker\'s domain',
      {
        replication_steps: [
          `curl -s -X POST "${resetUrl}" -H 'Host: attacker.com' -H 'X-Forwarded-Host: attacker.com' -d 'user_login=admin&wp-submit=Get+New+Password'`,
          'Observe: attacker.com appears in the response or reset email link.',
          'User clicks the reset link → password reset token sent to attacker.',
        ],
        remediation: "Use a hard-coded site URL for reset links (define('WP_HOME') and ('WP_SITEURL')).",
        evidence: JSON.stringify({ injected_host: attackerDomain }),
      },
    ));
  }
}

async function testResetTokenInUrl(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-login.php?action=lostpassword`;
  const res = await fetchURL(url);
  if (!res) return;

  let text = '';
  try { text = await res.text(); } catch { return; }

  if (/key=[a-zA-Z0-9]{20,}/.test(text)) {
    findings.push(finding(
      'RESET_TOKEN_IN_URL', 'MEDIUM', `${base}/wp-login.php`,
      'Password reset token appears in URL (GET parameter) — may leak via Referer header to third parties',
      {
        replication_steps: [
          'Trigger a password reset and observe the emailed link format.',
          'If the link contains ?key=TOKEN, and the reset page loads third-party scripts,',
          'the token leaks via the Referer header to those third parties.',
        ],
        remediation: 'Ensure reset tokens are POST-only or use short-lived tokens with no third-party scripts on reset page.',
      },
    ));
  }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const resetUrl = await testResetFormPresent(target, findings);
    if (!resetUrl) {
      findings.push(finding(
        'PASSWORD_RESET_BLOCKED', 'INFO', `${target}/wp-login.php`,
        'Password reset form not accessible (may be disabled or login page renamed)',
        { replication_steps: [`curl -s "${target}/wp-login.php?action=lostpassword"`] },
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    await testEmailEnumeration(target, resetUrl, findings);
    await testHostHeaderInjection(target, resetUrl, findings);
    await testResetTokenInUrl(target, findings);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
