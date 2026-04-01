import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Account Enumeration via Login';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const loginUrl = `${target}/wp-login.php`;

    // Test with a known-invalid username
    const invalidUserRes = await fetchURL(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'log=definitelynotavaliduser_xyzzy&pwd=wrongpassword&wp-submit=Log+In',
    });

    // Test with a common username
    const adminRes = await fetchURL(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'log=admin&pwd=wrongpassword&wp-submit=Log+In',
    });

    if (!invalidUserRes || !adminRes) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const invalidBody = await invalidUserRes.text();
    const adminBody = await adminRes.text();

    // Check for different error messages (username enumeration)
    const invalidError = extractErrorMessage(invalidBody);
    const adminError = extractErrorMessage(adminBody);

    if (invalidError && adminError && invalidError !== adminError) {
      // Different messages = enumeration possible
      const isUsernameEnum = (
        (invalidError.includes('not registered') || invalidError.includes('Unknown username') || invalidError.includes('invalid username')) &&
        (adminError.includes('incorrect') || adminError.includes('password') || adminError.includes('is not correct'))
      );

      if (isUsernameEnum) {
        findings.push(finding('LOGIN_USERNAME_ENUMERATION', 'MEDIUM', loginUrl,
          'Login error messages differ for valid vs invalid usernames — enables account enumeration', {
            evidence: `Invalid user error: "${invalidError.substring(0, 100)}" vs valid user error: "${adminError.substring(0, 100)}"`,
            replication_steps: [
              `POST to ${loginUrl} with log=nonexistentuser&pwd=test`,
              `POST to ${loginUrl} with log=admin&pwd=test`,
              'Compare error messages — different responses reveal which usernames exist',
            ],
            remediation: 'Use a security plugin to standardize login error messages (e.g., "Invalid username or password") for both cases.',
          }));
      }
    }

    // Check for email-based enumeration via lost password
    const lostPassUrl = `${target}/wp-login.php?action=lostpassword`;
    const invalidEmailRes = await fetchURL(lostPassUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'user_login=definitelynotexist%40example.com&redirect_to=&wp-submit=Get+New+Password',
    });

    if (invalidEmailRes) {
      const lostBody = await invalidEmailRes.text();
      if (lostBody.includes('no account') || lostBody.includes('not registered') ||
          lostBody.includes('no user') || lostBody.includes('invalid username or email')) {
        findings.push(finding('LOSTPASS_EMAIL_ENUMERATION', 'LOW', lostPassUrl,
          'Password reset reveals whether email addresses are registered', {
            evidence: 'Lost password form returns different responses for registered vs unregistered emails',
            replication_steps: [
              `POST to ${lostPassUrl} with user_login=nonexistent@example.com`,
              'Error message indicates the email is not registered',
              'This reveals which email addresses have accounts',
            ],
            remediation: 'Use a generic success message like "If that email exists, a reset link has been sent" regardless of whether the account exists.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}

function extractErrorMessage(html: string): string {
  const match = html.match(/<div[^>]*id="login_error"[^>]*>([\s\S]*?)<\/div>/i);
  if (match) {
    return match[1].replace(/<[^>]+>/g, '').trim();
  }
  return '';
}
