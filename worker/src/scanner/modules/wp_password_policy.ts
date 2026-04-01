import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Password Policy Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check if registration is open first
    const regUrl = `${target}/wp-login.php?action=register`;
    const regRes = await fetchURL(regUrl);
    if (!regRes) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const regBody = await regRes.text();

    if (regRes.status === 200 && regBody.includes('user_login') && regBody.includes('user_email')) {
      // Registration is open — WordPress sends password by email by default (no policy enforcement)
      // Check if there's a custom password field (some plugins add this)
      const hasPasswordField = regBody.includes('user_pass') || regBody.includes('password');

      if (hasPasswordField) {
        findings.push(finding('WEAK_PASSWORD_POLICY', 'MEDIUM', regUrl,
          'Registration form allows setting passwords — verify password strength enforcement is in place', {
            evidence: 'Registration form contains password input field',
            replication_steps: [
              `Visit ${regUrl}`,
              'Observe that users can set their own password during registration',
              'Test if weak passwords like "123456" are accepted',
            ],
            remediation: 'Implement a password strength policy using a security plugin (e.g., iThemes Security, Wordfence) that enforces minimum length, complexity, and blocks common passwords.',
          }));
      } else {
        // Default WP registration — sends password reset link via email
        findings.push(finding('DEFAULT_REGISTRATION_FLOW', 'INFO', regUrl,
          'WordPress uses default registration flow (password sent via email)', {
            evidence: 'Registration form uses email-based password setup (no password field in form)',
            replication_steps: [
              `Visit ${regUrl}`,
              'Submit a registration — WordPress sends password setup link via email',
            ],
            remediation: 'Consider adding a strong password policy plugin to enforce complexity requirements when users set their password.',
          }));
      }
    }

    // Check password reset endpoint for information disclosure
    const resetUrl = `${target}/wp-login.php?action=lostpassword`;
    const resetRes = await fetchURL(resetUrl);
    if (resetRes && resetRes.status === 200) {
      const resetBody = await resetRes.text();
      if (resetBody.includes('user_login') && !resetBody.includes('captcha') && !resetBody.includes('recaptcha')) {
        findings.push(finding('PASSWORD_RESET_NO_CAPTCHA', 'LOW', resetUrl,
          'Password reset form lacks CAPTCHA protection — susceptible to automated abuse', {
            evidence: 'Lost password form has no CAPTCHA or rate limiting indicators',
            replication_steps: [
              `Visit ${resetUrl}`,
              'Observe no CAPTCHA challenge on the form',
              'Automated tools could abuse this to flood reset emails',
            ],
            remediation: 'Add CAPTCHA to the password reset form using a security plugin.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
