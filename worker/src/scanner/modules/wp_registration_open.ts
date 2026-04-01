import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Open Registration Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const regUrl = `${target}/wp-login.php?action=register`;
    const res = await fetchURL(regUrl);
    if (!res) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();
    const status = res.status;

    // A 200 status with a registration form means open registration
    if (status === 200 && body.includes('user_login') && body.includes('user_email')) {
      findings.push(finding('REGISTRATION_OPEN', 'MEDIUM', regUrl,
        'WordPress user registration is open to the public', {
          evidence: 'Registration form with user_login and user_email fields found at wp-login.php?action=register',
          replication_steps: [
            `Navigate to ${regUrl}`,
            'Observe the registration form is accessible',
            'A new user account can be created by anyone',
          ],
          remediation: 'Disable open registration in Settings > General > "Anyone can register" unless intentionally enabled. If needed, use a plugin to add CAPTCHA and email verification.',
        }));

      // Check if the default subscriber role is elevated
      if (body.includes('role') && !body.includes('subscriber')) {
        findings.push(finding('ELEVATED_DEFAULT_ROLE', 'HIGH', regUrl,
          'Default registration role may be set to a role higher than Subscriber', {
            evidence: 'Registration form contains role field without subscriber as default',
            replication_steps: [
              `Navigate to ${regUrl}`,
              'Check the default role assigned to new users',
            ],
            remediation: 'Set the default user role to "Subscriber" in Settings > General > New User Default Role.',
          }));
      }
    }

    // Also check multisite registration
    const msRegUrl = `${target}/wp-signup.php`;
    const msRes = await fetchURL(msRegUrl);
    if (msRes && msRes.status === 200) {
      const msBody = await msRes.text();
      if (msBody.includes('signup_for') || msBody.includes('user_name')) {
        findings.push(finding('MULTISITE_REGISTRATION_OPEN', 'MEDIUM', msRegUrl,
          'WordPress Multisite registration is open (wp-signup.php accessible)', {
            evidence: 'Multisite signup form found at wp-signup.php',
            replication_steps: [
              `Navigate to ${msRegUrl}`,
              'Observe the multisite registration form',
            ],
            remediation: 'Disable Multisite registration or restrict it to admin-only in Network Settings.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
