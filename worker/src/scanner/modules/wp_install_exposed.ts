import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Installation Page Exposure';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const installUrl = `${target}/wp-admin/install.php`;
    const res = await fetchURL(installUrl);
    if (!res) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();
    const status = res.status;

    if (status === 200) {
      // Check if it's an actual install page (not redirected to login or already installed)
      if (body.includes('wp-install') || body.includes('setup-config')) {
        // Fresh install — not yet configured
        if (body.includes('language') && body.includes('setup-config')) {
          findings.push(finding('INSTALL_SETUP_EXPOSED', 'CRITICAL', installUrl,
            'WordPress installation setup page is accessible — site can be taken over by completing installation', {
              evidence: 'install.php shows setup-config form (WordPress not yet fully installed)',
              replication_steps: [
                `Navigate to ${installUrl}`,
                'Observe the WordPress setup/configuration wizard',
                'An attacker could complete installation and gain admin access',
              ],
              remediation: 'Complete the WordPress installation immediately or restrict access to install.php via server configuration.',
            }));
        } else if (!body.includes('already installed') && !body.includes('Log In')) {
          // Installation page accessible but not the "already installed" message
          findings.push(finding('INSTALL_PAGE_ACCESSIBLE', 'HIGH', installUrl,
            'WordPress install.php is accessible and may allow re-installation', {
              evidence: 'install.php returns 200 without "already installed" message',
              replication_steps: [
                `Navigate to ${installUrl}`,
                'Check if the installation can be re-triggered',
              ],
              remediation: 'Block access to install.php via .htaccess or nginx configuration.',
            }));
        } else {
          // Already installed but page is still accessible
          findings.push(finding('INSTALL_PAGE_INFO_LEAK', 'LOW', installUrl,
            'WordPress install.php is accessible (shows "already installed" — low risk but information disclosure)', {
              evidence: 'install.php returns 200 with "already installed" message',
              replication_steps: [
                `Navigate to ${installUrl}`,
                'Page confirms WordPress is installed',
              ],
              remediation: 'Block access to install.php via server configuration to prevent information leakage.',
            }));
        }
      }
    }

    // Also check setup-config.php
    const setupUrl = `${target}/wp-admin/setup-config.php`;
    const setupRes = await fetchURL(setupUrl);
    if (setupRes && setupRes.status === 200) {
      const setupBody = await setupRes.text();
      if (setupBody.includes('database') && setupBody.includes('wp-config.php')) {
        findings.push(finding('SETUP_CONFIG_EXPOSED', 'CRITICAL', setupUrl,
          'WordPress setup-config.php is accessible — database credentials can be configured by an attacker', {
            evidence: 'setup-config.php returns database configuration form',
            replication_steps: [
              `Navigate to ${setupUrl}`,
              'Observe the database configuration form',
              'An attacker could point WordPress to a malicious database',
            ],
            remediation: 'Delete or restrict access to setup-config.php after installation is complete.',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
