import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, getCachedResponse, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Admin Panel Exposure';

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  const checks: [string, string][] = [
    ['/wp-login.php',            'Login page'],
    ['/wp-admin/',               'Admin panel'],
    ['/admin/',                  'Admin alias /admin/'],
    ['/login/',                  'Login alias /login/'],
    ['/dashboard/',              'Dashboard alias'],
    ['/wp-admin/admin-ajax.php', 'Admin AJAX'],
    ['/wp-register.php',         'Registration page'],
    ['/?action=register',        'Registration via query param'],
    ['/wp-signup.php',           'Multisite signup'],
  ];

  try {
    await Promise.allSettled([
      parallelProbe(checks, async ([path, label]) => {
        const url = target + path;
        const res = await fetchURL(url);
        if (!res) return;

        if (path === '/wp-login.php' && res.status === 200) {
          const text = await res.text();
          if (text.includes('log') && text.includes('pwd')) {
            findings.push(finding('WP_LOGIN_EXPOSED', 'INFO', url,
              'Default WordPress login URL accessible — should be renamed or hidden',
              { replication_steps: [`curl -s "${url}" | grep -i 'login'`, 'Observe WordPress login form in response.', 'Rename login URL using WPS Hide Login or similar plugin.', 'This endpoint is the primary brute-force target — protect it.'] },
            ));
          }
        } else if (path === '/wp-admin/' && res.status === 200) {
          findings.push(finding('WP_ADMIN_NO_AUTH_REDIRECT', 'HIGH', url,
            'wp-admin accessible without authentication redirect — possible auth bypass',
            { replication_steps: [`curl -sI "${url}"`, 'Observe: 200 OK (not 302 to wp-login.php).', 'Navigate to URL — check if admin panel is accessible without login.'] },
          ));
        } else if (path === '/wp-admin/admin-ajax.php') {
          if (res.status === 200 || res.status === 400) {
            findings.push(finding('ADMIN_AJAX_EXPOSED', 'INFO', url,
              'admin-ajax.php accessible without authentication — enumerate exposed AJAX actions',
              { replication_steps: [`curl -s "${url}" -d 'action=heartbeat'`, 'Observe: -1 or JSON response (not blocked/firewall page).', "Use wfuzz to enumerate exposed AJAX actions: wfuzz -d 'action=FUZZ'"] },
            ));
          }
        } else if (['/?action=register', '/wp-signup.php', '/wp-register.php'].includes(path)) {
          if (res.status === 200) {
            const text = await res.text();
            if (text.includes('Register') || text.includes('register')) {
              findings.push(finding('REGISTRATION_OPEN', 'MEDIUM', url,
                `User registration is open at ${label} — attackers can create accounts`,
                { replication_steps: [`curl -s "${url}" | grep -i 'register'`, 'Observe registration form.', 'Register a test account and explore subscriber/contributor capabilities.', 'Disable in Settings → General → Membership if not needed.'] },
              ));
            }
          }
        }
      }),
      (async () => {
        const homeRes = await getCachedResponse(target + '/', state);
        if (!homeRes) return;
        const homeText = await homeRes.text();
        if (homeText.toLowerCase().includes('name="generator"')) {
          const m = homeText.match(/name=["']generator["'][^>]*content=["']([^"']+)["']/i);
          if (m) {
            findings.push(finding('GENERATOR_TAG_EXPOSED', 'INFO', target + '/',
              `WordPress generator tag exposed: '${m[1]}'`,
              { replication_steps: [`curl -s "${target}/" | grep -i 'generator'`, 'Observe meta generator tag disclosing CMS name and version.', "Remove via: add_filter('the_generator', '__return_empty_string');"], evidence: m[1] },
            ));
          }
        }
      })(),
    ]);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
