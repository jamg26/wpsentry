import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, getCachedResponse, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Clickjacking';

function pocIframe(url: string): string {
  return (
    `<!-- Clickjacking PoC for ${url} -->\n` +
    `<html><body>\n` +
    `  <style>iframe{opacity:0.5;position:absolute;top:0;left:0;width:100%;height:100%;}</style>\n` +
    `  <h1>Click the button below!</h1>\n` +
    `  <button style='position:absolute;top:50px;left:50px;'>Click me</button>\n` +
    `  <iframe src='${url}'></iframe>\n` +
    `</body></html>`
  );
}

async function checkFraming(url: string, label: string, critical: boolean, prefetchedRes?: Response | null): Promise<Finding | null> {
  const res = prefetchedRes ?? await fetchURL(url);
  if (!res || res.status >= 400) return null;

  const xfo = (res.headers.get('X-Frame-Options') ?? '').trim().toUpperCase();
  const csp = res.headers.get('Content-Security-Policy') ?? '';
  const faMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
  const faValue = faMatch ? faMatch[1].trim() : '';

  const xfoOk = xfo === 'DENY' || xfo === 'SAMEORIGIN';
  const faRestrictive = faValue.length > 0 && !/^\s*\*\s*$/.test(faValue);

  // Dangerously permissive explicit values
  if (xfo === 'ALLOWALL' || /^\s*\*\s*$/.test(faValue)) {
    const sev = critical ? 'CRITICAL' as const : 'MEDIUM' as const;
    return finding(
      'missing_frame_options', sev, url,
      `${label} has a dangerously permissive framing policy (X-Frame-Options: ${xfo || 'absent'}, frame-ancestors: ${faValue || 'absent'})`,
      {
        replication_steps: [
          `curl -I ${url} | grep -i 'x-frame\\|frame-ancestors'`,
          pocIframe(url),
        ],
        remediation: "Replace ALLOWALL/wildcard with: X-Frame-Options: SAMEORIGIN and/or Content-Security-Policy: frame-ancestors 'self';",
      },
    );
  }

  if (xfoOk || faRestrictive) return null; // adequately protected

  const sev = critical ? 'CRITICAL' as const : 'MEDIUM' as const;
  const ftype = (url.includes('login') || url.includes('admin'))
    ? 'clickjacking_login'
    : 'clickjacking_homepage';
  const issues: string[] = [];
  if (xfo) {
    issues.push(`X-Frame-Options: ${xfo} (not DENY/SAMEORIGIN)`);
  } else {
    issues.push('X-Frame-Options: missing');
  }
  if (!faValue) issues.push('CSP frame-ancestors: missing');

  return finding(
    ftype, sev, url,
    `${label} is frameable — clickjacking risk. Issues: ${issues.join('; ')}`,
    {
      replication_steps: [
        `curl -I ${url} | grep -i 'x-frame\\|frame-ancestors'`,
        pocIframe(url),
      ],
      remediation: "Add both: X-Frame-Options: SAMEORIGIN and Content-Security-Policy: frame-ancestors 'self'; to every sensitive response.",
    },
  );
}

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // Test 1: Homepage (LOW — no sensitive actions on homepage)
    const cachedHome = await getCachedResponse(`${target}/`, state);
    const homepageF = await checkFraming(`${target}/`, 'Homepage', false, cachedHome);
    if (homepageF) findings.push({ ...homepageF, severity: 'LOW' });

    // Test 2: wp-login.php (MEDIUM — requires user interaction / social engineering)
    const loginF = await checkFraming(`${target}/wp-login.php`, 'WordPress Login Page', false);
    if (loginF) findings.push({ ...loginF, type: 'clickjacking_login' });

    // Test 3: wp-admin/ (MEDIUM — requires user interaction / social engineering)
    const adminF = await checkFraming(`${target}/wp-admin/`, 'WordPress Admin Panel', false);
    if (adminF) findings.push({ ...adminF, type: 'clickjacking_admin' });

    // Test 4: Inconsistent XFO vs permissive CSP frame-ancestors
    await parallelProbe([['/wp-login.php', 'Login'], ['/wp-admin/', 'Admin'], ['/', 'Homepage']] as [string, string][], async ([path, label]) => {
      const res = await fetchURL(`${target}${path}`);
      if (!res || res.status >= 400) return;
      const xfo = (res.headers.get('X-Frame-Options') ?? '').trim().toUpperCase();
      const csp = res.headers.get('Content-Security-Policy') ?? '';
      const faMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
      const faValue = faMatch ? faMatch[1].trim() : '';
      if ((xfo === 'DENY' || xfo === 'SAMEORIGIN') && faValue && /^\s*\*\s*$/.test(faValue)) {
        findings.push(finding(
          'missing_frame_options', 'MEDIUM', `${target}${path}`,
          `${label}: X-Frame-Options=${xfo} conflicts with permissive frame-ancestors=${faValue}`,
          {
            replication_steps: [
              `curl -I ${target}${path} | grep -i 'x-frame\\|frame-ancestors\\|content-security'`,
            ],
            remediation: "Align both headers: set X-Frame-Options: SAMEORIGIN and Content-Security-Policy: frame-ancestors 'self';",
          },
        ));
      }
    });

    // Test 5: WooCommerce checkout / cart
    for (const [path, label] of [['/checkout/', 'WooCommerce Checkout'], ['/cart/', 'WooCommerce Cart']] as [string, string][]) {
      const res = await fetchURL(`${target}${path}`);
      if (res && res.status === 200) {
        const body = await res.text();
        if (body.toLowerCase().includes('woocommerce')) {
          const wooF = await checkFraming(`${target}${path}`, label, false);
          if (wooF) findings.push({ ...wooF, type: 'clickjacking_checkout' });
        }
      }
    }

  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
