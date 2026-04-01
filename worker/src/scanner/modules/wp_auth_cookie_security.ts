import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Auth Cookie Security Audit';

interface CookieAnalysis {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  path: string | null;
  domain: string | null;
}

function parseCookies(setCookieHeader: string): CookieAnalysis[] {
  const results: CookieAnalysis[] = [];
  // set-cookie headers may be combined with comma, but cookies use ; for attributes
  const parts = setCookieHeader.split(/,(?=[^ ])/);
  for (const part of parts) {
    const segments = part.split(';').map(s => s.trim());
    const nameVal = segments[0];
    if (!nameVal) continue;
    const eqIdx = nameVal.indexOf('=');
    const name = eqIdx > 0 ? nameVal.substring(0, eqIdx).trim() : nameVal.trim();
    const lower = segments.map(s => s.toLowerCase());
    results.push({
      name,
      secure: lower.some(s => s === 'secure'),
      httpOnly: lower.some(s => s === 'httponly'),
      sameSite: lower.find(s => s.startsWith('samesite='))?.split('=')[1] ?? null,
      path: segments.find(s => s.toLowerCase().startsWith('path='))?.split('=')[1] ?? null,
      domain: segments.find(s => s.toLowerCase().startsWith('domain='))?.split('=')[1] ?? null,
    });
  }
  return results;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Fetch the login page to trigger cookie setting
    const loginUrl = `${target}/wp-login.php`;
    const res = await fetchURL(loginUrl);
    if (!res) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const setCookie = res.headers.get('set-cookie') ?? '';
    if (!setCookie) {
      // Also check homepage
      const homeRes = await fetchURL(`${target}/`);
      if (!homeRes) return moduleResult(MODULE_NAME, target, findings, errors, start);
      const homeCookie = homeRes.headers.get('set-cookie') ?? '';
      if (!homeCookie) return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    const allCookieHeaders = setCookie;
    const cookies = parseCookies(allCookieHeaders);

    const isHttps = target.startsWith('https://');
    const wpCookies = cookies.filter(c =>
      c.name.includes('wordpress') || c.name.includes('wp-') || c.name === 'PHPSESSID'
    );

    for (const cookie of wpCookies) {
      // Check Secure flag
      if (isHttps && !cookie.secure) {
        findings.push(finding('COOKIE_MISSING_SECURE', 'MEDIUM', loginUrl,
          `Cookie "${cookie.name}" lacks Secure flag on HTTPS site — may be sent over HTTP`, {
            evidence: `Cookie "${cookie.name}" does not have the Secure attribute`,
            replication_steps: [
              `Fetch ${loginUrl}`,
              `Check Set-Cookie header for "${cookie.name}"`,
              'Verify the Secure flag is missing',
            ],
            remediation: `Add the Secure flag to the "${cookie.name}" cookie. Set FORCE_SSL_ADMIN to true in wp-config.php.`,
          }));
      }

      // Check HttpOnly flag
      if (!cookie.httpOnly) {
        findings.push(finding('COOKIE_MISSING_HTTPONLY', 'MEDIUM', loginUrl,
          `Cookie "${cookie.name}" lacks HttpOnly flag — accessible via JavaScript (XSS risk)`, {
            evidence: `Cookie "${cookie.name}" does not have the HttpOnly attribute`,
            replication_steps: [
              `Fetch ${loginUrl}`,
              `Check Set-Cookie header for "${cookie.name}"`,
              'Confirm HttpOnly flag is absent',
            ],
            remediation: `Ensure the "${cookie.name}" cookie has the HttpOnly flag set to prevent client-side access.`,
          }));
      }

      // Check SameSite flag
      if (!cookie.sameSite) {
        findings.push(finding('COOKIE_MISSING_SAMESITE', 'LOW', loginUrl,
          `Cookie "${cookie.name}" lacks SameSite attribute — may be sent in cross-site requests`, {
            evidence: `Cookie "${cookie.name}" does not have SameSite attribute`,
            replication_steps: [
              `Fetch ${loginUrl}`,
              `Check Set-Cookie header for "${cookie.name}"`,
            ],
            remediation: `Set SameSite=Lax or SameSite=Strict on the "${cookie.name}" cookie.`,
          }));
      } else if (cookie.sameSite === 'none' && !cookie.secure) {
        findings.push(finding('COOKIE_SAMESITE_NONE_INSECURE', 'MEDIUM', loginUrl,
          `Cookie "${cookie.name}" has SameSite=None without Secure flag — will be rejected by modern browsers`, {
            evidence: `Cookie "${cookie.name}" has SameSite=None but lacks Secure`,
            replication_steps: [
              `Fetch ${loginUrl}`,
              'Check cookie attributes',
            ],
            remediation: `Add Secure flag when using SameSite=None, or change to SameSite=Lax.`,
          }));
      }
    }

    // If no WordPress-specific cookies found, note it
    if (cookies.length > 0 && wpCookies.length === 0) {
      // Check all cookies for issues anyway
      for (const cookie of cookies) {
        if (isHttps && !cookie.secure) {
          findings.push(finding('COOKIE_MISSING_SECURE', 'LOW', loginUrl,
            `Cookie "${cookie.name}" on login page lacks Secure flag`, {
              evidence: `Cookie "${cookie.name}" missing Secure attribute`,
              replication_steps: [`Fetch ${loginUrl}`, 'Check Set-Cookie headers'],
              remediation: 'Add Secure flag to all cookies on HTTPS sites.',
            }));
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
