import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget} from '../utils.js';

const MODULE_NAME = 'Cookie Security Flags';

interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
}

function parseCookies(res: Response): ParsedCookie[] {
  const cookies: ParsedCookie[] = [];
  const setCookieHeaders: string[] = [];

  // Cloudflare Workers supports getAll() on Headers
  if (typeof (res.headers as unknown as { getAll?: (k: string) => string[] }).getAll === 'function') {
    const all = (res.headers as unknown as { getAll: (k: string) => string[] }).getAll('set-cookie');
    setCookieHeaders.push(...all);
  } else {
    const single = res.headers.get('set-cookie');
    if (single) setCookieHeaders.push(single);
  }

  for (const header of setCookieHeaders) {
    const parts = header.split(';').map(p => p.trim());
    const name = parts[0].split('=')[0].trim();
    let sameSite = '';
    for (const part of parts.slice(1)) {
      if (part.toLowerCase().startsWith('samesite=')) {
        sameSite = part.split('=', 2)[1]?.trim() ?? '';
        break;
      }
    }
    cookies.push({
      name,
      secure: /;\s*secure\b/i.test(header),
      httpOnly: /;\s*httponly\b/i.test(header),
      sameSite,
    });
  }
  return cookies;
}

function isWPCookie(name: string): boolean {
  return (
    name.startsWith('wordpress_') ||
    name.startsWith('wp_') ||
    name === 'PHPSESSID' ||
    name.toLowerCase().includes('session')
  );
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const res = await fetchURL(target + '/');
    if (!res) {
      findings.push(finding(
        'TARGET_UNREACHABLE', 'INFO', target + '/',
        'Target unreachable — site may be down, blocked, or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    const allCookies = parseCookies(res);

    const res2 = await fetchURL(target + '/wp-login.php');
    if (res2) {
      const loginCookies = parseCookies(res2);
      const existing = new Set(allCookies.map(c => c.name));
      for (const c of loginCookies) {
        if (!existing.has(c.name)) allCookies.push(c);
      }
    }

    if (allCookies.length === 0) {
      findings.push(finding(
        'NO_COOKIES_SET', 'INFO', target + '/',
        'No cookies set on homepage or login page (may be normal for cached sites)',
        { replication_steps: [`curl -sI "${target}/" | grep -i 'set-cookie'`] },
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    const wpCookies = allCookies.filter(c => isWPCookie(c.name));
    const loginUrl = target + '/wp-login.php';

    for (const cookie of wpCookies) {
      const { name } = cookie;

      if (target.startsWith('https://') && !cookie.secure) {
        findings.push(finding(
          'COOKIE_MISSING_SECURE_FLAG', 'MEDIUM', loginUrl,
          `Cookie '${name}' missing Secure flag — can be transmitted over HTTP`,
          {
            replication_steps: [
              `curl -sI "${loginUrl}" | grep -i 'set-cookie'`,
              `Observe: '${name}' cookie does not include 'Secure' attribute.`,
              'This allows the cookie to be sent over unencrypted HTTP connections.',
            ],
            remediation: 'Set COOKIE_SECURE in wp-config.php or configure via web server.',
            evidence: JSON.stringify({ cookie_name: name }),
          },
        ));
      }

      if (!cookie.httpOnly) {
        findings.push(finding(
          'COOKIE_MISSING_HTTPONLY_FLAG', 'MEDIUM', loginUrl,
          `Cookie '${name}' missing HttpOnly flag — accessible to JavaScript (XSS risk)`,
          {
            replication_steps: [
              `curl -sI "${loginUrl}" | grep -i 'set-cookie'`,
              `Observe: '${name}' cookie does not include 'HttpOnly' attribute.`,
              'If XSS is exploited, this cookie can be exfiltrated via document.cookie.',
            ],
            remediation: "Set COOKIE_HTTPONLY in wp-config.php: define('COOKIE_HTTPONLY', true);",
            evidence: JSON.stringify({ cookie_name: name }),
          },
        ));
      }

      const sameSite = cookie.sameSite.toLowerCase();
      if (!sameSite || sameSite === 'none') {
        findings.push(finding(
          'COOKIE_WEAK_SAMESITE', 'LOW', loginUrl,
          `Cookie '${name}' has no SameSite attribute (or SameSite=None) — CSRF risk`,
          {
            replication_steps: [
              `curl -sI "${loginUrl}" | grep -i 'set-cookie'`,
              `Observe: '${name}' cookie does not include 'SameSite=Strict' or 'SameSite=Lax'.`,
              'Cross-site requests will include this cookie, enabling CSRF attacks.',
            ],
            remediation: 'Configure SameSite=Strict or SameSite=Lax for WordPress auth cookies.',
            evidence: JSON.stringify({ cookie_name: name }),
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
