import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'SSL/TLS Audit';

function extractHostname(target: string): string {
  try {
    const url = new URL(target.includes('://') ? target : `https://${target}`);
    return url.hostname;
  } catch {
    return target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const hostname = extractHostname(target);
  const httpsUrl = `https://${hostname}/`;
  const httpUrl = `http://${hostname}/`;

  // NOTE: Raw TLS socket inspection (certificate expiry dates, TLS version negotiation,
  // cipher suite enumeration, CN/SAN extraction) requires native socket access which is
  // not available in Cloudflare Workers. Those checks are documented below as server-side
  // commands. Workers perform the HTTP-level checks that ARE feasible.

  try {
    // Test 1: HTTPS accessibility — proxy for certificate validity.
    // Cloudflare Workers lack native TLS socket access, so we infer SSL health from
    // fetch() success. Retry once to filter transient network/timeout errors before
    // flagging — a single null result is not reliable enough for a HIGH finding.
    let httpsCheck = await fetchURL(httpsUrl);
    if (!httpsCheck) {
      // One retry after a short pause to rule out transient failures
      await new Promise(r => setTimeout(r, 2000));
      httpsCheck = await fetchURL(httpsUrl);
    }
    if (!httpsCheck) {
      findings.push(finding(
        'https_unreachable', 'MEDIUM', httpsUrl,
        'HTTPS endpoint did not respond after two attempts — SSL certificate may be expired, invalid, hostname-mismatched, or the server may not support TLS. Manual verification required.',
        {
          replication_steps: [
            `curl -vI https://${hostname}/ 2>&1 | grep -i 'SSL\\|certificate\\|expire\\|verify'`,
            `openssl s_client -connect ${hostname}:443 -servername ${hostname} </dev/null 2>/dev/null | openssl x509 -noout -dates`,
          ],
          remediation: 'Verify the SSL certificate is valid and not expired. Install a certificate from a trusted CA if needed.',
          evidence: 'fetch() to HTTPS URL returned null on two consecutive attempts (connection failed, timeout, or SSL error)',
        },
      ));
    } else {
      // Test 5: Mixed content — scan the HTTPS homepage for HTTP references
      try {
        const body = await httpsCheck.text();
        const mixed = [...body.matchAll(/(?:src|href)=["']http:\/\/[^"']+["']/gi)].map(m => m[0]);
        if (mixed.length > 0) {
          findings.push(finding(
            'mixed_content', 'MEDIUM', httpsUrl,
            `Mixed content: ${mixed.length} HTTP resource(s) referenced on HTTPS page`,
            {
              replication_steps: [
                `curl -sk https://${hostname}/ | grep -oiE '(src|href)="http://[^"]+"' | head -20`,
              ],
              remediation: 'Update all resource URLs to HTTPS. Use protocol-relative URLs (//example.com/asset.js) as a fallback.',
              evidence: JSON.stringify(mixed.slice(0, 5)),
            },
          ));
        }
      } catch (e) {
        errors.push(`Mixed content check failed: ${String(e)}`);
      }

      // HSTS check skipped — covered by wp_security_headers module
    }
  } catch (e) {
    errors.push(`HTTPS check failed: ${String(e)}`);
  }

  // Test 3: HTTP → HTTPS redirect
  // Use fetch() directly with redirect:'manual' to inspect the 3xx response before following.
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    const redirectRes = await fetch(httpUrl, { redirect: 'manual', signal: controller.signal });
    clearTimeout(timer);
    const location = redirectRes.headers.get('Location') ?? '';
    const redirected = [301, 302, 307, 308].includes(redirectRes.status) && location.startsWith('https://');
    if (!redirected) {
      findings.push(finding(
        'http_no_redirect', 'MEDIUM', httpUrl,
        `HTTP does not permanently redirect to HTTPS (status ${redirectRes.status}, Location: ${location || 'none'})`,
        {
          replication_steps: [
            `curl -I http://${hostname}/ | grep -i 'location\\|strict\\|301\\|302'`,
          ],
          remediation: `Redirect all HTTP traffic to HTTPS. Apache: Redirect permanent / https://${hostname}/ | Nginx: return 301 https://$host$request_uri;`,
        },
      ));
    }
  } catch {
    // HTTP may be unreachable or redirect check unsupported; skip silently
  }

  // Tests requiring raw TLS sockets (not available in Cloudflare Workers):
  //
  // Test 2: Weak TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
  //   openssl s_client -connect hostname:443 -tls1 </dev/null 2>&1 | grep -i 'handshake\|Protocol'
  //   openssl s_client -connect hostname:443 -tls1_1 </dev/null 2>&1 | grep -i handshake
  //   nmap --script ssl-enum-ciphers -p 443 hostname
  //
  // Test 6: Certificate CN/SAN hostname match
  //   openssl s_client -connect hostname:443 -servername hostname </dev/null 2>/dev/null \
  //     | openssl x509 -noout -text | grep -A5 'Subject Alternative\|Subject:'
  //
  // Test 1 (extended): Certificate expiry date
  //   openssl s_client -connect hostname:443 -servername hostname </dev/null 2>/dev/null \
  //     | openssl x509 -noout -dates

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
