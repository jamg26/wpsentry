import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Subdomain Takeover';

const COMMON_SUBDOMAINS = [
  'www', 'blog', 'shop', 'store', 'wp', 'staging', 'dev', 'test',
  'api', 'media', 'cdn', 'assets', 'mail', 'admin', 'portal',
];

const VULNERABLE_CNAME_TARGETS: Record<string, string> = {
  'wordpress.com': 'WordPress.com',
  'wpengine.com': 'WP Engine',
  'kinsta.com': 'Kinsta',
  'flywheel.com': 'Flywheel',
  'pantheon.io': 'Pantheon',
  'fly.io': 'Fly.io',
  'heroku.com': 'Heroku',
  'herokussl.com': 'Heroku',
  'amazonaws.com': 'AWS',
  'azurewebsites.net': 'Azure',
  'cloudapp.net': 'Azure',
  'github.io': 'GitHub Pages',
  'fastly.net': 'Fastly',
};

const UNCLAIMED_MESSAGES = [
  'there is no site at this address',
  'no site here',
  'fly.io \u2014 there is no app',
  'herokucdn.com/error-pages/no-such-app',
  'the requested url was not found',
  '404 not found',
  "this github pages site doesn't exist",
  "this site can't be reached",
  'project not found',
];

function extractBaseDomain(target: string): string {
  try {
    const url = new URL(target.includes('://') ? target : `https://${target}`);
    return url.hostname;
  } catch {
    return target.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  }
}

function isIP(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const baseDomain = extractBaseDomain(target);

    // Skip subdomain checks for bare IP targets
    if (isIP(baseDomain)) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    await parallelProbe(COMMON_SUBDOMAINS, async (sub) => {
      const hostname = `${sub}.${baseDomain}`;

      // Try HTTPS first, fall back to HTTP — mirrors Python scheme loop
      let res: Response | null = null;
      let subUrl = '';
      for (const scheme of ['https', 'http']) {
        subUrl = `${scheme}://${hostname}`;
        res = await fetchURL(subUrl, { timeoutMs: 6000 });
        if (res) break;
      }
      if (!res) return; // subdomain not reachable — skip

      const status = res.status;
      const body = await res.text();
      const bodyLower = body.toLowerCase();
      const finalUrl = res.url;

      // Check CNAME to vulnerable platforms (detected via final redirect URL)
      for (const [cnameSuffix, platform] of Object.entries(VULNERABLE_CNAME_TARGETS)) {
        if (finalUrl.includes(cnameSuffix)) {
          const hasUnclaimedMsg = UNCLAIMED_MESSAGES.some(msg => bodyLower.includes(msg));
          const severity = hasUnclaimedMsg ? 'CRITICAL' as const : 'MEDIUM' as const;
          const desc = hasUnclaimedMsg
            ? `Subdomain ${hostname} resolves to ${platform} (${cnameSuffix}) and shows an unclaimed page. Subdomain takeover is likely possible.`
            : `Subdomain ${hostname} resolves to ${platform} (${cnameSuffix}). CNAME detected but no unclaimed message found — verify manually whether the resource is claimed.`;
          findings.push(finding(
            'subdomain_takeover', severity, subUrl,
            desc,
            {
              replication_steps: [
                `dig CNAME ${hostname}`,
                `curl -s "${subUrl}" | grep -i "no site\\|not found\\|unclaimed"`,
                `# Claim the ${platform} site at ${cnameSuffix} to take over ${hostname}`,
              ],
              remediation: `Remove CNAME for ${hostname} or claim the ${platform} resource it points to.`,
              evidence: `${hostname} redirected to URL containing ${cnameSuffix}`,
            },
          ));
        }
      }

      // Check for unclaimed/error messages
      for (const msgPattern of UNCLAIMED_MESSAGES) {
        if (bodyLower.includes(msgPattern)) {
          findings.push(finding(
            'unclaimed_subdomain', 'HIGH', subUrl,
            `Subdomain ${hostname} shows an unclaimed/error page (matched: '${msgPattern}'). Subdomain takeover likely possible.`,
            {
              replication_steps: [
                `curl -s "${subUrl}" | grep -i "no site\\|not found\\|unclaimed"`,
                `dig ${hostname}`,
                '# Register/claim the upstream service to prevent takeover',
              ],
              remediation: `Remove DNS record for ${hostname} or claim the upstream resource.`,
              evidence: `Page contains: '${msgPattern}'`,
            },
          ));
          break;
        }
      }

      // Staging/dev/test subdomain publicly accessible
      if (['staging', 'dev', 'test'].includes(sub) && status === 200) {
        findings.push(finding(
          'staging_exposed', 'MEDIUM', subUrl,
          `Staging/development subdomain ${hostname} is publicly accessible (HTTP 200). These environments often have weaker security controls.`,
          {
            replication_steps: [
              `curl -s -o /dev/null -w "%{http_code}" "${subUrl}"`,
              `curl -s "${subUrl}/wp-config.php.bak"`,
              `curl -s "${subUrl}/?debug=true"`,
            ],
            remediation: 'Restrict staging/dev environments to VPN or IP allowlist. Use HTTP basic auth as an additional layer.',
            evidence: `HTTP ${status} from ${subUrl}`,
          },
        ));
      }
    });

    // SSL SAN inspection requires raw TLS socket — not available in Cloudflare Workers.
    // Use: echo | openssl s_client -connect <hostname>:443 2>/dev/null | openssl x509 -noout -ext subjectAltName
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
