import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'oEmbed Security Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check oEmbed discovery endpoint
    const oembedUrl = `${target}/wp-json/oembed/1.0/embed?url=${encodeURIComponent(target + '/')}`;
    const res = await fetchURL(oembedUrl);
    if (res && res.status === 200) {
      const body = await res.text();
      try {
        const data = JSON.parse(body);
        if (data && typeof data === 'object') {
          findings.push(finding('OEMBED_ENDPOINT_EXPOSED', 'INFO', oembedUrl,
            'WordPress oEmbed endpoint is publicly accessible', {
              evidence: `oEmbed response type: ${data.type || 'unknown'}, provider: ${data.provider_name || 'unknown'}`,
              replication_steps: [
                `Fetch ${oembedUrl}`,
                'Observe JSON response with site metadata',
              ],
              remediation: 'Disable oEmbed if not needed by removing wp_oembed_add_discovery_links action.',
            }));

          // Check for internal URL leak in response
          const responseStr = JSON.stringify(data);
          if (/(?:localhost|127\.0\.0\.1|10\.\d+|192\.168\.|172\.(?:1[6-9]|2\d|3[01]))/.test(responseStr)) {
            findings.push(finding('OEMBED_INTERNAL_URL', 'MEDIUM', oembedUrl,
              'oEmbed response contains internal/private IP address', {
                evidence: 'Internal URL found in oEmbed response',
                replication_steps: [
                  `Fetch ${oembedUrl}`,
                  'Check response for internal IP addresses',
                ],
                remediation: 'Ensure the site URL in WordPress settings points to the public domain, not an internal address.',
              }));
          }
        }
      } catch { /* not valid JSON */ }
    }

    // Check if oEmbed proxy is exposed (potential SSRF vector)
    const proxyUrl = `${target}/wp-json/oembed/1.0/proxy?url=${encodeURIComponent('https://example.com')}`;
    const proxyRes = await fetchURL(proxyUrl);
    if (proxyRes && proxyRes.status === 200) {
      const proxyBody = await proxyRes.text();
      if (proxyBody.length > 50 && !proxyBody.includes('rest_forbidden')) {
        findings.push(finding('OEMBED_PROXY_EXPOSED', 'MEDIUM', proxyUrl,
          'WordPress oEmbed proxy endpoint is accessible without authentication — potential SSRF vector', {
            evidence: `oEmbed proxy returned ${proxyBody.length} bytes for external URL`,
            replication_steps: [
              `Fetch ${proxyUrl}`,
              'Observe that the proxy fetches external URLs',
              'This could be used to probe internal network resources',
            ],
            remediation: 'Restrict the oEmbed proxy endpoint to authenticated users or disable it entirely.',
          }));
      }
    }

    // Check for oEmbed link tag in HTML head (information disclosure)
    const homeRes = await fetchURL(`${target}/`);
    if (homeRes && homeRes.status === 200) {
      const html = await homeRes.text();
      const oembedLink = html.match(/<link[^>]+type="application\/json\+oembed"[^>]+href="([^"]+)"/i);
      if (oembedLink) {
        findings.push(finding('OEMBED_DISCOVERY_TAG', 'INFO', `${target}/`,
          'oEmbed discovery link tag present in HTML head', {
            evidence: `oEmbed URL: ${oembedLink[1]}`,
            replication_steps: [
              `Visit ${target}/`,
              'View source and look for <link rel="alternate" type="application/json+oembed">',
            ],
            remediation: 'Remove oEmbed discovery links with remove_action(\'wp_head\', \'wp_oembed_add_discovery_links\').',
          }));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
