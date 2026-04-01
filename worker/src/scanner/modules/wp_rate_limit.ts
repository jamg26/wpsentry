import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Rate Limiting';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const restUrl = `${target}/wp-json/wp/v2/posts`;

  try {
    // Login endpoint rate limiting is tested by wp_bruteforce module — only test REST API here

    // Test 1: 20 rapid REST API GETs — check for throttling
    const restPromises = Array.from({ length: 20 }, () => fetchURL(restUrl));
    const restResults = await Promise.all(restPromises);
    const restStatuses: number[] = [];
    for (const res of restResults) {
      if (res) restStatuses.push(res.status);
    }
    const blocked = restStatuses.filter(s => s === 429).length;
    const uniqueRest = [...new Set(restStatuses)].join(', ');
    if (blocked > 0) {
      findings.push(finding(
        'rate_limiting_present', 'INFO', restUrl,
        `Rate limiting detected on REST API: ${blocked}/20 requests returned HTTP 429.`,
        {
          replication_steps: [
            `for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}\\n" "${restUrl}"; done`,
            '# HTTP 429 responses indicate rate limiting is active',
          ],
          remediation: 'No action required — rate limiting is functioning.',
          evidence: `Statuses: ${uniqueRest}; ${blocked}/20 blocked`,
        },
      ));
    } else {
      findings.push(finding(
        'no_rate_limiting', 'MEDIUM', restUrl,
        'No rate limiting (HTTP 429) detected on REST API after 20 rapid requests.',
        {
          replication_steps: [
            `for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}\\n" "${restUrl}"; done`,
            '# Absence of 429 = no REST API rate limiting',
          ],
          remediation: 'Add rate limiting to REST API via nginx/Cloudflare or WP REST API Cache plugin.',
          evidence: `Statuses: ${uniqueRest}`,
        },
      ));
    }

    // Test 2: robots.txt and main page response headers for rate limit info
    const [robotsRes, mainRes] = await Promise.all([
      fetchURL(`${target}/robots.txt`),
      fetchURL(`${target}/`),
    ]);

    if (robotsRes && robotsRes.status === 200) {
      const rlHdrs: Record<string, string> = {};
      robotsRes.headers.forEach((v, k) => {
        const kl = k.toLowerCase();
        if (kl.includes('x-ratelimit') || kl.includes('retry-after') || kl.includes('x-rate-limit')) {
          rlHdrs[k] = v;
        }
      });
      if (Object.keys(rlHdrs).length > 0) {
        findings.push(finding(
          'rate_limiting_present', 'INFO', `${target}/robots.txt`,
          `Rate limit headers detected: ${JSON.stringify(rlHdrs)}`,
          {
            replication_steps: [`curl -sI "${target}/robots.txt" | grep -i "ratelimit\\|retry"`],
            remediation: 'Rate limiting is configured; verify it is effective.',
            evidence: JSON.stringify(rlHdrs),
          },
        ));
      }
    }

    if (mainRes) {
      const rlHdrs: Record<string, string> = {};
      mainRes.headers.forEach((v, k) => {
        const kl = k.toLowerCase();
        if (kl.includes('x-ratelimit') || kl.includes('retry-after')) {
          rlHdrs[k] = v;
        }
      });
      if (Object.keys(rlHdrs).length === 0) {
        findings.push(finding(
          'no_rate_limiting', 'INFO', `${target}/`,
          'No X-RateLimit-Limit or Retry-After headers found in response headers.',
          {
            replication_steps: [`curl -sI "${target}/" | grep -iE "x-ratelimit|retry-after"`],
            remediation: 'Configure server-side rate limiting and include X-RateLimit headers.',
            evidence: 'No rate limit headers in HTTP response',
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
