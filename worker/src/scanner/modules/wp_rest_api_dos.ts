import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'REST API DoS Check';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Check if REST API accepts large per_page values
    const largePageUrl = `${target}/wp-json/wp/v2/posts?per_page=100`;
    const res = await fetchURL(largePageUrl);
    if (res && res.status === 200) {
      const body = await res.text();
      try {
        const data = JSON.parse(body);
        if (Array.isArray(data) && data.length > 50) {
          findings.push(finding('REST_API_LARGE_RESPONSE', 'LOW', largePageUrl,
            `REST API returns large responses (${data.length} items with per_page=100)`, {
              evidence: `${data.length} items returned in single request`,
              replication_steps: [
                `Fetch ${largePageUrl}`,
                'Observe large response payload',
              ],
              remediation: 'Limit maximum per_page value in REST API via rest_post_collection_params filter.',
            }));
        }
      } catch { /* not JSON */ }
    }

    // Check for search-based DoS (complex regex searches)
    const searchUrl = `${target}/wp-json/wp/v2/posts?search=${'a'.repeat(200)}`;
    const searchStart = Date.now();
    const searchRes = await fetchURL(searchUrl);
    const searchDuration = Date.now() - searchStart;

    if (searchRes && searchRes.status === 200 && searchDuration > 1500) {
      findings.push(finding('REST_API_SLOW_SEARCH', 'MEDIUM', `${target}/wp-json/wp/v2/posts?search=...`,
        `REST API search takes ${searchDuration}ms with long query — potential DoS vector`, {
          evidence: `Search with 200-char query took ${searchDuration}ms`,
          replication_steps: [
            `Send GET request to ${target}/wp-json/wp/v2/posts?search=[200 characters]`,
            `Response took ${searchDuration}ms`,
            'Multiple concurrent requests could exhaust server resources',
          ],
          remediation: 'Implement rate limiting on REST API search endpoints. Consider using a caching layer.',
        }));
    }

    // Check for _embed parameter (expensive JOIN queries)
    const embedUrl = `${target}/wp-json/wp/v2/posts?per_page=20&_embed`;
    const embedStart = Date.now();
    const embedRes = await fetchURL(embedUrl);
    const embedDuration = Date.now() - embedStart;

    if (embedRes && embedRes.status === 200) {
      const embedBody = await embedRes.text();
      if (embedBody.length > 50000) {
        findings.push(finding('REST_API_EMBED_EXPENSIVE', 'LOW', embedUrl,
          `REST API _embed parameter returns large payloads (${Math.round(embedBody.length / 1024)}KB, ${embedDuration}ms)`, {
            evidence: `_embed response: ${Math.round(embedBody.length / 1024)}KB in ${embedDuration}ms`,
            replication_steps: [
              `Fetch ${embedUrl}`,
              'Observe large response with embedded author, media, and term data',
            ],
            remediation: 'Disable or restrict the _embed parameter for unauthenticated requests. Implement response caching.',
          }));
      }
    }

    // Check for multiple parameter combinations that cause expensive queries
    const expensiveUrl = `${target}/wp-json/wp/v2/posts?per_page=100&_embed&orderby=relevance&search=test`;
    const expStart = Date.now();
    const expRes = await fetchURL(expensiveUrl);
    const expDuration = Date.now() - expStart;

    if (expRes && expRes.status === 200 && expDuration > 1500) {
      findings.push(finding('REST_API_EXPENSIVE_QUERY', 'MEDIUM',
        `${target}/wp-json/wp/v2/posts?per_page=100&_embed&orderby=relevance&search=test`,
        `Complex REST API query takes ${expDuration}ms — amplified DoS risk`, {
          evidence: `Combined query parameters resulted in ${expDuration}ms response time`,
          replication_steps: [
            'Combine per_page=100, _embed, orderby=relevance, and search parameters',
            `Response time: ${expDuration}ms`,
          ],
          remediation: 'Implement rate limiting and query complexity limits on REST API endpoints.',
        }));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
