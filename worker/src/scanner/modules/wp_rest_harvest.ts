import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget} from '../utils.js';

const MODULE_NAME = 'REST API Deep Harvest';

const SENSITIVE_EXTENSIONS = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'csv', 'sql', 'zip',
  'tar', 'gz', 'bak', 'txt', 'xml', 'json', 'log', 'cfg',
]);

const INTERNAL_SLUG_PATTERNS = [
  /admin/i, /staging/i, /dev/i, /test/i, /beta/i, /internal/i,
  /private/i, /secret/i, /backup/i, /temp/i, /draft/i, /hidden/i,
  /portal/i, /dashboard/i, /account/i, /register/i, /login/i,
  /talent.*account/i, /new.*account/i, /user.*portal/i,
];

const EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const DOMAIN_RE = /https?:\/\/([a-zA-Z0-9\-.]+\.[a-zA-Z]{2,})/g;

function extractHost(url: string): string {
  try { return new URL(url).hostname; } catch { return ''; }
}

function detectInternalDomains(
  targetHost: string,
  content: string,
  sourceUrl: string,
  findings: ReturnType<typeof finding>[],
): void {
  const found = new Set<string>();
  for (const m of content.matchAll(DOMAIN_RE)) found.add(m[1]);
  for (const domain of found) {
    if (domain === targetHost) continue;
    if (/staging|beta|dev|test|internal|local/.test(domain)) {
      findings.push(finding(
        'INTERNAL_DOMAIN_LEAKED', 'HIGH', sourceUrl,
        `Internal/staging domain '${domain}' leaked in REST API response`,
        {
          replication_steps: [
            `curl -s "${sourceUrl}" | python3 -m json.tool | grep '${domain}'`,
            `Domain '${domain}' appears in REST API content — likely a staging/internal host.`,
            'This can expose internal infrastructure to attackers.',
          ],
          remediation: 'Sanitise post GUIDs and content; avoid referencing internal domains in published content.',
          evidence: JSON.stringify({ leaked_domain: domain }),
        },
      ));
    }
  }
}

async function checkJSONP(base: string, findings: ReturnType<typeof finding>[]): Promise<void> {
  const testCallback = 'jwp_jsonp_test_xss';
  const url = `${base}/wp-json/wp/v2/posts?_jsonp=${testCallback}`;
  const res = await fetchURL(url);
  if (!res || res.status !== 200) return;
  let text = '';
  try { text = await res.text(); } catch { return; }
  if (text.includes(testCallback)) {
    findings.push(finding(
      'REST_API_JSONP_ENABLED', 'MEDIUM', url,
      'REST API accepts JSONP callbacks — allows cross-origin data theft if target is authenticated',
      {
        replication_steps: [
          `curl -s "${url}"`,
          `Observe: response is wrapped in '${testCallback}(...)' callback.`,
          'A malicious page can include this as a <script> tag to steal REST API data from authenticated sessions.',
          'Proof: <script src="https://TARGET/wp-json/wp/v2/posts?_jsonp=stealData"></script>',
        ],
        remediation: "Disable JSONP in REST API: add_filter('rest_jsonp_enabled', '__return_false');",
        evidence: JSON.stringify({ callback: testCallback }),
      },
    ));
  }
}

async function harvestPosts(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-json/wp/v2/posts?per_page=100&_fields=id,slug,link,guid,content,excerpt,author,status`;
  const posts = await getJSON<unknown[]>(url);
  if (!Array.isArray(posts) || posts.length === 0) return;

  const targetHost = extractHost(base);
  const authorIds = new Set<number>();

  for (const p of posts as Record<string, unknown>[]) {
    const aid = p['author'];
    if (typeof aid === 'number') authorIds.add(aid);

    const guid = typeof p['guid'] === 'object' && p['guid'] !== null
      ? String((p['guid'] as Record<string, unknown>)['rendered'] ?? '')
      : String(p['guid'] ?? '');
    if (guid) detectInternalDomains(targetHost, guid, url, findings);

    const content = typeof p['content'] === 'object' && p['content'] !== null
      ? String((p['content'] as Record<string, unknown>)['rendered'] ?? '')
      : '';
    const excerpt = typeof p['excerpt'] === 'object' && p['excerpt'] !== null
      ? String((p['excerpt'] as Record<string, unknown>)['rendered'] ?? '')
      : '';
    const rendered = content + ' ' + excerpt;

    const emails = [...rendered.matchAll(EMAIL_RE)].map(m => m[0]);
    const uniqueEmails = [...new Set(emails)];
    if (uniqueEmails.length > 0) {
      findings.push(finding(
        'PII_EMAIL_IN_REST_CONTENT', 'MEDIUM', url,
        `Email address(es) found in REST API post content: ${uniqueEmails.slice(0, 3).join(', ')}`,
        {
          replication_steps: [
            `curl -s "${base}/wp-json/wp/v2/posts" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'`,
          ],
          evidence: JSON.stringify({ emails: uniqueEmails.slice(0, 10) }),
        },
      ));
    }

    detectInternalDomains(targetHost, rendered, url, findings);
  }

  if (authorIds.size > 0) {
    const sorted = [...authorIds].sort((a, b) => a - b);
    findings.push(finding(
      'AUTHOR_IDS_LEAKED_VIA_POSTS', 'LOW', url,
      `REST API post data leaks ${authorIds.size} author ID(s): ${JSON.stringify(sorted)} — enables targeted user lookup`,
      {
        replication_steps: [
          `curl -s "${base}/wp-json/wp/v2/posts" | python3 -m json.tool | grep '"author"'`,
          'Observe numeric author IDs in each post object.',
          `Probe: curl -s "${base}/wp-json/wp/v2/users/<id>" for each ID.`,
        ],
        evidence: JSON.stringify({ author_ids: sorted }),
      },
    ));
  }
}

async function harvestPages(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-json/wp/v2/pages?per_page=100&_fields=id,slug,link,title,status,parent`;
  const pages = await getJSON<unknown[]>(url);
  if (!Array.isArray(pages) || pages.length === 0) return;

  const sensitivePages: { slug: string; title: string; url: string }[] = [];
  for (const p of pages as Record<string, unknown>[]) {
    const slug = String(p['slug'] ?? '');
    const title = typeof p['title'] === 'object' && p['title'] !== null
      ? String((p['title'] as Record<string, unknown>)['rendered'] ?? '')
      : '';
    const link = String(p['link'] ?? '');
    if (INTERNAL_SLUG_PATTERNS.some(re => re.test(slug) || re.test(title))) {
      sensitivePages.push({ slug, title, url: link });
    }
  }

  if (sensitivePages.length > 0) {
    findings.push(finding(
      'SENSITIVE_PAGES_ENUMERATED', 'LOW', url,
      `REST API exposes ${sensitivePages.length} sensitive-looking page(s): ` +
        sensitivePages.slice(0, 5).map(p => `'${p.slug}'`).join(', '),
      {
        replication_steps: [
          `curl -s "${url}" | python3 -m json.tool | grep -iE 'slug|link|title'`,
          'Observe page slugs that suggest admin portals, talent accounts, staging pages.',
          'Browse each discovered URL for exposed functionality.',
        ],
        evidence: JSON.stringify({ pages: sensitivePages.slice(0, 10) }),
      },
    ));
  }
}

async function harvestMedia(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const url = `${base}/wp-json/wp/v2/media?per_page=100&_fields=id,slug,source_url,mime_type,title`;
  const items = await getJSON<unknown[]>(url);
  if (!Array.isArray(items) || items.length === 0) return;

  const sensitiveFiles: { url: string; type: string; id: unknown }[] = [];
  for (const item of items as Record<string, unknown>[]) {
    const src = String(item['source_url'] ?? '');
    if (!src) continue;
    const ext = src.split('?')[0].split('.').pop()?.toLowerCase() ?? '';
    if (SENSITIVE_EXTENSIONS.has(ext)) {
      sensitiveFiles.push({ url: src, type: ext, id: item['id'] });
    }
  }

  if (sensitiveFiles.length > 0) {
    findings.push(finding(
      'SENSITIVE_MEDIA_FILES_EXPOSED', 'HIGH', url,
      `REST API exposes ${sensitiveFiles.length} sensitive uploaded file(s): ` +
        sensitiveFiles.slice(0, 3).map(f => f.url.split('/').pop()?.slice(0, 40) ?? '').join(', '),
      {
        replication_steps: [
          `curl -s "${url}" | python3 -m json.tool | grep source_url`,
          'Observe direct download URLs for sensitive document types.',
          sensitiveFiles.length > 0 ? `wget "${sensitiveFiles[0].url}"` : '',
        ],
        evidence: JSON.stringify({ files: sensitiveFiles.slice(0, 20) }),
      },
    ));
  }

  if (items.length > 0) {
    findings.push(finding(
      'MEDIA_LIBRARY_ENUMERATED', 'LOW', url,
      `REST API exposes ${items.length} media file URL(s) — full upload library is publicly enumerable`,
      {
        replication_steps: [
          `curl -s "${url}" | python3 -m json.tool | grep source_url`,
          'All uploaded file URLs are accessible without authentication.',
        ],
        evidence: JSON.stringify({ count: items.length }),
      },
    ));
  }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await checkJSONP(target, findings);
    await harvestPosts(target, findings);
    await harvestPages(target, findings);
    await harvestMedia(target, findings);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
