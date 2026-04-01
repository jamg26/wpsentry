import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getCachedResponse, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Robots.txt & Sitemap Recon';

const SENSITIVE_PATTERNS = [
  /\/wp-admin/i, /\/admin/i, /\/staging/i, /\/dev/i, /\/test/i,
  /\/backup/i, /\/private/i, /\/secret/i, /\/internal/i, /\/api/i,
  /\/dashboard/i, /\/phpmyadmin/i, /\/cpanel/i, /\/wp-content\/uploads/i,
];

async function checkRobots(
  base: string,
  findings: ReturnType<typeof finding>[],
  state?: ScanState,
): Promise<void> {
  const url = `${base}/robots.txt`;
  const res = await getCachedResponse(url, state);
  if (!res || res.status !== 200) return;

  let text = '';
  try { text = await res.text(); } catch { return; }

  const disallowed: string[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.toLowerCase().startsWith('disallow:')) {
      const path = trimmed.split(':', 2)[1]?.trim() ?? '';
      if (path && path !== '/') disallowed.push(path);
    }
  }

  const sensitiveFound = disallowed.filter(path =>
    SENSITIVE_PATTERNS.some(p => p.test(path)),
  );

  if (sensitiveFound.length > 0) {
    findings.push(finding(
      'ROBOTS_TXT_DISCLOSES_PATHS', 'INFO', url,
      `robots.txt discloses ${sensitiveFound.length} sensitive path(s): ${sensitiveFound.slice(0, 5).join(', ')}`,
      {
        replication_steps: [
          `curl -s "${url}"`,
          'Observe Disallow entries that reveal internal path structure.',
          'Probe discovered paths for accessible content.',
        ],
        evidence: JSON.stringify({ paths: sensitiveFound }),
      },
    ));
  }

  if (disallowed.length > 0) {
    findings.push(finding(
      'ROBOTS_TXT_PRESENT', 'INFO', url,
      `robots.txt present with ${disallowed.length} Disallow rule(s) — exposes site structure`,
      { replication_steps: [`curl -s "${url}"`] },
    ));
  }
}

async function checkSitemap(
  base: string,
  findings: ReturnType<typeof finding>[],
): Promise<void> {
  const candidates = [
    `${base}/sitemap.xml`,
    `${base}/sitemap_index.xml`,
    `${base}/wp-sitemap.xml`,
  ];

  let sitemapFound = false;
  await parallelProbe(candidates, async (url) => {
    const res = await fetchURL(url);
    if (!res || res.status !== 200) return;
    if (sitemapFound) return;

    const ct = res.headers.get('content-type') ?? '';
    let text = '';
    try { text = await res.text(); } catch { return; }

    if (!ct.includes('xml') && !text.includes('<url')) return;

    const urls = [...text.matchAll(/<loc>\s*(https?:\/\/[^<]+)\s*<\/loc>/g)]
      .map(m => m[1].trim());
    if (urls.length === 0) return;

    sitemapFound = true;
    findings.push(finding(
      'SITEMAP_FOUND', 'INFO', url,
      `Sitemap found with ${urls.length} URL(s) — exposes full post/page structure`,
      {
        replication_steps: [
          `curl -s "${url}" | grep '<loc>'`,
          `Sitemap contains ${urls.length} URLs that reveal site content structure.`,
        ],
        evidence: JSON.stringify({ url_count: urls.length }),
      },
    ));

    const suspicious = urls.filter(u =>
      /\/(?:staging|dev|test|beta|private|draft|backup|admin|internal)\//i.test(u),
    );

    if (suspicious.length > 0) {
      findings.push(finding(
        'SITEMAP_EXPOSES_SENSITIVE_PATHS', 'MEDIUM', url,
        `Sitemap exposes ${suspicious.length} potentially sensitive path(s)`,
        {
          replication_steps: [
            `curl -s "${url}" | grep -iE 'staging|dev|test|private|draft'`,
            'Observe paths that should not be publicly indexed.',
          ],
          evidence: JSON.stringify({ suspicious_urls: suspicious.slice(0, 10) }),
        },
      ));
    }
  });
}

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await checkRobots(target, findings, state);
    await checkSitemap(target, findings);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
