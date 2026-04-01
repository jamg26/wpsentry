import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Subdomain Takeover Indicators';

// Subdomains commonly found in WordPress sites
const COMMON_SUBDOMAIN_PREFIXES = [
  'staging', 'dev', 'development', 'test', 'testing',
  'old', 'beta', 'demo', 'preview', 'sandbox',
  'api', 'cdn', 'static', 'assets', 'media',
  'mail', 'blog', 'shop', 'store', 'wp',
  'admin', 'backoffice', 'portal',
];

// Patterns that indicate abandoned/misconfigured subdomains
const TAKEOVER_INDICATORS: Record<string, string> = {
  'There is no app here': 'Heroku abandoned app',
  'herokucdn.com': 'Heroku CDN',
  'No such app': 'Heroku/Render abandoned',
  'Repository not found': 'GitHub Pages repo removed',
  '404 Not Found': 'Generic subdomain',
  'fastly error: unknown domain': 'Fastly CDN orphaned',
  'Fastly error: No such domain': 'Fastly CDN orphaned',
  '\'Cause we\'ve moved here': 'Tumblr subdomain',
  'There\'s nothing here': 'GitHub Pages',
  'Please renew your Pantheon': 'Pantheon orphaned site',
  'Does Not Exist': 'Azure/AWS orphaned',
  'S3 Bucket Not Found': 'AWS S3 orphaned',
  'NoSuchBucket': 'AWS S3 bucket missing',
  'The specified bucket does not exist': 'AWS S3 bucket missing',
  'azurewebsites.net': 'Azure Web Apps',
  'cloudfront.amazonaws.com': 'AWS CloudFront',
};

// CNAME targets that can be taken over
const TAKEOVER_CNAME_PATTERNS = [
  '.herokudns.com',
  '.herokudns.com.',
  '.herokuapp.com',
  '.fastly.net',
  '.pantheonsite.io',
  '.wpengine.com',
  '.wpenginepower.com',
  '.netlify.app',
  '.netlify.com',
  '.vercel.app',
  '.github.io',
  '.cloudfront.net',
  '.s3.amazonaws.com',
  '.s3-website',
  '.azurewebsites.net',
  '.azureedge.net',
  '.trafficmanager.net',
  '.ghost.io',
  '.shopify.com',
  '.tumblr.com',
  '.surge.sh',
  '.bitbucket.io',
  '.webflow.io',
];

function extractDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

function extractSubdomains(html: string, baseDomain: string): string[] {
  const seen = new Set<string>();
  const pattern = new RegExp(
    `https?://([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.${baseDomain.replace(/\./g, '\\.')})`,
    'gi'
  );
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(html)) !== null) {
    const subdomain = m[1].toLowerCase();
    // Only include subdomains (not the base domain itself)
    if (subdomain !== baseDomain) {
      seen.add(subdomain);
    }
  }
  return [...seen];
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const baseDomain = extractDomain(target);
    const protocol = target.startsWith('https') ? 'https' : 'http';

    const allSubdomains = new Set<string>();

    // 1. Harvest subdomains from sitemap.xml
    const sitemapRes = await fetchURL(target + '/sitemap.xml', { timeoutMs: 5_000 });
    if (sitemapRes?.status === 200) {
      const sitemapBody = await sitemapRes.text().catch(() => '');
      extractSubdomains(sitemapBody, baseDomain).forEach(s => allSubdomains.add(s));
    }

    // 2. Harvest from robots.txt
    const robotsRes = await fetchURL(target + '/robots.txt', { timeoutMs: 4_000 });
    if (robotsRes?.status === 200) {
      const robotsBody = await robotsRes.text().catch(() => '');
      extractSubdomains(robotsBody, baseDomain).forEach(s => allSubdomains.add(s));
    }

    // 3. Harvest from homepage
    const homeRes = await fetchURL(target + '/', { timeoutMs: 5_000 });
    if (homeRes) {
      const homeBody = await homeRes.text().catch(() => '');
      extractSubdomains(homeBody, baseDomain).forEach(s => allSubdomains.add(s));
    }

    // 4. Add common prefixes
    for (const prefix of COMMON_SUBDOMAIN_PREFIXES) {
      allSubdomains.add(`${prefix}.${baseDomain}`);
    }

    // 5. Report discovered subdomains
    const discovered = [...allSubdomains];
    if (discovered.length > 0) {
      const stagingSubdomains = discovered.filter(s =>
        COMMON_SUBDOMAIN_PREFIXES.some(prefix => s.startsWith(`${prefix}.`))
      );

      if (stagingSubdomains.length > 0) {
        findings.push(finding(
          'STAGING_SUBDOMAINS_DISCOVERED',
          'MEDIUM',
          target,
          `${stagingSubdomains.length} staging/dev subdomain(s) discovered — potential exposure or takeover target`,
          {
            evidence: `subdomains="${stagingSubdomains.slice(0, 10).join(', ')}"`,
            remediation: 'Remove or properly secure staging/dev subdomains. Implement DNS monitoring for CNAME changes.',
          },
        ));
      }
    }

    // 6. Check discovered subdomains for takeover indicators
    const toCheck = discovered.slice(0, 20); // Cap at 20 to stay within time budget
    const seenTakeover = new Set<string>();

    await Promise.all(toCheck.map(async (subdomain) => {
      if (seenTakeover.has(subdomain)) return;
      const subUrl = `${protocol}://${subdomain}`;

      const res = await fetchURL(subUrl, { timeoutMs: 4_000 });
      if (!res) {
        // DNS doesn't resolve or connection refused — could be dangling
        return;
      }

      const body = await res.text().catch(() => '');
      const bodyLower = body.toLowerCase();
      const serverHeader = res.headers.get('Server') ?? '';

      // Check for takeover indicators
      for (const [indicator, service] of Object.entries(TAKEOVER_INDICATORS)) {
        if (body.includes(indicator) || serverHeader.toLowerCase().includes(indicator.toLowerCase())) {
          if (!seenTakeover.has(subdomain)) {
            seenTakeover.add(subdomain);
            findings.push(finding(
              'SUBDOMAIN_TAKEOVER_INDICATOR',
              'HIGH',
              subUrl,
              `Subdomain takeover indicator on ${subdomain} — service: ${service} (indicator: '${indicator}')`,
              {
                evidence: `subdomain="${subdomain}" service="${service}" indicator="${indicator}" status=${res.status}`,
                remediation: 'Remove or reclaim this subdomain immediately. Update CNAME/DNS records to point to an active resource or remove the DNS entry.',
              },
            ));
            break;
          }
        }
      }

      // Check if response contains CNAME-to-takeover patterns
      for (const cnamePattern of TAKEOVER_CNAME_PATTERNS) {
        if (bodyLower.includes(cnamePattern.toLowerCase())) {
          if (!seenTakeover.has(subdomain)) {
            seenTakeover.add(subdomain);
            findings.push(finding(
              'SUBDOMAIN_DANGLING_CNAME',
              'MEDIUM',
              subUrl,
              `Subdomain ${subdomain} appears to have a dangling CNAME to ${cnamePattern}`,
              {
                evidence: `subdomain="${subdomain}" cname_target="${cnamePattern}"`,
                remediation: 'Remove or update the DNS CNAME record for this subdomain.',
              },
            ));
            break;
          }
        }
      }
    }));
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
