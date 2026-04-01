import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Supply Chain / CDN Integrity';

// High-risk CDN domains — external scripts loaded from these need SRI
const EXTERNAL_CDN_DOMAINS = [
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
  'unpkg.com',
  'ajax.googleapis.com',
  'code.jquery.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'cdn.bootcss.com',
  'rawgit.com',
  'raw.githubusercontent.com',
  'gitcdn.xyz',
  'cdn.datatables.net',
  's3.amazonaws.com',
  'storage.googleapis.com',
  'd1wp6m56sqw74a.cloudfront.net',
];

// High-risk domains (payment/analytics): flag even pk_ if sk_ also present
const HIGH_RISK_DOMAINS = [
  'js.stripe.com',
  'js.braintreegateway.com',
  'www.paypalobjects.com',
  'checkout.stripe.com',
  'pay.google.com',
  'applepay',
];

// Pattern to find script/link tags
const SCRIPT_PATTERN = /<script[^>]+src=['"]([^'"]+)['"]/gi;
const LINK_PATTERN = /<link[^>]+href=['"]([^'"]+)['"]/gi;
const SRI_PATTERN = /integrity=['"][^'"]+['"]/i;

function isExternal(url: string, targetHost: string): boolean {
  try {
    const u = new URL(url);
    return u.hostname !== targetHost && !url.startsWith('/') && !url.startsWith('./');
  } catch {
    return url.startsWith('http') && !url.includes(targetHost);
  }
}

function getHostname(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

interface ResourceTag {
  type: 'script' | 'link';
  src: string;
  hasSRI: boolean;
  tag: string;
}

function extractResources(html: string): ResourceTag[] {
  const resources: ResourceTag[] = [];

  let m: RegExpExecArray | null;

  // Reset lastIndex
  SCRIPT_PATTERN.lastIndex = 0;
  LINK_PATTERN.lastIndex = 0;

  while ((m = SCRIPT_PATTERN.exec(html)) !== null) {
    const tag = m[0];
    resources.push({ type: 'script', src: m[1], hasSRI: SRI_PATTERN.test(tag), tag });
  }

  while ((m = LINK_PATTERN.exec(html)) !== null) {
    const tag = m[0];
    // Only care about stylesheets
    if (!tag.includes('stylesheet')) continue;
    resources.push({ type: 'link', src: m[1], hasSRI: SRI_PATTERN.test(tag), tag });
  }

  return resources;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const targetHost = getHostname(target);

    // Fetch homepage
    const homepageRes = await fetchURL(target + '/', { timeoutMs: 6_000 });
    if (!homepageRes) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const html = await homepageRes.text().catch(() => '');
    if (!html) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const resources = extractResources(html);
    const externalNoSRI: ResourceTag[] = [];
    const highRiskNoSRI: ResourceTag[] = [];
    const wcNoSRI: ResourceTag[] = [];

    for (const res of resources) {
      if (!isExternal(res.src, targetHost)) continue;
      const host = getHostname(res.src);

      const isCDN = EXTERNAL_CDN_DOMAINS.some(cdn => host.includes(cdn) || host === cdn);
      const isHighRisk = HIGH_RISK_DOMAINS.some(hr => host.includes(hr));

      if (!res.hasSRI) {
        if (isHighRisk) {
          highRiskNoSRI.push(res);
        } else if (isCDN) {
          externalNoSRI.push(res);
        } else {
          // Any external domain without SRI
          externalNoSRI.push(res);
        }
      }
    }

    // Check for external WP core assets (CDN override)
    const wpCoreExternals = resources.filter(r =>
      isExternal(r.src, targetHost) &&
      (r.src.includes('wp-includes') || r.src.includes('wp-content/plugins')) &&
      !r.hasSRI
    );

    if (highRiskNoSRI.length > 0) {
      const srcs = highRiskNoSRI.map(r => r.src).slice(0, 5).join(', ');
      findings.push(finding(
        'SRI_MISSING_HIGH_RISK',
        'HIGH',
        target,
        `${highRiskNoSRI.length} high-risk external script(s) (payment/checkout) loaded WITHOUT Subresource Integrity (SRI) hash`,
        {
          evidence: `scripts="${srcs}"`,
          remediation: 'Add integrity="sha384-..." and crossorigin="anonymous" attributes to all external scripts. Use SRI Hash Generator at https://www.srihash.org/',
        },
      ));
    }

    if (externalNoSRI.length > 0) {
      const srcs = externalNoSRI.map(r => r.src).slice(0, 5).join(', ');
      const severity = externalNoSRI.length >= 3 ? 'MEDIUM' : 'LOW';
      findings.push(finding(
        'SRI_MISSING_EXTERNAL',
        severity,
        target,
        `${externalNoSRI.length} external script/stylesheet(s) loaded WITHOUT Subresource Integrity (SRI) — supply chain attack risk`,
        {
          evidence: `resources="${srcs}"`,
          remediation: 'Add SRI hashes to all external resources. Consider self-hosting critical libraries.',
        },
      ));
    }

    if (wpCoreExternals.length > 0) {
      const srcs = wpCoreExternals.map(r => r.src).slice(0, 3).join(', ');
      findings.push(finding(
        'WP_CORE_EXTERNAL_CDN',
        'MEDIUM',
        target,
        `WordPress core assets loaded from external CDN without SRI — if CDN is compromised, all visitors are affected`,
        {
          evidence: `assets="${srcs}"`,
          remediation: 'Serve WordPress core assets from your own domain. If using CDN, enforce SRI hashes.',
        },
      ));
    }

    // Report total external scripts scanned
    const totalExternal = resources.filter(r => isExternal(r.src, targetHost)).length;
    const withSRI = resources.filter(r => isExternal(r.src, targetHost) && r.hasSRI).length;
    if (totalExternal > 0 && findings.length === 0) {
      findings.push(finding(
        'SRI_AUDIT_PASSED',
        'INFO',
        target,
        `Supply chain integrity check: ${totalExternal} external resources found, ${withSRI} have SRI hashes`,
        { evidence: `total_external=${totalExternal} with_sri=${withSRI}` },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
