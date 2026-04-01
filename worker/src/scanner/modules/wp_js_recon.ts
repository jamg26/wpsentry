import type { ModuleResult, ScanState } from '../types.js';
import type { Severity } from '../types.js';
import { fetchURL, getCachedResponse, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'JavaScript Reconnaissance';

type SecretPattern = [RegExp, string, Severity];

const SECRET_PATTERNS: SecretPattern[] = [
  // Google APIs (AIza covers AIzaSy — no need for separate pattern)
  [/AIza[0-9A-Za-z_\-]{35}/g,                                                                   'Google API key',              'HIGH'],
  // AWS
  [/AKIA[0-9A-Z]{16}/g,                                                                          'AWS Access Key ID',           'CRITICAL'],
  [/(?:aws_secret|AWS_SECRET)[^=\s]*=\s*["']([A-Za-z0-9/+=]{40})["']/g,                        'AWS Secret Key',              'CRITICAL'],
  // Stripe
  [/sk_live_[0-9a-zA-Z]{24,}/g,                                                                  'Stripe Live Secret Key',      'CRITICAL'],
  [/rk_live_[0-9a-zA-Z]{24,}/g,                                                                  'Stripe Restricted Key',       'CRITICAL'],
  [/pk_live_[0-9a-zA-Z]{24,}/g,                                                                  'Stripe Live Publishable Key', 'LOW'],
  [/sk_test_[0-9a-zA-Z]{24,}/g,                                                                  'Stripe Test Secret Key',      'HIGH'],
  // Twilio — require JS context (near quotes/assignment) and filter false positives
  [/(?:["'`=:]\s*)AC[a-zA-Z0-9]{32}(?=["'`;\s,\)])/g,                                          'Twilio Account SID',          'MEDIUM'],
  [/(?:["'`=:]\s*)SK[a-zA-Z0-9]{32}(?=["'`;\s,\)])/g,                                          'Twilio API Key SID',          'HIGH'],
  // SendGrid
  [/SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/g,                                             'SendGrid API Key',             'CRITICAL'],
  // Mailchimp
  [/[a-zA-Z0-9]{32}-us\d+/g,                                                                     'Mailchimp API Key',            'HIGH'],
  // GitHub
  [/ghp_[a-zA-Z0-9]{36}/g,                                                                       'GitHub Personal Access Token', 'CRITICAL'],
  [/github_pat_[a-zA-Z0-9]{82}/g,                                                                'GitHub PAT (fine-grained)',   'CRITICAL'],
  // JWT
  [/eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g,                                  'JWT Token',                   'HIGH'],
  // Generic secrets
  [/(?:password|passwd|secret|private.key)\s*[=:]\s*["']([^"']{8,})["']/gi,                    'Hardcoded credential',        'HIGH'],
  [/(?:api.?key|api.?token|auth.?token)\s*[=:]\s*["']([a-zA-Z0-9\-_]{16,})["']/gi,            'API key/token',               'HIGH'],
  // WordPress specific
  [/"nonce"\s*:\s*"([a-f0-9]{10,})"/g,                                                           'WordPress nonce',             'INFO'],
  [/var\s+wpApiSettings\s*=\s*\{[^}]+\}/g,                                                      'wp REST API settings object', 'INFO'],
  [/window\.ajaxurl\s*=\s*["']([^"']+)["']/g,                                                   'ajaxurl exposed',             'LOW'],
  [/window\.restApiUrl\s*=\s*["']([^"']+)["']/g,                                                'REST API URL exposed',        'INFO'],
];

const INTERNAL_URL_RE = new RegExp(
  `["']((https?://(localhost|127\\.0\\.0\\.1|10\\.\\d+\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+|172\\.(1[6-9]|2[0-9]|3[01])\\.\\d+\\.\\d+)` +
  `|https?://[a-zA-Z0-9\\-]+\\.(local|internal|staging|dev|test|beta|intranet|corp|private))[^"']*)["']`,
  'gi',
);

const VENDOR_PATTERNS = [
  /jquery[.-][\d.]+/i,
  /lodash[.-][\d.]+/i,
  /bootstrap[.-][\d.]+/i,
  /react[.-][\d.]+/i,
  /vue[.-][\d.]+/i,
  /angular[.-][\d.]+/i,
  /moment[.-][\d.]+/i,
  /underscore[.-][\d.]+/i,
  /backbone[.-][\d.]+/i,
];

function isVendorJS(url: string): boolean {
  return VENDOR_PATTERNS.some(p => p.test(url));
}

const SCRIPT_SRC_RE    = /<script[^>]+src=["']([^"']+)["']/gi;
const INLINE_SCRIPT_RE = /<script[^>]*>([\s\S]*?)<\/script>/gi;

const SKIP_VALUES = ['example', 'placeholder', 'your_', 'insert_', 'xxx', 'test_key'];

function analyseContent(
  content: string,
  sourceUrl: string,
  findings: ReturnType<typeof finding>[],
  maxFindings = 5,
  isInline = false,
  seenValues?: Set<string>,
): void {
  let count = 0;
  const sourceLabel = isInline ? 'inline <script> on page' : sourceUrl;
  const seen = seenValues ?? new Set<string>();

  for (const [pattern, name, severity] of SECRET_PATTERNS) {
    if (count >= maxFindings) break;
    pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pattern.exec(content)) !== null) {
      const val = m[0];
      if (SKIP_VALUES.some(s => val.toLowerCase().includes(s))) continue;
      // Deduplicate: skip if this exact secret value was already reported
      if (seen.has(val)) continue;
      seen.add(val);
      // Filter Twilio SID false positives: reject all-uppercase-hex values (real SIDs have mixed case)
      if (name.startsWith('Twilio')) {
        const sidBody = val.replace(/^[^A-Z]*[A-Z]{2}/, '');
        if (/^[A-F0-9]+$/.test(sidBody)) continue;
      }
      const sanitized = name.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_').slice(0, 30);
      findings.push(finding(
        `JS_SECRET_${sanitized}`, severity, sourceUrl,
        `${name} found in ${sourceLabel}: ...${val.slice(0, 60)}...`,
        {
          replication_steps: [
            isInline
              ? `View page source of ${sourceUrl} and search inline <script> blocks for the pattern.`
              : `Download the script: curl -s "${sourceUrl}"`,
            `Search for: ${pattern.source.slice(0, 60)}`,
            `Found value: ${val.slice(0, 80)}`,
            `Immediately rotate/invalidate this ${name}.`,
          ],
          remediation: `Remove ${name} from client-side JavaScript. Use server-side proxying instead.`,
          evidence: JSON.stringify({
            secret_type: name,
            source: isInline ? 'inline script' : sourceUrl,
            value_preview: val.slice(0, 40) + (val.length > 40 ? '...' : ''),
          }),
        },
      ));
      count++;
      if (count >= maxFindings) break;
    }
  }

  // Internal URLs
  INTERNAL_URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = INTERNAL_URL_RE.exec(content)) !== null) {
    const urlFound = m[1];
    findings.push(finding(
      'INTERNAL_URL_IN_JS', 'MEDIUM', sourceUrl,
      `Internal/staging URL hardcoded in ${sourceLabel}: ${urlFound.slice(0, 80)}`,
      {
        replication_steps: [
          isInline
            ? `View page source of ${sourceUrl} and search inline scripts for internal URLs.`
            : `Download the script: curl -s "${sourceUrl}"`,
          `Search for internal/private network URLs.`,
          `Found internal URL: ${urlFound}`,
          'This reveals internal infrastructure topology.',
        ],
        evidence: JSON.stringify({ internal_url: urlFound }),
      },
    ));
  }
}

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const homeRes = await getCachedResponse(target + '/', state);
    if (!homeRes) {
      findings.push(finding(
        'TARGET_UNREACHABLE', 'INFO', target + '/',
        'Target unreachable — site may be down, blocked, or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    let homeHtml = '';
    try { homeHtml = await homeRes.text(); } catch {
      findings.push(finding(
        'TARGET_UNREACHABLE', 'INFO', target + '/',
        'Failed to read homepage body — response may be empty or malformed',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Analyse inline scripts
    const seenValues = new Set<string>();
    INLINE_SCRIPT_RE.lastIndex = 0;
    let im: RegExpExecArray | null;
    while ((im = INLINE_SCRIPT_RE.exec(homeHtml)) !== null) {
      const inline = im[1];
      if (inline.trim().length > 20) analyseContent(inline, target + '/', findings, 5, true, seenValues);
    }

    // Collect external JS URLs
    const targetDomain = (() => {
      try { return new URL(target).hostname; } catch { return ''; }
    })();

    const rawSrcs: string[] = [];
    SCRIPT_SRC_RE.lastIndex = 0;
    let sm: RegExpExecArray | null;
    while ((sm = SCRIPT_SRC_RE.exec(homeHtml)) !== null) rawSrcs.push(sm[1]);

    const resolvedSrcs = rawSrcs.map(src => {
      if (src.startsWith('//')) return 'https:' + src;
      if (src.startsWith('/')) return target + src;
      return src;
    });

    // Only process scripts from same domain
    const siteSrcs = resolvedSrcs.filter(src => {
      try { return new URL(src).hostname === targetDomain; } catch { return false; }
    });

    // Deduplicate by base URL (strip query string)
    const seen = new Set<string>();
    const uniqueSrcs: string[] = [];
    for (const src of siteSrcs) {
      const base = src.split('?')[0];
      if (!seen.has(base)) { seen.add(base); uniqueSrcs.push(src); }
    }

    // Download and analyse each JS file (cap at 15)
    await parallelProbe(uniqueSrcs.slice(0, 15), async (jsUrl) => {
      try {
        // Skip known vendor libraries — they never contain API secrets
        if (isVendorJS(jsUrl)) return;
        const r = await fetchURL(jsUrl, { timeoutMs: 15_000 });
        if (!r || r.status !== 200) return;
        let jsText = '';
        try { jsText = await r.text(); } catch { return; }
        // Large minified files that slipped through URL check are almost always vendor bundles
        if (jsText.length > 500_000 && /\bmin\.js$/i.test(jsUrl)) return;
        if (jsText.length > 2_000_000) return;
        analyseContent(jsText, jsUrl, findings, 5, false, seenValues);
      } catch { /* ignore per-file errors */ }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
