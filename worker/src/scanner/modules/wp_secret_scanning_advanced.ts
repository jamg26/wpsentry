import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Advanced Secret Detection';

// Secret patterns — [pattern, type, severity]
// NOTE: wp_js_recon.ts covers Google API keys, basic AWS, Stripe, SendGrid, Mailchimp, GitHub PAT, JWT.
// This module adds: private keys, connection strings, PayPal/Braintree, broader patterns,
// and scans ALL JS files (not just the first few).
type SecretType = [RegExp, string, 'CRITICAL' | 'HIGH' | 'MEDIUM'];

const ADVANCED_PATTERNS: SecretType[] = [
  // Private keys
  [/-----BEGIN RSA PRIVATE KEY-----/,                                    'RSA Private Key',                  'CRITICAL'],
  [/-----BEGIN EC PRIVATE KEY-----/,                                     'EC Private Key',                   'CRITICAL'],
  [/-----BEGIN OPENSSH PRIVATE KEY-----/,                                'OpenSSH Private Key',              'CRITICAL'],
  [/-----BEGIN PGP PRIVATE KEY BLOCK-----/,                              'PGP Private Key',                  'CRITICAL'],
  [/-----BEGIN DSA PRIVATE KEY-----/,                                    'DSA Private Key',                  'CRITICAL'],
  // AWS credentials
  [/AKIA[0-9A-Z]{16}/,                                                   'AWS Access Key ID',                'CRITICAL'],
  [/(?:aws[_\-\s]?secret|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})/i, 'AWS Secret Key', 'CRITICAL'],
  // Stripe
  [/sk_live_[0-9a-zA-Z]{24,}/,                                           'Stripe Live Secret Key',           'CRITICAL'],
  [/rk_live_[0-9a-zA-Z]{24,}/,                                           'Stripe Restricted Key',            'CRITICAL'],
  // GitHub tokens
  [/ghp_[a-zA-Z0-9]{36}/,                                               'GitHub Personal Access Token',     'CRITICAL'],
  [/github_pat_[a-zA-Z0-9_]{82}/,                                       'GitHub PAT (fine-grained)',         'CRITICAL'],
  [/ghs_[a-zA-Z0-9]{36}/,                                               'GitHub Actions Token',             'CRITICAL'],
  // SendGrid
  [/SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/,                       'SendGrid API Key',                 'CRITICAL'],
  // Mailchimp
  [/[a-f0-9]{32}-us\d{1,2}/,                                            'Mailchimp API Key',                'HIGH'],
  // PayPal/Braintree
  [/access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}/,             'Braintree Production Token',        'CRITICAL'],
  [/(?:paypal|braintree)[_\-\s]?(?:client|secret|api)[_\-\s]?(?:id|key|secret)\s*[=:]\s*["']([^"']{10,})/i, 'PayPal/Braintree Credential', 'CRITICAL'],
  // Twilio
  // NOTE: Twilio SID patterns are already handled by wp_js_recon.ts — removed to avoid cross-module duplicates
  // Slack
  [/xox[baprs]-[0-9a-zA-Z\-]{10,}/,                                     'Slack Token',                      'CRITICAL'],
  [/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/, 'Slack Webhook URL', 'HIGH'],
  // Database connection strings
  [/(?:mysql|postgresql|postgres|mongodb|redis):\/\/[a-zA-Z0-9_%\-]+:[^@\s"'`]+@[a-zA-Z0-9.\-]+/i, 'Database Connection String', 'CRITICAL'],
  [/(?:DB_PASSWORD|database_password|db_pass)\s*[=:]\s*["']([^"']{4,})/i, 'Database Password', 'CRITICAL'],
  // WooCommerce/payment keys
  [/(?:wc_|woocommerce_)(?:secret|api)[_\s]?key\s*[=:]\s*["']([^"']{8,})/i, 'WooCommerce API Secret', 'HIGH'],
  // Firebase/Google API key — covered by wp_js_recon.ts (AIza pattern) — removed to avoid cross-module duplicates
  [/[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,             'Google OAuth Client ID',           'MEDIUM'],
  // Hardcoded passwords
  [/(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})['"]\s*(?:,|}|;)/i, 'Hardcoded Password',             'HIGH'],
  // Generic API tokens
  [/(?:api[_\-]?(?:key|token|secret)|auth[_\-]?token)\s*[:=]\s*["']([a-zA-Z0-9\-_.]{20,})["']/i, 'Generic API Token', 'MEDIUM'],
];

// False-positive filters: skip if matched text contains these
const FALSE_POSITIVE_INDICATORS = [
  'example',
  'your_',
  'YOUR_',
  'REPLACE_',
  'insert_',
  'placeholder',
  'xxxxxxxx',
  '12345678',
  'abcdefgh',
  'test_key',
  'dummy',
  '<api_key>',
];

function isFalsePositive(match: string): boolean {
  const lower = match.toLowerCase();
  return FALSE_POSITIVE_INDICATORS.some(fp => lower.includes(fp.toLowerCase()));
}

// Extract JS URLs from HTML
function extractJsUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const pattern = /<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]/gi;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(html)) !== null) {
    const src = m[1];
    if (src.startsWith('http')) {
      urls.push(src);
    } else if (src.startsWith('/')) {
      urls.push(baseUrl + src);
    } else {
      urls.push(baseUrl + '/' + src);
    }
  }
  return [...new Set(urls)];
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Fetch homepage and collect JS URLs
    const homeRes = await fetchURL(target + '/', { timeoutMs: 6_000 });
    if (!homeRes) return moduleResult(MODULE_NAME, target, findings, errors, start);

    const html = await homeRes.text().catch(() => '');
    const jsUrls = extractJsUrls(html, target).slice(0, 30); // Max 30 JS files

    // Also check the homepage HTML itself for secrets
    const sourcesToScan: Array<[string, string]> = [[target + '/', html]];

    // Fetch all JS files
    await parallelProbe(jsUrls, async (jsUrl) => {
      const res = await fetchURL(jsUrl, { timeoutMs: 4_000 });
      if (!res || res.status !== 200) return;
      const jsBody = await res.text().catch(() => '');
      if (jsBody) sourcesToScan.push([jsUrl, jsBody]);
    }, 10);

    // Scan all sources
    const seenSecrets = new Set<string>();

    for (const [sourceUrl, content] of sourcesToScan) {
      for (const [pattern, secretType, severity] of ADVANCED_PATTERNS) {
        const globalPattern = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
        let match: RegExpExecArray | null;

        while ((match = globalPattern.exec(content)) !== null) {
          const fullMatch = match[0];
          const capturedGroup = match[1] ?? fullMatch;

          if (isFalsePositive(fullMatch)) continue;

          // Deduplicate by secret type + first 20 chars
          const dedupeKey = `${secretType}:${capturedGroup.slice(0, 20)}`;
          if (seenSecrets.has(dedupeKey)) continue;
          seenSecrets.add(dedupeKey);

          // Redact middle of secret for evidence
          const redacted = capturedGroup.length > 8
            ? capturedGroup.slice(0, 4) + '...[REDACTED]...' + capturedGroup.slice(-4)
            : '[REDACTED]';

          findings.push(finding(
            'SECRET_DETECTED',
            severity,
            sourceUrl,
            `${secretType} detected in ${sourceUrl.includes('.js') ? 'JavaScript file' : 'HTML source'}`,
            {
              evidence: `type="${secretType}" value="${redacted}" url="${sourceUrl}"`,
              remediation: `Immediately rotate the ${secretType}. Move secrets to server-side environment variables. Never commit secrets to source code or expose them in JS.`,
            },
          ));

          if (findings.length >= 50) return; // Cap to avoid noise
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
