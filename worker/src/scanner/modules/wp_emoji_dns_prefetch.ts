import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Emoji DNS Prefetch Detection';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const res = await fetchURL(`${target}/`);
    if (!res || res.status !== 200) return moduleResult(MODULE_NAME, target, findings, errors, start);
    const body = await res.text();

    // Check for wp-emoji-release.min.js — indicates emoji script is loaded
    const hasEmojiScript = body.includes('wp-emoji-release.min.js') || body.includes('wp-emoji');

    // Check for DNS prefetch to s.w.org (WordPress emoji CDN)
    const hasDnsPrefetch = body.includes('dns-prefetch') && body.includes('s.w.org');

    if (hasEmojiScript) {
      findings.push(finding('WP_EMOJI_SCRIPT_LOADED', 'INFO', `${target}/`,
        'WordPress emoji script (wp-emoji-release.min.js) is loaded on the page', {
          evidence: 'wp-emoji-release.min.js found in page source',
          replication_steps: [
            `Visit ${target}/`,
            'View page source and search for "wp-emoji"',
          ],
          remediation: 'Disable WordPress emoji script if not needed by adding remove_action(\'wp_head\', \'print_emoji_detection_script\', 7) to functions.php or using a performance plugin.',
        }));
    }

    if (hasDnsPrefetch) {
      findings.push(finding('WP_EMOJI_DNS_PREFETCH', 'INFO', `${target}/`,
        'DNS prefetch to s.w.org (WordPress emoji CDN) detected — privacy and performance concern', {
          evidence: 'dns-prefetch link to s.w.org found in page head',
          replication_steps: [
            `Visit ${target}/`,
            'View page source and search for "s.w.org"',
          ],
          remediation: 'Remove DNS prefetch by adding remove_action(\'wp_head\', \'wp_resource_hints\', 2) to functions.php. This prevents unnecessary DNS lookups to WordPress servers.',
        }));
    }

    // Check for outdated wp-emoji version (signals old WordPress)
    const emojiVersionMatch = body.match(/wp-emoji-release\.min\.js\?ver=([0-9.]+)/);
    if (emojiVersionMatch) {
      const emojiVer = emojiVersionMatch[1];
      findings.push(finding('WP_EMOJI_VERSION', 'INFO', `${target}/`,
        `WordPress emoji script version ${emojiVer} detected (indicates WordPress version)`, {
          evidence: `wp-emoji-release.min.js?ver=${emojiVer}`,
          replication_steps: [
            `Visit ${target}/`,
            'Check emoji script version parameter',
          ],
          remediation: 'Keep WordPress updated to the latest version. Remove version query strings to reduce fingerprinting.',
        }));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
