import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'RSS/Atom Feed Exposure';

const FEED_PATHS = [
  '/feed/',
  '/feed/atom/',
  '/feed/rdf/',
  '/comments/feed/',
  '/wp-json/wp/v2/posts?per_page=5',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(FEED_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      // Check for author/user info leakage
      const authorMatches = body.match(/<dc:creator><!\[CDATA\[([^\]]+)\]\]>/gi) ??
                           body.match(/<author>[\s\S]*?<name>([^<]+)<\/name>/gi);
      if (authorMatches && authorMatches.length > 0) {
        const authors = new Set<string>();
        for (const m of authorMatches) {
          const nameMatch = m.match(/\[CDATA\[([^\]]+)\]\]/) ?? m.match(/<name>([^<]+)<\/name>/);
          if (nameMatch) authors.add(nameMatch[1]);
        }
        if (authors.size > 0) {
          findings.push(finding('FEED_AUTHOR_DISCLOSURE', 'INFO', url,
            `RSS feed exposes ${authors.size} author username(s): ${Array.from(authors).slice(0, 5).join(', ')}`, {
              evidence: `Authors found in feed: ${Array.from(authors).join(', ')}`,
              replication_steps: [
                `Fetch ${url}`,
                'Parse XML for <dc:creator> or <author><name> elements',
              ],
              remediation: 'Use a plugin to replace usernames with display names in feeds, or disable feeds if not needed.',
            }));
        }
      }

      // Check for internal URLs that shouldn't be exposed
      const internalPatterns = [
        /https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/gi,
        /https?:\/\/[^"<\s]+\.local[/"<\s]/gi,
        /https?:\/\/[^"<\s]+\.staging[/"<\s]/gi,
        /https?:\/\/[^"<\s]+\.dev[/"<\s]/gi,
      ];
      for (const pattern of internalPatterns) {
        const internalMatch = body.match(pattern);
        if (internalMatch) {
          findings.push(finding('FEED_INTERNAL_URL_LEAK', 'MEDIUM', url,
            `Feed contains internal/staging URL: ${internalMatch[0].slice(0, 80)}`, {
              evidence: `Internal URL found: ${internalMatch[0]}`,
              replication_steps: [
                `Fetch ${url}`,
                'Search for internal IP addresses or staging domains',
              ],
              remediation: 'Ensure all URLs in feeds point to the production domain. Run a search-and-replace to fix internal URLs.',
            }));
          break;
        }
      }

      // Check for email addresses in feed content
      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const emails = body.match(emailPattern);
      if (emails && emails.length > 0) {
        const uniqueEmails = [...new Set(emails)].slice(0, 5);
        findings.push(finding('FEED_EMAIL_DISCLOSURE', 'LOW', url,
          `Feed exposes ${uniqueEmails.length} email address(es)`, {
            evidence: `Emails found: ${uniqueEmails.join(', ')}`,
            replication_steps: [
              `Fetch ${url}`,
              'Search for email addresses in the feed content',
            ],
            remediation: 'Avoid publishing email addresses in post content or author metadata.',
          }));
      }
    }, 5);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
