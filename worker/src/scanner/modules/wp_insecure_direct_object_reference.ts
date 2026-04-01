import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Insecure Direct Object Reference (Enhanced)';

// NOTE: wp_idor.ts covers basic post ID and user IDOR.
// This module adds: draft/private post enumeration, media IDOR, comment IDOR,
// user profile data leaks, and order IDOR for WooCommerce.

interface WpPost {
  id?: number;
  title?: { rendered?: string };
  status?: string;
  content?: { rendered?: string };
  author?: number;
}

interface WpUser {
  id?: number;
  name?: string;
  slug?: string;
  email?: string;
  roles?: string[];
  capabilities?: Record<string, boolean>;
}

interface WpMedia {
  id?: number;
  source_url?: string;
  title?: { rendered?: string };
  media_type?: string;
}

interface WpComment {
  id?: number;
  author_name?: string;
  author_email?: string;
  content?: { rendered?: string };
  status?: string;
}

const MAX_ID_PROBE = 10; // Check first N IDs for each type — reduced from 20 to fit 25s budget

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // 1. User profile IDOR — enumerate first N user IDs
    const userEmails: string[] = [];
    const userRoles: Array<{ id: number; role: string }> = [];

    await parallelProbe(
      Array.from({ length: MAX_ID_PROBE }, (_, i) => i + 1),
      async (id) => {
        const user = await getJSON<WpUser>(`${target}/wp-json/wp/v2/users/${id}`);
        if (!user?.id) return;

        if (user.email) userEmails.push(user.email);
        if (user.roles && user.roles.length > 0) {
          user.roles.forEach(role => userRoles.push({ id: user.id!, role }));
        }
        // capabilities leak
        if (user.capabilities && Object.keys(user.capabilities).length > 0) {
          const caps = Object.keys(user.capabilities).slice(0, 3).join(', ');
          findings.push(finding(
            'IDOR_USER_CAPABILITIES_EXPOSED',
            'HIGH',
            `${target}/wp-json/wp/v2/users/${id}`,
            `User ID ${id} capabilities exposed via REST API: ${caps}`,
            {
              evidence: `user_id=${id} name="${user.name}" capabilities="${caps}"`,
              remediation: 'Remove capabilities from public REST API user responses. Use "show_in_rest: false" for sensitive user meta fields.',
            },
          ));
        }
      },
      10,
    );

    if (userEmails.length > 0) {
      findings.push(finding(
        'IDOR_USER_EMAIL_EXPOSED',
        'HIGH',
        `${target}/wp-json/wp/v2/users`,
        `${userEmails.length} user email(s) accessible via REST API user enumeration`,
        {
          evidence: `emails="${userEmails.slice(0, 3).join(', ')}"`,
          remediation: 'Use "show_in_rest: false" for email field, or restrict with "rest_prepare_user" filter. Install a REST API access control plugin.',
        },
      ));
    }

    // 2. Post IDOR — check for private/draft posts accessible without auth
    const privatePosts: Array<{ id: number; status: string; title: string }> = [];

    await parallelProbe(
      Array.from({ length: 20 }, (_, i) => i + 1), // reduced from 50
      async (id) => {
        const post = await getJSON<WpPost>(`${target}/wp-json/wp/v2/posts/${id}`);
        if (!post?.id) return;

        const status = post.status ?? 'unknown';
        if (status === 'private' || status === 'draft' || status === 'pending') {
          privatePosts.push({
            id: post.id,
            status,
            title: post.title?.rendered ?? 'unknown',
          });
        }
      },
      15,
    );

    if (privatePosts.length > 0) {
      findings.push(finding(
        'IDOR_PRIVATE_POST_ACCESS',
        'HIGH',
        `${target}/wp-json/wp/v2/posts`,
        `${privatePosts.length} private/draft post(s) accessible via REST API without authentication`,
        {
          evidence: `posts="${JSON.stringify(privatePosts.slice(0, 3))}"`,
          remediation: 'Restrict REST API access to private/draft posts. Use "post_status" visibility controls and authentication middleware.',
        },
      ));
    }

    // 3. Media IDOR — enumerate attachment IDs for sensitive file URLs
    const sensitiveMedia: Array<{ id: number; url: string }> = [];

    await parallelProbe(
      Array.from({ length: 15 }, (_, i) => i + 1), // reduced from 30
      async (id) => {
        const media = await getJSON<WpMedia>(`${target}/wp-json/wp/v2/media/${id}`);
        if (!media?.id || !media.source_url) return;

        // Flag if media type suggests sensitive content
        const url = media.source_url;
        if (url.match(/\.(pdf|doc|docx|xls|xlsx|csv|sql|backup|bak)$/i)) {
          sensitiveMedia.push({ id: media.id, url });
        }
      },
      10,
    );

    if (sensitiveMedia.length > 0) {
      findings.push(finding(
        'IDOR_SENSITIVE_MEDIA_EXPOSED',
        'HIGH',
        `${target}/wp-json/wp/v2/media`,
        `${sensitiveMedia.length} potentially sensitive media file(s) enumerable via REST API`,
        {
          evidence: `files="${sensitiveMedia.slice(0, 3).map(m => m.url).join(', ')}"`,
          remediation: 'Protect sensitive uploaded documents. Add authentication to media REST API endpoints. Use signed URLs for sensitive files.',
        },
      ));
    }

    // 4. Comment IDOR — check for unapproved/spam comments
    await parallelProbe(
      Array.from({ length: 10 }, (_, i) => i + 1), // reduced from 20
      async (id) => {
        const comment = await getJSON<WpComment>(`${target}/wp-json/wp/v2/comments/${id}`);
        if (!comment?.id) return;

        if (comment.status === 'hold' || comment.status === 'spam') {
          const email = comment.author_email ?? '';
          findings.push(finding(
            'IDOR_COMMENT_UNAPPROVED',
            'MEDIUM',
            `${target}/wp-json/wp/v2/comments/${id}`,
            `Unapproved/spam comment accessible via REST API IDOR — author email may be exposed`,
            {
              evidence: `comment_id=${id} status="${comment.status}" has_email=${!!email}`,
              remediation: 'Restrict access to unapproved comments in REST API. Use "rest_comment_query" filter to hide pending/spam comments.',
            },
          ));
        }
      },
      10,
    );

    // 5. WooCommerce order IDOR
    const wcOrderStatuses: string[] = [];
    await parallelProbe(
      Array.from({ length: 10 }, (_, i) => i + 1), // reduced from 20
      async (id) => {
        const res = await fetchURL(`${target}/wp-json/wc/v3/orders/${id}`, { timeoutMs: 4_000 });
        if (!res || res.status === 404 || res.status === 401 || res.status === 403) return;
        const body = await res.text().catch(() => '');
        if (body.includes('"billing"') || body.includes('"shipping"')) {
          wcOrderStatuses.push(`order_id=${id}`);
        }
      },
      10,
    );

    if (wcOrderStatuses.length > 0) {
      findings.push(finding(
        'IDOR_WOOCOMMERCE_ORDER',
        'CRITICAL',
        `${target}/wp-json/wc/v3/orders`,
        `WooCommerce order data accessible without authentication — ${wcOrderStatuses.length} order(s) enumerated`,
        {
          evidence: `orders="${wcOrderStatuses.slice(0, 5).join(', ')}"`,
          remediation: 'Require authentication for all WooCommerce REST API order endpoints. Use WC API keys with proper scoping.',
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
