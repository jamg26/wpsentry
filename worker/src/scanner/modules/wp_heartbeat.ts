import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Heartbeat API';

const AJAX_PATH = '/wp-admin/admin-ajax.php';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const ajaxUrl = `${target}${AJAX_PATH}`;

  // Test 1: Basic heartbeat without authentication
  // Only flag when response is non-trivial JSON (not "-1", "0", or empty)
  try {
    const body = new URLSearchParams({
      'action': 'heartbeat',
      'data[wp-refresh]': '{"nonce":"test"}',
      '_nonce': 'test',
    }).toString();
    const res = await fetchURL(ajaxUrl, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (res && res.status === 200) {
      const text = (await res.text()).trim();
      const isRejection = ['-1', '0', '', 'false'].includes(text);
      if (!isRejection) {
        findings.push(finding('heartbeat_amplification', 'MEDIUM', ajaxUrl,
          'WordPress Heartbeat API responds with non-trivial data without authentication. ' +
          'This endpoint can be abused for DoS amplification.',
          {
            replication_steps: [
              `curl -s -X POST "${ajaxUrl}" ` +
              '-d "action=heartbeat&data[wp-refresh]={%22nonce%22:%22test%22}&_nonce=test"',
              '# Observe non-empty JSON (not -1) — unauthenticated heartbeat returned data',
            ],
            remediation:
              "Restrict Heartbeat API via add_filter('heartbeat_settings') or " +
              "disable with add_filter('heartbeat_settings', fn($s) => " +
              "{$s['autostart']=false; return $s;}).",
            evidence: `HTTP ${res.status}, body: ${text.slice(0, 100)}`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 2: Large nonce_life payload — amplified response test
  try {
    const body = new URLSearchParams({
      'action': 'heartbeat',
      'data[wp-auth-check]': '1',
      'data[nonce_life]': 'A'.repeat(5000),
      '_nonce': 'test',
    }).toString();
    const res = await fetchURL(ajaxUrl, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (res && res.status === 200) {
      const buf = await res.arrayBuffer();
      if (buf.byteLength > 1024) {
        findings.push(finding('heartbeat_amplification', 'MEDIUM', ajaxUrl,
          `Heartbeat API returned ${buf.byteLength} bytes in response to amplified payload. ` +
          'Could be leveraged for bandwidth amplification DoS.',
          {
            replication_steps: [
              `curl -s -X POST "${ajaxUrl}" ` +
              `-d "action=heartbeat&data[nonce_life]=${'A'.repeat(100)}&_nonce=test" ` +
              '-w "\\nResponse size: %{size_download} bytes"',
            ],
            remediation: 'Rate-limit AJAX requests; disable Heartbeat on non-admin pages.',
            evidence: `Response size: ${buf.byteLength} bytes`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 3: Check if response leaks post data without auth (JSON top-level keys only)
  try {
    const body = new URLSearchParams({
      'action': 'heartbeat',
      'data[postid]': '1',
      '_nonce': 'test',
    }).toString();
    const res = await fetchURL(ajaxUrl, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (res && res.status === 200) {
      const text = (await res.text()).trim();
      if (!['-1', '0', ''].includes(text)) {
        try {
          const data = JSON.parse(text);
          const leakKeywords = ['title', 'content', 'author', 'post_status', 'guid'];
          if (data && typeof data === 'object' && !Array.isArray(data)) {
            const leaked = leakKeywords.filter(kw => kw in data);
            if (leaked.length > 0) {
              findings.push(finding('heartbeat_data_leak', 'HIGH', ajaxUrl,
                `Heartbeat API response leaks post data keys at JSON top level: ${JSON.stringify(leaked)}. ` +
                'Unauthenticated users should not receive post metadata.',
                {
                  replication_steps: [
                    `curl -s -X POST "${ajaxUrl}" ` +
                    '-d "action=heartbeat&data[postid]=1&_nonce=test"',
                    '# Inspect JSON response for post title/content/author fields',
                  ],
                  remediation: 'Ensure Heartbeat handlers validate authentication before returning data.',
                  evidence: `Leaked top-level JSON keys: ${JSON.stringify(leaked)}`,
                },
              ));
            }
          }
        } catch {
          // not valid JSON — no leak
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 4: Measure response size — >5KB unauthenticated = data leak
  try {
    const body = new URLSearchParams({
      'action': 'heartbeat',
      'data[wp-auth-check]': '1',
      '_nonce': 'test',
    }).toString();
    const res = await fetchURL(ajaxUrl, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    if (res && res.status === 200) {
      const buf = await res.arrayBuffer();
      if (buf.byteLength > 5120) {
        findings.push(finding('heartbeat_data_leak', 'HIGH', ajaxUrl,
          `Heartbeat API unauthenticated response exceeds 5KB (${buf.byteLength} bytes). ` +
          'This suggests sensitive data is being returned without authentication.',
          {
            replication_steps: [
              `curl -s -X POST "${ajaxUrl}" ` +
              '-d "action=heartbeat&data[wp-auth-check]=1&_nonce=test" | wc -c',
              '# Response > 5120 bytes unauthenticated = data leak risk',
            ],
            remediation: 'Audit Heartbeat filters; require nonce validation.',
            evidence: `Response size: ${buf.byteLength} bytes (threshold: 5120)`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 5: No-nonce heartbeat skipped — always 200/-1 (known FP)

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
