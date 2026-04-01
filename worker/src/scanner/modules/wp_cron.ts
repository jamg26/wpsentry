import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'WP-Cron';

const CRON_PATH         = '/wp-cron.php';
const CRON_TRIGGER_PATH = '/wp-cron.php?doing_wp_cron=1&timestamp=0';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const cronUrl = `${target}${CRON_PATH}`;
  let accessible = false;

  try {
    // Test 1: Basic cron accessibility
    const res = await fetchURL(cronUrl);
    if (res && res.status === 200) {
      accessible = true;
      findings.push(finding('wpcron_dos', 'LOW', cronUrl,
        'wp-cron.php is publicly accessible. Any visitor can trigger scheduled tasks, ' +
        'potentially causing resource exhaustion.',
        {
          replication_steps: [
            `curl -s -o /dev/null -w "%{http_code}" "${cronUrl}"`,
            '# Expected: 200 — cron is triggerable without authentication',
          ],
          remediation:
            "Disable wp-cron.php public access by adding " +
            "define('DISABLE_WP_CRON', true) to wp-config.php and set up a real " +
            'system cron job instead.',
          evidence: `HTTP ${res.status} from ${cronUrl}`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 2: Sequential latency measurement to detect DoS degradation
  // HIGH-12: Replaced parallel requests (which measured wall-clock, not per-request latency)
  // with sequential requests so each latency sample is meaningful.
  if (accessible) {
    try {
      const latencies: number[] = [];
      for (let i = 0; i < 5; i++) {
        const start = Date.now();
        await fetchURL(cronUrl, { timeoutMs: 10_000 });
        latencies.push(Date.now() - start);
      }
      const first = latencies[0];
      const last = latencies[latencies.length - 1];
      const degradation = last / Math.max(first, 1);
      if (degradation > 3 && last > 3000) {
        findings.push(finding('wpcron_dos', 'HIGH', cronUrl,
          `WP-Cron sequential requests show latency degradation (${first}ms → ${last}ms, ${degradation.toFixed(1)}x). ` +
          'This indicates DoS amplification potential.',
          {
            replication_steps: [
              `for i in $(seq 1 5); do curl -s -o /dev/null -w "%{time_total}\\n" "${cronUrl}"; done`,
              '# Observe latency increasing across sequential requests',
            ],
            remediation: 'Disable public cron access. Rate-limit or block wp-cron.php.',
            evidence: `latencies=[${latencies.join(',')}]ms first=${first}ms last=${last}ms degradation=${degradation.toFixed(1)}x`,
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  // Test 3: Trigger all jobs via timestamp=0
  if (accessible) {
    const triggerUrl = `${target}${CRON_TRIGGER_PATH}`;
    try {
      const res = await fetchURL(triggerUrl);
      if (res && res.status === 200) {
        findings.push(finding('wpcron_dos', 'MEDIUM', triggerUrl,
          'Cron job trigger endpoint accessible with timestamp=0 — all overdue jobs can be forced.',
          {
            replication_steps: [
              `curl -s -o /dev/null -w "%{http_code} %{time_total}s" "${triggerUrl}"`,
            ],
            remediation: 'Disable public cron or restrict wp-cron.php via .htaccess/nginx.',
            evidence: `HTTP ${res.status}`,
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  // Test 4: Check for scheduled task name leakage in response body
  if (accessible) {
    try {
      const res = await fetchURL(cronUrl);
      if (res && res.status === 200) {
        const body = (await res.text()).trim();
        const isHtmlPage = body.toLowerCase().startsWith('<!doctype') ||
          body.toLowerCase().slice(0, 200).includes('<html');
        if (body.length > 200 && !isHtmlPage) {
          findings.push(finding('wpcron_dos', 'MEDIUM', cronUrl,
            `WP-Cron response body is non-empty (${body.length} bytes) and not a standard ` +
            'HTML page — may leak scheduled task output or debug information.',
            {
              replication_steps: [
                `curl -s "${cronUrl}"`,
                '# Observe any leaked hook names or debug output',
              ],
              remediation: 'Suppress cron output; disable public cron access.',
              evidence: body.slice(0, 200),
            },
          ));
        }
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  // Test 5: /?doing_wp_cron=1 skipped — always returns 200 (known FP)

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
