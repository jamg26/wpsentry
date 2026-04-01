import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Webhook Security Scanner';

const WEBHOOK_PATHS = [
  '/wp-json/wp/v2/webhooks',
  '/wp-json/wc/v3/webhooks',
  '/wp-json/wc/v2/webhooks',
  '/?wc-api=wc_gateway_paypal',
  '/?wc-api=WC_Gateway_Stripe',
  '/wp-json/jetpack/v4/webhooks',
  '/wp-admin/admin-ajax.php?action=webhook_handler',
  '/?webhook',
  '/webhook',
  '/webhooks',
  '/wp-json/zapier/v1/hooks',
  '/wp-cron.php',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(WEBHOOK_PATHS, async (path) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url);
      if (!res) return;
      const body = await res.text();

      // WooCommerce webhook listing
      if (path.includes('wc/v') && path.includes('webhooks') && res.status === 200) {
        try {
          const data = JSON.parse(body);
          if (Array.isArray(data) && data.length > 0) {
            findings.push(finding('WEBHOOK_LIST_EXPOSED', 'HIGH', url,
              `WooCommerce webhook list exposed — ${data.length} webhook(s) visible`, {
                evidence: `${data.length} webhook configurations returned without authentication`,
                replication_steps: [
                  `Fetch ${url}`,
                  'Observe webhook delivery URLs and configurations',
                ],
                remediation: 'Restrict webhook API endpoints to authenticated administrators only.',
              }));
          }
        } catch { /* not JSON */ }
      }

      // PayPal/Stripe callback endpoints
      if (path.includes('wc-api=') && res.status === 200 && body.length > 100) {
        if (!body.includes('error') && !body.includes('invalid')) {
          findings.push(finding('PAYMENT_WEBHOOK_EXPOSED', 'MEDIUM', url,
            'Payment gateway webhook endpoint is accessible — verify signature validation is in place', {
              evidence: `Payment webhook at ${path} returned ${res.status} status`,
              replication_steps: [
                `Fetch ${url}`,
                'Verify the endpoint validates webhook signatures',
              ],
              remediation: 'Ensure all payment webhook endpoints validate signatures from the payment provider. Never trust webhook data without verification.',
            }));
        }
      }

      // Generic webhook endpoints that shouldn't be exposed
      if ((path === '/webhook' || path === '/webhooks') && res.status === 200) {
        if (body.length > 50 && !body.includes('404') && !body.includes('not found')) {
          findings.push(finding('WEBHOOK_ENDPOINT_EXPOSED', 'LOW', url,
            'Generic webhook endpoint detected — verify authentication is required', {
              evidence: `Webhook endpoint at ${path} returned ${body.length} bytes`,
              replication_steps: [`Fetch ${url}`, 'Check if the endpoint accepts arbitrary webhook data'],
              remediation: 'Ensure webhook endpoints validate request signatures and restrict access.',
            }));
        }
      }
    }, 6);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
