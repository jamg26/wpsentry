import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Race Condition (WooCommerce Purchase)';

// Send N concurrent requests and check if more succeed than allowed
const CONCURRENCY = 5;

async function sendConcurrent(
  url: string,
  method: string,
  bodyFn: () => string,
  headers: Record<string, string>,
  n: number,
  timeoutMs: number,
): Promise<Array<{ status: number; body: string }>> {
  const promises = Array.from({ length: n }, () =>
    fetchURL(url, {
      method,
      headers,
      body: bodyFn(),
      timeoutMs,
    }).then(async (res) => {
      if (!res) return { status: 0, body: '' };
      const body = await res.text().catch(() => '');
      return { status: res.status, body };
    })
  );
  return Promise.all(promises);
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // First check if WooCommerce is present
    const shopRes = await fetchURL(target + '/shop/', { timeoutMs: 4_000 });
    const cartRes = await fetchURL(target + '/cart/', { timeoutMs: 4_000 });
    const homepageRes = await fetchURL(target + '/', { timeoutMs: 4_000 });
    const homepageBody = homepageRes ? await homepageRes.text().catch(() => '') : '';

    const isWoocommerce =
      (shopRes?.status === 200) ||
      (cartRes?.status === 200) ||
      homepageBody.toLowerCase().includes('woocommerce') ||
      homepageBody.includes('wc-ajax');

    if (!isWoocommerce) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Test 1: Race condition on coupon application
    // Use a test coupon code — we're checking the BEHAVIOR, not extracting real discount
    const couponCode = 'TESTCOUPON99';
    const couponUrl = target + '/?wc-ajax=apply_coupon';

    const couponResults = await sendConcurrent(
      couponUrl,
      'POST',
      () => `coupon_code=${couponCode}`,
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      CONCURRENCY,
      5_000,
    );

    const couponSuccesses = couponResults.filter(r =>
      r.status === 200 && (r.body.includes('"success":true') || r.body.includes('Coupon code applied'))
    ).length;

    if (couponSuccesses > 1) {
      findings.push(finding(
        'RACE_CONDITION_COUPON',
        'HIGH',
        couponUrl,
        `Race condition on coupon application — ${couponSuccesses}/${CONCURRENCY} concurrent requests succeeded (should be max 1 per cart)`,
        {
          evidence: `concurrent_requests=${CONCURRENCY} successes=${couponSuccesses} coupon="${couponCode}"`,
          remediation: 'Use database-level locking (SELECT ... FOR UPDATE) when applying coupons. Add usage limit checks with atomic operations.',
        },
      ));
    }

    // Test 2: Race condition on add-to-cart with limited stock
    // We don't have a real product ID, so we probe with a common one
    const productIds = ['1', '2', '3', '10', '100'];
    for (const productId of productIds.slice(0, 2)) {
      const addToCartUrl = target + '/?wc-ajax=add_to_cart';
      const addResults = await sendConcurrent(
        addToCartUrl,
        'POST',
        () => `product_id=${productId}&quantity=1`,
        { 'Content-Type': 'application/x-www-form-urlencoded' },
        CONCURRENCY,
        5_000,
      );

      const addSuccesses = addResults.filter(r =>
        r.status === 200 && (r.body.includes('"error":false') || r.body.includes('added to cart') || r.body.includes('"fragments"'))
      ).length;

      // MED-FP-1: Downgraded from MEDIUM to INFO.
      // "fragments" always appears in WooCommerce add-to-cart AJAX responses (it's a
      // normal cart fragment update), so this check was firing on every WooCommerce site.
      // Genuine stock-limit bypass requires authenticated testing with real product IDs.
      if (addSuccesses >= CONCURRENCY) {
        findings.push(finding(
          'RACE_CONDITION_ADD_TO_CART',
          'INFO',
          addToCartUrl,
          `Add-to-cart endpoint returns success for all ${CONCURRENCY} concurrent requests for product ${productId} — review with authenticated session to confirm stock limit bypass`,
          {
            evidence: `concurrent_requests=${CONCURRENCY} successes=${addSuccesses} product_id="${productId}"`,
            remediation: 'Implement stock reservation with optimistic locking. Use WooCommerce stock management with database row locking. Verify manually with authenticated session and a product with stock limits.',
          },
        ));
        break;
      }
    }

    // Test 3: Race condition on checkout/payment completion
    const checkoutUrl = target + '/checkout/';
    const checkoutRes = await fetchURL(checkoutUrl, { timeoutMs: 4_000 });

    if (checkoutRes?.status === 200) {
      // Just detect the checkout is accessible — actual payment race requires session state
      findings.push(finding(
        'RACE_CONDITION_CHECKOUT_ACCESSIBLE',
        'INFO',
        checkoutUrl,
        `WooCommerce checkout is accessible — race condition on payment completion should be tested manually with authenticated sessions`,
        {
          evidence: `status=200 checkout_accessible=true`,
          remediation: 'Ensure payment completion endpoint uses idempotency keys. Test with concurrent payment completion requests in authenticated test environment.',
        },
      ));
    }

    // Test 4: Race condition on WooCommerce order creation (concurrent orders)
    const orderUrl = target + '/?wc-ajax=checkout';
    const orderResults = await sendConcurrent(
      orderUrl,
      'POST',
      () => 'payment_method=cod&ship_to_different_address=0&terms=1&woocommerce_checkout_nonce=invalid',
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      3,
      5_000,
    );

    const orderSuccess = orderResults.filter(r =>
      r.status === 200 && (r.body.includes('"result":"success"') || r.body.includes('order-received'))
    ).length;

    if (orderSuccess > 0) {
      findings.push(finding(
        'RACE_CONDITION_ORDER_CREATION',
        'HIGH',
        orderUrl,
        `WooCommerce order creation succeeded without valid nonce — ${orderSuccess} concurrent orders processed`,
        {
          evidence: `concurrent=3 successes=${orderSuccess}`,
          remediation: 'Enforce nonce validation on all checkout endpoints. Use WooCommerce session locking for order creation.',
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
