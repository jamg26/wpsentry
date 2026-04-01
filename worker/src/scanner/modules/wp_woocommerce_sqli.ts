import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'WooCommerce SQL Injection';

// SQL error indicators
const SQL_ERRORS = [
  'you have an error in your sql syntax',
  'warning: mysql',
  'mysqli_fetch',
  'pg_query',
  'sqlite3',
  'ora-01756',
  'sqlstate',
  'mariadb server version',
  'mysql server version',
  'supplied argument is not a valid mysql',
  'division by zero',
  "table doesn't exist",
  'unknown column',
  'unrecognized token',
  'syntax error',
];

function hasSqlError(body: string): boolean {
  const lower = body.toLowerCase();
  return SQL_ERRORS.some(e => lower.includes(e));
}

// WooCommerce-specific SQL injection test vectors
const WC_SQLI_PROBES: Array<[string, string]> = [
  // Product category/taxonomy
  ["/?product_cat=1 AND 1=1--",               'product_cat_bool_true'],
  ["/?product_cat=1 AND 1=2--",               'product_cat_bool_false'],
  ["/?product_cat=1'",                        'product_cat_quote'],
  // Orderby injection
  ["/?orderby=rand(1=1)",                     'orderby_rand_inject'],
  ["/?orderby=1,2",                           'orderby_multi'],
  // Price filter
  ["/shop/?min_price=1 UNION SELECT 1,2,3--", 'min_price_union'],
  ["/shop/?max_price=1'",                     'max_price_quote'],
  ["/shop/?min_price=0&max_price=1' OR 1=1--", 'price_range_or'],
  // WC order params
  ["/?post_type=product&s=1' UNION SELECT NULL--", 'product_search_union'],
  // Product attribute filter
  ["/?pa_color=red' AND SLEEP(0)--",          'attribute_sleep'],
  // CVE-2023-28121 style — coupon endpoint
  ['/?wc-ajax=apply_coupon',                  'coupon_ajax'],
  // Order by product attribute
  ["/?orderby=price&order=1' AND '1'='1",     'order_attr_inject'],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // First, check if WooCommerce is present
    const shopRes = await fetchURL(target + '/shop/', { timeoutMs: 4_000 });
    const homepageRes = await fetchURL(target + '/', { timeoutMs: 4_000 });
    const homepageBody = homepageRes ? await homepageRes.text().catch(() => '') : '';

    const isWoocommerce =
      (shopRes && shopRes.status === 200) ||
      homepageBody.toLowerCase().includes('woocommerce') ||
      homepageBody.includes('wc-ajax');

    if (!isWoocommerce) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Baseline: fetch safe endpoints to get baseline response codes/body lengths
    const baselines = new Map<string, { status: number; len: number }>();

    // Get safe baselines
    const safeProbes: Array<[string, string]> = [
      ['/?product_cat=1', 'product_cat'],
      ['/shop/', 'shop'],
    ];

    for (const [path, key] of safeProbes) {
      const res = await fetchURL(target + path, { timeoutMs: 4_000 });
      if (res) {
        const body = await res.text().catch(() => '');
        baselines.set(key, { status: res.status, len: body.length });
      }
    }

    const seen = new Set<string>();

    await parallelProbe(WC_SQLI_PROBES, async ([path, label]) => {
      if (seen.has(label)) return;
      const url = target + path;

      const res = await fetchURL(url, { timeoutMs: 5_000 });
      if (!res) return;

      const body = await res.text().catch(() => '');
      const bodyLower = body.toLowerCase();

      // Check for SQL error
      if (hasSqlError(body)) {
        if (!seen.has(label)) {
          seen.add(label);
          findings.push(finding(
            'WOOCOMMERCE_SQLI',
            'CRITICAL',
            url,
            `WooCommerce SQL injection — SQL error triggered via '${label}' parameter`,
            {
              evidence: `label="${label}" error="${SQL_ERRORS.find(e => bodyLower.includes(e)) ?? 'sql_error'}"`,
              remediation: 'Update WooCommerce to latest version. Use $wpdb->prepare() for all queries. Install Wordfence or Sucuri WAF.',
            },
          ));
        }
        return;
      }

      // Boolean-based: compare true vs false responses
      if (label === 'product_cat_bool_true') {
        const baseline = baselines.get('product_cat');
        if (baseline && res.status === baseline.status) {
          // Now test false condition
          const falseRes = await fetchURL(target + '/?product_cat=1 AND 1=2--', { timeoutMs: 5_000 });
          if (falseRes) {
            const falseBody = await falseRes.text().catch(() => '');
            // True should return products, false should return empty
            const lenDiff = Math.abs(body.length - falseBody.length);
            if (lenDiff > 200 && body.length > falseBody.length) {
              findings.push(finding(
                'WOOCOMMERCE_BOOLEAN_SQLI',
                'HIGH',
                url,
                `WooCommerce boolean-based SQLi indicator on product_cat — true/false conditions produce different responses (${lenDiff} bytes diff)`,
                {
                  evidence: `true_len=${body.length} false_len=${falseBody.length} diff=${lenDiff}`,
                  remediation: 'Use $wpdb->prepare() for all taxonomy queries. Update WooCommerce to latest version.',
                },
              ));
            }
          }
        }
      }

      // CVE-2023-28121 pattern: Check for WooCommerce coupon authentication bypass
      if (label === 'coupon_ajax') {
        const couponRes = await fetchURL(target + '/?wc-ajax=apply_coupon', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-HTTP-Method-Override': 'PUT',
          },
          body: "coupon_code=1' OR 1=1--",
          timeoutMs: 5_000,
        });

        if (couponRes && couponRes.status !== 404) {
          const couponBody = await couponRes.text().catch(() => '');
          if (hasSqlError(couponBody)) {
            findings.push(finding(
              'WOOCOMMERCE_CVE_2023_28121',
              'CRITICAL',
              target + '/?wc-ajax=apply_coupon',
              `WooCommerce CVE-2023-28121 style SQL injection in coupon endpoint`,
              {
                evidence: `status=${couponRes.status} sql_error_present=true`,
                remediation: 'Update WooCommerce immediately. This CVE allows unauthenticated SQLi. Apply CVE-2023-28121 patch.',
              },
            ));
          }
        }
      }
    }, 15);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
