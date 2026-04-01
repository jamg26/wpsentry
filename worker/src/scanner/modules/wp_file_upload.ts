import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'File Upload Vulnerability Check';

// (filename, content, contentType, extLabel)
const TEST_FILES: [string, string, string, string][] = [
  ['jwp_test.php',   "<?php echo 'JWP_PHP_TEST'; ?>",                         'application/x-php',       'php'],
  ['jwp_test.php5',  "<?php echo 'JWP_PHP_TEST'; ?>",                         'application/x-php',       'php'],
  ['jwp_test.phtml', "<?php echo 'JWP_PHP_TEST'; ?>",                         'application/x-php',       'php'],
  ['jwp_test.asp',   '<% Response.Write("JWP") %>',                           'text/plain',              'asp'],
  ['jwp_test.aspx',  '<% Response.Write("JWP") %>',                           'text/plain',              'aspx'],
  ['jwp_test.html',  '<script>alert(1)</script>',                             'text/html',               'html'],
  ['jwp_test.svg',   '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>', 'image/svg+xml',    'svg'],
  ['jwp_test.js',    "alert('JWP_JS_TEST');",                                 'application/javascript',  'js'],
];

const UPLOAD_ENDPOINTS = [
  '/wp-json/wp/v2/media',
  '/wp-admin/async-upload.php',
  '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php',
  '/wp-content/plugins/file-manager-advanced/inc/',
  '/wp-content/plugins/mobile-app-builder-by-wappress/views/createpageapi.php',
  '/wp-content/plugins/wp-symposium/server/file_upload_form.php',
  '/wp-content/plugins/candidate-application-form/wp-downloadpdf.php',
  '/wp-content/plugins/video-conferencing-with-zoom-api/includes/vendor/action.php',
];

const JSON_SUCCESS_KEYWORDS = ['"url"', '"file"', '"path"', '"success":true', '"location"', '"id"'];

async function probeUploadEndpoint(
  base: string,
  endpoint: string,
  findings: Finding[],
  errors: string[],
): Promise<void> {
  const url = `${base}${endpoint}`;

  // First check if endpoint is reachable (non-404)
  const check = await fetchURL(url);
  if (!check || check.status === 404) return;

  await parallelProbe(TEST_FILES, async ([filename, content, contentType, extLabel]) => {
    try {
      const formData = new FormData();
      const blob = new Blob([content], { type: contentType });
      formData.append('file', blob, filename);

      const res = await fetchURL(url, { method: 'POST', body: formData });
      if (!res) return;

      let body: string;
      try { body = await res.text(); } catch { return; }

      const bodyLower = body.toLowerCase();
      const respContentType = res.headers.get('Content-Type') ?? '';

      const redirectedToLogin = (
        res.url.includes('wp-login') ||
        bodyLower.slice(0, 500).includes('wp-login') ||
        bodyLower.slice(0, 500).includes('log in')
      );

      const isJson = respContentType.includes('application/json') || bodyLower.trimStart().startsWith('{');

      const accepted = (
        [200, 201].includes(res.status) &&
        !redirectedToLogin &&
        isJson &&
        JSON_SUCCESS_KEYWORDS.some(kw => bodyLower.includes(kw)) &&
        !bodyLower.slice(0, 50).includes('error')
      );

      if (accepted) {
        findings.push(finding(
          'DANGEROUS_FILE_UPLOAD_ACCEPTED',
          'CRITICAL',
          url,
          `Endpoint accepted ${extLabel.toUpperCase()} upload without authentication: ${endpoint}`,
          { evidence: `filename: ${filename}; content_type: ${contentType}` },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  });
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(UPLOAD_ENDPOINTS, async (endpoint) => {
      await probeUploadEndpoint(target, endpoint, findings, errors);
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
