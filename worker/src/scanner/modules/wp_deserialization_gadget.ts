import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Phar Deserialization / File Upload Chain';

// Common upload endpoints
const UPLOAD_ENDPOINTS = [
  '/wp-admin/async-upload.php',
  '/wp-json/wp/v2/media',
  '/wp-admin/admin-ajax.php?action=upload-attachment',
  '/wp-content/plugins/wp-file-upload/lib/php/upload.php',
  '/wp-content/plugins/file-manager-advanced/upload.php',
];

// Polyglot and phar-related test filenames
const PHAR_TEST_NAMES = [
  'test.phar',
  'test.phar.jpg',
  'test.jpg.phar',
  'test.pHaR',
  'test.phar%00.jpg',
  'test.php.phar',
];

// Error patterns indicating file processing (possible deserialization)
const PHAR_INDICATORS = [
  'phar://',
  'phar file',
  '__HALT_COMPILER',
  'serialized data',
  'Phar',
  'UnexpectedValueException',
  'phar_parse_metadata',
];

// WordPress file upload filter indicators
const WP_UPLOAD_INDICATORS = [
  'wp_handle_upload',
  'wp_upload_dir',
  'application/octet-stream',
  'multipart/form-data',
];

// Check if .phar extension is explicitly allowed or if extension filtering is weak
const WEAK_UPLOAD_RESPONSE_INDICATORS = [
  '"url":', // successful upload returns URL
  '"source_url":', // WP media upload response
  '"id":', // media item ID returned
  'File uploaded',
  'successfully uploaded',
  'upload_success',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Test REST API media endpoint without authentication
    const mediaRes = await fetchURL(target + '/wp-json/wp/v2/media', {
      method: 'OPTIONS',
      timeoutMs: 4_000,
    });

    if (mediaRes) {
      const allow = mediaRes.headers.get('Allow') ?? '';
      const accessControl = mediaRes.headers.get('Access-Control-Allow-Methods') ?? '';
      const text = await mediaRes.text().catch(() => '');

      if (allow.includes('POST') || accessControl.includes('POST')) {
        // Try uploading a PHAR file unauthenticated
        const boundary = '----JWPScannerBoundary7x9k';
        const pharContent = '<?php __HALT_COMPILER(); ?>';
        const formData = [
          `--${boundary}`,
          'Content-Disposition: form-data; name="file"; filename="test.phar"',
          'Content-Type: application/octet-stream',
          '',
          pharContent,
          `--${boundary}--`,
        ].join('\r\n');

        const uploadRes = await fetchURL(target + '/wp-json/wp/v2/media', {
          method: 'POST',
          headers: {
            'Content-Type': `multipart/form-data; boundary=${boundary}`,
          },
          body: formData,
          timeoutMs: 5_000,
        });

        if (uploadRes) {
          const uploadBody = await uploadRes.text().catch(() => '');
          const uploadBodyLower = uploadBody.toLowerCase();

          const successInd = WEAK_UPLOAD_RESPONSE_INDICATORS.find(ind => uploadBody.includes(ind));
          if (uploadRes.status === 201 || successInd) {
            findings.push(finding(
              'PHAR_UPLOAD_UNAUTH',
              'CRITICAL',
              target + '/wp-json/wp/v2/media',
              `Unauthenticated PHAR file upload may be possible — REST media endpoint accepted upload without authentication`,
              {
                evidence: `status=${uploadRes.status} indicator="${successInd ?? 'HTTP 201'}" allow="${allow}"`,
                remediation: 'Require authentication for media uploads. Blacklist .phar extension in upload filters. Use wp_check_filetype_and_ext().',
              },
            ));
          }

          const pharInd = PHAR_INDICATORS.find(ind => uploadBodyLower.includes(ind.toLowerCase()));
          if (pharInd) {
            findings.push(finding(
              'PHAR_DESERIALIZATION_INDICATOR',
              'HIGH',
              target + '/wp-json/wp/v2/media',
              `PHAR deserialization indicator in upload response: '${pharInd}'`,
              {
                evidence: `indicator="${pharInd}" status=${uploadRes.status}`,
                remediation: 'Disable phar stream wrapper if not needed. Validate file contents, not just extensions.',
              },
            ));
          }
        }
      }
    }

    // Check if ajax upload endpoint is accessible without auth
    const ajaxUploadRes = await fetchURL(target + '/wp-admin/async-upload.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'action=upload-attachment&_wpnonce=invalid',
      timeoutMs: 4_000,
    });

    if (ajaxUploadRes && ajaxUploadRes.status !== 403) {
      const ajaxBody = await ajaxUploadRes.text().catch(() => '');
      if (!ajaxBody.includes('not allowed') && !ajaxBody.includes('insufficient permissions')) {
        findings.push(finding(
          'PHAR_ASYNC_UPLOAD_ACCESSIBLE',
          'MEDIUM',
          target + '/wp-admin/async-upload.php',
          `async-upload.php responds without authentication gate (HTTP ${ajaxUploadRes.status}) — PHAR file upload chains may be possible`,
          {
            evidence: `status=${ajaxUploadRes.status} body_prefix="${ajaxBody.slice(0, 100)}"`,
            remediation: 'Ensure wp-admin/async-upload.php requires authentication. Add nonce verification to all upload handlers.',
          },
        ));
      }
    }

    // Check for vulnerable file upload plugins
    const pluginPaths = [
      '/wp-content/plugins/wp-file-upload/readme.txt',
      '/wp-content/plugins/file-manager-advanced/readme.txt',
      '/wp-content/plugins/fancy-file-uploader/readme.txt',
    ];

    await parallelProbe(pluginPaths, async (path) => {
      const res = await fetchURL(target + path, { timeoutMs: 3_000 });
      if (res?.status !== 200) return;
      const text = await res.text().catch(() => '');
      if (!text.includes('Stable tag:')) return;

      const slug = path.match(/plugins\/([^/]+)\//)?.[1] ?? 'unknown';
      const version = text.match(/Stable tag:\s*([\d.]+)/i)?.[1] ?? 'unknown';

      findings.push(finding(
        'FILE_UPLOAD_PLUGIN_DETECTED',
        'MEDIUM',
        target + path,
        `File upload plugin '${slug}' v${version} detected — verify it blocks PHAR/PHP file extensions and prevents deserialization`,
        {
          evidence: `slug="${slug}" version="${version}"`,
          remediation: `Ensure ${slug} validates file extensions and MIME types. Disable phar:// stream wrapper.`,
        },
      ));
    }, 5);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
