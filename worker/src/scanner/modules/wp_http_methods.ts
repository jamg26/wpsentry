import type { ModuleResult, ScanState } from '../types.js';
import type { Severity } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, HEADERS , parallelProbe } from '../utils.js';

const MODULE_NAME = 'Dangerous HTTP Methods';

const DANGEROUS_METHODS: [string, Severity, string][] = [
  ['TRACE',    'HIGH',   'Cross-Site Tracing (XST) — headers reflected, may expose auth cookies'],
  ['PUT',      'HIGH',   'HTTP PUT enabled — potential file upload/overwrite'],
  ['DELETE',   'HIGH',   'HTTP DELETE enabled — potential file deletion'],
  ['PROPFIND', 'MEDIUM', 'WebDAV PROPFIND enabled — may expose internal directory structure'],
  ['MKCOL',    'MEDIUM', 'WebDAV MKCOL enabled — potential directory creation'],
  ['MOVE',     'MEDIUM', 'WebDAV MOVE enabled — potential file move/rename'],
  ['PATCH',    'LOW',    'HTTP PATCH enabled — partial resource modification possible'],
];

const PROBE_PATHS = ['/', '/wp-content/uploads/', '/wp-admin/'];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    // OPTIONS probe — check declared allowed methods
    try {
      const r = await fetchURL(target + '/', { method: 'OPTIONS', redirect: 'manual' });
      if (r) {
        const allow = (r.headers.get('allow') ?? '') + (r.headers.get('public') ?? '');
        if (allow) {
          for (const [method, severity, desc] of DANGEROUS_METHODS) {
            if (allow.toUpperCase().includes(method)) {
              findings.push(finding(
                `HTTP_METHOD_${method}_DECLARED`, severity, target + '/',
                `OPTIONS response declares ${method} method: ${desc}`,
                {
                  replication_steps: [
                    `curl -sI -X OPTIONS "${target}/" | grep -i allow`,
                    `Observe: '${method}' listed in Allow header.`,
                  ],
                  evidence: JSON.stringify({ method, allow_header: allow }),
                },
              ));
            }
          }
        }
      }
    } catch { /* ignore OPTIONS failure */ }

    // TRACE test: send TRACE and check if request headers are reflected
    await parallelProbe(PROBE_PATHS, async (path) => {
      const url = target + path;
      try {
        const r = await fetchURL(url, {
          method: 'TRACE',
          headers: { ...HEADERS, 'X-JWP-Test': 'trace-reflection-check' },
          redirect: 'manual',
        });
        if (r && r.status === 200) {
          let body = '';
          try { body = await r.text(); } catch { /* ignore */ }
          if (body.toLowerCase().includes('x-jwp-test')) {
            findings.push(finding(
              'HTTP_TRACE_ENABLED', 'HIGH', url,
              `HTTP TRACE is enabled at ${path} — request headers are reflected (XST risk)`,
              {
                replication_steps: [
                  `curl -s -X TRACE "${url}" -H 'X-Cookie-Test: secret'`,
                  'Observe: custom headers are echoed back in response body.',
                  'Combined with XSS, this can expose HttpOnly cookies (Cross-Site Tracing).',
                ],
                remediation: 'Disable TRACE method: TraceEnable off (Apache) or deny TRACE (Nginx).',
                evidence: JSON.stringify({ method: 'TRACE', path }),
              },
            ));
            return;
          }
        }
      } catch { /* ignore */ }
    });

    // PUT / DELETE test on uploads path
    const uploadPath = '/wp-content/uploads/jwp-test-method.txt';
    await parallelProbe(['PUT', 'DELETE'], async (method) => {
      const url = target + uploadPath;
      try {
        const r = await fetchURL(url, {
          method,
          headers: HEADERS,
          body: method === 'PUT' ? 'JWP-method-test' : undefined,
          redirect: 'manual',
        });
        if (r && [200, 201, 204].includes(r.status)) {
          findings.push(finding(
            `HTTP_${method}_ACCEPTED`, 'HIGH', url,
            `HTTP ${method} accepted at ${uploadPath} — server returned ${r.status}`,
            {
              replication_steps: [
                `curl -s -X ${method} "${url}" -d 'test'`,
                `Observe: HTTP ${r.status} response — ${method} is allowed.`,
                'This could allow attackers to upload or delete files directly.',
              ],
              remediation: `Disable ${method} method in web server configuration.`,
              evidence: JSON.stringify({ method, status_code: r.status }),
            },
          ));
        }
      } catch { /* ignore */ }
    });

    // WebDAV PROPFIND
    try {
      const r = await fetchURL(target + '/', {
        method: 'PROPFIND',
        headers: { ...HEADERS, Depth: '0' },
        redirect: 'manual',
      });
      if (r && [200, 207].includes(r.status)) {
        findings.push(finding(
          'WEBDAV_PROPFIND_ENABLED', 'MEDIUM', target + '/',
          `WebDAV PROPFIND returned ${r.status} — directory metadata exposed`,
          {
            replication_steps: [
              `curl -s -X PROPFIND "${target}/" -H 'Depth: 0'`,
              'Observe: WebDAV XML response with file/directory metadata.',
              'WebDAV enables file listing, upload, and management operations.',
            ],
            evidence: JSON.stringify({ method: 'PROPFIND', status_code: r.status }),
          },
        ));
      }
    } catch { /* ignore */ }

  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
