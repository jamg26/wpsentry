import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, getCachedResponse, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Security Headers Audit';

type HeaderSpec = [string, Finding['severity'], string, string];

const HEADERS_SPEC: HeaderSpec[] = [
  [
    'Strict-Transport-Security',
    'LOW',
    'HSTS header missing — site can be downgraded to HTTP',
    'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  ],
  [
    'Content-Security-Policy',
    'LOW',
    'Content-Security-Policy missing — XSS attacks not mitigated by browser',
    "Define a strict CSP: Content-Security-Policy: default-src 'self'",
  ],
  // X-Frame-Options check removed — wp_clickjacking module covers this with per-page context
  [
    'X-Content-Type-Options',
    'LOW',
    'X-Content-Type-Options missing — MIME sniffing attacks possible',
    'Add: X-Content-Type-Options: nosniff',
  ],
  [
    'Referrer-Policy',
    'LOW',
    'Referrer-Policy missing — sensitive URLs may leak via Referer header',
    'Add: Referrer-Policy: strict-origin-when-cross-origin',
  ],
  [
    'Permissions-Policy',
    'LOW',
    'Permissions-Policy missing — browser features not restricted',
    'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
  ],
  [
    'X-XSS-Protection',
    'INFO',
    'X-XSS-Protection: 1; mode=block not set (legacy browsers)',
    'Add: X-XSS-Protection: 1; mode=block',
  ],
];

export async function run(target: string, state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const r = await getCachedResponse(`${target}/`, state);
    if (!r) {
      findings.push(finding(
        'TARGET_UNREACHABLE', 'INFO', `${target}/`,
        'Target unreachable — site may be down, blocked, or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    await parallelProbe(HEADERS_SPEC, async ([header, severity, desc, rec]) => {
      const val = r.headers.get(header) ?? '';

      if (!val) {
        findings.push(finding(
          'MISSING_SECURITY_HEADER',
          severity,
          `${target}/`,
          desc,
          {
            replication_steps: [
              `curl -sI "${target}/" | grep -i '${header}'`,
              `Observe: header '${header}' is absent from the response.`,
              `Fix: ${rec}`,
            ],
            evidence: `header: ${header}; recommendation: ${rec}`,
          },
        ));
      } else {
        if (header === 'Content-Security-Policy') {
          if (val.includes('unsafe-inline') || val.includes('unsafe-eval')) {
            findings.push(finding(
              'WEAK_CSP',
              'MEDIUM',
              `${target}/`,
              `CSP present but weak — contains 'unsafe-inline' or 'unsafe-eval': ${val.slice(0, 80)}`,
              {
                replication_steps: [
                  `curl -sI "${target}/" | grep -i 'content-security-policy'`,
                  "Observe: CSP contains 'unsafe-inline' or 'unsafe-eval' directives.",
                ],
                evidence: `header: ${header}; value: ${val.slice(0, 80)}`,
              },
            ));
          }
        } else if (header === 'Strict-Transport-Security') {
          const m = val.match(/max-age=(\d+)/i);
          if (m && parseInt(m[1], 10) < 31536000) {
            findings.push(finding(
              'WEAK_HSTS',
              'LOW',
              `${target}/`,
              `HSTS max-age too short: ${m[1]}s (recommended: 31536000+)`,
              {
                replication_steps: [
                  `curl -sI "${target}/" | grep -i 'strict-transport'`,
                ],
                evidence: `header: ${header}; max-age: ${m[1]}`,
              },
            ));
          }
        }
      }
    });

    // Check if HTTPS is enforced
    if (target.startsWith('http://')) {
      const r2 = await fetchURL(`${target}/`, { redirect: 'manual' });
      if (r2 && ![301, 302].includes(r2.status)) {
        findings.push(finding(
          'HTTPS_NOT_ENFORCED',
          'HIGH',
          `${target}/`,
          'Site does not redirect HTTP to HTTPS — traffic can be intercepted',
          {
            replication_steps: [
              `curl -sI "${target}/"`,
              'Observe: no 301/302 redirect to HTTPS.',
              'Attacker on same network can perform MITM attack.',
            ],
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
