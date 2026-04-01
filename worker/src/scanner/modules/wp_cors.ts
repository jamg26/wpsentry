import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'CORS Misconfiguration Check';

const PROBE_ENDPOINTS = [
  '/wp-json/wp/v2/users',
  '/wp-json/wp/v2/posts',
  '/wp-json/',
  '/wp-admin/admin-ajax.php',
];

const EVIL_ORIGIN = 'https://evil.attacker-controlled.com';
const NULL_ORIGIN = 'null';

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const pairs: [string, string][] = PROBE_ENDPOINTS.flatMap(path =>
      [EVIL_ORIGIN, NULL_ORIGIN].map(origin => [path, origin] as [string, string])
    );
    await parallelProbe(pairs, async ([path, originHeader]) => {
      const url = `${target}${path}`;
      const res = await fetchURL(url, { headers: { Origin: originHeader } });
      if (!res) return;

      const acao = res.headers.get('access-control-allow-origin') ?? '';
      const acac = (res.headers.get('access-control-allow-credentials') ?? 'false').toLowerCase();

      if (!acao) return;

      if (acao === '*') {
        // Wildcard CORS is only exploitable if credentials are also allowed.
        // Public read-only endpoints with * and no credentials are safe by design.
        if (acac === 'true') {
          // Browsers block ACAO:* + ACAC:true but this config is still misconfigured
          findings.push(finding('CORS_WILDCARD_WITH_CREDENTIALS', 'HIGH', url,
            `CORS wildcard with credentials on ${path} — misconfigured (browsers will block, but fix immediately)`,
            { evidence: `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: ${acac}`, remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials.' },
          ));
        }
        // No finding for wildcard without credentials — public APIs are intentionally open
      } else if (acao === originHeader || acao.includes(originHeader)) {
        if (acac === 'true') {
          findings.push(finding('CORS_ARBITRARY_ORIGIN_REFLECTED', 'CRITICAL', url,
            `CORS reflects origin '${originHeader}' WITH credentials on ${path} — authenticated cross-origin reads possible (session hijacking risk)`,
            { evidence: `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: ${acac}`, remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials.' },
          ));
        } else {
          // Reflecting arbitrary origin without credentials is not directly exploitable,
          // but it's still a misconfiguration worth noting
          findings.push(finding('CORS_ORIGIN_REFLECTED_NO_CREDENTIALS', 'LOW', url,
            `CORS reflects origin '${originHeader}' without credentials on ${path} — misconfiguration but not directly exploitable`,
            { evidence: `Access-Control-Allow-Origin: ${acao}; Access-Control-Allow-Credentials: ${acac}`, remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials.' },
          ));
        }
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
