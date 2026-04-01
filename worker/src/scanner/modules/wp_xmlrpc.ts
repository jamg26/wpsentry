import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'XML-RPC Security Check';

const XML_HEADERS = { 'Content-Type': 'text/xml' };

const LIST_METHODS_BODY = `<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>`;

const GET_USERS_BODY = `<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>invalid_user_jwp</string></value></param>
    <param><value><string>invalid_pass_jwp</string></value></param>
  </params>
</methodCall>`;

function parseMethods(xmlText: string): string[] {
  const matches = Array.from(xmlText.matchAll(/<string>([^<]+)<\/string>/g));
  return matches.map(m => m[1]).filter(Boolean);
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const xmlrpc = `${target}/xmlrpc.php`;

  try {
    // 1. Accessibility check
    const res = await fetchURL(xmlrpc);
    if (!res) {
      findings.push(finding(
        'XMLRPC_UNREACHABLE', 'INFO', xmlrpc,
        'xmlrpc.php unreachable — endpoint may be blocked or non-existent',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    const enabled =
      res.status === 405 ||
      (res.status === 200 && (await res.text()).includes('XML-RPC server accepts POST requests only'));

    if (!enabled) {
      findings.push(finding(
        'XMLRPC_DISABLED', 'INFO', xmlrpc,
        'xmlrpc.php appears disabled or inaccessible (good)',
      ));
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    findings.push(finding(
      'XMLRPC_ENABLED', 'INFO', xmlrpc,
      'XML-RPC is enabled — attack surface exposed',
    ));

    // 2. Method enumeration
    const r2 = await fetchURL(xmlrpc, {
      method: 'POST',
      body: LIST_METHODS_BODY,
      headers: XML_HEADERS,
    });

    if (r2 && r2.status === 200) {
      const r2Text = await r2.text();
      if (r2Text.includes('<methodResponse>')) {
        const methods = parseMethods(r2Text);
        const dangerous = methods.filter(m =>
          m.startsWith('wp.') || m.startsWith('system.') || m.startsWith('pingback.')
        );
        findings.push(finding(
          'XMLRPC_METHOD_ENUM', 'MEDIUM', xmlrpc,
          `system.listMethods returned ${methods.length} methods (${dangerous.length} sensitive)`,
          { evidence: JSON.stringify(dangerous) },
        ));

        // Check wp.getUsersBlogs
        if (methods.includes('wp.getUsersBlogs')) {
          const rUb = await fetchURL(xmlrpc, {
            method: 'POST',
            body: GET_USERS_BODY,
            headers: XML_HEADERS,
          });
          if (rUb && rUb.status === 200) {
            const ubText = await rUb.text();
            if (
              ubText.includes('faultCode') ||
              ubText.includes('Incorrect username') ||
              ubText.includes('faultString')
            ) {
              findings.push(finding(
                'XMLRPC_GETUSERSBLOGS_ACTIVE', 'MEDIUM', xmlrpc,
                'wp.getUsersBlogs is active — confirms auth endpoint reachable for credential stuffing',
              ));
            }
          }
        }

        // 3. Multicall amplification check
        if (methods.includes('system.multicall')) {
          findings.push(finding(
            'XMLRPC_MULTICALL_ENABLED', 'HIGH', xmlrpc,
            'system.multicall is available — enables credential stuffing with thousands of attempts per request',
          ));
        }

        if (methods.includes('pingback.ping')) {
          findings.push(finding(
            'XMLRPC_PINGBACK_ENABLED', 'HIGH', xmlrpc,
            'pingback.ping is available — SSRF/DDoS amplification risk',
          ));
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
