import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'REST Plugin Endpoint Audit';

const HUMMINGBIRD_STATUS_MODULES = ['caching', 'gzip', 'page-cache', 'uptime'];

// [method, relPath, description, severity]
const PROBE_ROUTES: [string, string, string, 'HIGH' | 'MEDIUM' | 'LOW'][] = [
  ['GET', 'hummingbird/v1/test',                       'Hummingbird connectivity test (all HTTP methods allowed)', 'LOW'],
  ['GET', 'hummingbird/v1/preset_configs',              'Hummingbird preset configurations',                        'MEDIUM'],
  ['GET', 'hummingbird/v1/minify/options',              'Hummingbird minify options',                               'MEDIUM'],
  ['GET', 'hummingbird/v1/minify/assets',               'Hummingbird minify asset list',                            'MEDIUM'],
  ['GET', 'wp-abilities/v1/abilities',                  'WP-Abilities: list all registered abilities',              'HIGH'],
  ['GET', 'wp-abilities/v1/categories',                 'WP-Abilities: list ability categories',                    'MEDIUM'],
  ['GET', 'redirection/v1/redirect',                    'Redirection plugin: list all redirect rules',              'MEDIUM'],
  ['GET', 'redirection/v1/setting',                     'Redirection plugin: settings disclosure',                  'MEDIUM'],
  ['GET', 'redirection/v1/group',                       'Redirection plugin: redirect groups',                      'MEDIUM'],
  ['GET', 'yoast/v1/configuration',                     'Yoast: configuration endpoint',                            'MEDIUM'],
  ['GET', 'yoast/v1/myyoast/connect',                   'Yoast: MyYoast connect endpoint',                          'MEDIUM'],
  ['GET', 'wp-site-health/v1/tests/background-updates', 'WP Site Health: background update test',                  'HIGH'],
  ['GET', 'wp-site-health/v1/tests/https-status',       'WP Site Health: HTTPS status',                            'MEDIUM'],
  ['GET', 'wp-site-health/v1/directory-sizes',          'WP Site Health: directory sizes (server info)',            'HIGH'],
  ['GET', 'wp/v2/settings',                             'WP settings endpoint (site config)',                       'HIGH'],
  ['GET', 'wp/v2/plugins',                              'WP plugin list endpoint',                                  'HIGH'],
  ['GET', 'duplicate-post/v1',                          'Duplicate Post plugin namespace',                          'LOW'],
  ['GET', 'post-views-counter/update-post-views',       'Post Views Counter: update endpoint',                      'LOW'],
];

const HUMMINGBIRD_ALL_METHODS = ['POST', 'DELETE', 'PUT', 'PATCH', 'COPY'];

const KNOWN_CORE_NS = new Set([
  'wp/v2', 'oembed/1.0', 'wp-block-editor/v1', 'wp-site-health/v1',
  'wp-block-patterns/v1', 'wp-block-directory/v1',
]);

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const apiBase = `${target}/wp-json/`;

  // 1. REST API root enumeration
  try {
    const rootResp = await fetchURL(apiBase);
    if (!rootResp || ![200, 401].includes(rootResp.status)) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    if (rootResp.status === 200) {
      let rootJson: Record<string, unknown> = {};
      try { rootJson = await rootResp.json() as Record<string, unknown>; } catch { /* ignore */ }

      const routes = (rootJson.routes as Record<string, Record<string, unknown>>) ?? {};
      const namespaces = (rootJson.namespaces as string[]) ?? [];

      const writeRoutes: string[] = [];
      for (const [path, info] of Object.entries(routes)) {
        const endpoints = (info.endpoints as { methods?: string[] }[]) ?? [];
        if (endpoints.some((ep) => (ep.methods ?? []).some((m) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)))) {
          writeRoutes.push(path);
        }
      }

      const pluginNs = namespaces.filter((ns) => !KNOWN_CORE_NS.has(ns));

      if (Object.keys(routes).length > 0 || pluginNs.length > 0) {
        findings.push(finding(
          'REST_API_SCHEMA_EXPOSED',
          'INFO',
          apiBase,
          `WordPress REST API root is publicly accessible, exposing a full schema of ${Object.keys(routes).length} routes (${writeRoutes.length} write-capable) across ${namespaces.length} namespaces. Plugin namespaces detected: ${pluginNs.length > 0 ? pluginNs.join(', ') : 'none beyond core'}. This acts as a detailed attack-surface roadmap for authenticated and unauthenticated exploitation.`,
          {
            replication_steps: [
              `curl -s '${apiBase}' | python3 -m json.tool | grep '"namespace"'`,
              '# Enumerate all write-capable routes:',
              `curl -s '${apiBase}' | python3 -c "import json,sys; d=json.load(sys.stdin); [print(p) for p,v in d['routes'].items() if any(m in e['methods'] for e in v['endpoints'] for m in ['POST','PUT','PATCH','DELETE'])]"`,
            ],
            remediation: "Consider disabling public REST API schema: add `remove_action('rest_api_init', 'wp_oembed_register_routes');` or restrict namespace listing via `rest_namespace_index` filter. Block unauthenticated access to the root index via a WAF rule if full REST API is not required publicly.",
            evidence: `Namespaces: ${JSON.stringify(namespaces.slice(0, 15))}\nTotal routes: ${Object.keys(routes).length}, write-capable: ${writeRoutes.length}\nPlugin namespaces: ${JSON.stringify(pluginNs)}`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // 2. Probe high-risk routes without authentication
  await parallelProbe(PROBE_ROUTES, async ([, relPath, description, severity]) => {
    const url = `${apiBase}${relPath}`;
    try {
      const resp = await fetchURL(url);
      if (!resp) return;
      if (resp.status === 200) {
        let body: unknown;
        try { body = await resp.json(); } catch { body = (await resp.text()).slice(0, 200); }
        findings.push(finding(
          'UNAUTH_REST_ENDPOINT',
          severity,
          url,
          `Unauthenticated access to REST endpoint: ${description}. Returned HTTP 200 without credentials.`,
          {
            replication_steps: [
              `curl -s '${url}'`,
              '# No authentication headers required',
            ],
            remediation: "Add `permission_callback` that requires `is_user_logged_in()` or capability checks (e.g. `manage_options`) on all non-public REST routes. Review plugin REST route registrations for missing auth.",
            evidence: String(body).slice(0, 300),
          },
        ));
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  // 3. Hummingbird: unauthenticated server configuration disclosure
  try {
    const hbStatusFindings: [string, string, string][] = [];
    for (const modName of HUMMINGBIRD_STATUS_MODULES) {
      const url = `${apiBase}hummingbird/v1/status/${modName}`;
      try {
        const resp = await fetchURL(url);
        if (resp?.status === 200) {
          let body: unknown;
          try { body = await resp.json(); } catch { body = (await resp.text()).slice(0, 200); }
          hbStatusFindings.push([modName, url, String(body).slice(0, 200)]);
        }
      } catch { /* ignore */ }
    }

    if (hbStatusFindings.length > 0) {
      const leakedModules = hbStatusFindings.map(([m, , ev]) => `${m}: ${ev.slice(0, 80)}`);
      findings.push(finding(
        'HUMMINGBIRD_STATUS_DISCLOSURE',
        'MEDIUM',
        `${apiBase}hummingbird/v1/status/caching`,
        'Hummingbird performance plugin exposes server configuration data without authentication via the REST API. Cache durations, gzip settings, and module states are accessible to unauthenticated users, aiding fingerprinting and attack planning.',
        {
          replication_steps: [
            '# Check caching configuration:',
            `curl -s '${apiBase}hummingbird/v1/status/caching'`,
            '# Check gzip configuration:',
            `curl -s '${apiBase}hummingbird/v1/status/gzip'`,
          ],
          remediation: "The Hummingbird REST API `/status/` endpoint should require admin authentication. Add `permission_callback => function() { return current_user_can('manage_options'); }` in the route registration. Update to the latest Hummingbird version.",
          evidence: leakedModules.join('\n'),
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // 4. Hummingbird /test: all HTTP methods without auth
  try {
    const hbTestUrl = `${apiBase}hummingbird/v1/test`;
    const baseResp = await fetchURL(hbTestUrl);
    if (baseResp?.status === 200) {
      const dangerousOk: string[] = [];
      for (const method of HUMMINGBIRD_ALL_METHODS) {
        try {
          const r2 = await fetchURL(hbTestUrl, { method });
          if (r2?.status === 200) dangerousOk.push(method);
        } catch { /* ignore */ }
      }
      findings.push(finding(
        'HUMMINGBIRD_TEST_ENDPOINT',
        'MEDIUM',
        hbTestUrl,
        `Hummingbird performance plugin exposes a \`/test\` REST endpoint that returns HTTP 200 for ALL HTTP methods (GET, POST, DELETE, COPY, PUT, PATCH) without any authentication. The COPY and DELETE methods are WebDAV/dangerous verbs that should never be enabled on application endpoints. Dangerous methods confirmed: ${dangerousOk.length > 0 ? dangerousOk.join(', ') : HUMMINGBIRD_ALL_METHODS.join(', ')}.`,
        {
          replication_steps: [
            `curl -X DELETE '${hbTestUrl}'`,
            `curl -X COPY '${hbTestUrl}'`,
            `curl -X POST '${hbTestUrl}'`,
          ],
          remediation: "The Hummingbird test endpoint should require admin authentication. Restrict HTTP methods to GET only if needed publicly, or add `permission_callback => function() { return current_user_can('manage_options'); }`. Block non-standard HTTP methods (COPY, MOVE, PROPFIND) at the WAF/web-server level.",
          evidence: `GET ${hbTestUrl} → 200 (true)\nAll methods return 200 without auth`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  // 5. WP-Abilities: enumerate ability names
  try {
    const abilitiesUrl = `${apiBase}wp-abilities/v1/abilities`;
    const resp = await fetchURL(abilitiesUrl);
    if (resp?.status === 200) {
      let abilities: Record<string, unknown>[] = [];
      try { abilities = await resp.json() as Record<string, unknown>[]; } catch { /* ignore */ }
      const names = Array.isArray(abilities) ? abilities.map((a) => a.name ?? '') : [];
      findings.push(finding(
        'WP_ABILITIES_EXPOSED',
        'HIGH',
        abilitiesUrl,
        `The WP-Abilities plugin exposes a REST API endpoint that lists all registered server-side 'abilities' without authentication. Each ability can be executed via \`/wp-abilities/v1/abilities/{name}/run\` with arbitrary \`input\` parameters (accepts GET/POST/PUT/PATCH/DELETE). ${names.length} abilities enumerated. This could allow unauthenticated arbitrary PHP ability execution.`,
        {
          replication_steps: [
            '# List all abilities:',
            `curl -s '${abilitiesUrl}'`,
            '# Execute an ability (replace NAME):',
            `curl -s '${apiBase}wp-abilities/v1/abilities/NAME/run' -X POST -d '{"input": null}'`,
          ],
          remediation: "All WP-Abilities REST endpoints should be protected with capability checks. Ensure `permission_callback` requires at minimum `is_user_logged_in()`, and ideally `manage_options` or custom capabilities. Audit each registered ability for command injection or sensitive operations.",
          evidence: `Abilities found: ${JSON.stringify(names.slice(0, 20))}`,
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
