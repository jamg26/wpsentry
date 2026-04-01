import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget , parallelProbe } from '../utils.js';

const MODULE_NAME = 'WPGraphQL Exposure';
const JSON_HEADERS = { 'Content-Type': 'application/json' };

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  // Test 1: Endpoint discovery
  let graphqlUrl: string | null = null;
  const probePaths = ['/graphql', '/wp/graphql', '/?graphql', '/api/graphql'];

  await parallelProbe(probePaths, async (path) => {
    const url = `${target}${path}`;
    try {
      const rGet = await fetchURL(`${url}?query={__typename}`);
      if (rGet?.status === 200) {
        try {
          const data = await rGet.json() as Record<string, unknown>;
          if ((data?.data as Record<string, unknown>)?.__typename === 'RootQuery') {
            graphqlUrl = url;
            return;
          }
        } catch { /* ignore */ }
      }

      const rPost = await fetchURL(url, {
        method: 'POST',
        body: JSON.stringify({ query: '{__typename}' }),
        headers: JSON_HEADERS,
      });
      if (rPost?.status === 200) {
        try {
          const data = await rPost.json() as Record<string, unknown>;
          if ((data?.data as Record<string, unknown>)?.__typename === 'RootQuery') {
            graphqlUrl = url;
            return;
          }
          if ('data' in data || 'errors' in data) {
            graphqlUrl = url;
            return;
          }
        } catch { /* ignore */ }
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  if (!graphqlUrl) {
    return moduleResult(MODULE_NAME, target, findings, errors, start);
  }

  findings.push(finding(
    'WPGRAPHQL_ENDPOINT_FOUND',
    'INFO',
    graphqlUrl,
    `WPGraphQL endpoint discovered at ${graphqlUrl} — GraphQL API is publicly accessible`,
    {
      replication_steps: [
        `curl -s '${graphqlUrl}?query={__typename}'`,
        'Observe JSON response confirming WPGraphQL is active.',
      ],
      remediation: "Consider restricting GraphQL access to authenticated users if not required publicly. Use WPGraphQL's built-in authentication settings.",
      evidence: 'GraphQL __typename query returned a valid GraphQL response',
    },
  ));

  // Test 2: Introspection enabled
  try {
    const r = await fetchURL(graphqlUrl, {
      method: 'POST',
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
      headers: JSON_HEADERS,
    });
    if (r?.status === 200) {
      try {
        const data = await r.json() as Record<string, unknown>;
        const types = (((data?.data as Record<string, unknown>)?.__schema as Record<string, unknown>)?.types ?? []) as Record<string, unknown>[];
        if (types.length > 5) {
          const sample = types.slice(0, 5).map((t) => t.name ?? '');
          findings.push(finding(
            'WPGRAPHQL_INTROSPECTION_ENABLED',
            'LOW',
            graphqlUrl,
            'WPGraphQL introspection is enabled — full schema exposed including field names, types, and potentially sensitive operations',
            {
              replication_steps: [
                `curl -s -X POST "${graphqlUrl}" -H 'Content-Type: application/json' -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool`,
                `Observe ${types.length} type definitions — complete API schema is public.`,
                'Visualise schema at https://ivangoncharov.github.io/graphql-voyager/',
              ],
              remediation: 'Disable introspection in production via WPGraphQL settings. Add graphql_debug => false to wp-config.php.',
              evidence: `Introspection returned ${types.length} types (sample: ${JSON.stringify(sample)})`,
            },
          ));
        }
      } catch { /* ignore */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 3: User enumeration via GraphQL
  try {
    const r = await fetchURL(graphqlUrl, {
      method: 'POST',
      body: JSON.stringify({ query: '{ users { nodes { id name email databaseId } } }' }),
      headers: JSON_HEADERS,
    });
    if (r?.status === 200) {
      try {
        const data = await r.json() as Record<string, unknown>;
        const nodes = (((data?.data as Record<string, unknown>)?.users as Record<string, unknown>)?.nodes ?? []) as Record<string, unknown>[];
        if (nodes.length > 0) {
          const emails = nodes.filter((n) => n.email).map((n) => n.email);
          const names = nodes.filter((n) => n.name).map((n) => n.name);
          findings.push(finding(
            'WPGRAPHQL_USER_ENUM',
            'HIGH',
            graphqlUrl,
            `WPGraphQL exposes WordPress users including email addresses — enables targeted attacks (${nodes.length} user(s) enumerated)`,
            {
              replication_steps: [
                `curl -s -X POST "${graphqlUrl}" -H 'Content-Type: application/json' -d '{"query":"{ users { nodes { id name email databaseId } } }"}' | python3 -m json.tool`,
                `Observe ${nodes.length} user record(s) with names and emails.`,
                'Use extracted usernames/emails for credential stuffing or phishing.',
              ],
              remediation: 'Restrict user queries to authenticated users in WPGraphQL settings. Set Show in GraphQL to off for sensitive fields.',
              evidence: `Enumerated ${nodes.length} user(s); names: ${JSON.stringify(names.slice(0, 3))}, emails: ${JSON.stringify(emails.slice(0, 3))}`,
            },
          ));
        }
      } catch { /* ignore */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 4: Private/draft post access
  try {
    const r = await fetchURL(graphqlUrl, {
      method: 'POST',
      body: JSON.stringify({ query: '{ posts(where:{status:DRAFT}) { nodes { id title content } } }' }),
      headers: JSON_HEADERS,
    });
    if (r?.status === 200) {
      try {
        const data = await r.json() as Record<string, unknown>;
        const nodes = (((data?.data as Record<string, unknown>)?.posts as Record<string, unknown>)?.nodes ?? []) as unknown[];
        if (nodes.length > 0) {
          findings.push(finding(
            'WPGRAPHQL_DRAFT_EXPOSURE',
            'HIGH',
            graphqlUrl,
            `WPGraphQL exposes draft/private posts without authentication — ${nodes.length} draft post(s) accessible`,
            {
              replication_steps: [
                `curl -s -X POST "${graphqlUrl}" -H 'Content-Type: application/json' -d '{"query":"{ posts(where:{status:DRAFT}) { nodes { id title content } } }"}' | python3 -m json.tool`,
                'Observe draft post content returned without authentication.',
              ],
              remediation: 'Restrict draft/private post access to authenticated users in WPGraphQL. Add post_status permission checks in custom resolvers.',
              evidence: `${nodes.length} draft post(s) returned without authentication`,
            },
          ));
        }
      } catch { /* ignore */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 5: Viewer / sensitive field exposure
  try {
    const r = await fetchURL(graphqlUrl, {
      method: 'POST',
      body: JSON.stringify({ query: '{ viewer { id name email capabilities roles { nodes { name } } } }' }),
      headers: JSON_HEADERS,
    });
    if (r?.status === 200) {
      try {
        const data = await r.json() as Record<string, unknown>;
        const viewer = (data?.data as Record<string, unknown>)?.viewer as Record<string, unknown> | null;
        if (viewer?.id) {
          const capFields = viewer.capabilities || viewer.roles;
          findings.push(finding(
            'WPGRAPHQL_VIEWER_EXPOSED',
            capFields ? 'HIGH' : 'MEDIUM',
            graphqlUrl,
            'WPGraphQL viewer query returns authenticated user data including roles/capabilities — review resolver authentication',
            {
              replication_steps: [
                `curl -s -X POST "${graphqlUrl}" -H 'Content-Type: application/json' -d '{"query":"{ viewer { id name email capabilities roles { nodes { name } } } }"}'`,
                'Observe user data including roles returned — check capabilities for privilege mapping.',
              ],
              remediation: 'Ensure viewer returns null for unauthenticated requests. Review all resolver authentication checks.',
              evidence: `Viewer: id=${viewer.id}, name=${viewer.name}`,
            },
          ));
        }
      } catch { /* ignore */ }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 6: GraphQL CORS check
  try {
    const r = await fetchURL(graphqlUrl, {
      headers: { Origin: 'https://evil.example.com' },
    });
    if (r) {
      const acao = r.headers.get('Access-Control-Allow-Origin') ?? '';
      const acac = (r.headers.get('Access-Control-Allow-Credentials') ?? 'false').toLowerCase();
      if (acao === '*' || acao.includes('evil.example.com')) {
        findings.push(finding(
          'WPGRAPHQL_CORS_MISCONFIGURED',
          acac === 'true' ? 'HIGH' : 'MEDIUM',
          graphqlUrl,
          `WPGraphQL endpoint has permissive CORS policy (Access-Control-Allow-Origin: ${acao}) — cross-origin GraphQL queries possible`,
          {
            replication_steps: [
              `curl -sI "${graphqlUrl}" -H 'Origin: https://evil.example.com'`,
              `Observe: Access-Control-Allow-Origin: ${acao}`,
              "Malicious sites can issue GraphQL queries using the victim's session cookies.",
            ],
            remediation: 'Restrict CORS origins to known trusted domains. Never combine Access-Control-Allow-Origin: * with credentials.',
            evidence: `ACAO: ${acao}, ACAC: ${acac}`,
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
