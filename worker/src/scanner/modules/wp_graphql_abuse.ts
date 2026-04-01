import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'WPGraphQL Abuse';

// The existing wp_wpgraphql.ts covers basic introspection; this module adds:
// - Batch query attacks
// - Field-level auth bypass (draft/private posts)
// - Alias-based rate limit bypass
// - User email harvesting

const GRAPHQL_ENDPOINTS = [
  '/graphql',
  '/wp-json/wp/v2/graphql',
  '/?graphql',
  '/index.php?graphql',
];

const INTROSPECTION_QUERY = JSON.stringify({
  query: `{__schema{queryType{name}mutationType{name}types{name kind}}}`,
});

// Alias-based bypass: query draft and private posts simultaneously
const ALIAS_BYPASS_QUERY = JSON.stringify({
  query: `{
    drafts:posts(where:{status:DRAFT}){nodes{id title content}}
    private:posts(where:{status:PRIVATE}){nodes{id title content}}
    trash:posts(where:{status:TRASH}){nodes{id title content}}
  }`,
});

// User enumeration via GraphQL
const USER_ENUM_QUERY = JSON.stringify({
  query: `{users{nodes{id name email username roles{nodes{name}}}}}`,
});

// Password reset via GraphQL mutation
const RESET_MUTATION = JSON.stringify({
  query: `mutation{sendPasswordResetEmail(input:{username:"admin"}){success clientMutationId}}`,
});

// Batch query: 50 user queries in one request (DoS amplification)
const batchQueries = Array.from({ length: 50 }, (_, i) =>
  `q${i}:user(id:"${i + 1}"){id name email username}`
).join('\n');
const BATCH_QUERY = JSON.stringify({ query: `{${batchQueries}}` });

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Find active GraphQL endpoint
    let graphqlEndpoint: string | null = null;

    for (const ep of GRAPHQL_ENDPOINTS) {
      const res = await fetchURL(target + ep, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: INTROSPECTION_QUERY,
        timeoutMs: 5_000,
      });
      if (!res) continue;
      const text = await res.text().catch(() => '');
      if ((res.status === 200 || res.status === 201) && text.includes('"data"')) {
        graphqlEndpoint = target + ep;
        break;
      }
    }

    if (!graphqlEndpoint) return moduleResult(MODULE_NAME, target, findings, errors, start);

    // Introspection check
    const introRes = await fetchURL(graphqlEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: INTROSPECTION_QUERY,
      timeoutMs: 5_000,
    });

    if (introRes?.status === 200) {
      const introBody = await introRes.text().catch(() => '');
      if (introBody.includes('"__schema"') || introBody.includes('"queryType"')) {
        findings.push(finding(
          'GRAPHQL_INTROSPECTION',
          'MEDIUM',
          graphqlEndpoint,
          'WPGraphQL introspection is enabled — full schema exposed to unauthenticated users',
          {
            evidence: `endpoint="${graphqlEndpoint}" schema_keys="${introBody.slice(0, 150)}"`,
            remediation: 'Disable introspection in production. Use WPGraphQL settings to restrict introspection to authenticated users.',
          },
        ));
      }
    }

    // Alias-based bypass for draft/private posts
    const aliasRes = await fetchURL(graphqlEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: ALIAS_BYPASS_QUERY,
      timeoutMs: 5_000,
    });

    if (aliasRes?.status === 200) {
      const aliasBody = await aliasRes.text().catch(() => '');
      let exposedContent = '';
      if (aliasBody.includes('"nodes"')) {
        // Check if any non-empty nodes returned
        try {
          const parsed = JSON.parse(aliasBody) as Record<string, unknown>;
          const data = parsed?.data as Record<string, { nodes: unknown[] }> | undefined;
          if (data) {
            for (const [key, val] of Object.entries(data)) {
              if (Array.isArray(val?.nodes) && val.nodes.length > 0) {
                exposedContent += `${key}:${val.nodes.length}posts `;
              }
            }
          }
        } catch { /* ignore */ }
      }

      if (exposedContent) {
        findings.push(finding(
          'GRAPHQL_AUTH_BYPASS',
          'CRITICAL',
          graphqlEndpoint,
          `WPGraphQL field-level authorization bypass — unauthenticated access to non-public posts: ${exposedContent}`,
          {
            evidence: `exposed="${exposedContent}" query="ALIAS_BYPASS_QUERY"`,
            remediation: 'Implement field-level authorization in WPGraphQL. Use WPGraphQL Smart Cache or Helmet plugin to restrict access by role.',
          },
        ));
      }
    }

    // User enumeration
    const userRes = await fetchURL(graphqlEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: USER_ENUM_QUERY,
      timeoutMs: 5_000,
    });

    if (userRes?.status === 200) {
      const userBody = await userRes.text().catch(() => '');
      if (userBody.includes('"email"') && userBody.includes('@')) {
        const emailMatches = userBody.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) ?? [];
        if (emailMatches.length > 0) {
          findings.push(finding(
            'GRAPHQL_USER_EMAIL_ENUM',
            'HIGH',
            graphqlEndpoint,
            `WPGraphQL exposes user emails to unauthenticated requests — ${emailMatches.length} email(s) harvested`,
            {
              evidence: `emails="${emailMatches.slice(0, 3).join(', ')}"`,
              remediation: 'Restrict user email fields to authenticated users in WPGraphQL schema. Use "show_in_graphql" field restrictions.',
            },
          ));
        }
      }
    }

    // Batch query DoS potential
    const batchT0 = Date.now();
    const batchRes = await fetchURL(graphqlEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: BATCH_QUERY,
      timeoutMs: 10_000,
    });
    const batchElapsed = Date.now() - batchT0;

    if (batchRes?.status === 200) {
      const batchBody = await batchRes.text().catch(() => '');
      if (batchBody.includes('"data"')) {
        findings.push(finding(
          'GRAPHQL_BATCH_ATTACK',
          'HIGH',
          graphqlEndpoint,
          `WPGraphQL allows batch queries — 50-query batch completed in ${batchElapsed}ms. No rate limiting detected.`,
          {
            evidence: `batch_queries=50 elapsed_ms=${batchElapsed} status=${batchRes.status}`,
            remediation: 'Enable query depth and complexity limits. Use graphql-query-complexity package. Rate limit GraphQL endpoint.',
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
