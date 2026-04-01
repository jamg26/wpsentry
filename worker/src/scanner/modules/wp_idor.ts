import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Insecure Direct Object Reference (IDOR)';

const ID_RANGE_MAX = 21; // IDs 1–20 inclusive (fits within timeout budget)

type EndpointConfig = [
  endpoint: string,
  ftype: string,
  severity: 'HIGH' | 'MEDIUM' | 'LOW',
  privateStatuses: string[],
];

const ENDPOINTS: EndpointConfig[] = [
  ['posts',  'idor_post_exposure',  'HIGH',   ['draft', 'private', 'password']],
  ['users',  'idor_user_exposure',  'LOW',    []],   // public user listing is standard WP behavior
  ['media',  'idor_media_exposure', 'MEDIUM', ['private', 'draft']],
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Flatten endpoints × IDs to avoid sequential inner loop (100 IDs each)
    const combos: [EndpointConfig, number][] = ENDPOINTS.flatMap((ep) =>
      Array.from({ length: ID_RANGE_MAX - 1 }, (_, i) => [ep, i + 1] as [EndpointConfig, number]),
    );
    await parallelProbe(combos, async ([[endpoint, ftype, severity, privateStatuses], objId]) => {
      const url = `${target}/wp-json/wp/v2/${endpoint}/${objId}`;
      try {
        const res = await fetchURL(url);
        if (!res || res.status !== 200) return;

        let data: Record<string, unknown>;
        try {
          data = await res.json() as Record<string, unknown>;
        } catch { return; }

        const statusVal = (data.status as string) ?? '';
        const objType = (data.type as string) ?? '';

        const isPrivate = privateStatuses.length > 0
          ? privateStatuses.includes(statusVal)
          : true;

        if (!isPrivate) return;

        let title = '';
        if (typeof data.title === 'object' && data.title !== null) {
          title = ((data.title as Record<string, unknown>).rendered as string) ?? '';
        } else if (typeof data.name === 'string') {
          title = data.name;
        } else if (typeof data.slug === 'string') {
          title = data.slug;
        }

        const desc =
          `Unauthenticated access to ${endpoint.replace(/s$/, '')} ID ${objId} ` +
          `(status: '${statusVal}', type: '${objType}'). ` +
          `Title/Name: '${title.slice(0, 80)}'.`;

        findings.push(finding(
          ftype, severity, url, desc,
          {
            replication_steps: [
              `curl -s "${url}" | python3 -m json.tool`,
              `# Observe '${statusVal}' status — should not be accessible without auth.`,
              `# Iterate IDs 1-20: for i in $(seq 1 20); do curl -s "${target}/wp-json/wp/v2/${endpoint}/$i" | grep -E 'status|title|name'; done`,
            ],
            remediation:
              `Restrict REST API access to private/draft ${endpoint} to authenticated ` +
              'users only. Use register_rest_route with permission_callback. ' +
              'Consider disabling the REST API for unauthenticated users.',
            evidence: `HTTP 200 on ${endpoint} ID ${objId} with status='${statusVal}'.`,
          },
        ));
      } catch { /* continue */ }
    }, 30);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
