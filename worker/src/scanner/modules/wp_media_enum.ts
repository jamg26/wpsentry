import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Media Enumeration';

const MEDIA_API    = '/wp-json/wp/v2/media';
const UPLOADS_BASE = '/wp-content/uploads';

const SENSITIVE_EXTENSIONS = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv']);
const BACKUP_EXTENSIONS    = new Set(['.sql', '.zip', '.tar', '.gz', '.bak', '.tar.gz']);
const SENSITIVE_KEYWORDS   = new Set([
  'password', 'config', 'backup', 'private', 'confidential',
  'invoice', 'contract', 'secret', 'credential', 'token',
]);

function classifyExt(filename: string): 'backup' | 'sensitive' | null {
  const fn = filename.toLowerCase();
  for (const ext of BACKUP_EXTENSIONS) {
    if (fn.endsWith(ext)) return 'backup';
  }
  for (const ext of SENSITIVE_EXTENSIONS) {
    if (fn.endsWith(ext)) return 'sensitive';
  }
  return null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  // Test 1: REST API media listing
  const mediaUrl = `${target}${MEDIA_API}?per_page=100`;
  try {
    const res = await fetchURL(mediaUrl);
    if (res && res.status === 200) {
      findings.push(finding('media_endpoint_open', 'LOW', mediaUrl,
        'WordPress REST API media endpoint is publicly accessible and lists uploaded files.',
        {
          replication_steps: [
            `curl -s "${mediaUrl}" | python3 -m json.tool | grep -E "source_url|slug"`,
            `curl -s "${mediaUrl}" | python3 -c "import sys,json; ` +
            `[print(m['source_url']) for m in json.load(sys.stdin)]"`,
          ],
          remediation:
            'Restrict REST API media listing: ' +
            "add_filter('rest_endpoints', fn($ep) => { " +
            "unset($ep['/wp/v2/media']); return $ep; }).",
          evidence: `HTTP ${res.status} — media listing available`,
        },
      ));

      const text = await res.text();
      let items: Record<string, unknown>[];
      try {
        items = JSON.parse(text);
      } catch {
        items = [];
      }

      for (const item of items) {
        const sourceUrl  = String(item['source_url']  ?? '');
        const slug       = String(item['slug']        ?? '');
        const titleObj   = item['title']       as Record<string, unknown> | undefined;
        const descObj    = item['description'] as Record<string, unknown> | undefined;
        const title      = String(titleObj?.['rendered'] ?? '');
        const description = String(descObj?.['rendered'] ?? '');
        const combinedText = `${slug} ${title} ${description}`.toLowerCase();

        const kind = classifyExt(sourceUrl);
        if (kind === 'backup') {
          findings.push(finding('media_backup_exposed', 'CRITICAL', sourceUrl,
            `Backup/archive file exposed via media library: ${sourceUrl}`,
            {
              replication_steps: [
                `curl -O "${sourceUrl}"`,
                '# File may contain database dumps, source code, or credentials',
              ],
              remediation: 'Remove backup files from uploads. Block .sql/.zip/.bak via server config.',
              evidence: `Source URL: ${sourceUrl}`,
            },
          ));
        } else if (kind === 'sensitive') {
          findings.push(finding('media_sensitive_file', 'HIGH', sourceUrl,
            `Sensitive document exposed via media library: ${sourceUrl}`,
            {
              replication_steps: [
                `curl -O "${sourceUrl}"`,
                '# Review document for confidential data',
              ],
              remediation: 'Restrict access to sensitive documents; use authenticated download.',
              evidence: `Source URL: ${sourceUrl}`,
            },
          ));
        }

        const keywordHits = [...SENSITIVE_KEYWORDS].filter(kw => combinedText.includes(kw));
        if (keywordHits.length > 0) {
          findings.push(finding('media_sensitive_file', 'HIGH', sourceUrl || mediaUrl,
            `Media item '${title}' contains sensitive keywords: ${JSON.stringify(keywordHits)}`,
            {
              replication_steps: [
                `curl -s "${mediaUrl}" | grep -iE "${keywordHits.join('|')}"`,
              ],
              remediation: 'Rename or restrict access to files with sensitive names/descriptions.',
              evidence: `Keywords: ${JSON.stringify(keywordHits)} in title/slug/description`,
            },
          ));
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  // Test 2: Year-based uploads directory enumeration
  const currentYear = new Date().getFullYear();
  const yearMonthPairs: [number, number][] = [];
  for (let y = 2020; y <= currentYear; y++) {
    for (let m = 1; m <= 12; m++) yearMonthPairs.push([y, m]);
  }
  await parallelProbe(yearMonthPairs, async ([year, month]) => {
    const mm = String(month).padStart(2, '0');
    const dirUrl = `${target}${UPLOADS_BASE}/${year}/${mm}/`;
    try {
      const res = await fetchURL(dirUrl);
      if (!res || res.status !== 200) return;
      const body = await res.text();
      if (!body.includes('Index of') && !body.includes('<a href=')) return;

      // Directory listing enabled — find backup/sensitive files
      const hrefs = [...body.matchAll(/href="([^"]+)"/g)].map(m => m[1]);
      for (const link of hrefs) {
        if (link.startsWith('?') || link.startsWith('/') || link === '../' || link === './') continue;
        const fileUrl = dirUrl + link;
        const kind = classifyExt(link);
        if (kind === 'backup') {
          findings.push(finding('media_backup_exposed', 'CRITICAL', fileUrl,
            `Backup file exposed via uploads directory listing: ${fileUrl}`,
            {
              replication_steps: [
                `curl -O "${fileUrl}"`,
                '# Directory listing enabled — file directly downloadable',
              ],
              remediation: 'Disable directory listing; move backups off web root.',
              evidence: `Found via directory index at ${dirUrl}`,
            },
          ));
        } else if (kind === 'sensitive') {
          findings.push(finding('media_sensitive_file', 'HIGH', fileUrl,
            `Sensitive file exposed via open uploads directory: ${fileUrl}`,
            {
              replication_steps: [`curl -O "${fileUrl}"`],
              remediation: 'Disable directory listing and restrict document access.',
              evidence: `Found via ${dirUrl}`,
            },
          ));
        }
      }
    } catch (e) {
      errors.push(String(e));
    }
  });

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
