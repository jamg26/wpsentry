import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Directory Listing Check';

const DIRECTORIES = [
  '/wp-content/uploads/',
  '/wp-content/plugins/',
  '/wp-content/themes/',
  '/wp-content/',
  '/wp-includes/',
  '/wp-includes/js/',
  '/wp-includes/css/',
  '/wp-admin/',
  '/wp-admin/css/',
  '/wp-admin/js/',
  '/wp-content/languages/',
  '/wp-content/cache/',
  '/wp-content/backup-db/',
  '/wp-content/backups/',
  '/wp-content/uploads/woocommerce_uploads/',
];

const LISTING_INDICATORS = [
  'Index of /',
  'Directory listing for',
  '<title>Index of',
  'Parent Directory',
  '[DIR]',
  '[PARENTDIR]',
];

function isListing(text: string): boolean {
  const lower = text.toLowerCase();
  return LISTING_INDICATORS.some(ind => lower.includes(ind.toLowerCase()));
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(DIRECTORIES, async (directory) => {
      const url = `${target}${directory}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();
      if (isListing(body)) {
        findings.push(finding(
          'DIRECTORY_LISTING_ENABLED', 'MEDIUM', url,
          `Directory listing enabled: ${directory}`,
        ));
      }
    });
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
