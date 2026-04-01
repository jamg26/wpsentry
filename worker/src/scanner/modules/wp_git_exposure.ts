import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Git/Env File Exposure Scanner';

type ProbeConfig = {
  path: string;
  desc: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  indicators: (string | RegExp)[];
};

const PROBES: ProbeConfig[] = [
  {
    path: '/.git/HEAD',
    desc: '.git directory exposed — full source code can be cloned',
    severity: 'CRITICAL',
    indicators: ['ref: refs/', 'refs/heads/'],
  },
  {
    path: '/.git/config',
    desc: '.git/config exposed — repository remote URLs and credentials may be visible',
    severity: 'CRITICAL',
    indicators: ['[core]', '[remote', 'repositoryformatversion'],
  },
  {
    path: '/.env',
    desc: '.env file exposed — environment variables including secrets/credentials',
    severity: 'CRITICAL',
    indicators: [/DB_(?:HOST|USER|PASSWORD|NAME)\s*=/i, /APP_KEY\s*=/i, /SECRET/i, /API_KEY/i],
  },
  {
    path: '/.env.local',
    desc: '.env.local exposed — local environment secrets',
    severity: 'CRITICAL',
    indicators: [/DB_/i, /SECRET/i, /KEY=/i],
  },
  {
    path: '/.env.production',
    desc: '.env.production exposed — production secrets',
    severity: 'CRITICAL',
    indicators: [/DB_/i, /SECRET/i, /KEY=/i],
  },
  {
    path: '/.env.backup',
    desc: '.env.backup exposed — backup of environment secrets',
    severity: 'CRITICAL',
    indicators: [/DB_/i, /SECRET/i, /KEY=/i],
  },
  {
    path: '/.htaccess',
    desc: '.htaccess file readable — server configuration exposed',
    severity: 'MEDIUM',
    indicators: ['RewriteEngine', 'RewriteRule', 'RewriteCond', 'AuthType', 'Require'],
  },
  {
    path: '/.htpasswd',
    desc: '.htpasswd file exposed — password hashes visible',
    severity: 'HIGH',
    indicators: [/^[a-zA-Z0-9_-]+:\$/, /^[a-zA-Z0-9_-]+:\{/],
  },
  {
    path: '/.gitignore',
    desc: '.gitignore exposed — reveals project structure and sensitive file locations',
    severity: 'LOW',
    indicators: ['node_modules', '.env', 'vendor/', 'wp-config', '*.log'],
  },
  {
    path: '/.svn/entries',
    desc: 'SVN repository metadata exposed',
    severity: 'HIGH',
    indicators: ['dir', 'svn:'],
  },
  {
    path: '/composer.json',
    desc: 'composer.json exposed — PHP dependency information visible',
    severity: 'LOW',
    indicators: ['"require"', '"name"', 'php'],
  },
  {
    path: '/composer.lock',
    desc: 'composer.lock exposed — exact dependency versions disclosed',
    severity: 'LOW',
    indicators: ['"packages"', '"hash"'],
  },
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    await parallelProbe(PROBES, async (probe) => {
      const url = `${target}${probe.path}`;
      const res = await fetchURL(url);
      if (!res || res.status !== 200) return;
      const body = await res.text();

      // Verify content matches expected indicators (avoid false positives on custom 404 pages)
      const hasIndicator = probe.indicators.some(ind =>
        typeof ind === 'string' ? body.includes(ind) : ind.test(body)
      );
      if (!hasIndicator) return;

      findings.push(finding('SENSITIVE_FILE_EXPOSED', probe.severity, url,
        probe.desc, {
          evidence: `File accessible at ${probe.path} with expected content patterns`,
          replication_steps: [
            `Fetch ${url}`,
            `Observe ${probe.path} content is returned`,
            ...(probe.severity === 'CRITICAL' ? ['This may expose credentials, API keys, or source code'] : []),
          ],
          remediation: `Block access to ${probe.path} via server configuration. Add deny rules for dotfiles in .htaccess or nginx config.`,
        }));
    }, 6);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
