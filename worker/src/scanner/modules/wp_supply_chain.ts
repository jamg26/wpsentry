import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, getJSON, finding, moduleResult, normalizeTarget, parallelProbe} from '../utils.js';

const MODULE_NAME = 'Supply Chain Risk';

const PLUGINS_DIR = '/wp-content/plugins/';

// [slug, reason]
const REMOVED_PLUGINS: [string, string][] = [
  ['display-widgets', 'Removed 2017 — contained backdoor sending user data to third party'],
  ['pinterest-pin-it-button-for-images', 'Removed — redirected users to malicious sites'],
  ['wp-http-compression', 'Abandoned — no security updates since 2010'],
  ['google-adsense-dashboard', 'Removed — adware injecting ads without consent'],
  ['wp-content-spinner', 'Removed — contained obfuscated malicious code'],
  ['superfish', 'Removed — spyware/adware'],
  ['social-buttons-pack', 'Removed — contained malware'],
  ['wp-base-seo', 'Removed — backdoor inserting spam links'],
  ['easy-wp-smtp', 'Flagged — credential exfiltration vulnerability'],
  ['loginizer', 'Critical RCE vulnerability — ensure updated'],
  ['wp-file-manager', 'CVE-2020-25213 — unauthenticated RCE'],
  ['wp-fastest-cache', 'SQL injection vulnerability'],
  ['backup-buddy', 'Path traversal vulnerability'],
  ['duplicator', 'CVE-2020-11738 — directory traversal'],
  ['wptouch', 'Abandoned — last updated 2020'],
];

const MALICIOUS_PATTERNS: [RegExp, string][] = [
  [/eval\s*\(\s*base64_decode\s*\(/i, 'eval(base64_decode()) — common obfuscation/backdoor pattern'],
  [/eval\s*\(\s*gzinflate\s*\(/i, 'eval(gzinflate()) — compressed code execution obfuscation'],
  [/eval\s*\(\s*str_rot13\s*\(/i, 'eval(str_rot13()) — obfuscated code execution'],
  [/\$[a-zA-Z_]{1,3}\s*=\s*\$[a-zA-Z_]{1,3}\s*\(\s*\$[a-zA-Z_]{1,3}/i, 'Chained variable function call — possible webshell'],
  [/assert\s*\(\s*base64_decode/i, 'assert(base64_decode()) — code injection pattern'],
  [/preg_replace\s*\(\s*['"]\/.*\/e['"]/i, 'preg_replace /e modifier — code execution'],
];

const THREE_YEARS_MS = 3 * 365 * 24 * 60 * 60 * 1000;

function parseVersionDate(text: string): Date | null {
  const patterns = [
    /Last Updated:\s*(\d{4}-\d{2}-\d{2})/i,
    /(\d{4}-\d{2}-\d{2})/,
  ];
  for (const pat of patterns) {
    const m = text.match(pat);
    if (m) {
      const d = new Date(m[1]);
      if (!isNaN(d.getTime())) return d;
    }
  }
  return null;
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  const threeYearsAgo = new Date(Date.now() - THREE_YEARS_MS);

  try {
    // Test 1: REST API plugin listing (may be exposed if misconfigured)
    const pluginsApiUrl = `${target}/wp-json/wp/v2/plugins`;
    const plugins = await getJSON<unknown[]>(pluginsApiUrl);
    if (Array.isArray(plugins) && plugins.length > 0) {
      findings.push(finding(
        'supply_chain_risk', 'HIGH', pluginsApiUrl,
        `REST API /wp/v2/plugins endpoint exposed ${plugins.length} plugin(s) without authentication. Plugin names and versions disclosed.`,
        {
          replication_steps: [
            `curl -s "${pluginsApiUrl}" | python3 -m json.tool`,
          ],
          remediation: "Restrict /wp/v2/plugins endpoint to authenticated admins only. Add capability check: current_user_can('manage_options').",
          evidence: `${plugins.length} plugins returned at ${pluginsApiUrl}`,
        },
      ));
    }

    // Test 2 & 3: Check known removed/abandoned plugins via readme.txt
    await parallelProbe(REMOVED_PLUGINS, async ([slug, reason]) => {
      const readmeUrl = `${target}${PLUGINS_DIR}${slug}/readme.txt`;
      const mainUrl = `${target}${PLUGINS_DIR}${slug}/`;

      const readmeRes = await fetchURL(readmeUrl, { timeoutMs: 10000 });
      if (!readmeRes) return;

      if (readmeRes.status === 200) {
        const readmeBody = await readmeRes.text();
        const lastUpdated = parseVersionDate(readmeBody);
        const isAbandoned = lastUpdated !== null && lastUpdated < threeYearsAgo;
        const reasonLower = reason.toLowerCase();
        const severity = (reasonLower.includes('backdoor') || reasonLower.includes('malware') || reason.includes('RCE'))
          ? 'CRITICAL' as const
          : 'HIGH' as const;
        const ftype = severity === 'CRITICAL' ? 'potentially_backdoored_plugin' : 'abandoned_plugin';
        const ageNote = lastUpdated ? ` Last updated: ${lastUpdated.toISOString().slice(0, 10)}.` : '';

        findings.push(finding(
          ftype, severity, readmeUrl,
          `Plugin '${slug}' detected.${ageNote} ${reason}`,
          {
            replication_steps: [
              `curl -s "${readmeUrl}" | grep -iE "stable tag|version|last updated"`,
              `curl -sI "${mainUrl}"`,
              `# Plugin: ${slug} — ${reason}`,
              `# Check: https://wordpress.org/plugins/${slug}/`,
            ],
            remediation: `Immediately deactivate and remove '${slug}'. ${reason}. Replace with an actively maintained alternative.`,
            evidence: `readme.txt accessible at ${readmeUrl}`,
          },
        ));
        void isAbandoned; // included in ageNote above
      } else if (readmeRes.status === 403) {
        // 403 means server blocks access — check if readme.txt is actually present
        const mainRes = await fetchURL(mainUrl, { timeoutMs: 10000 });
        if (mainRes && mainRes.status === 200) {
          const mainBody = await mainRes.text();
          if (mainBody.includes('readme.txt') || mainBody.includes('===')) {
            findings.push(finding(
              'supply_chain_risk', 'HIGH', mainUrl,
              `Plugin directory for '${slug}' exists (HTTP ${mainRes.status}) with readme.txt content. ${reason}`,
              {
                replication_steps: [
                  `curl -sI "${mainUrl}"`,
                  `# Plugin: ${slug} — ${reason}`,
                ],
                remediation: `Verify and remove '${slug}' if not needed.`,
                evidence: `HTTP ${mainRes.status} from ${mainUrl}`,
              },
            ));
          }
        }
      }
    });

    // Test 4: Directory listing on /wp-content/plugins/
    const pluginsDirUrl = `${target}${PLUGINS_DIR}`;
    const dirRes = await fetchURL(pluginsDirUrl);
    const foundPlugins: string[] = [];
    if (dirRes && dirRes.status === 200) {
      const body = await dirRes.text();
      if (body.includes('Index of') || body.includes('<a href=')) {
        const links = [...body.matchAll(/href="([^"?/][^"]*\/)?"/g)]
          .map(m => (m[1] ?? '').replace(/\/$/, ''))
          .filter(l => l && !l.startsWith('?') && !l.startsWith('..'));
        foundPlugins.push(...links);
        findings.push(finding(
          'supply_chain_risk', 'HIGH', pluginsDirUrl,
          `Plugin directory listing is enabled. ${foundPlugins.length} plugin(s) enumerated: ${JSON.stringify(foundPlugins.slice(0, 10))}`,
          {
            replication_steps: [
              `curl -s "${pluginsDirUrl}" | grep -oP 'href="\\K[^"]+(?=/")' `,
            ],
            remediation: "Disable directory listing: add 'Options -Indexes' to .htaccess or 'autoindex off;' in nginx.conf.",
            evidence: `Directory index at ${pluginsDirUrl}`,
          },
        ));
      }
    }

    // Test 5: Scan accessible plugin PHP files for malicious patterns
    for (const pluginSlug of foundPlugins.slice(0, 10)) {
      for (const phpFile of ['index.php', `${pluginSlug}.php`]) {
        const fileUrl = `${target}${PLUGINS_DIR}${pluginSlug}/${phpFile}`;
        const fileRes = await fetchURL(fileUrl, { timeoutMs: 10000 });
        if (fileRes && fileRes.status === 200) {
          const body = await fileRes.text();
          if (body.includes('<?php')) {
            for (const [pattern, patternDesc] of MALICIOUS_PATTERNS) {
              if (pattern.test(body)) {
                findings.push(finding(
                  'potentially_backdoored_plugin', 'CRITICAL', fileUrl,
                  `Malicious code pattern detected in ${pluginSlug}/${phpFile}: ${patternDesc}`,
                  {
                    replication_steps: [
                      `curl -s "${fileUrl}" | grep -iE "${pattern.source.slice(0, 40)}"`,
                      `# Pattern: ${patternDesc}`,
                      '# Review full file for backdoor or obfuscated code',
                    ],
                    remediation: `Immediately deactivate and remove '${pluginSlug}'. Scan entire WordPress installation with a security scanner.`,
                    evidence: `Pattern '${patternDesc}' matched in ${fileUrl}`,
                  },
                ));
                break;
              }
            }
          }
        }
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
