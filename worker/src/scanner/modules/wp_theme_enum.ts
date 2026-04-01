import type { ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Theme Enumeration';

const POPULAR_THEMES = [
  'twentytwenty', 'twentytwentyone', 'twentytwentytwo', 'twentytwentythree',
  'avada', 'divi', 'flatsome', 'bridge', 'salient', 'the7', 'kalium',
  'enfold', 'betheme', 'jupiter', 'jupiter-x', 'astra', 'generatepress',
  'oceanwp', 'storefront', 'hestia',
];

// theme → [min_safe_version, cve_id, vuln_type]
const KNOWN_VULNS: Record<string, [string, string, string]> = {
  divi:   ['4.14.8', 'CVE-2022-1962', 'XSS'],
  avada:  ['7.9.0',  'CVE-2022-0760', 'SSRF'],
  enfold: ['4.8.8',  'CVE-2021-24347', 'File Read'],
};

function parseVersion(text: string): string | null {
  const m = text.match(/Version:\s*([\d.]+)/i);
  return m ? m[1] : null;
}

function versionLt(v1: string, v2: string): boolean {
  try {
    const a = v1.split('.').map(Number);
    const b = v2.split('.').map(Number);
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const ai = a[i] ?? 0;
      const bi = b[i] ?? 0;
      if (ai < bi) return true;
      if (ai > bi) return false;
    }
    return false;
  } catch {
    return false;
  }
}

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: ReturnType<typeof finding>[] = [];
  const errors: string[] = [];

  try {
    const foundThemes: [string, string | null, string][] = [];

    // Phase 1: Detect themes in parallel
    await parallelProbe(POPULAR_THEMES, async (theme) => {
      const cssUrl = `${target}/wp-content/themes/${theme}/style.css`;
      try {
        const res = await fetchURL(cssUrl);
        if (!res || res.status !== 200) return;
        const text = await res.text();
        // HIGH-08: Require canonical 'Theme Name:' header in style.css to confirm presence.
        // A bare HTTP 200 is insufficient — CDNs and WAFs can return 200 for non-existent paths.
        if (!text.includes('Theme Name:')) return;
        const version = parseVersion(text);
        foundThemes.push([theme, version, cssUrl]);
        findings.push(finding('theme_detected', 'INFO', cssUrl,
          `Theme '${theme}' detected (HTTP ${res.status})` + (version ? `, version ${version}` : ''),
          {
            replication_steps: [
              `curl -s "${cssUrl}" | grep -i "Version:"`,
              `curl -sI "${cssUrl}"`,
            ],
            remediation: 'Remove unused themes; keep active theme updated.',
            evidence: `HTTP ${res.status} from ${cssUrl}`,
          },
        ));
      } catch (e) {
        errors.push(String(e));
      }
    });

    // Phase 2+3+4 run in parallel per detected theme
    await Promise.allSettled([
      // Theme switching check (top 5 only)
      parallelProbe(foundThemes.slice(0, 5), async ([theme]) => {
        const switchUrl = `${target}/?theme=${theme}`;
        try {
          const res = await fetchURL(switchUrl);
          if (!res || res.status !== 200) return;
          const body = await res.text();
          // HIGH-08: Require theme asset path in body (not just the theme name)
          // to avoid false positives from blog content mentioning the theme name.
          if (body.includes(`/wp-content/themes/${theme}/`)) {
            findings.push(finding('theme_detected', 'INFO', switchUrl,
              `Theme switching via ?theme= may be active for '${theme}'`,
              {
                replication_steps: [`curl -s "${switchUrl}" | grep -i "${theme}"`],
                remediation: 'Disable unauthenticated theme switching.',
                evidence: `Theme asset path found in response body`,
              },
            ));
          }
        } catch (e) {
          errors.push(String(e));
        }
      }),
      // readme.txt for version + CVE checks
      parallelProbe(foundThemes.filter(([, v]) => !v), async ([theme, , cssUrl]: [string, string | null, string]) => {
        const readmeUrl = `${target}/wp-content/themes/${theme}/readme.txt`;
        try {
          const res = await fetchURL(readmeUrl);
          if (!res || res.status !== 200) return;
          const text = await res.text();
          const v = parseVersion(text);
          if (v) {
            const idx = foundThemes.findIndex(([t]) => t === theme);
            if (idx >= 0) foundThemes[idx] = [theme, v, cssUrl];
          }
        } catch (e) {
          errors.push(String(e));
        }
      }),
    ]);

    // CVE checks after version resolution
    for (const [theme, version, cssUrl] of foundThemes) {
      const vuln = KNOWN_VULNS[theme.toLowerCase()];
      if (!vuln || !version) continue;
      const [safeVer, cveId, vulnType] = vuln;
      if (versionLt(version, safeVer)) {
        findings.push(finding('theme_known_cve', 'HIGH', cssUrl,
          `Theme '${theme}' v${version} is vulnerable to ${vulnType} (${cveId}). ` +
          `Safe version: >= ${safeVer}.`,
          {
            replication_steps: [
              `curl -s "${cssUrl}" | grep -i "Version:"`,
              `# ${cveId}: ${vulnType} in ${theme} < ${safeVer}`,
              `# See: https://wpscan.com/vulnerability/search?text=${cveId}`,
            ],
            remediation: `Update ${theme} to >= ${safeVer} immediately.`,
            evidence: JSON.stringify({ version, safe_version: safeVer, cvss_score: vulnType === 'SSRF' ? 8.8 : 7.4, cve_refs: [cveId] }),
          },
        ));
      }
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
