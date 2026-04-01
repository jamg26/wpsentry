import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget, parallelProbe } from '../utils.js';

const MODULE_NAME = 'Advanced SSTI (Page Builders)';

// Uses unique high-entropy values to avoid false positives (7777*7777 = 60481729)
const SSTI_PAYLOADS: Array<[string, string]> = [
  ['{{7777*7777}}',               '60481729'],   // Twig / Jinja2
  ['${7777*7777}',                '60481729'],   // Velocity / FreeMarker / EL
  ['<%= 7777*7777 %>',           '60481729'],   // ERB / EJS
  ['#{7777*7777}',                '60481729'],   // Mako / Ruby
  ['*{7777*7777}',                '60481729'],   // Thymeleaf
  ['{{range(0,1).__class__.__mro__[1].__subclasses__()}}', '__subclasses__'],  // Jinja2 Python
  ['{{config.items()}}',          'SECRET_KEY'],  // Flask / Jinja2
  ['{{7*\'7\'}}',                 '7777777'],    // Twig string repeat
];

// Template engine error messages
const TWIG_ERRORS = [
  'Twig_Error',
  'Twig\\Error',
  'Unexpected token',
  'Expected name or number',
  'Variable "config" does not exist',
  'Twig_SyntaxError',
  'in Twig_Environment',
  'Twig\\Environment',
];

const SMARTY_ERRORS = [
  'Smarty Error',
  'Smarty error:',
  'Smarty\\Exception',
  'SmartyCompilerException',
];

const TIMBER_INDICATORS = [
  'timber',
  'TimberPost',
  'timber-library',
];

// Page builder endpoints + common contact/search form params
const PROBE_CONFIGS: Array<[string, string[]]> = [
  ['/?s=', ['s']],
  ['/?q=', ['q']],
  ['/?search=', ['search']],
  ['/?keyword=', ['keyword']],
  ['/wp-comments-post.php?comment=', ['comment']],
  // Elementor form preview
  ['/?elementor_library&preview=1&id=', ['id']],
  // WPBakery shortcode preview
  ['/?vc_action=vc_get_content&shortcode=', ['shortcode']],
  // Beaver Builder
  ['/?fl_builder_preview=1&title=', ['title']],
  // Divi builder
  ['/?et_fb=1&page_id=', ['page_id']],
];

// Plugins that use template engines
const TEMPLATE_PLUGIN_PATHS = [
  '/wp-content/plugins/timber-library/readme.txt',
  '/wp-content/themes/timber/functions.php',
  '/wp-content/plugins/twig/readme.txt',
  '/wp-content/plugins/smarty/readme.txt',
  '/wp-content/plugins/wp-smarty/readme.txt',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    const seen = new Set<string>();

    // Check for template engine plugins
    await parallelProbe(TEMPLATE_PLUGIN_PATHS, async (path) => {
      const res = await fetchURL(target + path, { timeoutMs: 3_000 });
      if (res?.status !== 200) return;
      const text = await res.text().catch(() => '');
      if (!text.includes('Stable tag:') && !text.length) return;

      const engine = path.includes('timber') ? 'Timber/Twig'
        : path.includes('smarty') ? 'Smarty'
        : 'Unknown template engine';

      findings.push(finding(
        'TEMPLATE_ENGINE_DETECTED',
        'MEDIUM',
        target + path,
        `Template engine plugin detected: ${engine} — SSTI may be possible if user input reaches templates`,
        {
          evidence: `path="${path}" engine="${engine}"`,
          remediation: 'Ensure user input is never passed directly into Twig/Smarty render calls. Use sandboxed environments.',
        },
      ));
    }, 5);

    // Test SSTI payloads across probe configs
    const combos: Array<[string, string, string, string]> = [];
    for (const [paramPath, [paramName]] of PROBE_CONFIGS) {
      for (const [payload, expected] of SSTI_PAYLOADS) {
        combos.push([paramPath, paramName, payload, expected]);
      }
    }

    await parallelProbe(combos, async ([paramPath, paramName, payload, expected]) => {
      const key = `${paramName}:${payload}`;
      if (seen.has(paramName)) return;

      const url = target + paramPath + encodeURIComponent(payload);
      const res = await fetchURL(url, { timeoutMs: 5_000 });
      if (!res) return;

      const text = await res.text().catch(() => '');

      // Check for arithmetic result (strongest evidence)
      if (text.includes(expected) && expected.match(/^\d+$/)) {
        if (!seen.has(paramName)) {
          seen.add(paramName);
          findings.push(finding(
            'SSTI_CONFIRMED',
            'CRITICAL',
            url,
            `SSTI confirmed via arithmetic evaluation: payload '${payload}' produced '${expected}' in response`,
            {
              evidence: `payload="${payload}" expected="${expected}" param="${paramName}"`,
              remediation: 'Never pass user input into template render functions. Use Twig sandbox mode. Escape all user-controlled variables with |e filter.',
            },
          ));
        }
        return;
      }

      // Check for template engine error (medium confidence)
      const twigErr = TWIG_ERRORS.find(e => text.includes(e));
      const smartyErr = SMARTY_ERRORS.find(e => text.includes(e));
      const errFound = twigErr ?? smartyErr;
      if (errFound && !seen.has(key)) {
        seen.add(key);
        findings.push(finding(
          'SSTI_ERROR_TRIGGERED',
          'HIGH',
          url,
          `Template engine error triggered — SSTI payload caused: '${errFound}'`,
          {
            evidence: `error="${errFound}" payload="${payload}" param="${paramName}"`,
            remediation: 'Never pass user input into template render functions. Update template engine to latest version.',
          },
        ));
      }

      // Check Timber/Twig indicators in response
      const timberInd = TIMBER_INDICATORS.find(t => text.toLowerCase().includes(t));
      if (timberInd && !seen.has('timber_detected')) {
        seen.add('timber_detected');
        findings.push(finding(
          'TIMBER_TWIG_DETECTED',
          'MEDIUM',
          url,
          `Timber/Twig template engine detected in response — test SSTI manually`,
          {
            evidence: `indicator="${timberInd}"`,
            remediation: 'Ensure user input is never directly passed into Twig render contexts.',
          },
        ));
      }
    }, 20);
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
