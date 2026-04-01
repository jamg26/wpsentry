import { run as run1 } from './wp_version_detect.js';
import { run as run2 } from './wp_user_enum.js';
import { run as run3 } from './wp_plugin_enum.js';
import { run as run4 } from './wp_xmlrpc.js';
import { run as run5 } from './wp_sensitive_files.js';
import { run as run6 } from './wp_directory_listing.js';
import { run as run7 } from './wp_backup_finder.js';
import { run as run8 } from './wp_rest_api.js';
import { run as run9 } from './wp_cors.js';
import { run as run10 } from './wp_sqli.js';
import { run as run11 } from './wp_xss.js';
import { run as run12 } from './wp_lfi.js';
import { run as run13 } from './wp_rfi.js';
import { run as run14 } from './wp_file_upload.js';
import { run as run15 } from './wp_debug_info.js';
import { run as run16 } from './wp_path_traversal.js';
import { run as run17 } from './wp_bruteforce.js';
import { run as run18 } from './wp_security_headers.js';
import { run as run19 } from './wp_open_redirect.js';
import { run as run20 } from './wp_csrf.js';
import { run as run21 } from './wp_admin_exposure.js';
import { run as run22 } from './wp_login_protection.js';
import { run as run23 } from './wp_ssrf.js';
import { run as run24 } from './wp_xxe.js';
import { run as run25 } from './wp_ssti.js';
import { run as run26 } from './wp_host_header.js';
import { run as run27 } from './wp_object_injection.js';
import { run as run28 } from './wp_email_injection.js';
import { run as run29 } from './wp_idor.js';
import { run as run30 } from './wp_timthumb.js';
import { run as run31 } from './wp_revslider.js';
import { run as run32 } from './wp_file_manager_cve.js';
import { run as run33 } from './wp_contact_form7.js';
import { run as run34 } from './wp_woocommerce.js';
import { run as run35 } from './wp_plugin_cve.js';
import { run as run36 } from './wp_theme_enum.js';
import { run as run37 } from './wp_cron.js';
import { run as run38 } from './wp_heartbeat.js';
import { run as run39 } from './wp_gdpr.js';
import { run as run40 } from './wp_media_enum.js';
import { run as run41 } from './wp_rate_limit.js';
import { run as run42 } from './wp_cache_poisoning.js';
import { run as run43 } from './wp_subdomain.js';
import { run as run44 } from './wp_multisite.js';
import { run as run45 } from './wp_php_wrappers.js';
import { run as run46 } from './wp_supply_chain.js';
import { run as run47 } from './wp_nonce.js';
import { run as run48 } from './wp_ssl_tls.js';
import { run as run49 } from './wp_api_auth.js';
import { run as run50 } from './wp_clickjacking.js';
import { run as run51 } from './wp_robots_sitemap.js';
import { run as run52 } from './wp_cookie_security.js';
import { run as run53 } from './wp_http_methods.js';
import { run as run54 } from './wp_rest_harvest.js';
import { run as run55 } from './wp_ajax_enum.js';
import { run as run56 } from './wp_js_recon.js';
import { run as run57 } from './wp_password_reset.js';
import { run as run58 } from './wp_error_analysis.js';
import { run as run59 } from './wp_race_conditions.js';
import { run as run60 } from './wp_mass_assignment.js';
import { run as run61 } from './wp_wpgraphql.js';
import { run as run62 } from './wp_jwt_auth.js';
import { run as run63 } from './wp_app_passwords.js';
import { run as run64 } from './wp_rest_plugin_audit.js';
import { run as run65 } from './wp_bfla.js';
import { run as run66 } from './wp_cmd_injection.js';
import { run as run67 } from './wp_business_logic.js';
import { run as run68 } from './wp_theme_vuln.js';
import { run as run69 } from './wp_db_prefix.js';
import { run as run70 } from './wp_registration_open.js';
import { run as run71 } from './wp_feeds_exposure.js';
import { run as run72 } from './wp_emoji_dns_prefetch.js';
import { run as run73 } from './wp_oembed.js';
import { run as run74 } from './wp_install_exposed.js';
import { run as run75 } from './wp_session_fixation.js';
import { run as run76 } from './wp_password_policy.js';
import { run as run77 } from './wp_2fa_bypass.js';
import { run as run78 } from './wp_auth_cookie_security.js';
import { run as run79 } from './wp_concurrent_sessions.js';
import { run as run80 } from './wp_account_enumeration.js';
import { run as run81 } from './wp_logout_security.js';
import { run as run82 } from './wp_elementor_vuln.js';
import { run as run83 } from './wp_yoast_vuln.js';
import { run as run84 } from './wp_acf_vuln.js';
import { run as run85 } from './wp_wpforms_vuln.js';
import { run as run86 } from './wp_wordfence_bypass.js';
import { run as run87 } from './wp_updraftplus_vuln.js';
import { run as run88 } from './wp_all_in_one_seo.js';
import { run as run89 } from './wp_php_info.js';
import { run as run90 } from './wp_error_log_exposure.js';
import { run as run91 } from './wp_git_exposure.js';
import { run as run92 } from './wp_database_dump.js';
import { run as run93 } from './wp_staging_env.js';
import { run as run94 } from './wp_wp_config_backup.js';
import { run as run95 } from './wp_rest_api_dos.js';
import { run as run96 } from './wp_webhook_security.js';
import { run as run97 } from './wp_oauth_vuln.js';
import { run as run98 } from './wp_rest_api_enum_v2.js';
import { run as run99 } from './wp_content_injection.js';
import { run as run100 } from './wp_upload_dir_listing.js';
import { run as run101 } from './wp_php_deserialization.js';
import { run as run102 } from './wp_prototype_pollution.js';
import { run as run103 } from './wp_log4shell_indicators.js';
import { run as run104 } from './wp_ssti_advanced.js';
import { run as run105 } from './wp_deserialization_gadget.js';
import { run as run106 } from './wp_graphql_abuse.js';
import { run as run107 } from './wp_supply_chain_integrity.js';
import { run as run108 } from './wp_credential_stuffing.js';
import { run as run109 } from './wp_webshell_indicators.js';
import { run as run110 } from './wp_malware_indicators.js';
import { run as run111 } from './wp_woocommerce_sqli.js';
import { run as run112 } from './wp_admin_ajax_unauth.js';
import { run as run113 } from './wp_cors_misconfiguration.js';
import { run as run114 } from './wp_xxe_advanced.js';
import { run as run115 } from './wp_race_condition_purchase.js';
import { run as run116 } from './wp_cve_2024_scanner.js';
import { run as run117 } from './wp_subdomain_takeover.js';
import { run as run118 } from './wp_secret_scanning_advanced.js';
import { run as run119 } from './wp_path_traversal_advanced.js';
import { run as run120 } from './wp_insecure_direct_object_reference.js';
import { run as run121 } from './wp_plugin_slurp.js';
import { run as run122 } from './wp_header_injection.js';

import type { ScanState, ModuleResult } from '../types.js';

export interface ModuleSpec {
  id: number;
  name: string;
  desc: string;
  /** When false, module runs on any site. When true or undefined, module requires WordPress. */
  requiresWordPress?: boolean;
  run: (target: string, state?: ScanState) => Promise<ModuleResult>;
}

export const MODULES: ModuleSpec[] = [
  { id: 1,  name: 'Version Detection',          desc: 'Detect WordPress version and flag end-of-life',                               run: run1 },
  { id: 2,  name: 'User Enumeration',           desc: 'Enumerate users via author archives & REST API',                             run: run2 },
  { id: 3,  name: 'Plugin Enumeration',         desc: 'Probe common plugins for existence & version',                              run: run3 },
  { id: 4,  name: 'XML-RPC Abuse',              desc: 'Multicall brute-force, pingback SSRF',                                     run: run4 },
  { id: 5,  name: 'Sensitive Files',            desc: 'wp-config backups, .env, .git, SQL dumps',                                 run: run5 },
  { id: 6,  name: 'Directory Listing',          desc: 'Apache/Nginx open directory listing',                                      run: run6 },
  { id: 7,  name: 'Backup Finder',              desc: 'SQL dumps & zip archive discovery',                                        run: run7 },
  { id: 8,  name: 'REST API Exposure',          desc: 'Unauthenticated REST endpoint enumeration',                                run: run8 },
  { id: 9,  name: 'CORS Misconfiguration',      desc: 'Wildcard & reflected CORS',                                                run: run9 },
  { id: 10, name: 'SQL Injection',              desc: 'Error-based SQLi in common endpoints',                                     run: run10 },
  { id: 11, name: 'Cross-Site Scripting',       desc: 'Reflected XSS in search & params',                                        run: run11 },
  { id: 12, name: 'Local File Inclusion',       desc: 'LFI with traversal & encoding variants',                                  run: run12 },
  { id: 13, name: 'Remote File Inclusion',      desc: 'RFI via PHP wrappers',                                                    run: run13 },
  { id: 14, name: 'File Upload Bypass',         desc: 'PHP/SVG/HTML unrestricted upload',                                        run: run14 },
  { id: 15, name: 'Debug Information',          desc: 'debug.log, phpinfo, error headers',                                       run: run15 },
  { id: 16, name: 'Path Traversal',             desc: 'High-severity traversal targets only',                                    run: run16 },
  { id: 17, name: 'Brute Force',                desc: 'Login brute force with common credentials',                               run: run17 },
  { id: 18, name: 'Security Headers',           desc: 'HSTS, CSP, X-Frame-Options audit',                                       run: run18 },
  { id: 19, name: 'Open Redirect',              desc: 'Open redirect via redirect_to parameter',                                 run: run19 },
  { id: 20, name: 'CSRF Checks',                desc: 'CSRF token absence on sensitive forms',                                   run: run20 },
  { id: 21, name: 'Admin Exposure',             desc: 'wp-login/wp-admin hardening check',                                      run: run21 },
  { id: 22, name: 'Login Protection',           desc: 'Rate limiting, lockout, CAPTCHA',                                        run: run22 },
  { id: 23, name: 'SSRF',                       desc: 'SSRF via xmlrpc pingback & oEmbed',                                      run: run23 },
  { id: 24, name: 'XXE Injection',              desc: 'XML External Entity injection',                                           run: run24 },
  { id: 25, name: 'SSTI',                       desc: 'Server-Side Template Injection',                                          run: run25 },
  { id: 26, name: 'Host Header Injection',      desc: 'Password reset poisoning via Host header',                               run: run26 },
  { id: 27, name: 'Object Injection',           desc: 'PHP unserialize gadget chain abuse',                                     run: run27 },
  { id: 28, name: 'Email Injection',            desc: 'CRLF injection in contact form email headers',                           run: run28 },
  { id: 29, name: 'IDOR',                       desc: 'Private/draft post access via ID enumeration',                           run: run29 },
  { id: 30, name: 'TimThumb RFI',               desc: 'CVE-2011-4106 TimThumb remote file include',                            run: run30 },
  { id: 31, name: 'RevSlider LFI',              desc: 'CVE-2014-9734 Revolution Slider file read',                             run: run31 },
  { id: 32, name: 'WP File Manager RCE',        desc: 'CVE-2020-25213 unauthenticated file upload',                            run: run32 },
  { id: 33, name: 'Contact Form 7',             desc: 'CVE-2020-35489 upload bypass & XSS',                                    run: run33 },
  { id: 34, name: 'WooCommerce Vulns',          desc: 'SQLi, price manipulation, order IDOR',                                   run: run34 },
  { id: 35, name: 'Plugin CVE Scanner',         desc: '30 high-value plugins vs known CVEs',                                   run: run35 },
  { id: 36, name: 'Theme Enumeration',          desc: 'Active theme detection & known CVEs',                                   run: run36 },
  { id: 37, name: 'WP-Cron Abuse',              desc: 'Cron DoS amplification & info disclosure',                              run: run37 },
  { id: 38, name: 'Heartbeat API Abuse',        desc: 'DoS amplification & data exfiltration',                                 run: run38 },
  { id: 39, name: 'GDPR Data Exposure',         desc: 'Personal data export/erasure bypass',                                   run: run39 },
  { id: 40, name: 'Media Enumeration',          desc: 'Sensitive uploaded file discovery',                                     run: run40 },
  { id: 41, name: 'Rate Limit Bypass',          desc: 'Login/API rate limit bypass via IP spoofing',                           run: run41 },
  { id: 42, name: 'Cache Poisoning',            desc: 'Unkeyed header cache poisoning',                                        run: run42 },
  { id: 43, name: 'Subdomain Takeover',         desc: 'Dangling DNS & unclaimed subdomain detection',                          run: run43 },
  { id: 44, name: 'Multisite Misconfig',        desc: 'Open registration & network exposure',                                  run: run44 },
  { id: 45, name: 'PHP Wrappers',               desc: 'php://filter, php://input, data:// abuse',                              run: run45 },
  { id: 46, name: 'Supply Chain Risks',         desc: 'Abandoned/backdoored plugin detection',                                 run: run46 },
  { id: 47, name: 'Nonce Weakness',             desc: 'Nonce bypass, reuse, and absence checks',                              run: run47 },
  { id: 48, name: 'SSL/TLS Audit',              desc: 'Certificate, cipher, HSTS, mixed content',                             run: run48 },
  { id: 49, name: 'REST API Auth Bypass',       desc: 'Unauthenticated read/write via REST API',                              run: run49 },
  { id: 50, name: 'Clickjacking',               desc: 'X-Frame-Options & CSP frame-ancestors',                                run: run50 },
  { id: 51, name: 'Robots & Sitemap Recon',     desc: 'robots.txt & sitemap.xml information disclosure',                      run: run51 },
  { id: 52, name: 'Cookie Security Flags',      desc: 'HttpOnly/Secure/SameSite cookie flag audit',                          run: run52 },
  { id: 53, name: 'Dangerous HTTP Methods',     desc: 'TRACE/PUT/DELETE/WebDAV method testing',                               run: run53 },
  { id: 54, name: 'REST API Deep Harvest',      desc: 'Staging domains, PII, JSONP, media files via REST',                   run: run54 },
  { id: 55, name: 'Admin AJAX Enumeration',     desc: '120+ nopriv AJAX action exposure testing',                            run: run55 },
  { id: 56, name: 'JavaScript Recon',           desc: 'API keys, nonces, secrets in JS files',                               run: run56 },
  { id: 57, name: 'Password Reset Security',    desc: 'Email enum, host header poisoning, token leak',                       run: run57 },
  { id: 58, name: 'Error & Exception Analysis', desc: 'HTTP 500s, PHP errors, path/DB disclosure',                           run: run58 },
  { id: 59, name: 'Race Condition Testing',     desc: 'Coupon race, registration race, REST concurrent writes',              run: run59 },
  { id: 60, name: 'REST Mass Assignment',       desc: 'Role escalation, context=edit leaks, draft post access',              run: run60 },
  { id: 61, name: 'WPGraphQL Exposure',         desc: 'GraphQL endpoint, introspection, user/post enumeration',              run: run61 },
  { id: 62, name: 'JWT Auth Testing',           desc: 'alg:none, algorithm confusion, token endpoint brute force',           run: run62 },
  { id: 63, name: 'Application Passwords',      desc: 'WP 5.6+ app password creation, weak creds, REST basic auth',         run: run63 },
  { id: 64, name: 'REST Plugin Endpoint Audit', desc: 'Hummingbird info disclosure, WP-Abilities, unauth plugin REST routes', run: run64 },
  { id: 65, name: 'Broken Function Level Auth', desc: 'Privileged REST/AJAX actions callable without auth',                 run: run65 },
  { id: 66, name: 'Command Injection / RCE',    desc: 'OS command injection via params, REST, AJAX',                        run: run66 },
  { id: 67, name: 'Business Logic Flaws',       desc: 'WooCommerce price manipulation, coupon abuse, order IDOR',           run: run67 },
  { id: 68, name: 'Theme Vulnerability Scanner', desc: 'Check installed themes against known vulnerable versions',            run: run68 },
  { id: 69, name: 'Database Prefix Exposure',    desc: 'Detect non-default DB table prefix via SQL errors or debug output',   run: run69 },
  { id: 70, name: 'Open Registration',           desc: 'Check if user registration is open to the public',                   run: run70 },
  { id: 71, name: 'RSS/Atom Feed Exposure',      desc: 'Check feeds for author names, internal URLs, email leakage',         run: run71 },
  { id: 72, name: 'Emoji DNS Prefetch',          desc: 'Detect WP emoji DNS prefetch (privacy/tracking concern)',             run: run72 },
  { id: 73, name: 'oEmbed Security',             desc: 'Test oEmbed endpoint for SSRF and information disclosure',            run: run73 },
  { id: 74, name: 'Install Page Exposure',       desc: 'Check if wp-admin/install.php is accessible',                        run: run74 },
  { id: 75, name: 'Session Fixation',            desc: 'Test session cookie behavior and fixation resistance',                run: run75 },
  { id: 76, name: 'Password Policy',             desc: 'Test if weak passwords are accepted during registration',             run: run76 },
  { id: 77, name: '2FA Bypass Detection',        desc: 'Check for two-factor authentication bypass via XML-RPC/REST',         run: run77 },
  { id: 78, name: 'Auth Cookie Security',        desc: 'Verify auth cookies have Secure, HttpOnly, SameSite flags',           run: run78 },
  { id: 79, name: 'Concurrent Sessions',         desc: 'Check if concurrent sessions are limited',                            run: run79 },
  { id: 80, name: 'Account Enumeration',         desc: 'Test login error messages for username enumeration',                   run: run80 },
  { id: 81, name: 'Logout Security',             desc: 'Test if logout properly invalidates session with CSRF protection',     run: run81 },
  { id: 82, name: 'Elementor Vulnerabilities',   desc: 'Check Elementor for known CVEs (RCE, XSS, privilege escalation)',      run: run82 },
  { id: 83, name: 'Yoast SEO Vulnerabilities',   desc: 'Check Yoast SEO for known XSS and SQLi CVEs',                        run: run83 },
  { id: 84, name: 'ACF Vulnerabilities',         desc: 'Check Advanced Custom Fields for known CVEs',                         run: run84 },
  { id: 85, name: 'WPForms Vulnerabilities',     desc: 'Check WPForms for file upload and injection vulns',                   run: run85 },
  { id: 86, name: 'Wordfence WAF Bypass',        desc: 'Check Wordfence WAF bypass and config exposure',                      run: run86 },
  { id: 87, name: 'UpdraftPlus Vulnerabilities', desc: 'Check UpdraftPlus for unauthorized backup download CVEs',              run: run87 },
  { id: 88, name: 'All in One SEO Vulns',        desc: 'Check All in One SEO for privilege escalation CVEs',                  run: run88 },
  { id: 89, name: 'phpinfo() Exposure',          desc: 'Check for exposed phpinfo() pages across common paths',               run: run89 },
  { id: 90, name: 'Error Log Exposure',          desc: 'Check for exposed error logs (debug.log, error_log, php_errors)',     run: run90 },
  { id: 91, name: 'Git/Env File Exposure',       desc: 'Check for exposed .git, .env, .htaccess, .htpasswd files',           run: run91 },
  { id: 92, name: 'Database Dump Exposure',      desc: 'Check for exposed .sql, .sql.gz database dump files',                 run: run92 },
  { id: 93, name: 'Staging Environment',         desc: 'Detect staging/dev environments exposed to public',                   run: run93 },
  { id: 94, name: 'wp-config.php Backup',        desc: 'Check for wp-config.php backup files (.bak, .old, .orig, ~)',         run: run94 },
  { id: 95, name: 'REST API DoS',                desc: 'Check REST API for denial of service via expensive queries',          run: run95 },
  { id: 96, name: 'Webhook Security',            desc: 'Check for exposed webhook endpoints and payment callbacks',           run: run96 },
  { id: 97, name: 'OAuth Vulnerabilities',       desc: 'Check OAuth for redirect_uri manipulation and bypass',                run: run97 },
  { id: 98, name: 'REST API Deep Enumeration',   desc: 'Deep REST API endpoint enumeration (CPTs, taxonomies)',               run: run98 },
  { id: 99, name: 'Content Injection',           desc: 'Test REST API content injection (CVE-2017-1001000 style)',             run: run99 },
  { id: 100, name: 'Upload Dir Listing',         desc: 'Check wp-content/uploads for directory listing and sensitive files',   run: run100 },
  { id: 101, name: 'PHP Deserialization',        desc: 'PHP Object Injection / POP chain gadget detection via serialized payloads',      run: run101 },
  { id: 102, name: 'Prototype Pollution',        desc: 'JavaScript prototype pollution via GET params and REST API JSON bodies',         run: run102 },
  { id: 103, name: 'Log4Shell Indicators',       desc: 'JNDI injection probes in User-Agent/Referer/X-Forwarded-For headers',           run: run103 },
  { id: 104, name: 'SSTI Advanced',              desc: 'Advanced SSTI for Elementor/Divi/Beaver/WPBakery page builders + Twig/Smarty',  run: run104 },
  { id: 105, name: 'Phar Deserialization',       desc: 'Phar deserialization / file upload chain gadgets via media REST endpoint',      run: run105 },
  { id: 106, name: 'WPGraphQL Abuse',            desc: 'GraphQL batch queries, field-level auth bypass, user email harvesting',         run: run106 },
  { id: 107, name: 'Supply Chain Integrity',     desc: 'External scripts without SRI hashes — CDN and payment script audit',            run: run107 },
  { id: 108, name: 'Credential Stuffing',        desc: 'Login oracle detection, WooCommerce rate limit bypass, app password abuse',     run: run108 },
  { id: 109, name: 'Webshell Indicators',        desc: 'Common webshell paths (c99, r57, b374k) and PHP execution in uploads',         run: run109 },
  { id: 110, name: 'Malware Indicators',         desc: 'Hidden iframes, obfuscated JS, pharma/Japanese keyword hack detection',        run: run110 },
  { id: 111, name: 'WooCommerce SQLi',           desc: 'WooCommerce-specific SQL injection (product_cat, orderby, price filter)',      run: run111 },
  { id: 112, name: 'Admin AJAX Unauth',          desc: 'Unauthenticated admin-ajax.php action exposure (upload, Revslider, etc.)',     run: run112 },
  { id: 113, name: 'CORS Misconfiguration',      desc: 'Enhanced CORS: null origin, prefix/suffix bypass, wildcard+credentials',      run: run113 },
  { id: 114, name: 'XXE Advanced',               desc: 'XXE in XML-RPC, WP import, WooCommerce import — file disclosure probes',      run: run114 },
  { id: 115, name: 'Race Condition Purchase',    desc: 'WooCommerce race conditions: coupon reuse, add-to-cart, concurrent checkout', run: run115 },
  { id: 116, name: 'CVE 2024-2025 Scanner',      desc: 'WP core and plugin CVEs from 2024-2025 (CVE-2024-10924, 6386, 2879, etc.)',  run: run116 },
  { id: 117, name: 'Subdomain Takeover',         desc: 'Enumerate subdomains from sitemap/robots, detect dangling CNAMEs',            run: run117 },
  { id: 118, name: 'Secret Scanning Advanced',   desc: 'Private keys, DB connection strings, PayPal/Braintree/Slack secrets in JS',   run: run118 },
  { id: 119, name: 'Path Traversal Advanced',    desc: 'Double-encoding, Unicode, REST API, and theme template traversal attacks',    run: run119 },
  { id: 120, name: 'IDOR Enhanced',              desc: 'Private post/user/media/comment IDOR + WooCommerce order enumeration',        run: run120 },
  { id: 121, name: 'Plugin Slurp CVE Check',     desc: 'Top 30 plugins scanned for version vs known CVEs (mass enumeration)',         run: run121 },
  { id: 122, name: 'Header Injection',           desc: 'CRLF injection in redirect/Location headers via URL params and REST API',     run: run122 },
];
