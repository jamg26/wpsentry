---
name: jwp-scanner-orchestrator
description: A new orchestrator agent can read this and manage the product correctly from day one.
---

# JWP Scanner — Orchestrator Skill Document
> Battle-tested playbook compiled from 15 phases of audit→dev→test cycles.
> A new orchestrator agent can read this and manage the product correctly from day one.

---

## SECTION 1: Product Overview & Architecture

**JWP Scanner** is a WordPress security scanner micro-SaaS. Users sign up, submit a WordPress URL, and receive a detailed vulnerability report across 122 checks. Free tier: 5 scans/day, 50/month.

### Tech Stack
| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite + Tailwind CSS → Cloudflare Pages |
| API | Cloudflare Workers (Hono framework) |
| Database | Cloudflare D1 (`jwp-db`) |
| Sessions/Rate-limit | Cloudflare KV (`SESSIONS_KV`, `RATELIMIT_KV`) |
| Scan Reports | Cloudflare R2 (`jwp-scan-reports`) |
| Scan Queue | Cloudflare Queue (`jwp-scan-jobs`) |
| Analytics | Cloudflare Analytics Engine (`jwp_events`) |

### Binding IDs (wrangler.toml)
- D1: `a94cb518-a526-4921-8cf2-e6b160067ea9`
- KV SESSIONS: `acf1c55d8388427281e76d7117402a84`
- KV RATELIMIT: `b1797d9176b24b4fa8c74f7234dd702c`
- Account ID: `8846c8d2c9e982da3cee1c655ff8cb7c`

### URLs
- Frontend: `https://jwp-scanner.pages.dev`
- Worker API: `https://jwp-worker.jamg.workers.dev`
- Admin panel: `https://jwp-scanner.pages.dev/admin` (password-protected)
- GitHub: `https://github.com/jamg26/jwp-scanner`

### Deploy Commands (exact, copy-paste)
```bash
# Deploy worker
cd /home/jamg/strix/worker && CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler deploy

# Deploy frontend
cd /home/jamg/strix/frontend && npm run build && CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler pages deploy dist --project-name jwp-scanner

# Dry-run worker (build check)
cd /home/jamg/strix/worker && CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler deploy --dry-run 2>&1 | tail -5

# D1 query
cd /home/jamg/strix/worker && CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db --command "SQL_HERE" --remote

# Tail worker logs
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler tail jwp-worker
```

### D1 Schema (all tables)
```
users          — id, email, password_hash, is_verified, created_at, notification_prefs
scans          — id, user_id, url, status, findings_count, created_at, tags, is_public, public_token
findings       — id, scan_id, type, severity, title, description, evidence, remediation, url
system_config  — key, value
api_keys       — id, user_id, name, key_hash, key_prefix, last_used_at, created_at, enabled
scheduled_scans — id, user_id, url, schedule_cron, next_run_at, last_run_at, enabled, created_at
webhooks       — id, user_id, url, secret, events, enabled
```

### Test Credentials
- Email: `qatest@test.com` / Password: `QATest1234!`

---

## SECTION 2: Agent Role Definitions

### Auditor Agent
**Responsibility:** Read-only deep audit of codebase and live scan data.
**Always check:**
- `worker/src/routes/auth.ts` — rate limiting, timing attacks, constant-time compare
- `worker/src/routes/admin.ts` — SQL injection, DDL bypass, LIKE injection
- `worker/src/routes/scans.ts` — SSRF, JSON.parse safety, findings_count accuracy
- `worker/src/scanner/engine.ts` — AbortController, dedup Map key stability, batch size
- `worker/src/scanner/utils.ts` — redirect handling, signal propagation
- 15-20 scanner modules (sample across different vulnerability categories)
- `frontend/src/pages/Dashboard.tsx`, `ScanDetail.tsx`, `History.tsx` — error states, silent failures
**Output format:** CRITICAL/HIGH/MEDIUM/LOW findings with `file:line`, description, impact, exact fix
**Quality score:** Security(20%) + Scanner reliability(20%) + Admin security(15%) + Frontend(20%) + Code quality(15%) + Accessibility(10%)

### Vuln Module Dev Agent
**Responsibility:** Implement new scanner modules following the template in Section 3.
**Must do before marking done:**
- Answer all 10 questions in the FP prevention checklist (Section 3.3)
- Ensure module compiles with zero TypeScript errors
- Register in `modules/index.ts`
- Dry-run build passes

### UI/UX Dev Agent
**Stack:** React 18 + Vite + Tailwind CSS. No external UI library.
**Design tokens:** slate-900 background, emerald-500 primary, red-500 critical, orange-400 high, yellow-400 medium, blue-400 info
**Components:** Toast.tsx (useToast hook), ErrorBoundary.tsx, CookieConsent.tsx, FindingCard.tsx, ScanProgress.tsx, UsageBar.tsx, ScanStatusBadge.tsx
**Requirements:** Every interactive element needs `aria-label`. Labels need `htmlFor`. Focus rings visible. WCAG AA contrast.

### PM/BA Agent
**Target user:** WordPress developers, agency owners, freelancers, security-conscious site owners
**Feature priority:** Email/pw-reset (P0) → Scheduling/API keys (P1) → Teams/MFA (P2)
**Production gate:** Feature must work end-to-end OR be hidden with feature flag. No half-baked UX.

### Dev Fix Agent
**Fix verification checklist:**
- [ ] `wrangler deploy --dry-run` passes
- [ ] `npm run build` passes
- [ ] D1 migrations applied to remote AND verified with `PRAGMA table_info()` before worker deploy
- [ ] New routes use `c.get('user').sub` for user ID — NOT `c.get('auth')` or `.user_id`
- [ ] Smoke test new endpoints with `curl` after deploy (confirm no 500)
- [ ] No bare `JSON.parse()` without try/catch
- [ ] No `redirect: 'follow'` on write tests (must be `redirect: 'manual'`)
- [ ] Rate limit applied to any new auth-adjacent endpoint
- [ ] AbortController passed through `state.signal` for new fetch calls

### QA Test Agent
**Test sites:**
1. `https://knose.com.au` — WooCommerce, Cloudflare, Weglot multilingual, GTM, real debug.log exposed, real Google API key
2. `https://castingnetworks.com` — REST API exposed, real CORS misconfiguration, heavy CDN
3. `https://casting.com` — Use as negative/clean control

**Test protocol:**
1. Login → get session cookie
2. Trigger scan (POST /scans)
3. Poll until `status === 'completed'` (max 6 min)
4. Query D1 for findings_count
5. Fetch R2 report: `scans/{user_id}/{scan_id}.json`
6. Classify every CRITICAL + HIGH as TP / FP / DUPE / SEVERITY_MISMATCH
7. Check D1 count == R2 array length
8. Check 0 type+url duplicates
9. Score against rubric

---

## SECTION 3: Scanner Module Development Standards

### 3.1 Module Template
```typescript
import { ScanModule, Finding, ScanState } from '../types';
import { fetchURL } from '../utils';

const MODULE_ID = 'wp_example_check';

export const wpExampleCheck: ScanModule = {
  id: MODULE_ID,
  name: 'Example Vulnerability Check',

  async run(target: string, state: ScanState): Promise<Finding[]> {
    const findings: Finding[] = [];

    // 1. Reachability guard — skip if site is down
    if (!state.reachabilityCache?.get('homepage')) {
      try {
        const ping = await fetchURL(target, { signal: state.signal, timeout: 5000 });
        if (!ping.ok && ping.status !== 403) return findings;
      } catch { return findings; }
    }

    try {
      const url = `${target}/wp-specific-endpoint`;
      const res = await fetchURL(url, {
        method: 'GET',
        redirect: 'manual',   // ALWAYS manual for anything that might redirect
        signal: state.signal, // ALWAYS pass AbortController signal
        timeout: 15000,
      });

      // ALWAYS check HTTP status before parsing
      if (res.status !== 200) return findings;

      const body = await res.text();

      // ALWAYS validate content, not just status
      if (!body.includes('specific-indicator') || body.includes('"code"')) {
        return findings; // WP error object guard
      }

      findings.push({
        type: 'EXAMPLE_VULN_TYPE',
        severity: 'HIGH',
        title: 'Descriptive title of the vulnerability',
        description: 'What this vulnerability is and why it matters.',
        evidence: `HTTP ${res.status} — matched "specific-indicator" in response body: ${body.slice(0, 200)}`,
        remediation: 'Specific actionable steps to fix this issue.',
        url,
      });

    } catch (err: unknown) {
      if ((err as Error)?.name === 'AbortError') return findings; // Timeout — skip gracefully
      // Other errors: log and return empty
    }

    return findings;
  },
};
```

### 3.2 The Golden Rules

#### ✅ DO
- Always use `fetchURL` from `../utils` — never raw `fetch()`
- Always pass `signal: state.signal` to every fetchURL call
- Always use `redirect: 'manual'` for write tests (POST/PUT/DELETE) and URL-param checks
- After `redirect: 'manual'`, validate actual response body content, not just HTTP status
- Always wrap response parsing in try/catch
- Always check `res.status === 200` before parsing JSON/body
- Guard against WP error objects: `if (data.code) return findings` (WP REST errors have `code` field)
- Return `[]` gracefully on timeout (`AbortError`), network failure, non-WP sites
- Include meaningful `evidence` field with actual response snippets, matched values, exact URLs
- Include specific `remediation` with version numbers, config settings, plugin names
- Check for duplicate type with existing modules before adding new one

#### ❌ DON'T
- **Never infer plugin/theme presence from 403** — WAF returns 403 on everything; require HTTP 200 + valid content
- **Never use `redirect: 'follow'` on write tests** — redirects strip query params like `?status=private`, turning a private-post check into a public-post check
- **Never use `Promise.any()`** for lockout/rate-limit detection — it resolves on the lockout 429 itself, inverting your logic. Use `Promise.allSettled()`
- **Never match `"java"` or `"javascript"` in body** — matches JavaScript on 100% of WP sites
- **Never flag `wp-includes/ms-settings.php`** as malware — it's a legitimate WordPress Multisite core file shipped since WP 3.0
- **Never flag hidden iframes without checking `src`** against known-safe analytics origins (GTM, Google, Facebook, etc.)
- **Never flag CJK characters as Japanese keyword hack** on multilingual sites — check for Weglot/WPML/Polylang/`hreflang` first
- **Never use `body.includes('wp-admin/admin')`** to detect admin content — matches AJAX URLs (`/wp-admin/admin-ajax.php`) in page JS on 99% of WP sites. Require `id="wpbody"` or `id="adminmenuwrap"`
- **Never flag `CF-Cache-Status: HIT`** as a vulnerability — it's normal Cloudflare CDN caching
- **Never use `getJSON()` without checking HTTP status** — 401 error responses have keys too
- **Never use `body.includes(themeName)`** for theme detection — theme names appear in blog posts. Require `/wp-content/themes/{slug}/style.css` with `Theme Name:` in body
- **Never use `/\[\d{2}-\w{3}-\d{4}/`** for PHP error log detection — matches blog post dates. Require `PHP Fatal error:` / `PHP Warning:` prefix
- **Never send parallel requests to measure rate limiting** — use sequential + measure per-request latency delta
- **Never leave bare `JSON.parse()`** without try/catch — KV corruption or race causes unhandled 500
- **Never strip SQL DDL check using only `\s` whitespace** — `DROP/**/TABLE` bypasses it. Strip `/* */` and `--` comments first
- **Never use `CORS_ORIGIN ?? '*'`** — fail closed if env var not set
- **Never trust `X-Forwarded-For`** for rate limiting — only use `CF-Connecting-IP` on Cloudflare Workers
- **Never deploy without applying D1 migrations to remote first** — schema mismatch causes 500s
- **Never implement actual exploit execution** (RCE, credential brute-force, file planting) — legally prohibited (Section 12.3)
- **Never add new PII collection from target sites without updating Privacy Policy first** — GDPR violation risk
- **Never remove the scan consent checkbox** in NewScan.tsx — it is a legal requirement (Section 12.2)

### 3.3 FP Prevention Checklist
Answer ALL before committing a new module:

1. Does it fire on WAF-protected sites returning 403/429 for everything?
2. Does it fire on sites using Cloudflare (CF-Cache-Status, CF-Connecting-IP headers)?
3. Does it fire on multilingual sites (Weglot, WPML, Polylang, `hreflang` tags)?
4. Does it fire on sites using Google Tag Manager (GTM noscript hidden iframe)?
5. Does it fire because `admin-ajax.php` URL appears in page's JavaScript?
6. Does any write test use `redirect: 'follow'`? (Must use `redirect: 'manual'`)
7. Does it validate response body content, or just HTTP status code?
8. Does its `type` string overlap with an existing module? (grep for the type)
9. Would any legitimate WordPress core file trigger this? (check WP source)
10. Would a 500 Internal Server Error trigger this as a false positive?

### 3.4 Severity Guidelines
| Severity | Criteria |
|----------|---------|
| CRITICAL | Immediate exploitable RCE, active malware confirmed, exposed credentials/secrets, database dump accessible, full auth bypass |
| HIGH | Significant data exposure, exploitable injection (SQLi/XSS confirmed), confirmed secret in source, major auth weakness |
| MEDIUM | Information disclosure enabling further attack, missing rate limiting, security misconfiguration |
| LOW | Version disclosure, informational headers, best-practice violations with low exploitability |
| INFO | Passive fingerprinting, presence of features (not vulnerabilities), technology detection |

### 3.5 Hall of Shame — All Confirmed FPs (18 entries)

| Module | FP Type | Root Cause | Fix Applied |
|--------|---------|------------|-------------|
| `wp_app_passwords` | APP_PASSWORDS_WEAK_CREDS CRITICAL | `redirect:follow` stripped `?status=private`; public posts reported as private | `redirect:manual` + validate `post.status === 'private'` |
| `wp_api_auth` | REST_DRAFT_POST_EXPOSURE HIGH | `redirect:follow` stripped `?status=draft` | `redirect:manual` + post status validation |
| `wp_api_auth` | rest_api_settings_exposed HIGH | 401 error object `{"code":…}` has 3 keys → "3 settings exposed" | Check `res.status === 200` AND no `code` field |
| `wp_cache_poisoning` | cache_poisoning HIGH | `body.includes('wp-admin/admin')` matched AJAX URLs in normal page JS | Require `id="wpbody"` or `id="adminmenuwrap"` |
| `wp_cache_poisoning` | cache_header_leak HIGH | `CF-Cache-Status: HIT` flagged as vulnerability (normal CDN) | Downgraded to `CDN_CACHING_ACTIVE` INFO |
| `wp_malware_indicators` | MALWARE_HIDDEN_IFRAME CRITICAL | Google Tag Manager noscript `<iframe>` flagged | `SAFE_IFRAME_ORIGINS` allowlist (GTM, Google, FB, YT, etc.) |
| `wp_malware_indicators` | MALWARE_JAPANESE_KEYWORD_HACK CRITICAL | Weglot/multilingual Chinese content flagged | Check `hasTranslationPlugin` + require hidden CJK (CSS display:none) |
| `wp_malware_indicators` | MALWARE_MS_SETTINGS_ACCESSIBLE HIGH | `wp-includes/ms-settings.php` flagged as backdoor | Never flag known WP core files; only flag on backdoor content |
| `wp_log4shell_indicators` | LOG4SHELL_PROBE_SENT MEDIUM | `"java"` keyword matched JavaScript on PHP site | Skip if `X-Powered-By: php`; require Java server headers (Tomcat/Jetty/JBoss) |
| `wp_login_protection` | NO_ACCOUNT_LOCKOUT CRITICAL FP | `Promise.any()` resolved on the 429 lockout response itself | `Promise.allSettled()` + require ≥2/5 responses show lockout |
| `wp_plugin_enum` | PLUGIN_DETECTED HIGH | 403 from WAF treated as plugin confirmed | Require HTTP 200 + `Plugin Name:` in `readme.txt` body |
| `wp_theme_enum` | THEME_DETECTED | Theme name string matched in blog post content | Require `/wp-content/themes/{slug}/style.css` + `Theme Name:` |
| `wp_debug_info` | DEBUG_LOG_PATTERN HIGH | `/\[\d{2}-\w{3}-\d{4}/` matched blog post dates | Require `PHP Fatal error:` / `PHP Warning:` prefix |
| `wp_cron` | DoS timer meaningless | Parallel requests give same wall-clock time as 1 request | Sequential requests + measure latency delta (last/first > 3×) |
| `wp_credential_stuffing` | WOOCOMMERCE_LOGIN_ORACLE MEDIUM | `/?wc-ajax=get_refreshed_fragments` always returns `"fragments"` | Removed — endpoint always returns cart data regardless |
| `wp_secret_scanning_advanced` | SECRET_DETECTED duplicate | Google API key / Twilio patterns overlap with `wp_js_recon.ts` | Removed overlapping patterns from `wp_secret_scanning_advanced` |
| `engine.ts` | dedup attribution lost | `findingToModule` Map keyed by object reference; `{...spread}` creates new identity | Use stable string key: `type::url::evidence[:50]` |
| `wp_ssl_tls` | ssl_expired HIGH FP | Transient `fetch()` null on valid cert | Retry ×2 + downgrade to `https_unreachable MEDIUM` |

---

## SECTION 4: Deployment Runbook

### 4.1 Pre-Deploy Checklist (run before EVERY deploy)
```
[ ] wrangler deploy --dry-run passes (0 TypeScript errors)
[ ] npm run build passes in frontend/
[ ] All new D1 tables/columns applied to remote (PRAGMA table_info check)
[ ] No hardcoded secrets or API keys in source
[ ] CORS_ORIGIN set in wrangler.toml (never wildcard *)
[ ] No console.log with sensitive user data
[ ] No half-baked features visible in UI (feature flags set correctly)
[ ] Any new scanner module sending active payloads reviewed against legal rules (Section 12)
[ ] Any new data collection from scanned sites disclosed in Privacy Policy
```

### 4.2 D1 Migration Protocol
```bash
# Step 1: Check existing tables
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name" --remote

# Step 2: Check columns on modified tables
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "PRAGMA table_info(table_name)" --remote

# Step 3: Apply missing migration
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "CREATE TABLE IF NOT EXISTS ... / ALTER TABLE ... ADD COLUMN ..." --remote

# Step 4: Verify
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "PRAGMA table_info(table_name)" --remote
```

### 4.3 Deploy Order (always in this sequence)
1. D1 migrations → 2. Worker deploy → 3. Frontend build + deploy → 4. Smoke test → 5. Git commit + push

### 4.4 Commit Format
```
fix: phase N — brief description

- file1.ts: what changed and why
- file2.ts: what changed and why
```

> ⚠️ **Do NOT add `Co-authored-by: Copilot` trailers to commits.** The repo owner has explicitly requested clean commit history without automation attribution.

### 4.5 Rollback
```bash
# Roll back worker
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler rollback

# Roll back frontend: redeploy previous commit's dist
git checkout {last-good-sha} -- frontend/dist
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler pages deploy dist --project-name jwp-scanner
```

---

## SECTION 5: Quality Gates

### 5.1 Phase PASS Criteria (all must be true)
- Quality score ≥ 8.0 / 10
- Zero CRITICAL false positives
- Zero HIGH false positives
- FP rate < 5%
- Duplicate rate < 5%
- D1 `findings_count` exactly matches R2 `findings` array length
- Scan completes within 4 minutes on standard targets

### 5.2 Scoring Rubric (100 pts → quality score = pts/10)
| Criterion | Points |
|-----------|--------|
| No CRITICAL FPs | 25 |
| No HIGH FPs | 20 |
| FP rate < 5% | 15 |
| Duplicate rate < 5% | 10 |
| D1 == R2 count | 10 |
| Scan time < 4 min | 10 |
| New modules fire valid findings (≥3) | 5 |
| Key API endpoints return 200 | 5 |

### 5.3 Test Sites (always use these 3)
| Site | Why | Key Expected Findings |
|------|-----|----------------------|
| `https://knose.com.au` | WooCommerce + Cloudflare + Weglot + GTM + real vuln | `ERROR_LOG_EXPOSED` CRITICAL, `JS_SECRET_GOOGLE_API_KEY` HIGH |
| `https://castingnetworks.com` | REST API exposed + real CORS bug + CDN | `CORS_ARBITRARY_ORIGIN_REFLECTED` CRITICAL |
| `https://casting.com` | Negative control (minimal/no WP) | Mostly INFO or clean |

---

## SECTION 6: Security Hardening Standards

### Rate Limiting (KV-based, key = `{prefix}:{ip}`)
| Endpoint | Limit | Window | KV Key Prefix |
|----------|-------|--------|---------------|
| Login | 10 | 15 min | `auth_login_ip:` |
| Signup | 5 | 1 hour | `auth_signup_ip:` |
| Password change | 5 | 15 min | `pw_change_ip:` |
| Admin login | 5 | 5 min | `admin_login_ip:` |

**IP source:** ONLY `CF-Connecting-IP`. Never `X-Forwarded-For`. Return 400 if missing in production.

### Constant-Time Auth
```typescript
// ALWAYS run bcrypt.compare regardless of user existence
const DUMMY_HASH = await hashPassword('dummy-constant-time-placeholder');
const hashToCompare = user?.password_hash ?? DUMMY_HASH;
const valid = await bcrypt.compare(password, hashToCompare);
if (!user || !valid) return unauthorized;
```

### CORS — Fail Closed
```typescript
const origin = c.env.CORS_ORIGIN ?? (c.env.ENVIRONMENT === 'development' ? 'http://localhost:5173' : null);
if (!origin) return c.json({ error: 'Server misconfiguration: CORS_ORIGIN not set' }, 500);
```

### Admin SQL Safety
```typescript
// ALWAYS strip SQL comments before any check
const normalized = sql
  .replace(/\/\*[\s\S]*?\*\//g, ' ')  // block comments
  .replace(/--[^\n]*/g, ' ')           // line comments
  .replace(/\s+/g, ' ').trim().toUpperCase();
// Then check prefix and DDL patterns against normalized
```

### SSRF Protection
Block: `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`, `127.x.x.x`, `.local`, `.internal`, `::ffff:192.168.x.x` (IPv4-mapped IPv6)

---

## SECTION 7: Performance Standards

| Parameter | Value | Notes |
|-----------|-------|-------|
| `PARALLEL_BATCH` | 12 | Was 4; raised in Phase 8 for ~60% wall-clock reduction |
| `MODULE_TIMEOUT_MS` | 25000 | Per module; AbortController cancels underlying fetch |
| AbortController | Per module | Prevent orphaned fetches burning CPU after timeout |
| Response body cache | `state.responseCache` | Cache homepage body — prevents ~30 duplicate fetches |
| Reachability pre-fetch | `state.reachabilityCache` | Pre-fetch 5 common paths before modules run |
| Target performance | < 4 min | 122 modules on knose.com.au: ~2:22 ✅ |

**Rust/WASM:** Not worth it. Scanner is I/O-bound 50-200×. WASM gives 0% benefit for 99/100 modules.

---

## SECTION 8: Feature Flag System

### Production Readiness Gate
A feature MUST NOT be visible to users unless it works end-to-end OR is clearly marked "coming soon".

```typescript
// In frontend Settings.tsx
const FEATURES = {
  apiKeys: true,        // Bearer token auth working — smoke tested
  scheduling: true,     // Cron wired, D1 table exists, full CRUD
  publicSharing: true,  // share/revoke + /public/scans/:token route
  tags: true,           // column exists, filter works
  webhooks: true,       // HMAC-SHA256 dispatch on scan.completed
  scanComparison: true, // API-only, documented
  notifications: true,  // prefs saved; email_delivery: false transparent
};
```

### Email Notifications Policy
- **No email provider configured.** Until Resend/SendGrid/Mailgun is added:
- Keep toggle UI (saving prefs is useful for when email is enabled)
- Always show amber banner: *"Email delivery will be enabled in a future update"*
- `PUT /user/notifications` must return `{"saved": true, "email_delivery": false}`
- **Never silently pretend emails are being sent**

### P0 Backlog (not yet implemented)
| Feature | Blocker | Notes |
|---------|---------|-------|
| Email verification | No email provider | `is_verified` column exists, never set |
| Password reset | No email provider | Users permanently locked out |
| MFA/TOTP | Design needed | P2 but trust issue for security SaaS |
| Admin audit log table | Low effort | Just a table + log writes |

---

## SECTION 9: Orchestration Loop Protocol

### The Cycle
```
PHASE N:
  ┌─ AUDIT (parallel, safe) ──────────────────────────────────────┐
  │  • Security Auditor      → CRITICAL/HIGH/MEDIUM findings       │
  │  • Scanner QA Tester     → FP patterns, dedup, accuracy       │
  │  • PM/BA Agent           → Feature gaps, UX issues, prod gaps │
  │  • (opt) Vuln Researcher → New modules needed                 │
  └───────────────────────────────────────────────────────────────┘
           ↓ Orchestrator consolidates + prioritizes
  ┌─ DEV (parallel where files don't overlap) ────────────────────┐
  │  • Security Fix Agent    → CRITICAL/HIGH security issues      │
  │  • Scanner Fix Agent     → FP fixes, module accuracy         │
  │  • Feature Dev Agent     → New features / new modules        │
  └───────────────────────────────────────────────────────────────┘
           ↓ D1 migrations → worker deploy → frontend deploy
  ┌─ TEST ────────────────────────────────────────────────────────┐
  │  • QA Agent → fresh scans on all 3 test sites               │
  │  • Classify all CRITICAL + HIGH → TP / FP / DUPE            │
  │  • Score against rubric                                       │
  └───────────────────────────────────────────────────────────────┘
           ↓
  Score ≥ 8.0/10 → PASS → next phase introduces new features
  Score < 8.0/10 → FAIL → spawn targeted fix agents → re-test
```

### Parallel Agent Safety Rules
| Agents | Safe to parallelize? |
|--------|---------------------|
| Multiple auditors/testers | ✅ Always (read-only) |
| Dev agents on different files | ✅ Safe |
| Dev agents on same file (e.g. `engine.ts`) | ❌ Sequential only |
| Deploy agents | ❌ Sequential only (never 2 deploys at once) |
| Audit + Dev simultaneously | ⚠️ Only if dev is fixing a different area than audit is reading |

### Escalation Rules
- Same blocker in 3 consecutive phases → root cause analysis required before another fix attempt
- CRITICAL FP introduced by new module → revert immediately, fix before reintroducing
- Never ship a new feature batch in the same phase as unresolved CRITICAL FPs
- New vuln modules must pass standalone FP test (all 3 sites) before general QA

---

## SECTION 10: Emergency Procedures

### CRITICAL FP in Production
```
1. Identify exact module + condition (check R2 report for evidence field)
2. Add guard that skips the FP case (quick patch — 5 min fix)
3. Deploy worker only (no frontend needed)
4. Add to Hall of Shame table (Section 3.5)
5. Proper root-cause fix in next dev phase
```

### Worker 500s in Production
```bash
# Tail live logs
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler tail jwp-worker

# Common causes: bare JSON.parse, missing try/catch, D1 schema mismatch
# Rollback if needed:
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler rollback
```

### D1 Schema Mismatch (column not found errors)
```bash
# Check what columns exist
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "PRAGMA table_info(table_name)" --remote

# Add missing column
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "ALTER TABLE table_name ADD COLUMN col_name TEXT DEFAULT ''" --remote
```

---

## SECTION 11: Phase History Summary

| Phase | Key Achievement | Quality Score |
|-------|----------------|---------------|
| 1-3 | Initial MVP: auth, scanning, 67 modules, Playwright tests | ~5/10 |
| 4-6 | fetchURL redirect bug, reachabilityCache, dedup engine | 6.5/10 |
| 7-9 | APP_PASSWORDS FP, draft FP, findings_count accuracy, dedup overhaul | 6.5/10 |
| 10-12 | GTM iframe FP, settings 401 FP, cache_poisoning FP, ssl FP | **8.5/10** ✅ |
| 13 | +22 new modules (122 total), UI/UX overhaul, 8 product features | — |
| 14 | 7 CRITICAL + 12 HIGH audit fixes, AbortController, constant-time auth | 4.0/10 (new FPs) |
| 15 | GTM/CJK/cache_header FPs fixed, API key schema fixed, prod-ready audit | **10.0/10** ✅ |
| 16 | CI/CD integration, queue max_concurrency=10, 122 module count fix, 4 timeout module fixes | — |
| 17 | Legal compliance: scan consent checkbox, ToS indemnification/warranty/prohibited-use, Privacy GDPR+DSA | — |

---

*Document compiled from 17 phases of audit→dev→test cycles. Last updated: Phase 17 (Legal Compliance).*

---

## SECTION 12: Legal Compliance — Open Scanner Rules

> **Context:** JWP Scanner allows ANY registered user to scan ANY WordPress URL without ownership verification. This "open scanner" model creates legal exposure that must be managed through technical safeguards, documentation, and UI controls.

---

### 12.1 Legal Risk Summary

| Risk | Law / Regulation | Severity | Mitigated By |
|------|-----------------|----------|--------------|
| Unauthorized access probe | CFAA (US), Computer Misuse Act (UK) | HIGH | Consent checkbox + ToS warranty clause |
| DDoS-like scan volume | CFAA § 1030(a)(5) "intentional damage" | HIGH | Per-user queue guard (≥2 concurrent = 429), `max_concurrency = 10` |
| Active payload injection (XSS/SQLi/XXE tests) | CFAA "accessing without auth" grey area | MEDIUM | ToS indemnification + prohibited use clause |
| PII collection (usernames via /?author=1) | GDPR Art. 5, EU DSA | HIGH | Privacy Policy discloses + 90-day retention |
| robots.txt bypass | Evidence of bad faith in court | MEDIUM | Privacy Policy discloses explicitly + transparent User-Agent |
| No ToS indemnification | Civil liability if user misuses tool | CRITICAL | Added Sections 8-10 to ToS |
| False negative lawsuit ("said secure, got hacked") | Common law negligence | HIGH | ToS Section 4 "As-Is" + Limitation of Liability |
| EU DSA "automated profiling" | EU Digital Services Act 2026 | MEDIUM | Privacy Policy Section 8 DSA disclosure |

---

### 12.2 Minimum Legal Shield (Non-Negotiable)
These controls must NEVER be removed or bypassed:

1. **Consent checkbox + BACKEND ENFORCEMENT** — dual-layer, both required
   - Frontend: `frontend/src/pages/NewScan.tsx` — checkbox must be checked before scan starts; resets on URL change
   - **Backend (CRITICAL): `worker/src/routes/scans.ts` POST /scans** must reject if `authorization_confirmed !== true` with HTTP 400
   - Attestation timestamp (`authorization_confirmed_at`) and IP (`authorization_ip`) stored in D1 scans table
   - **If frontend-only:** Technically bypassable via direct API calls — no legal protection
   - **If backend removed:** Attacker submits POST without header → zero attestation → direct CFAA exposure

2. **Server-side ToS acceptance recording** (`worker/src/routes/auth.ts` POST /auth/signup)
   - Require `agreed_to_terms: true` in signup request body → reject with HTTP 400 if missing
   - Store `tos_accepted_at` (timestamp) and `tos_version` in users D1 table
   - D1 schema: `ALTER TABLE users ADD COLUMN tos_accepted_at INTEGER; ALTER TABLE users ADD COLUMN tos_version TEXT;`
   - **If removed:** Cannot prove user agreed to ToS terms; indemnification clause unenforceable

3. **Terms of Service — Five Critical Sections** (`frontend/src/pages/Terms.tsx`)
   - Authorized Use Warranty — user warrants they have permission
   - Prohibited Uses — explicit ban on malicious recon, hit-lists, competitive intel
   - Indemnification — users indemnify JWP Scanner for their misuse
   - **Governing Law** — jurisdiction, arbitration clause
   - **Law Enforcement Cooperation** — explicit statement that scan records are disclosed to law enforcement on valid legal process
   - **If removed:** No liability shield, full exposure on user misuse; Indemnification unenforceable without governing law

4. **Privacy Policy — Full GDPR/CCPA Compliance** (`frontend/src/pages/Privacy.tsx`)
   - Must disclose that scans collect PII from target sites (usernames, server headers)
   - Must state data retention period (90-day or actual retention, whichever is less)
   - Must include GDPR rights (access, deletion, portability) + CCPA opt-out
   - Must include robots.txt behavior disclosure
   - **GDPR legal basis:** Art. 6(1)(b) for account data; Art. 6(1)(f) legitimate interest for scan data (with balancing test language)
   - **International transfers:** Cloudflare SCC/DPF disclosure with link to `cloudflare.com/cloudflare-customer-dpa`
   - **Third-party data subjects:** Must include how scanned-site users can request deletion (`abuse@jwp-scanner.com`)
   - **If removed:** GDPR/EU DSA breach, regulatory fine risk

5. **Transparent User-Agent** (`worker/src/scanner/utils.ts`)
   - Must be: `'JWP-Scanner/3.0 (+https://jwp-scanner.pages.dev/report-abuse; abuse@jwp-scanner.com)'`
   - Identifies scanner + provides abuse contact directly in HTTP request headers
   - **If disguised as a browser UA:** Legal "intent to bypass" evidence in court

6. **Abuse reporting mechanism** (`frontend/src/pages/ReportAbuse.tsx`)
   - Public page at `/report-abuse` accessible without authentication
   - Linked from footer of all pages AND embedded in User-Agent string
   - Contact: `abuse@jwp-scanner.com`
   - **If removed:** Fails EU DSA, CFAA "good faith" defense weakened; no recourse for scan targets

7. **Scan rate limiting** (queue `max_concurrency = 10`, per-user ≥2 = 429)
   - Prevents scanner from becoming a DDoS tool against target sites
   - **If removed:** "Intentional damage" under CFAA applies above ~50 req/sec

---

### 12.3 Legal Rules for Scanner Module Developers

#### ✅ LEGALLY SAFE (module types that are fine)
- **Version fingerprinting:** Compare observed version against CVE database (read-only)
- **Header inspection:** Read HTTP response headers (publicly broadcast)
- **File existence probes:** GET request to publicly accessible paths
- **Configuration disclosure:** Check if debug info, readme.txt, etc. are public
- **Certificate inspection:** TLS/SSL status checks (passive)

#### ⚠️ LEGALLY GREY (allowed but must be minimal + documented)
- **Payload injection probes:** Sending XXE/SQLI/LFI payloads to check for reflection
  - ONLY check for file content in response (not execute further)
  - ONLY use read-safe payloads (e.g., `file:///etc/passwd` — not RCE payloads)
  - Per-module timeout MUST be ≤ 25s
  - Evidence field must be specific (not "sent payload", but "indicator found in response")
- **Username enumeration:** /?author=1 endpoint probing
  - Results are PII — finding severity must reflect sensitivity
  - Already disclosed in Privacy Policy — do not add new PII types without updating Privacy Policy

#### ❌ LEGALLY PROHIBITED (never implement)
- **Actual exploitation:** Downloading exploits, triggering RCE, accessing `/etc/passwd` content beyond checking existence
- **Credential testing:** Actually trying passwords (brute force) — even "default credential" checks that submit real auth
- **Persistent access:** Any probe that plants files, tokens, or backdoors on target sites
- **Mass automated scanning without individual user consent:** Backend cronjob scanning URLs not submitted by users
- **Storing target site data beyond scan scope:** Never log raw response bodies of target sites to permanent storage

---

### 12.4 Ongoing Compliance Checklist

**Every 90 days:**
- [ ] Verify D1 scan cleanup job running (delete scans older than 90 days)
- [ ] Update "Last updated" date in Terms.tsx and Privacy.tsx if content changed
- [ ] Review any new legal developments re: CFAA, EU DSA, CCPA enforcement

**Every new scanner module:**
- [ ] Classify module type against Section 12.3 (Safe / Grey / Prohibited)
- [ ] If collecting new type of PII from target site → update Privacy Policy first
- [ ] Ensure module doesn't exceed 3 active payload attempts per endpoint

**Every major product change:**
- [ ] If new data type collected: Privacy Policy update required before launch
- [ ] If scan behavior changes significantly: ToS update required before launch
- [ ] Consent checkbox text must stay accurate to actual scan behavior

---

### 12.5 Responsible Disclosure Policy
If a user discovers a vulnerability through JWP Scanner and the target site is NOT theirs, direct them to:
1. Not exploit the vulnerability
2. Notify the site owner responsibly
3. Use coordinated disclosure (e.g., `security@{domain}` or CERT/national CSIRT)

This should be added to future documentation / FAQ pages.

---

### 12.6 Legal Pages Location
| Page | Route | File | Last Updated |
|------|-------|------|-------------|
| Terms of Service | `/terms` | `frontend/src/pages/Terms.tsx` | April 1, 2026 |
| Privacy Policy | `/privacy` | `frontend/src/pages/Privacy.tsx` | April 1, 2026 |
| Cookie Consent | (banner) | `frontend/src/components/CookieConsent.tsx` | — |
| Report Abuse | `/report-abuse` | `frontend/src/pages/ReportAbuse.tsx` | April 1, 2026 |

---

### 12.7 Backend Legal Tables (D1 Schema Requirements)

These columns must exist in D1 or backend legal enforcement silently fails:

```sql
-- Required for scan attestation recording (P0 — CRITICAL)
ALTER TABLE scans ADD COLUMN authorization_confirmed_at INTEGER;
ALTER TABLE scans ADD COLUMN authorization_ip TEXT;

-- Required for ToS server-side acceptance proof (P0 — CRITICAL)
ALTER TABLE users ADD COLUMN tos_accepted_at INTEGER;
ALTER TABLE users ADD COLUMN tos_version TEXT DEFAULT '2026-04-01';
```

**Enforcement logic:**
- `POST /scans`: If `authorization_confirmed !== true` → HTTP 400 `{ error: 'authorization_required' }`
- `POST /auth/signup`: If `agreed_to_terms !== true` → HTTP 400 `{ error: 'Terms acceptance required' }`
- Both endpoints must store timestamps and IP for audit trail

**CLI script enforcement (`jwp-scan.sh`):**
```bash
# The CLI user must pass authorization_confirmed: true in the payload
# Comment in the script must state the certification clearly
```

---

## SECTION 13: Agent Mistakes Log

> Every mistake made by an agent is recorded here so future agents don't repeat it.
> Read this section before writing any new worker route or running any deploy.

---

### 13.1 Auth Context — Always `c.get('user').sub`, Never `c.get('auth')`

**Mistake:** New route used `c.get('auth')` and destructured `.user_id` from it.  
**Reality:** The auth middleware sets `c.set('user', payload)` where `payload.sub` is the user ID. Every existing route uses `c.get('user').sub`.  
**Fix:** Always use `c.get('user').sub` to get the user ID in worker routes.  
**Rule:** Before writing any new authenticated route, grep existing routes for the pattern:
```bash
grep -n "c.get('user')" worker/src/routes/scans.ts | head -3
```

---

### 13.2 D1 Migrations — Always Execute Before Worker Deploy

**Mistake:** Designed and documented a new D1 table (`false_positive_reports`) but never ran `CREATE TABLE` on the remote database before deploying the worker. First user request caused a 500 error.  
**Reality:** `PRAGMA table_info()` returning zero rows means the table doesn't exist — D1 silently ignores tables that were only written in code.  
**Fix:** After any new `CREATE TABLE` or `ALTER TABLE ADD COLUMN`, immediately run it on remote and verify with `PRAGMA table_info(table_name)` before deploying the worker.  
**Rule:** The 4.3 deploy order is non-negotiable: **D1 migrations FIRST, then worker deploy.**

Verification command after every migration:
```bash
CLOUDFLARE_ACCOUNT_ID=8846c8d2c9e982da3cee1c655ff8cb7c npx wrangler d1 execute jwp-db \
  --command "PRAGMA table_info(new_table_name)" --remote
# MUST return rows — if 0 rows, the table was not created
```

---

### 13.4 Module Count — Update All References When Adding/Removing Modules

**Mistake (historical):** New scanner modules were added to `modules/index.ts` but the module count displayed to users stayed stale (e.g. said "100 checks" when there were 122).  
**Rule:** Every time a scanner module is added or removed, update ALL of the following references:

| File | Location | What to update |
|------|----------|----------------|
| `worker/src/scanner/modules/index.ts` | Module array | Add/remove the module import + entry |
| `frontend/src/pages/Landing.tsx` | Line ~21 `'122 Security Checks'` | Update number |
| `frontend/src/pages/Landing.tsx` | Line ~57 `'runs 122 security checks'` | Update number |
| `frontend/src/pages/Landing.tsx` | Line ~193 stat badge | Update number |
| `frontend/src/pages/Landing.tsx` | Line ~411 feature description | Update number |
| `frontend/src/pages/NewScan.tsx` | Last module `{ id: 122, label: ... }` | Update max id |

**How to get the real count:**
```bash
grep -c "{ id:" /home/jamg/strix/worker/src/scanner/modules/index.ts
# or
grep "run as run" /home/jamg/strix/worker/src/scanner/modules/index.ts | wc -l
```

**Search command to find ALL hardcoded counts before shipping:**
```bash
grep -rn "122\|100 checks\|100+ checks" frontend/src/
# Every hit must be updated to the new count
```

---

### 13.5 Smoke Test After Every Deploy

**Mistake:** Deployed a worker with a 500 error, only discovered it because the user tried the feature.  
**Rule:** After every worker deploy, smoke test the changed endpoint with `curl` before closing the task. A 200 response (or expected 4xx for auth failures) confirms the deploy is working.

```bash
# Example smoke test pattern
curl -s -o /dev/null -w "%{http_code}" https://api.wpsentry.link/health
# New authenticated endpoints: test with a real session cookie from cookies.txt
```

---

*Last updated: Phase 17 (Module sync rule + False Positive Reporting fix)*
