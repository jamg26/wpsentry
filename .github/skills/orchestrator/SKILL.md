---
name: jwp-scanner-orchestrator
description: Orchestrator playbook for JWP Scanner. Read this first on every session.
---

# JWP Scanner — Orchestrator Brain

> WordPress security scanner micro-SaaS. 122 checks, Cloudflare stack, free tier.
> **Read the BRAIN card first, then jump to the branch you need.**

---

## 🧠 BRAIN — Quick-Start Card

| What | Value |
|------|-------|
| Product | WordPress vulnerability scanner, 122 checks, 5 scans/day free |
| Frontend | `https://wpsentry.link` (Cloudflare Pages → `jwp-scanner`) |
| API | `https://api.wpsentry.link` (Cloudflare Worker → `jwp-worker`) |
| Admin | `https://wpsentry.link/admin` |
| GitHub | `https://github.com/jamg26/wpsentry` |
| QA login | `qatest@test.com` / `QATest1234!` |
| CF Account | `8846c8d2c9e982da3cee1c655ff8cb7c` |
| D1 DB | `jwp-db` (`a94cb518-a526-4921-8cf2-e6b160067ea9`) |

### One-liner deploy sequence
```
D1 migration → wrangler deploy → npm run build + pages deploy → curl smoke test → git commit
```

### Copy-paste commands
```bash
export CFID=8846c8d2c9e982da3cee1c655ff8cb7c

# Deploy worker
cd worker && CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler deploy

# Deploy frontend
cd frontend && npm run build && CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler pages deploy dist --project-name jwp-scanner

# Dry-run (build check only)
cd worker && CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler deploy --dry-run 2>&1 | tail -5

# D1 query
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler d1 execute jwp-db --command "SQL_HERE" --remote

# Tail logs
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler tail jwp-worker
```

### D1 Schema
```
users               — id, email, password_hash, full_name, is_verified, tos_accepted_at, tos_version, notification_prefs, created_at
scans               — id, user_id, url, status, findings_count, created_at, tags, is_public, public_token, authorization_confirmed_at, authorization_ip
findings            — id, scan_id, type, severity, title, description, evidence, remediation, url
false_positive_reports — id, scan_id, user_id, finding_type, finding_url, finding_severity, reason, status, created_at
api_keys            — id, user_id, name, key_hash, key_prefix, last_used_at, created_at, enabled
scheduled_scans     — id, user_id, url, schedule_cron, next_run_at, last_run_at, enabled, created_at
webhooks            — id, user_id, url, secret, events, enabled
system_config       — key, value
```

---

## 🌿 BRANCH 1 — Deploy & Commit

### Pre-deploy checklist (EVERY deploy)
```
[ ] wrangler deploy --dry-run passes
[ ] npm run build passes
[ ] D1 migrations applied to remote AND verified with PRAGMA table_info()
[ ] New routes use c.get('user').sub — NOT c.get('auth') or .user_id
[ ] Smoke test changed endpoints with curl after deploy
[ ] No hardcoded secrets or API keys in source
[ ] Module count updated in all 5 Landing.tsx locations if modules added/removed
[ ] No half-baked UI visible (feature flag it or hide it)
```

### D1 migration steps
```bash
# 1. Apply
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler d1 execute jwp-db \
  --command "CREATE TABLE IF NOT EXISTS ... / ALTER TABLE ... ADD COLUMN ..." --remote

# 2. Verify — MUST return rows, not empty
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler d1 execute jwp-db \
  --command "PRAGMA table_info(table_name)" --remote
```

### Commit format
```
feat|fix|docs: short description

- file.ts: what changed and why
- file2.ts: what changed and why
```
> ⚠️ **No `Co-authored-by: Copilot` trailers.** Owner wants clean history.

### Rollback
```bash
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler rollback  # worker only
```

### Module count — update ALL when adding/removing modules
| File | What to update |
|------|---------------|
| `worker/src/scanner/modules/index.ts` | Add/remove import + array entry |
| `frontend/src/pages/Landing.tsx` | 4× hardcoded count (~line 21, 57, 193, 411) |
| `frontend/src/pages/NewScan.tsx` | Last module `{ id: N }` |

```bash
# Get real count
grep "run as run" worker/src/scanner/modules/index.ts | wc -l
# Find all stale numbers
grep -rn "122\|100 checks\|100+ checks" frontend/src/
```

---

## 🌿 BRANCH 2 — Scanner Module Standards

### Module template (minimal)
```typescript
import { ScanModule, Finding, ScanState } from '../types';
import { fetchURL } from '../utils';

export const wpMyCheck: ScanModule = {
  id: 'wp_my_check',
  name: 'My Check',
  async run(target: string, state: ScanState): Promise<Finding[]> {
    const findings: Finding[] = [];
    try {
      const res = await fetchURL(`${target}/wp-endpoint`, {
        redirect: 'manual',    // ALWAYS manual
        signal: state.signal,  // ALWAYS pass signal
        timeout: 15000,
      });
      if (res.status !== 200) return findings;
      const body = await res.text();
      if (!body.includes('specific-indicator')) return findings;
      findings.push({
        type: 'MY_VULN_TYPE',
        severity: 'HIGH',
        title: 'Descriptive title',
        description: 'What this is and why it matters.',
        evidence: `HTTP ${res.status} — matched indicator: ${body.slice(0, 200)}`,
        remediation: 'Specific fix steps.',
        url: `${target}/wp-endpoint`,
      });
    } catch (err: unknown) {
      if ((err as Error)?.name === 'AbortError') return findings;
    }
    return findings;
  },
};
```

### Golden rules — DO ✅
- `fetchURL` from `../utils` — never raw `fetch()`
- `signal: state.signal` on every fetchURL call
- `redirect: 'manual'` always (follow strips URL params)
- `res.status === 200` check before parsing
- Guard WP REST errors: `if (data.code) return findings`
- `try/catch` around all response parsing
- Return `[]` on AbortError / network failure
- `evidence` must include actual response snippets
- Check for duplicate `type` before adding new module

### Golden rules — DON'T ❌
| Pattern | Why it's wrong |
|---------|---------------|
| 403 → plugin/theme exists | WAF returns 403 for everything |
| `redirect: 'follow'` on write tests | Strips `?status=private`, flips logic |
| `Promise.any()` for lockout detection | Resolves on the 429 itself |
| `body.includes('java')` | Matches JavaScript on all WP sites |
| `body.includes('wp-admin/admin')` | Matches AJAX URLs in page JS |
| `body.includes(themeName)` | Theme names appear in blog posts |
| `/\[\d{2}-\w{3}-\d{4}/` for error logs | Matches blog post dates |
| `CF-Cache-Status: HIT` as vulnerability | Normal Cloudflare CDN |
| Flag `wp-includes/ms-settings.php` | Legit WP Multisite core file |
| Flag hidden iframes without checking src | GTM noscript iframes are safe |
| Flag CJK without checking for translation plugins | Multilingual sites exist |
| Bare `JSON.parse()` | KV corruption causes unhandled 500 |
| `CORS_ORIGIN ?? '*'` | Fails open — must fail closed |
| `X-Forwarded-For` for rate limiting | Use `CF-Connecting-IP` only |

### FP prevention checklist (answer ALL before committing)
1. Fires on WAF sites returning 403/429 for everything?
2. Fires on Cloudflare CDN sites (CF-Cache-Status headers)?
3. Fires on multilingual sites (Weglot/WPML/Polylang/hreflang)?
4. Fires on GTM noscript iframes?
5. Fires because `admin-ajax.php` appears in page JS?
6. Any write test uses `redirect: 'follow'`?
7. Validates body content, not just HTTP status?
8. `type` string overlaps with existing module?
9. Would a legitimate WP core file trigger this?
10. Would a 500 error trigger this as a false positive?

### Severity guidelines
| Severity | Criteria |
|----------|---------|
| CRITICAL | Exploitable RCE, active malware, exposed credentials, full auth bypass |
| HIGH | Significant data exposure, confirmed SQLi/XSS, major auth weakness |
| MEDIUM | Info disclosure enabling further attack, security misconfiguration |
| LOW | Version disclosure, low-exploitability best-practice violations |
| INFO | Passive fingerprinting, technology detection |

### Hall of Shame — confirmed FPs
| Module | FP Type | Root Cause | Fix |
|--------|---------|------------|-----|
| `wp_app_passwords` | APP_PASSWORDS_WEAK_CREDS CRITICAL | `redirect:follow` stripped `?status=private` | `redirect:manual` + validate `post.status` |
| `wp_api_auth` | REST_DRAFT_POST_EXPOSURE HIGH | `redirect:follow` stripped `?status=draft` | `redirect:manual` + post status validation |
| `wp_api_auth` | rest_api_settings_exposed HIGH | 401 error object has 3 keys → "3 exposed" | Check `res.status === 200` AND no `code` field |
| `wp_cache_poisoning` | cache_poisoning HIGH | `body.includes('wp-admin/admin')` matched AJAX | Require `id="wpbody"` or `id="adminmenuwrap"` |
| `wp_cache_poisoning` | cache_header_leak HIGH | `CF-Cache-Status: HIT` flagged | Downgraded to `CDN_CACHING_ACTIVE` INFO |
| `wp_malware_indicators` | MALWARE_HIDDEN_IFRAME CRITICAL | GTM noscript iframe flagged | `SAFE_IFRAME_ORIGINS` allowlist |
| `wp_malware_indicators` | MALWARE_JAPANESE_KEYWORD_HACK CRITICAL | Weglot Chinese content flagged | Check `hasTranslationPlugin` + require hidden CJK |
| `wp_malware_indicators` | MALWARE_MS_SETTINGS_ACCESSIBLE HIGH | `wp-includes/ms-settings.php` flagged | Never flag known WP core files |
| `wp_log4shell_indicators` | LOG4SHELL_PROBE_SENT MEDIUM | `"java"` matched JavaScript | Skip if `X-Powered-By: php` |
| `wp_login_protection` | NO_ACCOUNT_LOCKOUT CRITICAL | `Promise.any()` resolved on 429 itself | `Promise.allSettled()` + require ≥2/5 lockout |
| `wp_plugin_enum` | PLUGIN_DETECTED HIGH | 403 treated as confirmed | Require HTTP 200 + `Plugin Name:` in body |
| `wp_theme_enum` | THEME_DETECTED | Theme name in blog post | Require `style.css` + `Theme Name:` |
| `wp_debug_info` | DEBUG_LOG_PATTERN HIGH | Date regex matched blog dates | Require `PHP Fatal error:` / `PHP Warning:` |
| `wp_cron` | DoS timer meaningless | Parallel requests same wall-clock time | Sequential + latency delta (last/first > 3×) |
| `wp_credential_stuffing` | WOOCOMMERCE_LOGIN_ORACLE MEDIUM | `wc-ajax=get_refreshed_fragments` always returns fragments | Removed |
| `wp_secret_scanning_advanced` | SECRET_DETECTED dupe | Overlaps with `wp_js_recon.ts` patterns | Removed overlapping patterns |
| `engine.ts` | dedup attribution lost | Map keyed by object ref; spread creates new identity | Stable string key: `type::url::evidence[:50]` |
| `wp_ssl_tls` | ssl_expired HIGH FP | Transient `fetch()` null on valid cert | Retry ×2 + downgrade to `https_unreachable MEDIUM` |

---

## 🌿 BRANCH 3 — Security Rules

### Auth pattern (worker routes)
```typescript
const user = c.get('user');   // ✅ correct
user.sub                       // ✅ user ID
// ❌ NEVER: c.get('auth'), c.get('user').user_id, c.get('auth').user_id
```

### Rate limits (KV-based, key = `{prefix}:{ip}`)
| Endpoint | Limit | Window | KV Prefix |
|----------|-------|--------|-----------|
| Login | 10 | 15 min | `auth_login_ip:` |
| Signup | 5 | 1 hour | `auth_signup_ip:` |
| Password change | 5 | 15 min | `pw_change_ip:` |
| Admin login | 5 | 5 min | `admin_login_ip:` |

**IP source:** `CF-Connecting-IP` only. Never `X-Forwarded-For`.

### Constant-time auth
```typescript
const DUMMY_HASH = await hashPassword('dummy-constant-time-placeholder');
const hashToCompare = user?.password_hash ?? DUMMY_HASH;
const valid = await bcrypt.compare(password, hashToCompare);
if (!user || !valid) return unauthorized;
```

### CORS — fail closed
```typescript
const origin = c.env.CORS_ORIGIN ?? (c.env.ENVIRONMENT === 'development' ? 'http://localhost:5173' : null);
if (!origin) return c.json({ error: 'CORS_ORIGIN not set' }, 500);
```

### Admin SQL — strip comments before DDL checks
```typescript
const normalized = sql
  .replace(/\/\*[\s\S]*?\*\//g, ' ')
  .replace(/--[^\n]*/g, ' ')
  .replace(/\s+/g, ' ').trim().toUpperCase();
```

### SSRF blocklist
`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`, `127.x.x.x`, `.local`, `.internal`, `::ffff:192.168.x.x`

---

## 🌿 BRANCH 4 — Quality & Testing

### Phase PASS criteria (all must be true)
- Quality score ≥ 8.0 / 10
- Zero CRITICAL or HIGH false positives
- FP rate < 5%, duplicate rate < 5%
- D1 `findings_count` === R2 `findings` array length
- Scan completes < 4 minutes

### Scoring rubric
| Criterion | Points |
|-----------|--------|
| No CRITICAL FPs | 25 |
| No HIGH FPs | 20 |
| FP rate < 5% | 15 |
| Duplicate rate < 5% | 10 |
| D1 == R2 count | 10 |
| Scan time < 4 min | 10 |
| New modules fire ≥3 valid findings | 5 |
| Key API endpoints 200 | 5 |

### Test sites
| Site | Why | Key expected findings |
|------|-----|-----------------------|
| `https://knose.com.au` | WooCommerce + Cloudflare + Weglot + GTM + real vulns | `ERROR_LOG_EXPOSED` CRITICAL, `JS_SECRET_GOOGLE_API_KEY` HIGH |
| `https://castingnetworks.com` | REST API exposed + CORS bug + CDN | `CORS_ARBITRARY_ORIGIN_REFLECTED` CRITICAL |
| `https://casting.com` | Negative control (non-WP / clean) | Mostly INFO or clean |

### QA protocol
1. Login → get session cookie
2. `POST /scans` → trigger scan
3. Poll until `status === 'completed'` (max 6 min)
4. Compare D1 `findings_count` vs R2 `scans/{user_id}/{scan_id}.json` array length
5. Classify every CRITICAL + HIGH → TP / FP / DUPE / SEVERITY_MISMATCH
6. Score against rubric

### Performance targets
| Parameter | Value |
|-----------|-------|
| `PARALLEL_BATCH` | 12 |
| `MODULE_TIMEOUT_MS` | 25000 |
| AbortController | Per module |
| Response body cache | `state.responseCache` |
| Reachability cache | `state.reachabilityCache` |
| Target scan time | < 4 min (knose.com.au: ~2:22 ✅) |

---

## 🌿 BRANCH 5 — Orchestration Loop

### Cycle
```
AUDIT (parallel, read-only)
  • Security Auditor   → CRITICAL/HIGH/MEDIUM findings
  • Scanner QA Tester  → FP patterns, dedup, accuracy
  • PM/BA Agent        → Feature gaps, UX, prod readiness
        ↓ orchestrator consolidates + prioritizes
DEV (parallel if different files)
  • Security Fix Agent → CRITICAL/HIGH fixes
  • Scanner Fix Agent  → FP fixes, module accuracy
  • Feature Dev Agent  → New features / modules
        ↓ D1 → worker deploy → frontend deploy → smoke test
TEST → score → PASS (≥8.0) or FAIL → fix → retest
```

### Parallel safety
| Combination | Safe? |
|-------------|-------|
| Multiple auditors/testers | ✅ always |
| Dev agents on different files | ✅ safe |
| Dev agents on same file | ❌ sequential only |
| Multiple deploys | ❌ sequential only |
| Audit + Dev (different areas) | ⚠️ ok |

### Escalation rules
- Same blocker 3 phases in a row → root cause analysis first
- CRITICAL FP from new module → revert immediately
- Never ship new features while CRITICAL FPs are unresolved
- New modules must pass solo FP test (all 3 sites) before general QA

### Agent roles
| Agent | Core job | Key constraint |
|-------|----------|---------------|
| **Auditor** | Read-only deep audit of routes, modules, frontend | Output: file:line + severity + exact fix |
| **Vuln Module Dev** | Write new scanner modules | Must pass 10-point FP checklist |
| **UI/UX Dev** | React/Tailwind frontend changes | WCAG AA, aria-labels, no external UI libs |
| **Dev Fix** | Fix issues from audit/QA | Full pre-deploy checklist before done |
| **QA** | Scan 3 test sites, classify findings | Score against rubric |

---

## 🌿 BRANCH 6 — Legal Compliance

### Non-negotiable controls (NEVER remove)
| Control | File | Why |
|---------|------|-----|
| Consent checkbox (frontend) | `NewScan.tsx` | CFAA legal shield |
| Backend consent enforcement | `POST /scans` — reject if `authorization_confirmed !== true` | Bypassed if frontend-only |
| ToS server-side acceptance | `POST /auth/signup` — reject if `agreed_to_terms !== true` | Indemnification unenforceable without it |
| Transparent User-Agent | `utils.ts` — `JWP-Scanner/3.0 (+https://wpsentry.link/report-abuse; abuse@wpsentry.link)` | Legal good faith |
| Abuse page | `/report-abuse` (public) | EU DSA requirement |
| Scan rate limiting | Queue `max_concurrency=10`, per-user ≥2 = 429 | Prevents DDoS classification |

### Module legality
| Type | Status |
|------|--------|
| Version fingerprinting, header inspection, file existence probes | ✅ Safe |
| Payload reflection probes (XXE/LFI — read-only) | ⚠️ Grey — max 3 attempts, ≤25s, specific evidence |
| RCE, credential brute-force, file planting, mass unattended scans | ❌ Prohibited |

### Every new module checklist
- [ ] Classify against legality table above
- [ ] If new PII type collected → update `Privacy.tsx` first
- [ ] Max 3 active payload attempts per endpoint

### Legal pages
| Page | Route | File |
|------|-------|------|
| Terms of Service | `/terms` | `frontend/src/pages/Terms.tsx` |
| Privacy Policy | `/privacy` | `frontend/src/pages/Privacy.tsx` |
| Report Abuse | `/report-abuse` | `frontend/src/pages/ReportAbuse.tsx` |

---

## 🌿 BRANCH 7 — Emergencies

### CRITICAL FP in production
```
1. Identify module + condition (check R2 report evidence field)
2. Add guard to skip the FP case (worker deploy only — 5 min)
3. Add to Hall of Shame in Branch 2
4. Proper root-cause fix next phase
```

### Worker 500s
```bash
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler tail jwp-worker
# Common causes: bare JSON.parse, missing try/catch, D1 schema mismatch
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler rollback  # if needed
```

### D1 schema mismatch
```bash
CLOUDFLARE_ACCOUNT_ID=$CFID npx wrangler d1 execute jwp-db \
  --command "PRAGMA table_info(table_name)" --remote
# Then ALTER TABLE ... ADD COLUMN ...
```

---

## 🌿 BRANCH 8 — Lessons Learned

> Mistakes made by agents. Read before writing new routes or deploying.

| # | Mistake | Rule |
|---|---------|------|
| 1 | Used `c.get('auth').user_id` in a new route | Always `c.get('user').sub` — grep existing routes first |
| 2 | Designed D1 table in code but never ran `CREATE TABLE` on remote | `PRAGMA table_info()` must return rows before worker deploy |
| 3 | Deployed broken code, user discovered the 500 | `curl` smoke test every endpoint after deploy |
| 4 | Added modules but didn't update `Landing.tsx` module count | Update all 5 count references when modules change |

---

## 🌿 BRANCH 9 — Phase History

| Phase | Key Achievement | Score |
|-------|----------------|-------|
| 1–3 | MVP: auth, scanning, 67 modules, Playwright tests | ~5/10 |
| 4–6 | fetchURL redirect bug, reachabilityCache, dedup engine | 6.5/10 |
| 7–9 | APP_PASSWORDS FP, draft FP, findings_count accuracy | 6.5/10 |
| 10–12 | GTM iframe FP, settings 401 FP, cache FP, ssl FP | **8.5/10** ✅ |
| 13 | +22 modules (122 total), UI overhaul, 8 product features | — |
| 14 | 7 CRITICAL + 12 HIGH audit fixes, AbortController, constant-time auth | 4.0/10 |
| 15 | GTM/CJK/cache_header FPs fixed, API key schema fixed | **10.0/10** ✅ |
| 16 | CI/CD, queue max_concurrency=10, timeout fixes | — |
| 17 | Legal compliance, email, open-source, FP reporting feature | — |

---

*Compiled from 17 phases. Keep this lean — add only what future agents will act on.*
