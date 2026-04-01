# WPSentry

A WordPress security scanner built on Cloudflare's serverless stack. Scan any WordPress site for 100+ vulnerabilities — from SQLi and XSS to plugin CVEs and misconfigurations — with results in seconds.

**Try it:** https://wpsentry.link

---

## Features

- **100+ security modules** covering OWASP Top 10 + WordPress-specific CVEs
- **Real-time scan progress** via live event stream
- **Findings sorted by severity** (Critical → High → Medium → Low → Info)
- **Free tier** with rate limiting (5 scans/day, 50/month per user)
- **Scan history** with full JSON reports stored in R2
- **Usage dashboard** with per-day/month metrics
- **Zero infrastructure** — fully serverless on Cloudflare

### Scan Coverage

| Category | Modules |
|---|---|
| Injection | SQLi, XSS, LFI, RFI, XXE, SSTI, Command Injection, Object Injection, Email Injection |
| Auth | Brute Force, Login Protection, User Enumeration, JWT Auth, App Passwords, BFLA |
| Enumeration | Plugin, Theme, User, Media, Backup Files, Sensitive Files, Directory Listing |
| WordPress CVEs | TimThumb RFI, RevSlider LFI, WP File Manager RCE, Contact Form 7, WooCommerce |
| API | REST API Exposure/Bypass, CORS, Admin-AJAX Enum, WPGraphQL |
| Infrastructure | SSRF, Open Redirect, Path Traversal, PHP Wrappers, Subdomain Takeover, Supply Chain |
| Headers & Cookies | Clickjacking, Cookie Flags, Dangerous HTTP Methods, Cache Poisoning |
| Misc | GDPR Exposure, Debug Info, Admin Exposure, Multisite Misconfig, IDOR |

---

## Tech Stack

| Layer | Technology |
|---|---|
| API / Worker | Cloudflare Workers (TypeScript) |
| Database | Cloudflare D1 (SQLite) |
| Session / Rate Limit | Cloudflare KV |
| Scan Reports | Cloudflare R2 |
| Scan Queue | Cloudflare Queues |
| Analytics | Cloudflare Analytics Engine |
| Frontend | React + Vite (Cloudflare Pages) |

---

## Architecture

```
Browser
  └── Cloudflare Pages (React SPA)
        └── /api/* → Cloudflare Worker
                       ├── Auth  (D1 users + KV sessions)
                       ├── Rate  (KV counters)
                       ├── Scans (D1 metadata + R2 reports)
                       └── Queue → Scanner Worker
                                    ├── 100+ modules (parallel)
                                    ├── Results → R2
                                    └── Live events → D1
```

---

## CLI Usage

Scan any WordPress site from the terminal using [the hosted API](https://wpsentry.link):

```bash
./jwp-scan.sh https://example.com
```

Requires an API key — get one at [wpsentry.link](https://wpsentry.link).

---

## License

MIT
