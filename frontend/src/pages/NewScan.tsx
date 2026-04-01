import { useState, useEffect, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api.ts';
import type { ScanSummary, UsageStats } from '../lib/api.ts';
import { ScanIcon, WarningIcon, CheckIcon, ArrowRightIcon, ClockIcon, TagIcon } from '../components/Icons.tsx';

interface ModuleDef {
  id: number;
  label: string;
}

interface Category {
  name: string;
  modules: ModuleDef[];
}

const CATEGORIES: Category[] = [
  {
    name: 'Recon',
    modules: [
      { id: 1,  label: 'Version Detection' },
      { id: 2,  label: 'User Enum' },
      { id: 3,  label: 'Plugin Enum' },
      { id: 36, label: 'Theme Enum' },
      { id: 51, label: 'Robots & Sitemap' },
      { id: 40, label: 'Media Enum' },
      { id: 56, label: 'JS Recon' },
      { id: 69, label: 'DB Prefix Exposure' },
      { id: 71, label: 'RSS/Atom Feed' },
      { id: 72, label: 'Emoji DNS Prefetch' },
      { id: 80, label: 'Account Enum' },
      { id: 93, label: 'Staging Env' },
    ],
  },
  {
    name: 'Auth',
    modules: [
      { id: 17, label: 'Brute Force' },
      { id: 22, label: 'Login Protection' },
      { id: 21, label: 'Admin Exposure' },
      { id: 49, label: 'REST Auth Bypass' },
      { id: 62, label: 'JWT Auth' },
      { id: 63, label: 'App Passwords' },
      { id: 57, label: 'Password Reset' },
      { id: 75, label: 'Session Fixation' },
      { id: 76, label: 'Password Policy' },
      { id: 77, label: '2FA Bypass' },
      { id: 78, label: 'Auth Cookie Security' },
      { id: 79, label: 'Concurrent Sessions' },
      { id: 81, label: 'Logout Security' },
      { id: 108, label: 'Credential Stuffing' },
    ],
  },
  {
    name: 'Injection',
    modules: [
      { id: 10,  label: 'SQL Injection' },
      { id: 11,  label: 'XSS' },
      { id: 12,  label: 'LFI' },
      { id: 13,  label: 'RFI' },
      { id: 14,  label: 'File Upload Bypass' },
      { id: 23,  label: 'SSRF' },
      { id: 24,  label: 'XXE' },
      { id: 25,  label: 'SSTI' },
      { id: 66,  label: 'Command Injection' },
      { id: 45,  label: 'PHP Wrappers' },
      { id: 101, label: 'PHP Deserialization' },
      { id: 102, label: 'Prototype Pollution' },
      { id: 104, label: 'SSTI Advanced' },
      { id: 105, label: 'Phar Deserialization' },
      { id: 111, label: 'WooCommerce SQLi' },
      { id: 114, label: 'XXE Advanced' },
      { id: 119, label: 'Path Traversal Advanced' },
      { id: 122, label: 'Header Injection' },
    ],
  },
  {
    name: 'API',
    modules: [
      { id: 8,   label: 'REST API' },
      { id: 54,  label: 'REST API Deep' },
      { id: 55,  label: 'Admin AJAX' },
      { id: 61,  label: 'WPGraphQL' },
      { id: 64,  label: 'REST Plugin Audit' },
      { id: 65,  label: 'BFLA' },
      { id: 60,  label: 'REST Mass Assignment' },
      { id: 73,  label: 'oEmbed Security' },
      { id: 95,  label: 'REST API DoS' },
      { id: 98,  label: 'REST Deep Enum' },
      { id: 106, label: 'WPGraphQL Abuse' },
      { id: 112, label: 'Admin AJAX Unauth' },
      { id: 113, label: 'CORS Enhanced' },
    ],
  },
  {
    name: 'Config',
    modules: [
      { id: 18, label: 'Security Headers' },
      { id: 9,  label: 'CORS' },
      { id: 15, label: 'Debug Info' },
      { id: 6,  label: 'Directory Listing' },
      { id: 4,  label: 'XML-RPC' },
      { id: 53, label: 'HTTP Methods' },
      { id: 52, label: 'Cookie Security' },
      { id: 50, label: 'Clickjacking' },
      { id: 48, label: 'SSL/TLS' },
      { id: 70, label: 'Open Registration' },
      { id: 74, label: 'Install Page Exposure' },
      { id: 89, label: 'phpinfo() Exposure' },
      { id: 90, label: 'Error Log Exposure' },
      { id: 91, label: 'Git/Env Files' },
      { id: 92, label: 'Database Dump' },
      { id: 94, label: 'wp-config Backup' },
      { id: 96, label: 'Webhook Security' },
      { id: 97, label: 'OAuth Vulns' },
    ],
  },
  {
    name: 'Vulns',
    modules: [
      { id: 7,   label: 'Backup Finder' },
      { id: 5,   label: 'Sensitive Files' },
      { id: 16,  label: 'Path Traversal' },
      { id: 30,  label: 'TimThumb' },
      { id: 31,  label: 'RevSlider' },
      { id: 32,  label: 'WP File Manager' },
      { id: 33,  label: 'Contact Form 7' },
      { id: 34,  label: 'WooCommerce' },
      { id: 35,  label: 'Plugin CVE' },
      { id: 46,  label: 'Supply Chain' },
      { id: 68,  label: 'Theme Vuln Scanner' },
      { id: 82,  label: 'Elementor Vulns' },
      { id: 83,  label: 'Yoast SEO Vulns' },
      { id: 84,  label: 'ACF Vulns' },
      { id: 85,  label: 'WPForms Vulns' },
      { id: 86,  label: 'Wordfence Bypass' },
      { id: 87,  label: 'UpdraftPlus Vulns' },
      { id: 88,  label: 'All in One SEO Vulns' },
      { id: 100, label: 'Upload Dir Listing' },
      { id: 107, label: 'Supply Chain Integrity' },
      { id: 116, label: 'CVE 2024-2025' },
      { id: 121, label: 'Plugin Slurp CVE' },
    ],
  },
  {
    name: 'Advanced',
    modules: [
      { id: 19,  label: 'Open Redirect' },
      { id: 20,  label: 'CSRF' },
      { id: 26,  label: 'Host Header' },
      { id: 27,  label: 'Object Injection' },
      { id: 28,  label: 'Email Injection' },
      { id: 29,  label: 'IDOR' },
      { id: 37,  label: 'WP-Cron' },
      { id: 38,  label: 'Heartbeat' },
      { id: 39,  label: 'GDPR' },
      { id: 41,  label: 'Rate Limit Bypass' },
      { id: 42,  label: 'Cache Poisoning' },
      { id: 43,  label: 'Subdomain Takeover' },
      { id: 44,  label: 'Multisite' },
      { id: 47,  label: 'Nonce Weakness' },
      { id: 58,  label: 'Error Analysis' },
      { id: 59,  label: 'Race Conditions' },
      { id: 67,  label: 'Business Logic' },
      { id: 99,  label: 'Content Injection' },
      { id: 103, label: 'Log4Shell' },
      { id: 109, label: 'Webshell Indicators' },
      { id: 110, label: 'Malware Indicators' },
      { id: 115, label: 'Race Condition Purchase' },
      { id: 117, label: 'Subdomain Takeover+' },
      { id: 118, label: 'Secret Scanning Advanced' },
      { id: 120, label: 'IDOR Enhanced' },
    ],
  },
];

const ALL_MODULE_IDS = CATEGORIES.flatMap((c) => c.modules.map((m) => m.id));

const QUICK_SCAN_IDS = new Set([1, 2, 3, 8, 9, 10, 11, 12, 17, 18, 19, 21, 22, 23, 24, 4, 5, 6, 7, 15, 16, 31, 33, 34, 35, 36, 48, 50, 51, 52]);

function timeUntil(isoDate: string): string {
  const diff = new Date(isoDate).getTime() - Date.now();
  if (diff <= 0) return 'soon';
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  if (h > 24) return `${Math.floor(h / 24)}d`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function usageBarColor(pct: number): string {
  if (pct >= 90) return 'bg-red-500';
  if (pct >= 70) return 'bg-amber-500';
  return 'bg-emerald-500';
}

function isValidUrl(str: string): boolean {
  try {
    const url = new URL(str);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export default function NewScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState<'full' | 'quick' | 'custom'>('full');
  const [selected, setSelected] = useState<Set<number>>(new Set(ALL_MODULE_IDS));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [tagInput, setTagInput] = useState('');
  const [tags, setTags] = useState<string[]>([]);
  const [recentScans, setRecentScans] = useState<ScanSummary[]>([]);
  const [hasConsent, setHasConsent] = useState(false);
  const [usageStats, setUsageStats] = useState<UsageStats | null>(null);
  const [usageLoading, setUsageLoading] = useState(true);

  useEffect(() => {
    const prefill = searchParams.get('target');
    if (prefill) setTarget(prefill);
  }, [searchParams]);

  useEffect(() => {
    api.listScans(5, 0)
      .then((r) => setRecentScans(r.scans))
      .catch(() => {});
  }, []);

  useEffect(() => {
    api.getUsage()
      .then((r) => setUsageStats(r))
      .catch(() => {})
      .finally(() => setUsageLoading(false));
  }, []);

  useEffect(() => { setHasConsent(false); }, [target]);

  const urlValid = target.trim() === '' || isValidUrl(target.trim());

  const moduleCount = mode === 'full' ? ALL_MODULE_IDS.length : mode === 'quick' ? QUICK_SCAN_IDS.size : selected.size;

  const estimatedTime = mode === 'full'
    ? '~3-5 minutes'
    : mode === 'quick'
    ? '~1-2 minutes'
    : (() => {
        const mins = Math.max(1, Math.ceil((selected.size * 2.5) / 60));
        return `~${mins} minute${mins !== 1 ? 's' : ''}`;
      })();

  const addTag = () => {
    const t = tagInput.trim().toLowerCase().replace(/\s+/g, '-').slice(0, 50);
    if (t && !tags.includes(t)) setTags((prev) => [...prev, t]);
    setTagInput('');
  };

  const removeTag = (tag: string) => setTags((prev) => prev.filter((t) => t !== tag));

  const toggleModule = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleCategory = (cat: Category) => {
    const catIds = cat.modules.map((m) => m.id);
    const allSelected = catIds.every((id) => selected.has(id));
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) catIds.forEach((id) => next.delete(id));
      else catIds.forEach((id) => next.add(id));
      return next;
    });
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    if (!target.trim()) {
      setError('Please enter a target URL');
      return;
    }
    if (!isValidUrl(target.trim())) {
      setError('Please enter a valid URL (e.g., https://example.com)');
      return;
    }
    setLoading(true);
    try {
      const modules = mode === 'full'
        ? undefined
        : mode === 'quick'
        ? Array.from(QUICK_SCAN_IDS)
        : Array.from(selected);
      const scan = await api.createScan(target.trim(), modules);
      navigate(`/scans/${scan.id}`);
    } catch (err: unknown) {
      const e = err as { message?: string };
      setError(e.message ?? 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-8">
      <div className="animate-fade-in-up">
        <h1 className="text-2xl font-bold text-slate-100">New Security Scan</h1>
        <p className="text-slate-400 mt-1 text-sm">Scan a WordPress site for security vulnerabilities</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Usage & Limits */}
        {usageLoading ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 animate-pulse space-y-3 animate-fade-in-up">
            <div className="h-3 w-28 bg-slate-800 rounded-full" />
            <div className="space-y-2">
              <div className="h-2.5 w-full bg-slate-800 rounded-full" />
              <div className="h-1.5 w-full bg-slate-800 rounded-full" />
            </div>
            <div className="space-y-2">
              <div className="h-2.5 w-full bg-slate-800 rounded-full" />
              <div className="h-1.5 w-full bg-slate-800 rounded-full" />
            </div>
          </div>
        ) : usageStats ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 animate-fade-in-up">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Usage this period</p>

            {usageStats.daily_remaining === 0 && (
              <div className="flex items-center gap-2 text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2 mb-3">
                <WarningIcon className="w-3.5 h-3.5 shrink-0" />
                Daily scan limit reached — resets in {timeUntil(usageStats.reset_daily_at)}
              </div>
            )}
            {usageStats.monthly_remaining === 0 && (
              <div className="flex items-center gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 mb-3">
                <WarningIcon className="w-3.5 h-3.5 shrink-0" />
                Monthly scan limit reached — resets in {timeUntil(usageStats.reset_monthly_at)}
              </div>
            )}

            <div className="space-y-3">
              {/* Daily */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-slate-400">Daily scans</span>
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-medium text-slate-200">{usageStats.daily_used} / {usageStats.daily_limit} used</span>
                    <span className="text-xs text-slate-400">Resets in {timeUntil(usageStats.reset_daily_at)}</span>
                  </div>
                </div>
                <div className="bg-slate-800 rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full transition-all ${usageBarColor(Math.round((usageStats.daily_used / Math.max(usageStats.daily_limit, 1)) * 100))}`}
                    style={{ width: `${Math.min(100, Math.round((usageStats.daily_used / Math.max(usageStats.daily_limit, 1)) * 100))}%` }}
                  />
                </div>
              </div>

              {/* Monthly */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-slate-400">Monthly scans</span>
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-medium text-slate-200">{usageStats.monthly_used} / {usageStats.monthly_limit} used</span>
                    <span className="text-xs text-slate-400">Resets in {timeUntil(usageStats.reset_monthly_at)}</span>
                  </div>
                </div>
                <div className="bg-slate-800 rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full transition-all ${usageBarColor(Math.round((usageStats.monthly_used / Math.max(usageStats.monthly_limit, 1)) * 100))}`}
                    style={{ width: `${Math.min(100, Math.round((usageStats.monthly_used / Math.max(usageStats.monthly_limit, 1)) * 100))}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        ) : null}

        {/* Target */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4 animate-fade-in-up shadow-lg shadow-black/10" style={{ animationDelay: '100ms' }}>
          <label className="block text-sm font-semibold text-slate-200">Target URL</label>
          <div className="relative">
            <input
              data-testid="target-input"
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className={`w-full bg-slate-800/80 border rounded-xl px-4 py-3.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 transition-all pr-12 ${
                target && !urlValid
                  ? 'border-red-500/50 focus:border-red-500 focus:ring-red-500/20'
                  : target && urlValid
                  ? 'border-brand-500/30 focus:border-brand-500 focus:ring-brand-500/20'
                  : 'border-slate-700 focus:border-brand-500 focus:ring-brand-500/20'
              }`}
            />
            <div className="absolute right-3 top-1/2 -translate-y-1/2">
              {target && urlValid && <CheckIcon className="w-5 h-5 text-brand-400" />}
              {target && !urlValid && <WarningIcon className="w-5 h-5 text-red-400" />}
              {!target && <ScanIcon className="w-5 h-5 text-slate-500" />}
            </div>
          </div>
          {target && !urlValid && (
            <p className="text-xs text-red-400 animate-fade-in">Please enter a valid URL starting with http:// or https://</p>
          )}
          <div className="flex items-start gap-2 text-xs text-amber-400/80 bg-amber-500/5 border border-amber-500/10 rounded-xl px-4 py-3">
            <WarningIcon className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            Only scan sites you own or have explicit authorization to test
          </div>
        </div>

        {/* Consent */}
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 mt-4 animate-fade-in-up" style={{ animationDelay: '150ms' }}>
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={hasConsent}
              onChange={(e) => setHasConsent(e.target.checked)}
              className="accent-brand-500 mt-0.5 shrink-0"
            />
            <span className="text-xs text-slate-400 leading-relaxed">
              I confirm I own this website or have explicit written authorization to perform security testing on it. I understand unauthorized scanning may violate computer crime laws in my jurisdiction.{' '}
              <a href="/terms" className="text-brand-400 hover:text-brand-300 transition-colors underline">Terms of Service</a>
            </span>
          </label>
        </div>

        {/* Modules */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4 animate-fade-in-up shadow-lg shadow-black/10" style={{ animationDelay: '200ms' }}>
          <label className="block text-sm font-semibold text-slate-200">Scan Mode</label>
          <div className="space-y-2.5">
            <label className={`flex items-start gap-3 cursor-pointer p-3 rounded-xl border transition-all ${mode === 'full' ? 'border-brand-500/30 bg-brand-500/5' : 'border-transparent hover:bg-slate-800/30'}`}>
              <input
                type="radio"
                name="mode"
                checked={mode === 'full'}
                onChange={() => setMode('full')}
                className="accent-brand-500 mt-0.5"
              />
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-200">Full Scan ({ALL_MODULE_IDS.length} modules)</span>
                  <span className="text-xs text-brand-400 bg-brand-500/10 border border-brand-500/20 px-2 py-0.5 rounded-full font-medium">Recommended</span>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">Complete security audit — recommended for thorough testing. ~3-5 minutes.</p>
              </div>
            </label>
            <label className={`flex items-start gap-3 cursor-pointer p-3 rounded-xl border transition-all ${mode === 'quick' ? 'border-brand-500/30 bg-brand-500/5' : 'border-transparent hover:bg-slate-800/30'}`}>
              <input
                type="radio"
                name="mode"
                checked={mode === 'quick'}
                onChange={() => setMode('quick')}
                className="accent-brand-500 mt-0.5"
              />
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-200">Quick Scan ({QUICK_SCAN_IDS.size} modules)</span>
                  <span className="text-xs text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full font-medium">Fast</span>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">Fast scan covering most common vulnerabilities. ~1-2 minutes.</p>
              </div>
            </label>
            <label className={`flex items-start gap-3 cursor-pointer p-3 rounded-xl border transition-all ${mode === 'custom' ? 'border-brand-500/30 bg-brand-500/5' : 'border-transparent hover:bg-slate-800/30'}`}>
              <input
                type="radio"
                name="mode"
                checked={mode === 'custom'}
                onChange={() => setMode('custom')}
                className="accent-brand-500 mt-0.5"
              />
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-slate-200">Custom selection</span>
                  {mode === 'custom' && (
                    <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">{selected.size} selected</span>
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-0.5">Choose exactly which modules to run.</p>
              </div>
            </label>
          </div>

          {mode === 'custom' && (
            <div className="space-y-5 pt-4 border-t border-slate-800">
              {CATEGORIES.map((cat) => {
                const catIds = cat.modules.map((m) => m.id);
                const allCatSelected = catIds.every((id) => selected.has(id));
                const someCatSelected = catIds.some((id) => selected.has(id));
                return (
                  <div key={cat.name}>
                    <div className="flex items-center justify-between mb-2.5">
                      <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{cat.name}</span>
                      <button
                        type="button"
                        onClick={() => toggleCategory(cat)}
                        className={`text-xs px-2.5 py-1 rounded-lg transition-all ${
                          allCatSelected
                            ? 'text-brand-400 bg-brand-500/10 border border-brand-500/20'
                            : someCatSelected
                            ? 'text-slate-400 bg-slate-800 border border-slate-700'
                            : 'text-slate-500 bg-slate-800 border border-slate-700'
                        }`}
                      >
                        {allCatSelected ? 'Deselect all' : 'Select all'}
                      </button>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                      {cat.modules.map((mod) => (
                        <label
                          key={mod.id}
                          className={`flex items-center gap-2 px-3 py-2 rounded-xl cursor-pointer border text-xs transition-all ${
                            selected.has(mod.id)
                              ? 'bg-brand-500/10 border-brand-500/20 text-brand-300'
                              : 'bg-slate-800/60 border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-300'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={selected.has(mod.id)}
                            onChange={() => toggleModule(mod.id)}
                            className="accent-brand-500 shrink-0"
                          />
                          <span className="truncate">{mod.label}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Scan preview */}
        {target.trim() && urlValid && (
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 animate-fade-in">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Scan Preview</h3>
            <div className="flex items-center gap-4 text-sm flex-wrap">
              <div>
                <p className="text-slate-500 text-xs">Target</p>
                <p className="text-slate-200 font-medium truncate max-w-xs">{target.trim()}</p>
              </div>
              <div className="border-l border-slate-700 pl-4">
                <p className="text-slate-500 text-xs">Modules</p>
                <p className="text-slate-200 font-medium">{moduleCount}</p>
              </div>
              <div className="border-l border-slate-700 pl-4 flex items-center gap-1.5">
                <ClockIcon className="w-3.5 h-3.5 text-slate-500" />
                <p className="text-slate-400 text-xs">{estimatedTime}</p>
              </div>
            </div>
          </div>
        )}

        {error && (
          <div data-testid="error-message" className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 text-sm text-red-400 flex items-center gap-2.5 animate-fade-in">
            <WarningIcon className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        {/* Tags */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-3 animate-fade-in-up shadow-lg shadow-black/10" style={{ animationDelay: '250ms' }}>
          <div className="flex items-center gap-2">
            <TagIcon className="w-4 h-4 text-slate-400" />
            <label className="text-sm font-semibold text-slate-200">Tags <span className="text-slate-500 font-normal text-xs">(optional)</span></label>
          </div>

          {/* Recent Targets */}
          {recentScans.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1.5">Recent Targets</p>
              <div className="flex flex-wrap gap-1.5">
                {recentScans.map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => setTarget(s.target)}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-brand-400 hover:border-brand-500/30 text-xs transition-all truncate max-w-[200px]"
                    title={s.target}
                  >
                    {s.target.replace(/^https?:\/\//, '').replace(/\/$/, '')}
                  </button>
                ))}
              </div>
            </div>
          )}

          {tags.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {tags.map((t) => (
                <span key={t} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-300 text-xs font-medium">
                  {t}
                  <button type="button" onClick={() => removeTag(t)} className="hover:text-red-400 transition-colors">×</button>
                </span>
              ))}
            </div>
          )}
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addTag(); } }}
              placeholder="Add tag (press Enter)"
              className="flex-1 bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
            />
            <button type="button" onClick={addTag} disabled={!tagInput.trim()} className="px-3 py-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-sm text-slate-300 disabled:opacity-50 transition-all">Add</button>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <button
            type="submit"
            disabled={loading || !hasConsent || (mode === 'custom' && selected.size === 0) || usageStats?.daily_remaining === 0 || usageStats?.monthly_remaining === 0}
            className="group flex items-center gap-2.5 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3 px-7 rounded-xl text-sm transition-all hover:shadow-lg hover:shadow-brand-500/20"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Starting scan…
              </>
            ) : (
              <>
                <ScanIcon className="w-4 h-4" />
                Start Security Scan
                <ArrowRightIcon className="w-4 h-4 transition-transform group-hover:translate-x-0.5" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
