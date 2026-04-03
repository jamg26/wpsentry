import { Link } from 'react-router-dom';
import { useAuth } from '../lib/auth.tsx';
import {
  ShieldIcon,
  CheckIcon,
  ZapIcon,
  EyeIcon,
  LayersIcon,
  GlobeIcon,
  LockIcon,
  DatabaseIcon,
  ServerIcon,
  ArrowRightIcon,
  GithubIcon,
} from '../components/Icons.tsx';

const features = [
  {
    icon: <ShieldIcon className="w-6 h-6" />,
    color: 'emerald' as const,
    title: '122 Security Checks',
    description: 'SQL injection, XSS, plugin CVEs, authentication flaws, misconfigurations, and more — all automated.',
    detail: 'Detects: CVE-2024-27956, WP-SQLi, xmlrpc.php exploits',
  },
  {
    icon: <ZapIcon className="w-6 h-6" />,
    color: 'amber' as const,
    title: 'Real-Time Results',
    description: 'Watch findings appear live as each module completes. No waiting for the full scan to finish.',
    detail: 'Stream: Real-time progress updates',
  },
  {
    icon: <LayersIcon className="w-6 h-6" />,
    color: 'sky' as const,
    title: 'Severity Sorting',
    description: 'Findings ranked from Critical to Info. AI generates contextual remediation instructions tailored to each vulnerability.',
    detail: 'Levels: Critical → High → Medium → Low → Info',
  },
  {
    icon: <GlobeIcon className="w-6 h-6" />,
    color: 'violet' as const,
    title: 'Zero Setup',
    description: 'No agents to install, no plugins required. Just enter your WordPress URL and start scanning.',
    detail: 'Works with: WordPress 4.x, 5.x, 6.x',
  },
];

const featureColors = {
  emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400' },
  amber: { bg: 'bg-amber-500/10', border: 'border-amber-500/20', text: 'text-amber-400' },
  sky: { bg: 'bg-sky-500/10', border: 'border-sky-500/20', text: 'text-sky-400' },
  violet: { bg: 'bg-violet-500/10', border: 'border-violet-500/20', text: 'text-violet-400' },
};

const steps = [
  { num: '01', title: 'Enter Target URL', description: 'Paste your WordPress site URL. No plugins, no agents, no setup required.' },
  { num: '02', title: 'Automated Scanning', description: 'Our engine runs 122 security checks — SQL injection, XSS, plugin CVEs, auth flaws and more.' },
  { num: '03', title: 'Review Findings', description: 'Get actionable vulnerability reports sorted by severity, each with detailed remediation steps.' },
];

const categories = [
  { icon: <DatabaseIcon className="w-5 h-5" />, name: 'Injection', desc: 'SQLi, XSS, LFI, RFI, SSTI', count: 12 },
  { icon: <LockIcon className="w-5 h-5" />, name: 'Authentication', desc: 'Brute force, session, JWT', count: 10 },
  { icon: <EyeIcon className="w-5 h-5" />, name: 'Enumeration', desc: 'Users, plugins, themes, media', count: 18 },
  { icon: <ShieldIcon className="w-5 h-5" />, name: 'Plugin CVEs', desc: 'Known vulnerabilities in plugins', count: 24 },
  { icon: <ServerIcon className="w-5 h-5" />, name: 'API Security', desc: 'REST API, GraphQL, AJAX', count: 14 },
  { icon: <GlobeIcon className="w-5 h-5" />, name: 'Infrastructure', desc: 'Headers, SSL, CORS, cookies', count: 22 },
];

const scanLines = [
  { module: 'WordPress Version Detection', status: 'done', finding: 'v6.4.3' },
  { module: 'XML-RPC Enumeration', status: 'done', finding: 'Enabled — brute force risk' },
  { module: 'Plugin Vulnerability Scan', status: 'done', finding: '2 CVEs found' },
  { module: 'SQL Injection Tests', status: 'done', finding: 'Clean' },
  { module: 'Header Security Analysis', status: 'done', finding: 'Missing X-Frame-Options' },
  { module: 'REST API Exposure Check', status: 'active', finding: 'Scanning...' },
];

const mockFindings = [
  { severity: 'Critical', title: 'CVE-2024-27956 — WP-Automatic SQL Injection', module: 'Plugin CVEs' },
  { severity: 'High', title: 'XML-RPC brute force amplification enabled', module: 'Authentication' },
  { severity: 'Medium', title: 'X-Frame-Options header missing', module: 'Infrastructure' },
  { severity: 'Low', title: 'WordPress version exposed in meta tag', module: 'Enumeration' },
];

const severityColors: Record<string, string> = {
  Critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  High: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  Medium: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  Low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
};

export default function Landing() {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Nav */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
              <ShieldIcon className="w-[18px] h-[18px] text-brand-400" />
            </div>
            <span className="text-sm font-bold text-slate-100">WPSentry</span>

          </Link>
          <div className="flex items-center gap-3">
            <a
              href="https://github.com/jamg26/wpsentry"
              target="_blank"
              rel="noopener noreferrer"
              className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 font-medium transition-colors px-2 py-1.5 rounded-lg hover:bg-slate-800"
            >
              <GithubIcon className="w-4 h-4" />
              <span>Open Source</span>
            </a>
            {user ? (
              <Link
                to="/dashboard"
                className="text-sm bg-brand-600 hover:bg-brand-500 text-white font-medium px-4 py-2 rounded-lg transition-colors"
              >
                Dashboard
              </Link>
            ) : (
              <>
                <Link
                  to="/login"
                  className="text-sm text-slate-400 hover:text-slate-200 font-medium transition-colors px-3 py-2"
                >
                  Sign In
                </Link>
                <Link
                  to="/signup"
                  className="text-sm bg-brand-600 hover:bg-brand-500 text-white font-medium px-4 py-2 rounded-lg transition-colors"
                >
                  Get Started
                </Link>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="relative pt-32 pb-20 md:pt-40 md:pb-28 overflow-hidden">
        <div className="absolute inset-0 bg-grid" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-brand-500/5 rounded-full blur-3xl" />
        <div className="absolute top-20 right-1/4 w-[400px] h-[400px] bg-emerald-500/5 rounded-full blur-3xl" />

        <div className="relative max-w-6xl mx-auto px-6">
          <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
            {/* Left: Copy */}
            <div className="text-center lg:text-left">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-brand-500/10 border border-brand-500/20 text-xs font-medium text-brand-400 mb-3 animate-fade-in-up">
                <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse" />
                OWASP Top 10
              </div>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-violet-500/10 border border-violet-500/20 text-xs font-medium text-violet-400 mb-8 animate-fade-in-up ml-2">
                ✦ AI-Powered Remediation
              </div>

              <h1 className="text-4xl md:text-5xl lg:text-6xl font-extrabold tracking-tight mb-6 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
                <span className="text-slate-100">Find WordPress</span>
                <br />
                <span className="text-slate-100">vulnerabilities</span>
                <br />
                <span className="bg-gradient-to-r from-brand-400 via-emerald-300 to-teal-400 bg-clip-text text-transparent">before attackers do</span>
              </h1>

              <p className="text-lg md:text-xl text-slate-400 max-w-xl mb-10 animate-fade-in-up mx-auto lg:mx-0" style={{ animationDelay: '200ms' }}>
                100+ automated security checks covering SQL injection, XSS, plugin CVEs, and misconfigurations.
                <span className="text-slate-300 font-medium"> Completely free.</span>
              </p>

              <div className="flex items-center justify-center lg:justify-start gap-4 flex-wrap animate-fade-in-up" style={{ animationDelay: '300ms' }}>
                <Link
                  to={user ? '/scans/new' : '/signup'}
                  className="group flex items-center gap-2.5 bg-brand-600 hover:bg-brand-500 text-white font-bold py-4 px-10 rounded-xl text-base transition-all hover:shadow-xl hover:shadow-brand-500/30 hover:scale-[1.02]"
                >
                  {user ? 'Start a Scan' : 'Start Scanning — Free'}
                  <ArrowRightIcon className="w-5 h-5 transition-transform group-hover:translate-x-1" />
                </Link>
                <a
                  href="#features"
                  className="hidden sm:flex items-center gap-2 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-slate-300 hover:text-white font-medium py-3 px-8 rounded-xl text-sm transition-all"
                >
                  Learn More
                </a>
              </div>

              {/* Trust bar */}
              <div className="flex items-center justify-center lg:justify-start gap-x-6 gap-y-2 flex-wrap mt-10 animate-fade-in-up" style={{ animationDelay: '400ms' }}>
                <div className="flex items-center gap-1.5 text-xs text-slate-500">
                  <CheckIcon className="w-3.5 h-3.5 text-brand-400" />
                  122 Security Checks
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-500">
                  <CheckIcon className="w-3.5 h-3.5 text-brand-400" />
                  OWASP Top 10 Coverage
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-500">
                  <CheckIcon className="w-3.5 h-3.5 text-brand-400" />
                  Free Forever
                </div>
                <div className="flex items-center gap-1.5 text-xs text-violet-400 font-medium">
                  <span>✦</span>
                  AI Remediation
                </div>
                <a
                  href="https://github.com/jamg26/wpsentry"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300 transition-colors font-medium"
                >
                  <GithubIcon className="w-3.5 h-3.5" />
                  Open Source
                </a>
                <div className="flex items-center gap-1.5 text-xs font-medium text-brand-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse" />
                  10,000+ scans run
                </div>
              </div>
            </div>

            {/* Right: Live scan mockup terminal */}
            <div className="animate-fade-in-up" style={{ animationDelay: '400ms' }}>
              <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl shadow-black/20">
                {/* Terminal header */}
                <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800/80 bg-slate-900/60">
                  <div className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
                    <div className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                  </div>
                  <div className="flex-1 text-center">
                    <span className="text-[11px] text-slate-500 font-mono">WPSentry — Scan in Progress</span>
                  </div>
                </div>
                {/* Terminal body */}
                <div className="p-4 md:p-5 font-mono text-xs space-y-2.5">
                  <div className="text-slate-500 mb-3">$ jwp-scan https://example.com</div>
                  {scanLines.map((line, i) => (
                    <div
                      key={line.module}
                      className="flex items-start gap-2 scan-line-reveal"
                      style={{ animationDelay: `${800 + i * 600}ms` }}
                    >
                      {line.status === 'done' ? (
                        <CheckIcon className="w-3.5 h-3.5 text-brand-400 mt-0.5 shrink-0" />
                      ) : (
                        <span className="w-3.5 h-3.5 mt-0.5 shrink-0 flex items-center justify-center">
                          <span className="w-2 h-2 rounded-full bg-brand-400 animate-pulse" />
                        </span>
                      )}
                      <span className="text-slate-300">{line.module}</span>
                      <span className="text-slate-600 ml-auto shrink-0">
                        {line.status === 'active' ? (
                          <span className="text-brand-400">{line.finding}</span>
                        ) : (
                          line.finding
                        )}
                      </span>
                    </div>
                  ))}
                  <div
                    className="pt-2 mt-2 border-t border-slate-800/60 text-slate-500 scan-line-reveal"
                    style={{ animationDelay: `${800 + scanLines.length * 600}ms` }}
                  >
                    ✓ 5/6 modules complete — 3 findings detected
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 md:py-28 border-t border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-slate-100 mb-4">
              Everything you need to secure WordPress
            </h2>
            <p className="text-slate-400 max-w-xl mx-auto">
              Comprehensive scanning with actionable results. No false positives, just real security insights.
            </p>
          </div>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 stagger-children">
            {features.map((f) => {
              const colors = featureColors[f.color];
              return (
                <div
                  key={f.title}
                  className="animate-fade-in-up bg-slate-900/60 border border-slate-800 rounded-xl p-6 hover:border-slate-700 hover:bg-slate-900/80 transition-all group"
                >
                  <div className={`w-12 h-12 rounded-xl ${colors.bg} border ${colors.border} flex items-center justify-center ${colors.text} mb-4 group-hover:scale-110 transition-transform`}>
                    {f.icon}
                  </div>
                  <h3 className="text-base font-semibold text-slate-200 mb-2">{f.title}</h3>
                  <p className="text-sm text-slate-400 leading-relaxed mb-3">{f.description}</p>
                  <div className="text-[11px] font-mono text-slate-600 bg-slate-800/50 rounded-lg px-3 py-2 border border-slate-800">
                    {f.detail}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Scan Demo/Preview */}
      <section className="py-20 md:py-28 bg-slate-900/30 border-t border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-slate-100 mb-4">
              See what you&apos;ll get
            </h2>
            <p className="text-slate-400 max-w-lg mx-auto">
              Every scan produces a detailed report with prioritized findings and remediation guidance.
            </p>
          </div>

          <div className="max-w-4xl mx-auto">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden">
              {/* Report header */}
              <div className="p-6 border-b border-slate-800/80">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <div className="w-2 h-2 rounded-full bg-brand-400" />
                      <span className="text-sm font-semibold text-slate-200">Scan Complete</span>
                    </div>
                    <p className="text-xs text-slate-500 font-mono">https://example.com — 43 modules · 2.4s</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {([
                      { label: 'Critical', count: 3, color: 'text-red-400' },
                      { label: 'High', count: 5, color: 'text-orange-400' },
                      { label: 'Medium', count: 12, color: 'text-yellow-400' },
                      { label: 'Low', count: 8, color: 'text-blue-400' },
                      { label: 'Info', count: 15, color: 'text-slate-400' },
                    ] as const).map((s) => (
                      <div key={s.label} className="text-center">
                        <div className={`text-lg font-bold ${s.color}`}>{s.count}</div>
                        <div className="text-[10px] text-slate-500 uppercase tracking-wider">{s.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              {/* Mock findings */}
              <div className="divide-y divide-slate-800/60">
                {mockFindings.map((f) => (
                  <div key={f.title} className="px-6 py-4 flex items-start gap-3 hover:bg-slate-800/20 transition-colors">
                    <span className={`shrink-0 mt-0.5 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-md border ${severityColors[f.severity]}`}>
                      {f.severity}
                    </span>
                    <div className="min-w-0">
                      <p className="text-sm text-slate-200 font-medium">{f.title}</p>
                      <p className="text-xs text-slate-500 mt-0.5">Module: {f.module}</p>
                    </div>
                  </div>
                ))}
              </div>
              {/* Report footer */}
              <div className="px-6 py-4 bg-slate-900/40 border-t border-slate-800/60 text-center">
                <span className="text-xs text-slate-500">Showing 4 of 43 findings — </span>
                <Link to={user ? '/history' : '/signup'} className="text-xs text-brand-400 hover:text-brand-300 font-medium">
                  {user ? 'View your scans →' : 'Sign up to run your own scan →'}
                </Link>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* AI Remediation Highlight */}
      <section className="py-20 md:py-28 border-t border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6">
          <div className="max-w-4xl mx-auto">
            <div className="relative rounded-2xl overflow-hidden border border-violet-500/20 bg-gradient-to-br from-violet-500/5 via-slate-900/60 to-slate-900/80 p-8 md:p-12">
              <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-violet-500/5 rounded-full blur-3xl pointer-events-none" />
              <div className="relative grid md:grid-cols-2 gap-10 items-center">
                <div>
                  <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-violet-500/10 border border-violet-500/20 text-xs font-medium text-violet-400 mb-6">
                    ✦ AI-Powered
                  </div>
                  <h2 className="text-2xl md:text-3xl font-bold text-slate-100 mb-4">
                    Remediation instructions written by AI
                  </h2>
                  <p className="text-slate-400 text-sm leading-relaxed mb-6">
                    After each scan, our AI analyses every finding and generates precise, contextual fix instructions — not generic advice. Each recommendation is tailored to the exact vulnerability found on your site.
                  </p>
                  <ul className="space-y-3">
                    {[
                      'Specific to the vulnerability type and context',
                      'Covers plugins, themes, server config, and code',
                      'Falls back to expert-written guidance when offline',
                    ].map((item) => (
                      <li key={item} className="flex items-start gap-2.5 text-sm text-slate-300">
                        <CheckIcon className="w-4 h-4 text-violet-400 mt-0.5 shrink-0" />
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
                {/* Mock AI remediation card */}
                <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                    <span className="text-xs font-semibold text-orange-400 uppercase tracking-wider">High — XML-RPC Enabled</span>
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-violet-500/15 text-violet-400 border border-violet-500/20">✦ AI</span>
                  </div>
                  <div className="p-4">
                    <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Remediation</p>
                    <p className="text-sm text-slate-300 leading-relaxed">
                      Disable XML-RPC entirely by adding <code className="text-violet-300 bg-violet-500/10 px-1 rounded">add_filter('xmlrpc_enabled', '__return_false')</code> to your theme's <code className="text-violet-300 bg-violet-500/10 px-1 rounded">functions.php</code>. Alternatively, install the "Disable XML-RPC" plugin or block the endpoint at the server level via your <code className="text-violet-300 bg-violet-500/10 px-1 rounded">.htaccess</code> file.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 md:py-28 border-t border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-slate-100 mb-4">
              How it works
            </h2>
            <p className="text-slate-400 max-w-lg mx-auto">
              Three simple steps to a comprehensive security audit of your WordPress site.
            </p>
          </div>
          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto stagger-children">
            {steps.map((step, i) => (
              <div key={step.num} className="animate-fade-in-up text-center relative">
                {i < steps.length - 1 && (
                  <div className="hidden md:flex absolute top-10 left-[calc(50%+48px)] w-[calc(100%-96px)] items-center">
                    <div className="flex-1 h-px bg-gradient-to-r from-slate-700 via-brand-500/30 to-slate-700" />
                    <ArrowRightIcon className="w-4 h-4 text-slate-600 -ml-1" />
                  </div>
                )}
                <div className="w-20 h-20 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-5">
                  <span className="text-2xl font-bold text-gradient">{step.num}</span>
                </div>
                <h3 className="text-lg font-semibold text-slate-200 mb-2">{step.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed max-w-[260px] mx-auto">{step.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Categories */}
      <section className="py-20 md:py-28 bg-slate-900/30 border-t border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-slate-100 mb-4">
              Comprehensive coverage
            </h2>
            <p className="text-slate-400 max-w-lg mx-auto">
              122 checks across every major vulnerability category for complete visibility into your WordPress security.
            </p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 max-w-3xl mx-auto stagger-children">
            {categories.map((cat) => (
              <div
                key={cat.name}
                className="animate-fade-in-up bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-brand-500/30 transition-all group"
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 group-hover:text-brand-400 transition-colors">
                    {cat.icon}
                  </div>
                  <span className="text-lg font-bold text-slate-600 group-hover:text-brand-400/60 transition-colors">{cat.count}</span>
                </div>
                <p className="text-sm font-semibold text-slate-200 mb-0.5">{cat.name}</p>
                <p className="text-xs text-slate-500">{cat.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Trust Indicators */}
      <section className="py-12 border-t border-slate-800/50">
        <div className="max-w-6xl mx-auto px-6">
          <div className="flex flex-col sm:flex-row items-center justify-center gap-8 sm:gap-12">
            <div className="flex items-center gap-2 text-sm text-slate-400">
              <ShieldIcon className="w-5 h-5 text-brand-400" />
              100% Free — No Credit Card
            </div>

          </div>
        </div>
      </section>

      {/* Open Source Banner */}
      <section className="py-16 border-t border-slate-800/50 bg-slate-900/20">
        <div className="max-w-6xl mx-auto px-6">
          <div className="max-w-2xl mx-auto text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 mb-5">
              <GithubIcon className="w-6 h-6 text-slate-300" />
            </div>
            <h2 className="text-2xl md:text-3xl font-bold text-slate-100 mb-3">Proudly Open Source</h2>
            <p className="text-slate-400 text-sm leading-relaxed mb-6">
              WPSentry is fully open source. Every scanning module, every line of code — transparent and community-driven.
              Audit the scanner, contribute new modules, or self-host it yourself.
            </p>
            <a
              href="https://github.com/jamg26/wpsentry"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-200 font-semibold py-3 px-6 rounded-xl text-sm transition-all hover:shadow-lg"
            >
              <GithubIcon className="w-4 h-4" />
              View on GitHub — jamg26/wpsentry
            </a>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 md:py-28 border-t border-slate-800/50 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-brand-500/5 to-transparent" />
        <div className="relative max-w-6xl mx-auto px-6 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-slate-100 mb-4">
            Find vulnerabilities before attackers do
          </h2>
          <p className="text-slate-400 max-w-lg mx-auto mb-8">
            Protect your WordPress site with a comprehensive security scan. Takes seconds, costs nothing.
          </p>
          <Link
            to={user ? '/scans/new' : '/signup'}
            className="inline-flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-semibold py-3 px-8 rounded-xl text-sm transition-all hover:shadow-lg hover:shadow-brand-500/20"
          >
            {user ? 'Start a Scan' : 'Start Scanning — Free'}
            <ArrowRightIcon className="w-4 h-4" />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800/50 py-12">
        <div className="max-w-6xl mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="flex items-center gap-2.5">
              <div className="w-7 h-7 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
                <ShieldIcon className="w-4 h-4 text-brand-400" />
              </div>
              <span className="text-sm font-bold text-slate-300">WPSentry</span>
            </div>

            <div className="flex items-center gap-4 text-xs text-slate-500">
              <a
                href="https://github.com/jamg26/wpsentry"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 hover:text-slate-300 transition-colors"
              >
                <GithubIcon className="w-3.5 h-3.5" />
                Open Source
              </a>
              <Link to="/terms" className="hover:text-slate-300 transition-colors">Terms of Service</Link>
              <Link to="/privacy" className="hover:text-slate-300 transition-colors">Privacy Policy</Link>
            </div>
          </div>
          <div className="mt-8 pt-6 border-t border-slate-800/50 text-center text-xs text-slate-600">
            &copy; {new Date().getFullYear()} WPSentry. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}
