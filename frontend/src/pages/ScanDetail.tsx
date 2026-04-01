import { useEffect, useState, useCallback } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.ts';
import type { ScanDetail as ScanDetailType, Finding } from '../lib/api.ts';
import ScanStatusBadge from '../components/ScanStatusBadge.tsx';
import FindingCard from '../components/FindingCard.tsx';
import { ChevronRightIcon, DownloadIcon, CopyIcon, CheckIcon, FileTextIcon, ScanIcon, SearchIcon, ShareIcon, TagIcon } from '../components/Icons.tsx';
import { generateScanPDF } from '../lib/pdfReport.ts';
import { generateScanCSV } from '../lib/csvExport.ts';
import { ScanProgress } from '../components/ScanProgress.tsx';
import { useToast } from '../components/Toast.tsx';

type SeverityFilter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
type SortMode = 'severity' | 'category' | 'type';

function computeDuration(started?: string | null, completed?: string | null): string | null {
  if (!started || !completed) return null;
  const ms = new Date(completed).getTime() - new Date(started).getTime();
  if (ms < 0) return null;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

function calcRiskScore(bySeverity: ScanDetailType['by_severity']): number {
  return Math.min(100, bySeverity.critical * 25 + bySeverity.high * 10 + bySeverity.medium * 3 + bySeverity.low * 1);
}

function RiskScoreBadge({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-red-500/10 text-red-400 border-red-500/20'
    : score >= 60 ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
    : score >= 30 ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
    : 'bg-green-500/10 text-green-400 border-green-500/20';
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-bold border ${color}`}>
      {score}
      <span className="text-xs font-normal opacity-70">/ 100</span>
    </span>
  );
}

function RiskBadge({ bySeverity }: { bySeverity: ScanDetailType['by_severity'] }) {
  if (bySeverity.critical > 0) return <span className="px-3 py-1.5 rounded-full text-sm font-semibold bg-red-500/10 text-red-400 border border-red-500/20">Critical Risk</span>;
  if (bySeverity.high > 0) return <span className="px-3 py-1.5 rounded-full text-sm font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/20">High Risk</span>;
  if (bySeverity.medium > 0) return <span className="px-3 py-1.5 rounded-full text-sm font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/20">Medium Risk</span>;
  if (bySeverity.low > 0) return <span className="px-3 py-1.5 rounded-full text-sm font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">Low Risk</span>;
  return <span className="px-3 py-1.5 rounded-full text-sm font-semibold bg-brand-500/10 text-brand-400 border border-brand-500/20">No Risk Detected</span>;
}

function deriveFindingCategory(type: string): string {
  const t = type.toLowerCase();
  if (t.includes('sql') || t.includes('injection') || t.includes('xss') || t.includes('lfi') || t.includes('rfi') || t.includes('ssti')) return 'Injection';
  if (t.includes('auth') || t.includes('login') || t.includes('brute') || t.includes('jwt') || t.includes('password')) return 'Authentication';
  if (t.includes('ssl') || t.includes('tls') || t.includes('header') || t.includes('cors') || t.includes('cookie')) return 'Configuration';
  if (t.includes('api') || t.includes('rest') || t.includes('graphql')) return 'API';
  if (t.includes('cve') || t.includes('plugin') || t.includes('vuln')) return 'Plugin CVE';
  return 'General';
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [scan, setScan] = useState<ScanDetailType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [errorsExpanded, setErrorsExpanded] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [findingSearch, setFindingSearch] = useState('');
  const [sortMode, setSortMode] = useState<SortMode>('severity');
  const [sharing, setSharing] = useState(false);
  const [shareUrl, setShareUrl] = useState('');
  const [shareCopied, setShareCopied] = useState(false);

  const fetchScan = useCallback(async () => {
    if (!id) return;
    try {
      const data = await api.getScan(id);
      setScan(data);
    } catch (err: unknown) {
      const e = err as { message?: string };
      setError(e.message ?? 'Failed to load scan');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchScan();
  }, [fetchScan]);

  // Poll for queued/running
  useEffect(() => {
    if (!scan || (scan.status !== 'queued' && scan.status !== 'running')) return;
    const timer = setInterval(fetchScan, 3000);
    return () => clearInterval(timer);
  }, [scan, fetchScan]);

  const handleDownload = () => {
    if (!scan?.report) return;
    const blob = new Blob([JSON.stringify(scan.report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-${scan.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyJson = async () => {
    if (!scan?.report) return;
    await navigator.clipboard.writeText(JSON.stringify(scan.report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleShare = async () => {
    if (!id) return;
    setSharing(true);
    try {
      const result = await api.shareScan(id);
      setShareUrl(result.public_url);
      setScan((prev) => prev ? { ...prev, is_public: true, public_token: result.token } : prev);
    } catch (err: unknown) {
      const e = err as { message?: string };
      toast({ message: e.message ?? 'Failed to share scan', type: 'error' });
    } finally {
      setSharing(false);
    }
  };

  const handleUnshare = async () => {
    if (!id) return;
    try {
      await api.unshareScan(id);
      setShareUrl('');
      setScan((prev) => prev ? { ...prev, is_public: false, public_token: null } : prev);
      toast({ message: 'Public access revoked', type: 'success' });
    } catch (err: unknown) {
      const e = err as { message?: string };
      toast({ message: e.message ?? 'Failed to revoke share', type: 'error' });
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 animate-fade-in">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-sm text-slate-400">Loading scan details…</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="text-center py-24 animate-fade-in">
        <p className="text-red-400 text-sm mb-4">{error || 'Scan not found'}</p>
        <Link to="/history" className="text-brand-400 hover:text-brand-300 text-sm transition-colors">← Back to history</Link>
      </div>
    );
  }

  const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const allFindings = (scan.report?.results.flatMap((r) => r.findings) ?? [])
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  const duration = computeDuration(scan.started_at, scan.completed_at);
  const modulesRun = scan.report?.summary.total_modules ?? scan.modules_selected?.length ?? 100;
  const isInProgress = scan.status === 'queued' || scan.status === 'running';
  const hasErrors = scan.report?.results.some((r) => r.errors.length > 0);
  const riskScore = calcRiskScore(scan.by_severity);

  const severityCounts = [
    { label: 'Critical', count: scan.by_severity.critical, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', ring: 'ring-red-500/20' },
    { label: 'High', count: scan.by_severity.high, color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', ring: 'ring-orange-500/20' },
    { label: 'Medium', count: scan.by_severity.medium, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', ring: 'ring-yellow-500/20' },
    { label: 'Low', count: scan.by_severity.low, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', ring: 'ring-blue-500/20' },
    { label: 'Info', count: scan.by_severity.info, color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20', ring: 'ring-slate-500/20' },
  ];

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-slate-500 animate-fade-in">
        <Link to="/history" className="hover:text-slate-300 transition-colors">History</Link>
        <ChevronRightIcon className="w-3.5 h-3.5" />
        <span className="text-slate-400 truncate max-w-xs">{scan.target}</span>
      </div>

      {/* Header card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-lg shadow-black/10 animate-fade-in-up">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-3 mb-3 flex-wrap">
              <h1 className="text-xl font-bold text-slate-100 break-all">{scan.target}</h1>
              <ScanStatusBadge status={scan.status} />
            </div>
            <div className="flex items-center gap-4 text-xs text-slate-500 flex-wrap">
              <span className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-slate-600" />
                Started {new Date(scan.created_at).toLocaleString()}
              </span>
              {duration && (
                <span className="flex items-center gap-1.5">
                  <span className="w-1 h-1 rounded-full bg-slate-600" />
                  Duration: {duration}
                </span>
              )}
              <span className="flex items-center gap-1.5">
                <span className="w-1 h-1 rounded-full bg-slate-600" />
                {modulesRun} modules
              </span>
            </div>
          </div>
          {scan.status === 'completed' && scan.report && (
            <div className="flex items-center gap-2 shrink-0 flex-wrap">
              <button
                onClick={() => navigate(`/scans/new?target=${encodeURIComponent(scan.target)}`)}
                className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-medium py-2 px-3 rounded-xl text-sm transition-all"
              >
                <ScanIcon className="w-4 h-4" />
                Re-scan
              </button>
              {scan.is_public && scan.public_token ? (
                <button
                  onClick={async () => {
                    const url = shareUrl || `${window.location.origin}/public/scans/${scan.public_token}`;
                    await navigator.clipboard.writeText(url);
                    setShareCopied(true);
                    setTimeout(() => setShareCopied(false), 2000);
                  }}
                  className="flex items-center gap-2 bg-brand-500/10 border border-brand-500/20 text-brand-400 font-medium py-2 px-3 rounded-xl text-sm transition-all"
                >
                  {shareCopied ? <CheckIcon className="w-4 h-4" /> : <ShareIcon className="w-4 h-4" />}
                  {shareCopied ? 'Copied!' : 'Copy Link'}
                </button>
              ) : (
                <button
                  onClick={handleShare}
                  disabled={sharing}
                  className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-slate-100 font-medium py-2 px-3 rounded-xl text-sm transition-all disabled:opacity-50"
                >
                  {sharing ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <ShareIcon className="w-4 h-4" />}
                  {sharing ? 'Sharing…' : 'Share'}
                </button>
              )}
              <button
                onClick={handleCopyJson}
                className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-slate-100 font-medium py-2 px-3 rounded-xl text-sm transition-all"
              >
                {copied ? <CheckIcon className="w-4 h-4 text-brand-400" /> : <CopyIcon className="w-4 h-4" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button
                onClick={handleDownload}
                className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-slate-100 font-medium py-2 px-3 rounded-xl text-sm transition-all"
              >
                <DownloadIcon className="w-4 h-4" />
                Export
              </button>
              <button
                onClick={() => generateScanCSV(scan)}
                className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-slate-100 font-medium py-2 px-3 rounded-xl text-sm transition-all"
              >
                <DownloadIcon className="w-4 h-4" />
                CSV
              </button>
              <button
                onClick={() => generateScanPDF(scan)}
                className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-slate-100 font-medium py-2 px-3 rounded-xl text-sm transition-all"
              >
                <FileTextIcon className="w-4 h-4" />
                PDF Report
              </button>
            </div>
          )}
        </div>
      </div>

      {/* In progress */}
      {isInProgress && (
        <div className="animate-fade-in-up">
          <ScanProgress scanId={scan.id} status={scan.status} />
        </div>
      )}

      {/* Tags + Public badge */}
      {(scan.tags.length > 0 || scan.is_public) && (
        <div className="flex items-center gap-2 flex-wrap animate-fade-in">
          {scan.is_public && (
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-brand-500/10 border border-brand-500/20 text-brand-400 text-xs font-medium">
                <ShareIcon className="w-3 h-3" />
                Public
              </span>
              <button onClick={handleUnshare} className="text-xs text-slate-500 hover:text-red-400 transition-colors">Revoke</button>
            </div>
          )}
          {scan.tags.map((tag) => (
            <span key={tag} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 text-xs">
              <TagIcon className="w-3 h-3" />
              {tag}
            </span>
          ))}
        </div>
      )}

      {/* Executive Summary */}
      {scan.status === 'completed' && allFindings.length > 0 && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 animate-fade-in-up flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Risk Score</span>
            <RiskScoreBadge score={riskScore} />
          </div>
          <div className="w-px h-8 bg-slate-800 hidden sm:block" />
          <p className="text-sm text-slate-400">
            <span className="font-medium text-slate-200">
              {[
                scan.by_severity.critical > 0 && `${scan.by_severity.critical} critical`,
                scan.by_severity.high > 0 && `${scan.by_severity.high} high`,
                scan.by_severity.medium > 0 && `${scan.by_severity.medium} medium`,
              ].filter(Boolean).join(', ')}
            </span>
            {' '}vulnerabilities detected across {modulesRun} modules.
          </p>
        </div>
      )}

      {/* Risk + severity breakdown */}
      {scan.status === 'completed' && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5 shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-3">
              <span className="text-sm font-semibold text-slate-300">Risk Level</span>
              <RiskBadge bySeverity={scan.by_severity} />
            </div>
          </div>
          <div className="grid grid-cols-5 gap-3">
            {severityCounts.map((s) => (
              <div key={s.label} className={`${s.bg} border ${s.border} rounded-xl p-4 text-center hover:ring-1 ${s.ring} transition-all`}>
                <p className={`text-2xl font-bold ${s.color} tracking-tight`}>{s.count}</p>
                <p className="text-xs text-slate-500 mt-1 font-medium">{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings */}
      {allFindings.length > 0 && (
        <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200">
              Findings <span className="text-slate-500 font-normal ml-1">{allFindings.length} total</span>
            </h2>
          </div>
          {/* Severity filter tabs */}
          <div className="flex flex-wrap gap-2">
            {([
              { key: 'ALL' as SeverityFilter, label: 'All', count: allFindings.length, activeBg: 'bg-brand-500/15', activeText: 'text-brand-400', activeBorder: 'border-brand-500/30' },
              { key: 'CRITICAL' as SeverityFilter, label: 'Critical', count: allFindings.filter((f: Finding) => f.severity === 'CRITICAL').length, activeBg: 'bg-red-500/15', activeText: 'text-red-400', activeBorder: 'border-red-500/30' },
              { key: 'HIGH' as SeverityFilter, label: 'High', count: allFindings.filter((f: Finding) => f.severity === 'HIGH').length, activeBg: 'bg-orange-500/15', activeText: 'text-orange-400', activeBorder: 'border-orange-500/30' },
              { key: 'MEDIUM' as SeverityFilter, label: 'Medium', count: allFindings.filter((f: Finding) => f.severity === 'MEDIUM').length, activeBg: 'bg-yellow-500/15', activeText: 'text-yellow-400', activeBorder: 'border-yellow-500/30' },
              { key: 'LOW' as SeverityFilter, label: 'Low', count: allFindings.filter((f: Finding) => f.severity === 'LOW').length, activeBg: 'bg-blue-500/15', activeText: 'text-blue-400', activeBorder: 'border-blue-500/30' },
              { key: 'INFO' as SeverityFilter, label: 'Info', count: allFindings.filter((f: Finding) => f.severity === 'INFO').length, activeBg: 'bg-slate-500/15', activeText: 'text-slate-400', activeBorder: 'border-slate-500/30' },
            ]).map((tab) => {
              const isActive = severityFilter === tab.key;
              return (
                <button
                  key={tab.key}
                  onClick={() => setSeverityFilter(tab.key)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                    isActive
                      ? `${tab.activeBg} ${tab.activeText} ${tab.activeBorder}`
                      : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-600 hover:text-slate-300'
                  }`}
                >
                  {tab.label}
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${isActive ? 'bg-black/20' : 'bg-slate-700/50'}`}>
                    {tab.count}
                  </span>
                </button>
              );
            })}
          </div>
          {/* Search + Sort */}
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex-1 min-w-48">
              <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input
                type="text"
                value={findingSearch}
                onChange={(e) => setFindingSearch(e.target.value)}
                placeholder="Search findings…"
                aria-label="Search findings"
                className="w-full bg-slate-800/80 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
              />
            </div>
            <div className="relative">
              <select
                value={sortMode}
                onChange={(e) => setSortMode(e.target.value as SortMode)}
                aria-label="Sort findings"
                className="appearance-none bg-slate-800 border border-slate-700 text-slate-300 rounded-lg pl-3 pr-7 py-1.5 text-xs focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 focus:outline-none transition-all"
              >
                <option value="severity">By Severity</option>
                <option value="category">By Category</option>
                <option value="type">By Type</option>
              </select>
              <svg className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-slate-500" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" /></svg>
            </div>
          </div>
          <div className="space-y-2.5">
            {(() => {
              let filtered = severityFilter === 'ALL' ? allFindings : allFindings.filter((f: Finding) => f.severity === severityFilter);
              if (findingSearch.trim()) {
                const q = findingSearch.toLowerCase();
                filtered = filtered.filter((f: Finding) =>
                  f.type.toLowerCase().includes(q) || f.description.toLowerCase().includes(q),
                );
              }
              if (sortMode === 'category') {
                filtered = [...filtered].sort((a, b) =>
                  deriveFindingCategory(a.type).localeCompare(deriveFindingCategory(b.type)),
                );
              } else if (sortMode === 'type') {
                filtered = [...filtered].sort((a, b) => a.type.localeCompare(b.type));
              }
              if (filtered.length === 0) {
                return (
                  <div className="text-center py-8 text-sm text-slate-500">
                    No findings match your search.
                  </div>
                );
              }
              return filtered.map((finding: Finding, i: number) => (
                <FindingCard key={i} finding={finding} scanId={scan.id} />
              ));
            })()}
          </div>
        </div>
      )}

      {scan.status === 'completed' && allFindings.length === 0 && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-10 text-center animate-fade-in-up">
          <div className="w-14 h-14 rounded-2xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center mx-auto mb-4">
            <CheckIcon className="w-7 h-7 text-brand-400" />
          </div>
          <p className="text-lg text-slate-200 font-semibold">No vulnerabilities found</p>
          <p className="text-slate-500 text-sm mt-1.5">This site passed all {modulesRun} security checks</p>
        </div>
      )}

      {/* Module errors — collapsible */}
      {hasErrors && (
        <div className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden animate-fade-in-up">
          <button
            onClick={() => setErrorsExpanded(!errorsExpanded)}
            className="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-slate-800/20 transition-all"
          >
            <span className="text-sm font-medium text-slate-500">
              Module Errors
              <span className="text-xs text-slate-600 ml-2">
                ({scan.report!.results.filter((r) => r.errors.length > 0).length} modules)
              </span>
            </span>
            <ChevronRightIcon className={`w-4 h-4 text-slate-600 transition-transform ${errorsExpanded ? 'rotate-90' : ''}`} />
          </button>
          {errorsExpanded && (
            <div className="px-6 pb-4 space-y-2 border-t border-slate-800 pt-3 animate-fade-in">
              {scan.report!.results
                .filter((r) => r.errors.length > 0)
                .map((r) => (
                  <div key={r.module} className="text-xs text-slate-500">
                    <span className="text-slate-400 font-medium">{r.module}:</span>{' '}
                    {r.errors.join(', ')}
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
