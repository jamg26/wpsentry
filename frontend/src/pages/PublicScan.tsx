import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../lib/api.ts';
import type { ScanDetail, Finding } from '../lib/api.ts';
import ScanStatusBadge from '../components/ScanStatusBadge.tsx';
import FindingCard from '../components/FindingCard.tsx';
import { ShieldIcon, CheckIcon } from '../components/Icons.tsx';

type SeverityFilter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export default function PublicScan() {
  const { token } = useParams<{ token: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');

  useEffect(() => {
    if (!token) return;
    api.getPublicScan(token)
      .then(setScan)
      .catch((e: { message?: string }) => setError(e.message ?? 'Scan not found'))
      .finally(() => setLoading(false));
  }, [token]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-sm text-slate-400">Loading scan report…</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center animate-fade-in-up">
          <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-6">
            <ShieldIcon className="w-8 h-8 text-slate-700" />
          </div>
          <p className="text-red-400 mb-4">{error || 'Scan not found'}</p>
          <p className="text-slate-500 text-sm">This report may have been deleted or the link revoked.</p>
          <Link to="/" className="mt-6 inline-block text-brand-400 hover:text-brand-300 text-sm transition-colors">← Back to WPSentry</Link>
        </div>
      </div>
    );
  }

  const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const allFindings = (scan.report?.findings ?? scan.report?.results.flatMap((r) => r.findings) ?? [])
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <div className="border-b border-slate-800 px-6 py-4 flex items-center gap-3">
        <ShieldIcon className="w-6 h-6 text-brand-400" />
        <span className="font-bold text-slate-100">WPSentry</span>
        <span className="text-slate-600">·</span>
        <span className="text-sm text-slate-400">Public Scan Report</span>
      </div>

      <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
        {/* Scan header */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <div className="flex items-center gap-3 mb-3 flex-wrap">
                <h1 className="text-xl font-bold text-slate-100 break-all">{scan.target}</h1>
                <ScanStatusBadge status={scan.status} />
              </div>
              <div className="flex items-center gap-4 text-xs text-slate-500 flex-wrap">
                <span>Scanned {new Date(scan.created_at).toLocaleString()}</span>
                {scan.completed_at && (
                  <span>Completed {new Date(scan.completed_at).toLocaleString()}</span>
                )}
                {scan.report && <span>{scan.report.summary.total_modules} modules run</span>}
              </div>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-slate-100">{scan.findings_count}</p>
              <p className="text-xs text-slate-500">total findings</p>
            </div>
          </div>
        </div>

        {/* Severity breakdown */}
        {scan.status === 'completed' && (
          <div className="grid grid-cols-5 gap-3">
            {[
              { label: 'Critical', count: scan.by_severity.critical, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
              { label: 'High', count: scan.by_severity.high, color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
              { label: 'Medium', count: scan.by_severity.medium, color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
              { label: 'Low', count: scan.by_severity.low, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
              { label: 'Info', count: scan.by_severity.info, color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20' },
            ].map((s) => (
              <div key={s.label} className={`${s.bg} border ${s.border} rounded-xl p-4 text-center`}>
                <p className={`text-2xl font-bold ${s.color} tracking-tight`}>{s.count}</p>
                <p className="text-xs text-slate-500 mt-1 font-medium">{s.label}</p>
              </div>
            ))}
          </div>
        )}

        {/* Findings */}
        {allFindings.length > 0 && (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              {([
                { key: 'ALL' as SeverityFilter, label: 'All', count: allFindings.length },
                { key: 'CRITICAL' as SeverityFilter, label: 'Critical', count: allFindings.filter((f: Finding) => f.severity === 'CRITICAL').length },
                { key: 'HIGH' as SeverityFilter, label: 'High', count: allFindings.filter((f: Finding) => f.severity === 'HIGH').length },
                { key: 'MEDIUM' as SeverityFilter, label: 'Medium', count: allFindings.filter((f: Finding) => f.severity === 'MEDIUM').length },
                { key: 'LOW' as SeverityFilter, label: 'Low', count: allFindings.filter((f: Finding) => f.severity === 'LOW').length },
                { key: 'INFO' as SeverityFilter, label: 'Info', count: allFindings.filter((f: Finding) => f.severity === 'INFO').length },
              ]).map((tab) => (
                <button
                  key={tab.key}
                  onClick={() => setSeverityFilter(tab.key)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                    severityFilter === tab.key
                      ? 'bg-brand-500/15 text-brand-400 border-brand-500/30'
                      : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-600'
                  }`}
                >
                  {tab.label} ({tab.count})
                </button>
              ))}
            </div>
            <div className="space-y-2.5">
              {(severityFilter === 'ALL' ? allFindings : allFindings.filter((f: Finding) => f.severity === severityFilter))
                .map((finding: Finding, i: number) => (
                  <FindingCard key={i} finding={finding} />
                ))}
            </div>
          </div>
        )}

        {scan.status === 'completed' && allFindings.length === 0 && (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-10 text-center">
            <div className="w-14 h-14 rounded-2xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center mx-auto mb-4">
              <CheckIcon className="w-7 h-7 text-brand-400" />
            </div>
            <p className="text-lg text-slate-200 font-semibold">No vulnerabilities found</p>
            <p className="text-slate-500 text-sm mt-1.5">This site passed all security checks</p>
          </div>
        )}

        {/* Footer */}
        <div className="text-center text-xs text-slate-600 pt-4 border-t border-slate-800">
          Report generated by <a href="/" className="text-brand-400 hover:text-brand-300">WPSentry</a>
        </div>
      </div>
    </div>
  );
}
