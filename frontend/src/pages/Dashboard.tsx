import { useEffect, useState, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import { api } from '../lib/api.ts';
import type { ScanSummary, ScansListResponse, UserStats, ScheduledScan } from '../lib/api.ts';
import { useAuth } from '../lib/auth.tsx';
import ScanStatusBadge from '../components/ScanStatusBadge.tsx';
import EmptyState from '../components/EmptyState.tsx';
import { PlusIcon, ShieldIcon, ScanIcon, HistoryIcon, WarningIcon, ArrowRightIcon, CalendarIcon, GlobeIcon } from '../components/Icons.tsx';

function getGreeting() {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function calcRiskScore(bySeverity: ScanSummary['by_severity']): number {
  return Math.min(100, bySeverity.critical * 25 + bySeverity.high * 10 + bySeverity.medium * 3 + bySeverity.low * 1);
}

function calcHealthScore(bySeverity: ScanSummary['by_severity']): number {
  return 100 - calcRiskScore(bySeverity);
}

interface StatCardProps {
  icon: ReactNode;
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
  gradient?: string;
  to?: string;
}

function StatCard({ icon, label, value, sub, accent = 'text-slate-100', gradient, to }: StatCardProps) {
  const inner = (
    <div className={`relative bg-slate-900/80 border border-slate-800 rounded-xl p-6 overflow-hidden hover:border-slate-700 transition-all animate-fade-in-up ${to ? 'cursor-pointer' : ''}`}>
      {gradient && <div className={`absolute inset-0 ${gradient} opacity-[0.03]`} />}
      <div className="relative">
        <div className="flex items-start justify-between mb-4">
          <div className="w-10 h-10 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
            {icon}
          </div>
        </div>
        <p className={`text-3xl font-bold ${accent} mb-1 tracking-tight`}>{value}</p>
        <p className="text-sm text-slate-400">{label}</p>
        {sub && <p className="text-xs text-slate-500 mt-1.5">{sub}</p>}
      </div>
    </div>
  );
  if (to) return <Link to={to}>{inner}</Link>;
  return inner;
}

function SeverityDots({ by_severity }: { by_severity: ScanSummary['by_severity'] }) {
  const items = [
    { key: 'critical', color: 'bg-red-500', count: by_severity.critical },
    { key: 'high', color: 'bg-orange-500', count: by_severity.high },
    { key: 'medium', color: 'bg-yellow-500', count: by_severity.medium },
    { key: 'low', color: 'bg-blue-500', count: by_severity.low },
    { key: 'info', color: 'bg-slate-500', count: by_severity.info },
  ];
  const anyFindings = items.some((i) => i.count > 0);
  if (!anyFindings) return <span className="text-xs text-slate-600">—</span>;
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {items
        .filter((i) => i.count > 0)
        .map((i) => (
          <span key={i.key} className="inline-flex items-center gap-1 text-xs text-slate-300">
            <span className={`w-1.5 h-1.5 rounded-full ${i.color}`} />
            {i.count}
          </span>
        ))}
    </div>
  );
}

function SkeletonCard() {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
      <div className="w-10 h-10 rounded-xl skeleton mb-4" />
      <div className="h-8 w-16 skeleton mb-2" />
      <div className="h-4 w-24 skeleton" />
    </div>
  );
}

function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-5 py-4">
      <div className="flex-1 space-y-2">
        <div className="h-4 w-48 skeleton" />
        <div className="h-3 w-24 skeleton" />
      </div>
      <div className="h-6 w-20 skeleton rounded-full" />
    </div>
  );
}

function SecuritySparkline({ scans }: { scans: ScanSummary[] }) {
  const completed = scans
    .filter((s) => s.status === 'completed')
    .slice(0, 7)
    .reverse();

  if (completed.length < 2) return null;

  const scores = completed.map((s) => calcHealthScore(s.by_severity));
  const min = Math.max(0, Math.min(...scores) - 10);
  const max = Math.min(100, Math.max(...scores) + 10);
  const range = max - min || 1;
  const w = 160;
  const h = 40;
  const pts = scores
    .map((v, i) => {
      const x = (i / (scores.length - 1)) * w;
      const y = h - ((v - min) / range) * h;
      return `${x},${y}`;
    })
    .join(' ');
  const lastScore = scores[scores.length - 1];
  const scoreColor = lastScore >= 70 ? 'text-green-400' : lastScore >= 40 ? 'text-yellow-400' : 'text-red-400';

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 animate-fade-in-up" style={{ animationDelay: '150ms' }}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <HistoryIcon className="w-4 h-4 text-brand-400" />
          <h2 className="text-sm font-semibold text-slate-200">Security Trend</h2>
        </div>
        <span className={`text-lg font-bold ${scoreColor}`}>{lastScore}</span>
      </div>
      <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="overflow-visible">
        <polyline
          points={pts}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="text-brand-400"
        />
        {scores.map((v, i) => {
          const x = (i / (scores.length - 1)) * w;
          const y = h - ((v - min) / range) * h;
          return <circle key={i} cx={x} cy={y} r="2" fill="currentColor" className="text-brand-400" />;
        })}
      </svg>
      <p className="text-xs text-slate-500 mt-2">Last {scores.length} completed scans · health score (100 = clean)</p>
    </div>
  );
}

function MostVulnerableSite({ scans }: { scans: ScanSummary[] }) {
  const completed = scans.filter((s) => s.status === 'completed');
  if (completed.length === 0) return null;
  const worst = completed.reduce((prev, curr) => {
    const pScore = prev.by_severity.critical * 25 + prev.by_severity.high * 10;
    const cScore = curr.by_severity.critical * 25 + curr.by_severity.high * 10;
    return cScore > pScore ? curr : prev;
  });
  if (worst.by_severity.critical === 0 && worst.by_severity.high === 0) return null;
  return (
    <div className="bg-red-500/5 border border-red-500/15 rounded-xl p-5 animate-fade-in-up" style={{ animationDelay: '150ms' }}>
      <div className="flex items-center gap-2 mb-2">
        <WarningIcon className="w-4 h-4 text-red-400" />
        <h2 className="text-sm font-semibold text-red-400">Most Vulnerable Site</h2>
      </div>
      <Link to={`/scans/${worst.id}`} className="group">
        <p className="text-sm font-medium text-slate-200 truncate group-hover:text-brand-400 transition-colors">{worst.target}</p>
        <div className="flex items-center gap-3 mt-1.5">
          {worst.by_severity.critical > 0 && (
            <span className="text-xs text-red-400">{worst.by_severity.critical} critical</span>
          )}
          {worst.by_severity.high > 0 && (
            <span className="text-xs text-orange-400">{worst.by_severity.high} high</span>
          )}
        </div>
      </Link>
    </div>
  );
}

export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [data, setData] = useState<ScansListResponse | null>(null);
  const [stats, setStats] = useState<UserStats | null>(null);
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const [loading, setLoading] = useState(true);
  // HIGH-11: Track API errors and provide a retry mechanism
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      api.listScans(10, 0),
      api.getUserStats(),
      api.listScheduledScans(),
    ]).then(([scansData, statsData, schedData]) => {
      setData(scansData);
      setStats(statsData);
      setScheduledScans(schedData.scheduled_scans);
    }).catch(err => {
      console.error(err);
      setError('Failed to load dashboard data.');
    }).finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const scans = data?.scans ?? [];
  const usage = data?.usage;

  const totalFindings = stats?.total_findings ?? scans.reduce((acc, s) => acc + (s.findings_count ?? 0), 0);
  const criticalTotal = stats?.critical_findings ?? scans.reduce((acc, s) => acc + (s.by_severity?.critical ?? 0), 0);

  // HIGH-11: Show error state with retry button if data fetch failed
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-4">
        <p className="text-red-400 text-sm">{error}</p>
        <button
          onClick={fetchData}
          className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-semibold py-2.5 px-5 rounded-xl text-sm transition-all"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 animate-fade-in-up">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">
            {getGreeting()}, <span className="text-gradient">{user?.full_name || user?.email?.split('@')[0]}</span>
          </h1>
          <p className="text-slate-400 mt-1 text-sm">Here's your security overview</p>
        </div>
        <button
          data-testid="new-scan-btn"
          onClick={() => navigate('/scans/new')}
          className="group flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-semibold py-2.5 px-5 rounded-xl text-sm transition-all hover:shadow-lg hover:shadow-brand-500/20 shrink-0"
        >
          <PlusIcon className="w-4 h-4" />
          New Scan
          <ArrowRightIcon className="w-3.5 h-3.5 opacity-0 -ml-1 group-hover:opacity-100 group-hover:ml-0 transition-all" />
        </button>
      </div>

      {/* Stat cards */}
      {loading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 stagger-children">
          <StatCard
            icon={<ScanIcon className="w-[18px] h-[18px]" />}
            label="Total Scans"
            value={stats?.total_scans ?? scans.length}
            sub={stats ? `${stats.scans_this_week} this week` : 'last 10 shown'}
            to="/history"
            gradient="bg-gradient-to-br from-brand-500 to-brand-700"
          />
          <StatCard
            icon={<ShieldIcon className="w-[18px] h-[18px]" />}
            label="Findings Found"
            value={totalFindings}
            sub={stats ? `${stats.high_findings} high severity` : 'across all scans'}
            to="/history"
            gradient="bg-gradient-to-br from-blue-500 to-blue-700"
          />
          <StatCard
            icon={<WarningIcon className="w-[18px] h-[18px]" />}
            label="Critical Issues"
            value={criticalTotal}
            accent={criticalTotal > 0 ? 'text-red-400' : 'text-slate-100'}
            sub="needs attention"
            to="/history"
            gradient="bg-gradient-to-br from-red-500 to-red-700"
          />
          <StatCard
            icon={<GlobeIcon className="w-[18px] h-[18px]" />}
            label="Sites Scanned"
            value={stats?.sites_scanned ?? new Set(scans.map((s) => s.target)).size}
            sub={stats?.avg_scan_duration_seconds ? `avg ${stats.avg_scan_duration_seconds}s/scan` : `${usage?.daily_used ?? 0}/${usage?.daily_limit ?? 5} today`}
            gradient="bg-gradient-to-br from-purple-500 to-purple-700"
          />
        </div>
      )}

      {/* Security trend + Most vulnerable */}
      {!loading && scans.length > 1 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <SecuritySparkline scans={scans} />
          <MostVulnerableSite scans={scans} />
        </div>
      )}

      {/* Quick actions */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
        <Link
          to="/scans/new"
          className="group bg-gradient-to-br from-brand-500/10 to-brand-500/5 border border-brand-500/20 rounded-xl p-5 hover:border-brand-500/40 transition-all flex items-center gap-4"
        >
          <div className="w-12 h-12 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 shrink-0 group-hover:scale-110 transition-transform">
            <PlusIcon className="w-5 h-5" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-200">Start New Scan</p>
            <p className="text-xs text-slate-400 mt-0.5">Scan a WordPress site for vulnerabilities</p>
          </div>
        </Link>
        <Link
          to="/history"
          className="group bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all flex items-center gap-4"
        >
          <div className="w-12 h-12 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-400 shrink-0 group-hover:scale-110 transition-transform">
            <HistoryIcon className="w-5 h-5" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-200">View History</p>
            <p className="text-xs text-slate-400 mt-0.5">Browse all past scan results</p>
          </div>
        </Link>
      </div>

      {/* Scheduled Scans */}
      {!loading && scheduledScans.length > 0 && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '250ms' }}>
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CalendarIcon className="w-4 h-4 text-brand-400" />
              <h2 className="text-sm font-semibold text-slate-200">Scheduled Scans</h2>
            </div>
          </div>
          <div className="divide-y divide-slate-800/50">
            {scheduledScans.map((s) => (
              <div key={s.id} className="flex items-center gap-4 px-6 py-4">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate">{s.url}</p>
                  <p className="text-xs text-slate-500 mt-0.5 capitalize">{s.schedule_cron} · next run {new Date(s.next_run_at).toLocaleDateString()}</p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded-full border ${s.enabled ? 'bg-brand-500/10 text-brand-400 border-brand-500/20' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                  {s.enabled ? 'Active' : 'Paused'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Activity */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '300ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Recent Activity</h2>
          <Link to="/history" className="text-xs text-brand-400 hover:text-brand-300 transition-colors flex items-center gap-1 font-medium">
            View all
            <ArrowRightIcon className="w-3 h-3" />
          </Link>
        </div>

        {loading ? (
          <div className="divide-y divide-slate-800">
            <SkeletonRow /><SkeletonRow /><SkeletonRow />
          </div>
        ) : scans.length === 0 ? (
          <EmptyState
            icon={<ShieldIcon className="w-8 h-8" />}
            title="No scans yet"
            description="Start your first security scan to see results here."
            action={
              <Link
                to="/scans/new"
                className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-medium py-2.5 px-5 rounded-xl text-sm transition-all"
              >
                <PlusIcon className="w-4 h-4" />
                Start First Scan
              </Link>
            }
          />
        ) : (
          <div className="divide-y divide-slate-800/50">
            {scans.slice(0, 5).map((scan) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center gap-4 px-6 py-4 hover:bg-slate-800/30 transition-all group"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate group-hover:text-brand-400 transition-colors">{scan.target}</p>
                  <p className="text-xs text-slate-500 mt-0.5">
                    <span title={new Date(scan.created_at).toLocaleString()}>{timeAgo(scan.created_at)}</span>
                    {scan.findings_count > 0 && <span className="ml-2 text-slate-400">· {scan.findings_count} findings</span>}
                  </p>
                </div>
                <SeverityDots by_severity={scan.by_severity} />
                <ScanStatusBadge status={scan.status} />
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
