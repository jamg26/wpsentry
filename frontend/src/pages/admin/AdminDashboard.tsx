import { useState, useEffect } from 'react';
import { getAdminStats, type AdminStats } from '../../lib/adminApi';

export default function AdminDashboard() {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    getAdminStats()
      .then(setStats)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
        {error}
      </div>
    );
  }

  if (!stats) return null;

  const statCards = [
    { label: 'Total Users', value: stats.total_users, color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
    { label: 'Total Scans', value: stats.total_scans, color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/20' },
    { label: 'Active Scans', value: stats.active_scans, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/20' },
    { label: 'Total Findings', value: stats.total_findings, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
  ];

  // Build a simple sparkline from recent scan dates
  const sparkline = buildSparkline(stats.recent_scan_dates);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-slate-400 mt-1">System overview and activity</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {statCards.map((card) => (
          <div
            key={card.label}
            className={`${card.bg} border rounded-xl p-5`}
          >
            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">{card.label}</p>
            <p className={`text-3xl font-bold mt-2 ${card.color}`}>
              {card.value.toLocaleString()}
            </p>
          </div>
        ))}
      </div>

      {/* Scan activity sparkline */}
      {sparkline.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 mb-8">
          <h2 className="text-sm font-medium text-slate-300 mb-4">Recent Scan Activity (last 7 days)</h2>
          <div className="flex items-end gap-1 h-20">
            {sparkline.map((count, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-1">
                <div
                  className="w-full bg-blue-500/30 rounded-sm min-h-[2px] transition-all"
                  style={{ height: `${Math.max(count * 100 / Math.max(...sparkline, 1), 4)}%` }}
                />
                <span className="text-[10px] text-slate-500">{count}</span>
              </div>
            ))}
          </div>
          <div className="flex justify-between mt-2">
            <span className="text-[10px] text-slate-500">7 days ago</span>
            <span className="text-[10px] text-slate-500">Today</span>
          </div>
        </div>
      )}

      {/* Quick links */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <a href="/admin/users" className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 hover:border-slate-600/50 transition-colors group">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-slate-400 group-hover:text-blue-400 transition-colors" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
            </svg>
            <div>
              <p className="text-sm font-medium text-white">Manage Users</p>
              <p className="text-xs text-slate-400">{stats.total_users} registered</p>
            </div>
          </div>
        </a>
        <a href="/admin/scans" className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 hover:border-slate-600/50 transition-colors group">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-slate-400 group-hover:text-emerald-400 transition-colors" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" />
            </svg>
            <div>
              <p className="text-sm font-medium text-white">View Scans</p>
              <p className="text-xs text-slate-400">{stats.total_scans} total</p>
            </div>
          </div>
        </a>
        <a href="/admin/db" className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 hover:border-slate-600/50 transition-colors group">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-slate-400 group-hover:text-amber-400 transition-colors" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
              <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
            </svg>
            <div>
              <p className="text-sm font-medium text-white">Database</p>
              <p className="text-xs text-slate-400">Run SQL queries</p>
            </div>
          </div>
        </a>
      </div>
    </div>
  );
}

function buildSparkline(dates: number[]): number[] {
  if (!dates.length) return [];
  const now = Date.now();
  const dayMs = 86400000;
  const buckets = new Array(7).fill(0);
  for (const ts of dates) {
    const daysAgo = Math.floor((now - ts) / dayMs);
    if (daysAgo >= 0 && daysAgo < 7) {
      buckets[6 - daysAgo]++;
    }
  }
  return buckets;
}
