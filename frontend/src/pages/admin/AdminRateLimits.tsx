import { useState, useEffect } from 'react';
import { getRateLimits, clearRateLimit, type RateLimitEntry } from '../../lib/adminApi';

export default function AdminRateLimits() {
  const [entries, setEntries] = useState<RateLimitEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState<string | null>(null);
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  const load = () => {
    setLoading(true);
    getRateLimits()
      .then((r) => setEntries(r.entries))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleClear = async (key?: string) => {
    const label = key ? `entry for ${key.split(':').pop()}` : 'all rate limit blocks';
    if (!confirm(`Clear ${label}?`)) return;
    setClearing(key ?? 'all');
    setMsg('');
    try {
      const r = await clearRateLimit(key);
      setMsg(r.message);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed');
    } finally {
      setClearing(null);
    }
  };

  const typeColor = (type: string) => {
    if (type === 'signup') return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    if (type === 'login') return 'bg-red-500/10 text-red-400 border-red-500/20';
    return 'bg-slate-700/40 text-slate-400 border-slate-600/30';
  };

  return (
    <div>
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Rate Limits</h1>
          <p className="text-sm text-slate-400 mt-1">Currently blocked IPs — clear individual entries or all at once.</p>
        </div>
        <div className="flex gap-2 shrink-0">
          <button onClick={load} className="px-3 py-2 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition-colors">
            Refresh
          </button>
          {entries.length > 0 && (
            <button
              onClick={() => handleClear()}
              disabled={clearing === 'all'}
              className="px-3 py-2 text-xs bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg transition-colors"
            >
              {clearing === 'all' ? 'Clearing…' : `Clear All (${entries.length})`}
            </button>
          )}
        </div>
      </div>

      {msg && (
        <div className="mb-4 px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">
          {msg}
        </div>
      )}
      {error && (
        <div className="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-20">
          <div className="w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : entries.length === 0 ? (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl px-6 py-12 text-center">
          <p className="text-2xl mb-2">✅</p>
          <p className="text-slate-300 font-medium">No blocked IPs</p>
          <p className="text-slate-500 text-sm mt-1">All rate limit counters are clear.</p>
        </div>
      ) : (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wide">IP Address</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wide">Type</th>
                <th className="px-4 py-3 text-right text-xs font-semibold text-slate-400 uppercase tracking-wide">Attempts</th>
                <th className="px-4 py-3 text-right text-xs font-semibold text-slate-400 uppercase tracking-wide">Action</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.key} className="border-b border-slate-700/30 last:border-0 hover:bg-slate-700/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-slate-300 text-xs">{e.ip}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 text-xs font-medium rounded-full border ${typeColor(e.type)}`}>
                      {e.type}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right text-slate-300 font-medium">{e.count}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleClear(e.key)}
                      disabled={clearing === e.key}
                      className="text-xs text-red-400 hover:text-red-300 disabled:opacity-50 transition-colors"
                    >
                      {clearing === e.key ? 'Clearing…' : 'Clear'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
