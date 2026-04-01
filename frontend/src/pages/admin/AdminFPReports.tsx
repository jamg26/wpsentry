import { useEffect, useState } from 'react';
import { api, type FpReport } from '../../lib/api.ts';
import { useToast } from '../../components/Toast.tsx';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/10 text-red-400 border border-red-500/20',
  HIGH:     'bg-orange-500/10 text-orange-400 border border-orange-500/20',
  MEDIUM:   'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  LOW:      'bg-blue-400/10 text-blue-400 border border-blue-400/20',
  INFO:     'bg-slate-500/10 text-slate-400 border border-slate-500/20',
};

const STATUS_COLORS: Record<string, string> = {
  pending:  'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20',
  confirmed:'bg-red-500/10 text-red-400 border border-red-500/20',
  rejected: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
};

export default function AdminFPReports() {
  const [reports, setReports] = useState<FpReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'pending' | 'confirmed' | 'rejected'>('all');
  const { toast } = useToast();

  const load = async () => {
    setLoading(true);
    try {
      const data = await api.adminGetFpReports();
      setReports(data.reports);
    } catch {
      toast({ message: 'Failed to load FP reports', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const updateStatus = async (id: string, status: 'pending' | 'confirmed' | 'rejected') => {
    try {
      await api.adminUpdateFpStatus(id, status);
      setReports(rs => rs.map(r => r.id === id ? { ...r, status } : r));
      toast({ message: 'Status updated', type: 'success' });
    } catch {
      toast({ message: 'Failed to update', type: 'error' });
    }
  };

  const filtered = filter === 'all' ? reports : reports.filter(r => r.status === filter);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">False Positive Reports</h1>
          <p className="text-sm text-slate-500 mt-1">User-submitted findings that may be incorrect</p>
        </div>
        <button onClick={load} className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded-lg transition-all">
          Refresh
        </button>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2">
        {(['all', 'pending', 'confirmed', 'rejected'] as const).map(s => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-all ${
              filter === s
                ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30'
                : 'bg-slate-800 text-slate-400 border border-slate-700 hover:text-slate-300'
            }`}
          >
            {s}
            <span className="ml-1.5 opacity-60">
              {s === 'all' ? reports.length : reports.filter(r => r.status === s).length}
            </span>
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12 text-slate-500 text-sm">No reports found</div>
      ) : (
        <div className="space-y-3">
          {filtered.map(r => (
            <div key={r.id} className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex flex-wrap items-start gap-3">
                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${SEVERITY_COLORS[r.finding_severity] ?? SEVERITY_COLORS.INFO}`}>
                  {r.finding_severity}
                </span>
                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${STATUS_COLORS[r.status]}`}>
                  {r.status}
                </span>
                <span className="text-xs text-slate-500 ml-auto">
                  {new Date(r.created_at * 1000).toLocaleString()}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Finding Type</p>
                  <p className="text-slate-300 font-mono text-xs">{r.finding_type}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-500 mb-0.5">Reporter</p>
                  <p className="text-slate-300 text-xs">{r.user_email}</p>
                </div>
                <div className="md:col-span-2">
                  <p className="text-xs text-slate-500 mb-0.5">URL</p>
                  <a href={r.finding_url} target="_blank" rel="noopener noreferrer"
                    className="text-brand-400 hover:text-brand-300 underline-offset-2 hover:underline text-xs break-all">
                    {r.finding_url}
                  </a>
                </div>
                <div className="md:col-span-2">
                  <p className="text-xs text-slate-500 mb-0.5">Scan</p>
                  <a href={`/scans/${r.scan_id}`} target="_blank" rel="noopener noreferrer"
                    className="text-brand-400 hover:text-brand-300 underline-offset-2 hover:underline text-xs font-mono">
                    {r.scan_id}
                  </a>
                </div>
                {r.reason && (
                  <div className="md:col-span-2">
                    <p className="text-xs text-slate-500 mb-0.5">Reason</p>
                    <p className="text-slate-300 text-xs bg-slate-800 rounded-lg px-3 py-2">{r.reason}</p>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex gap-2 pt-1">
                {r.status !== 'confirmed' && (
                  <button
                    onClick={() => updateStatus(r.id, 'confirmed')}
                    className="text-xs px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 rounded-lg transition-all"
                  >
                    Mark Confirmed FP
                  </button>
                )}
                {r.status !== 'rejected' && (
                  <button
                    onClick={() => updateStatus(r.id, 'rejected')}
                    className="text-xs px-3 py-1.5 bg-slate-700/50 hover:bg-slate-700 border border-slate-600 text-slate-400 rounded-lg transition-all"
                  >
                    Reject (Valid Finding)
                  </button>
                )}
                {r.status !== 'pending' && (
                  <button
                    onClick={() => updateStatus(r.id, 'pending')}
                    className="text-xs px-3 py-1.5 bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/20 text-yellow-400 rounded-lg transition-all"
                  >
                    Reset to Pending
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
