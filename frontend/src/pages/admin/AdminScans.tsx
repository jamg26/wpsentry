import { useState, useEffect, useCallback } from 'react';
import { getAdminScans, deleteAdminScan, type AdminScan } from '../../lib/adminApi';

const STATUS_OPTIONS = ['', 'queued', 'running', 'completed', 'failed'];

export default function AdminScans() {
  const [scans, setScans] = useState<AdminScan[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [targetFilter, setTargetFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const PAGE_SIZE = 25;

  const fetchScans = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAdminScans(PAGE_SIZE, page * PAGE_SIZE, {
        status: statusFilter,
        user: userFilter,
        target: targetFilter,
      });
      setScans(res.scans);
      setTotal(res.total);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, userFilter, targetFilter]);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  const handleDelete = async (scanId: string) => {
    try {
      await deleteAdminScan(scanId);
      setDeleteConfirm(null);
      fetchScans();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete scan');
    }
  };

  const statusBadge = (status: string) => {
    const styles: Record<string, string> = {
      queued: 'bg-slate-500/10 text-slate-400',
      running: 'bg-blue-500/10 text-blue-400',
      completed: 'bg-emerald-500/10 text-emerald-400',
      failed: 'bg-red-500/10 text-red-400',
    };
    return (
      <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${styles[status] ?? 'text-slate-400'}`}>
        {status}
      </span>
    );
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Scans</h1>
        <p className="text-sm text-slate-400 mt-1">{total} total scans</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-4">
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
          className="px-3 py-2 bg-slate-800 border border-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s || 'All statuses'}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Filter by user email…"
          value={userFilter}
          onChange={(e) => { setUserFilter(e.target.value); setPage(0); }}
          className="px-3 py-2 bg-slate-800 border border-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 placeholder-slate-500"
        />
        <input
          type="text"
          placeholder="Filter by target…"
          value={targetFilter}
          onChange={(e) => { setTargetFilter(e.target.value); setPage(0); }}
          className="px-3 py-2 bg-slate-800 border border-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 placeholder-slate-500"
        />
      </div>

      {error && (
        <div className="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
          {error}
          <button onClick={() => setError('')} className="ml-2 text-red-300 hover:text-white">✕</button>
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : (
        <>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Scan ID</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">User</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Target</th>
                    <th className="text-center px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Status</th>
                    <th className="text-center px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Findings</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Created</th>
                    <th className="text-right px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 font-mono text-xs text-slate-300" title={scan.id}>
                        {scan.id.slice(0, 8)}…
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{scan.user_email ?? 'unknown'}</td>
                      <td className="px-4 py-3 text-xs text-blue-400 max-w-[200px] truncate">{scan.target}</td>
                      <td className="px-4 py-3 text-center">{statusBadge(scan.status)}</td>
                      <td className="px-4 py-3 text-center text-slate-300">{scan.findings_count}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <a
                            href={`/scans/${scan.id}`}
                            className="px-2 py-1 text-xs text-blue-400 hover:bg-blue-500/10 rounded transition-colors"
                          >
                            View
                          </a>
                          <button
                            onClick={() => setDeleteConfirm(scan.id)}
                            className="px-2 py-1 text-xs text-red-400 hover:bg-red-500/10 rounded transition-colors"
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                        No scans found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4">
              <p className="text-xs text-slate-400">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of {total}
              </p>
              <div className="flex gap-1">
                <button
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                  className="px-3 py-1.5 text-xs bg-slate-800 border border-slate-700 text-slate-300 rounded-lg disabled:opacity-50 hover:bg-slate-700 transition-colors"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                  disabled={page >= totalPages - 1}
                  className="px-3 py-1.5 text-xs bg-slate-800 border border-slate-700 text-slate-300 rounded-lg disabled:opacity-50 hover:bg-slate-700 transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Delete confirmation modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-800 border border-slate-700 rounded-xl p-6 max-w-sm w-full mx-4">
            <h3 className="text-lg font-bold text-white mb-2">Delete Scan</h3>
            <p className="text-sm text-slate-400 mb-1">
              This will permanently delete the scan and its report.
            </p>
            <p className="text-sm text-red-400 font-medium mb-5">This action cannot be undone.</p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="px-4 py-2 text-sm text-slate-300 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteConfirm)}
                className="px-4 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
              >
                Delete Scan
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
