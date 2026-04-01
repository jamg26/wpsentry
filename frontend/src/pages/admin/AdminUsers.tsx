import { useState, useEffect, useCallback } from 'react';
import {
  getAdminUsers,
  updateAdminUser,
  deleteAdminUser,
  type AdminUser,
} from '../../lib/adminApi';

export default function AdminUsers() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editValues, setEditValues] = useState<{ daily_limit: string; monthly_limit: string }>({ daily_limit: '', monthly_limit: '' });
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);

  const PAGE_SIZE = 25;

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAdminUsers(PAGE_SIZE, page * PAGE_SIZE, search);
      setUsers(res.users);
      setTotal(res.total);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, [page, search]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const handleToggleBan = async (user: AdminUser) => {
    try {
      await updateAdminUser(user.id, { is_active: user.is_active ? 0 : 1 });
      fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    }
  };

  const handleSaveLimits = async (userId: string) => {
    try {
      await updateAdminUser(userId, {
        daily_limit: editValues.daily_limit,
        monthly_limit: editValues.monthly_limit,
      });
      setEditingId(null);
      fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update limits');
    }
  };

  const handleDelete = async (userId: string) => {
    try {
      await deleteAdminUser(userId);
      setDeleteConfirm(null);
      fetchUsers();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
    }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Users</h1>
        <p className="text-sm text-slate-400 mt-1">{total} total users</p>
      </div>

      {/* Search */}
      <div className="mb-4">
        <input
          type="text"
          placeholder="Search by email…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          className="w-full max-w-sm px-3 py-2 bg-slate-800 border border-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 placeholder-slate-500"
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
                    <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Email</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Created</th>
                    <th className="text-center px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Scans</th>
                    <th className="text-center px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Daily Limit</th>
                    <th className="text-center px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Monthly Limit</th>
                    <th className="text-center px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Status</th>
                    <th className="text-right px-4 py-3 text-xs font-medium text-slate-400 uppercase tracking-wide">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {users.map((user) => (
                    <tr key={user.id} className="hover:bg-slate-800/30">
                      <td className="px-4 py-3 text-white font-mono text-xs">{user.email}</td>
                      <td className="px-4 py-3 text-slate-400 text-xs">
                        {new Date(user.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-3 text-center text-slate-300">{user.scan_count}</td>
                      <td className="px-4 py-3 text-center">
                        {editingId === user.id ? (
                          <input
                            type="number"
                            value={editValues.daily_limit}
                            onChange={(e) => setEditValues({ ...editValues, daily_limit: e.target.value })}
                            className="w-16 px-2 py-1 bg-slate-700 border border-slate-600 text-white rounded text-xs text-center"
                          />
                        ) : (
                          <button
                            onClick={() => {
                              setEditingId(user.id);
                              setEditValues({ daily_limit: user.daily_limit, monthly_limit: user.monthly_limit });
                            }}
                            className="text-slate-300 hover:text-white cursor-pointer"
                          >
                            {user.daily_limit}
                          </button>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {editingId === user.id ? (
                          <input
                            type="number"
                            value={editValues.monthly_limit}
                            onChange={(e) => setEditValues({ ...editValues, monthly_limit: e.target.value })}
                            className="w-16 px-2 py-1 bg-slate-700 border border-slate-600 text-white rounded text-xs text-center"
                          />
                        ) : (
                          <button
                            onClick={() => {
                              setEditingId(user.id);
                              setEditValues({ daily_limit: user.daily_limit, monthly_limit: user.monthly_limit });
                            }}
                            className="text-slate-300 hover:text-white cursor-pointer"
                          >
                            {user.monthly_limit}
                          </button>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${
                          user.is_active ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
                        }`}>
                          {user.is_active ? 'Active' : 'Banned'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {editingId === user.id ? (
                            <>
                              <button
                                onClick={() => handleSaveLimits(user.id)}
                                className="px-2 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded transition-colors"
                              >
                                Save
                              </button>
                              <button
                                onClick={() => setEditingId(null)}
                                className="px-2 py-1 text-xs text-slate-400 hover:text-white transition-colors"
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <>
                              <button
                                onClick={() => handleToggleBan(user)}
                                className={`px-2 py-1 text-xs rounded transition-colors ${
                                  user.is_active
                                    ? 'text-amber-400 hover:bg-amber-500/10'
                                    : 'text-emerald-400 hover:bg-emerald-500/10'
                                }`}
                              >
                                {user.is_active ? 'Ban' : 'Unban'}
                              </button>
                              <button
                                onClick={() => setDeleteConfirm(user.id)}
                                className="px-2 py-1 text-xs text-red-400 hover:bg-red-500/10 rounded transition-colors"
                              >
                                Delete
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                        No users found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
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
            <h3 className="text-lg font-bold text-white mb-2">Delete User</h3>
            <p className="text-sm text-slate-400 mb-1">
              This will permanently delete the user and all their data including scans and reports.
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
                Delete User
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
