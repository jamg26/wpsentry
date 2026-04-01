import { useState } from 'react';
import { executeReadQuery, executeWriteQuery, type QueryResult } from '../../lib/adminApi';

export default function AdminDB() {
  const [sql, setSql] = useState('SELECT * FROM users LIMIT 10;');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [writeMode, setWriteMode] = useState(false);
  const [confirmWrite, setConfirmWrite] = useState(false);

  const handleExecute = async () => {
    if (!sql.trim()) return;

    const isReadOnly = /^\s*(SELECT|PRAGMA|EXPLAIN)/i.test(sql.trim());

    if (!isReadOnly && writeMode && !confirmWrite) {
      setConfirmWrite(true);
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setConfirmWrite(false);

    try {
      const res = writeMode && !isReadOnly
        ? await executeWriteQuery(sql)
        : await executeReadQuery(sql);
      setResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Query failed');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      handleExecute();
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">Database</h1>
        <p className="text-sm text-slate-400 mt-1">Execute SQL queries against the D1 database</p>
      </div>

      {/* Query editor */}
      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-4 mb-4">
        <textarea
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          onKeyDown={handleKeyDown}
          rows={6}
          className="w-full px-3 py-2 bg-slate-900 border border-slate-700 text-white rounded-lg font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 placeholder-slate-500 resize-y"
          placeholder="Enter SQL query…"
          spellCheck={false}
        />

        <div className="flex items-center justify-between mt-3">
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
              <input
                type="checkbox"
                checked={writeMode}
                onChange={(e) => { setWriteMode(e.target.checked); setConfirmWrite(false); }}
                className="rounded bg-slate-700 border-slate-600 text-red-500 focus:ring-red-500/50"
              />
              <span className={writeMode ? 'text-red-400' : ''}>
                Enable write queries
              </span>
            </label>
            <span className="text-xs text-slate-500">Ctrl+Enter to execute</span>
          </div>
          <button
            onClick={handleExecute}
            disabled={loading || !sql.trim()}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {loading ? 'Executing…' : 'Execute'}
          </button>
        </div>
      </div>

      {/* Write confirmation */}
      {confirmWrite && (
        <div className="mb-4 px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl">
          <p className="text-sm text-red-400 font-medium mb-2">
            ⚠ You are about to execute a write query. This may modify data.
          </p>
          <div className="flex gap-2">
            <button
              onClick={handleExecute}
              className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
            >
              Confirm Execute
            </button>
            <button
              onClick={() => setConfirmWrite(false)}
              className="px-3 py-1.5 text-xs text-slate-300 hover:text-white transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400 font-mono">
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden">
          {/* Meta */}
          <div className="px-4 py-2 border-b border-slate-700/50 flex items-center gap-4 text-xs text-slate-400">
            {result.rows.length > 0 && (
              <span>{result.rows.length} rows</span>
            )}
            {result.meta.rows_read !== undefined && (
              <span>{result.meta.rows_read} rows read</span>
            )}
            {result.meta.changes !== undefined && (
              <span>{result.meta.changes} rows changed</span>
            )}
            {result.meta.duration !== undefined && (
              <span>{result.meta.duration.toFixed(2)}ms</span>
            )}
          </div>

          {/* Table */}
          {result.columns.length > 0 && result.rows.length > 0 ? (
            <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-slate-800">
                  <tr className="border-b border-slate-700/50">
                    {result.columns.map((col) => (
                      <th key={col} className="text-left px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wide whitespace-nowrap">
                        {col}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-700/50">
                  {result.rows.map((row, i) => (
                    <tr key={i} className="hover:bg-slate-800/30">
                      {result.columns.map((col) => (
                        <td key={col} className="px-3 py-2 text-xs text-slate-300 font-mono whitespace-nowrap max-w-[300px] truncate">
                          {row[col] === null ? (
                            <span className="text-slate-600 italic">NULL</span>
                          ) : (
                            String(row[col])
                          )}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="px-4 py-6 text-center text-sm text-slate-500">
              {result.meta.changes !== undefined
                ? `Query executed successfully. ${result.meta.changes} row(s) affected.`
                : 'No results returned.'}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
