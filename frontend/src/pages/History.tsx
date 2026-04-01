import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../lib/api.ts';
import type { ScanSummary } from '../lib/api.ts';
import ScanStatusBadge from '../components/ScanStatusBadge.tsx';
import EmptyState from '../components/EmptyState.tsx';
import { useToast } from '../components/Toast.tsx';
import { PlusIcon, SearchIcon, DeleteIcon, HistoryIcon, ChevronRightIcon, DownloadIcon, TagIcon } from '../components/Icons.tsx';

type StatusFilter = 'all' | 'queued' | 'running' | 'completed' | 'failed';
type SortField = 'date' | 'findings' | 'status';

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function SeverityBadges({ by_severity }: { by_severity: ScanSummary['by_severity'] }) {
  const items = [
    { key: 'critical', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', count: by_severity.critical, label: 'C' },
    { key: 'high', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', count: by_severity.high, label: 'H' },
    { key: 'medium', bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20', count: by_severity.medium, label: 'M' },
    { key: 'low', bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', count: by_severity.low, label: 'L' },
    { key: 'info', bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20', count: by_severity.info, label: 'I' },
  ];
  const active = items.filter((i) => i.count > 0);
  if (active.length === 0) return <span className="text-xs text-slate-600">—</span>;
  return (
    <div className="flex items-center gap-1 flex-nowrap">
      {active.map((i) => (
        <span key={i.key} className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium border whitespace-nowrap ${i.bg} ${i.text} ${i.border}`}>
          {i.label}: {i.count}
        </span>
      ))}
    </div>
  );
}

const GRID_COLS = 'grid-cols-[24px_1fr_100px_220px_140px_40px]';
const MD_GRID_COLS = 'md:grid-cols-[24px_1fr_100px_220px_140px_40px]';

const STATUS_ORDER: Record<string, number> = { running: 0, queued: 1, completed: 2, failed: 3 };

function exportBulkCSV(scans: ScanSummary[]) {
  const header = ['ID', 'Target', 'Status', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Total Findings', 'Date'];
  const rows = scans.map((s) => [
    s.id,
    s.target,
    s.status,
    s.by_severity.critical,
    s.by_severity.high,
    s.by_severity.medium,
    s.by_severity.low,
    s.by_severity.info,
    s.findings_count,
    new Date(s.created_at).toISOString(),
  ]);
  const csv = [header, ...rows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'scan-history-export.csv';
  a.click();
  URL.revokeObjectURL(url);
}

export default function History() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [sortField, setSortField] = useState<SortField>('date');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [tagFilter, setTagFilter] = useState('');

  useEffect(() => {
    api.listScans(100, 0)
      .then((r) => setScans(r.scans))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  // Collect all unique tags across scans
  const allTags = Array.from(new Set(scans.flatMap((s) => s.tags ?? []))).sort();

  const filtered = scans
    .filter((s) => {
      const matchesSearch = s.target.toLowerCase().includes(search.toLowerCase());
      const matchesStatus = statusFilter === 'all' || s.status === statusFilter;
      const matchesTag = !tagFilter || (s.tags ?? []).includes(tagFilter);
      return matchesSearch && matchesStatus && matchesTag;
    })
    .sort((a, b) => {
      if (sortField === 'findings') return (b.findings_count ?? 0) - (a.findings_count ?? 0);
      if (sortField === 'status') return (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9);
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

  const handleDelete = async (id: string) => {
    setDeleting(id);
    try {
      await api.deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      setSelectedIds((prev) => { const n = new Set(prev); n.delete(id); return n; });
      // HIGH-10: Only close confirm dialog on success
      setConfirmDeleteId(null);
    } catch (err) {
      console.error(err);
      toast({ message: 'Failed to delete scan. Please try again.', type: 'error' });
      // Keep dialog open — don't close on failure
      return;
    } finally {
      setDeleting(null);
    }
  };

  const handleBulkDelete = async () => {
    setBulkDeleting(true);
    const ids = Array.from(selectedIds);
    await Promise.allSettled(ids.map((id) => api.deleteScan(id)));
    setScans((prev) => prev.filter((s) => !selectedIds.has(s.id)));
    setSelectedIds(new Set());
    setBulkDeleting(false);
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === filtered.length && filtered.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((s) => s.id)));
    }
  };

  const statusCounts = {
    all: scans.length,
    queued: scans.filter((s) => s.status === 'queued').length,
    running: scans.filter((s) => s.status === 'running').length,
    completed: scans.filter((s) => s.status === 'completed').length,
    failed: scans.filter((s) => s.status === 'failed').length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 animate-fade-in-up">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Scan History</h1>
          <p className="text-slate-400 mt-1 text-sm">{scans.length} total scans</p>
        </div>
        <button
          onClick={() => navigate('/scans/new')}
          className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-semibold py-2.5 px-5 rounded-xl text-sm transition-all hover:shadow-lg hover:shadow-brand-500/20 shrink-0"
        >
          <PlusIcon className="w-4 h-4" />
          New Scan
        </button>
      </div>

      {/* Bulk action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-3 bg-brand-500/10 border border-brand-500/20 rounded-xl animate-fade-in">
          <span className="text-sm text-brand-400 font-medium">{selectedIds.size} selected</span>
          <div className="flex items-center gap-2 ml-auto">
            <button
              onClick={() => exportBulkCSV(filtered.filter((s) => selectedIds.has(s.id)))}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 border border-slate-700 text-slate-300 hover:text-slate-100 transition-all"
            >
              <DownloadIcon className="w-3.5 h-3.5" />
              Export CSV
            </button>
            <button
              onClick={handleBulkDelete}
              disabled={bulkDeleting}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 disabled:opacity-50 transition-all"
            >
              {bulkDeleting ? (
                <div className="w-3.5 h-3.5 border-2 border-red-400/30 border-t-red-400 rounded-full animate-spin" />
              ) : (
                <DeleteIcon className="w-3.5 h-3.5" />
              )}
              Delete Selected
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
        <div className="relative flex-1 min-w-0">
          <SearchIcon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by URL…"
            className="w-full bg-slate-800/80 border border-slate-700 rounded-xl pl-10 pr-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
          />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
              className="appearance-none bg-slate-800 border border-slate-700 text-slate-300 rounded-lg pl-3 pr-8 py-2 text-sm focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 focus:outline-none transition-all"
            >
              <option value="all">All ({statusCounts.all})</option>
              <option value="queued">Queued ({statusCounts.queued})</option>
              <option value="running">Running ({statusCounts.running})</option>
              <option value="completed">Completed ({statusCounts.completed})</option>
              <option value="failed">Failed ({statusCounts.failed})</option>
            </select>
            <svg className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" /></svg>
          </div>
          {allTags.length > 0 && (
            <div className="relative">
              <TagIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
              <select
                value={tagFilter}
                onChange={(e) => setTagFilter(e.target.value)}
                className="appearance-none bg-slate-800 border border-slate-700 text-slate-300 rounded-lg pl-8 pr-8 py-2 text-sm focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 focus:outline-none transition-all"
              >
                <option value="">All tags</option>
                {allTags.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
              <svg className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" /></svg>
            </div>
          )}
          <div className="relative">
            <select
              value={sortField}
              onChange={(e) => setSortField(e.target.value as SortField)}
              className="appearance-none bg-slate-800 border border-slate-700 text-slate-300 rounded-lg pl-3 pr-8 py-2 text-sm focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 focus:outline-none transition-all"
            >
              <option value="date">Sort: Date</option>
              <option value="findings">Sort: Findings</option>
              <option value="status">Sort: Status</option>
            </select>
            <svg className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" /></svg>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
        {loading ? (
          <div className="divide-y divide-slate-800">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="flex items-center gap-4 px-6 py-4">
                <div className="flex-1 space-y-2">
                  <div className="h-4 w-48 skeleton" />
                  <div className="h-3 w-32 skeleton" />
                </div>
                <div className="h-6 w-20 skeleton rounded-full" />
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<HistoryIcon className="w-8 h-8" />}
            title={search || statusFilter !== 'all' ? 'No matching scans' : 'No scans yet'}
            description={search || statusFilter !== 'all' ? 'Try adjusting your search or filters.' : 'Start your first scan to see history here.'}
            action={
              !search && statusFilter === 'all' ? (
                <button
                  onClick={() => navigate('/scans/new')}
                  className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-medium py-2.5 px-5 rounded-xl text-sm transition-all"
                >
                  <PlusIcon className="w-4 h-4" />
                  Start First Scan
                </button>
              ) : undefined
            }
          />
        ) : (
          <>
            {/* Header row */}
            <div className={`hidden md:grid ${GRID_COLS} gap-4 px-6 py-3 border-b border-slate-800 text-xs font-semibold text-slate-500 uppercase tracking-wider items-center`}>
              <input
                type="checkbox"
                aria-label="Select all scans"
                checked={selectedIds.size === filtered.length && filtered.length > 0}
                onChange={toggleSelectAll}
                className="accent-brand-500 w-4 h-4 rounded"
              />
              <span>Target</span>
              <span>Status</span>
              <span>Findings</span>
              <span>Date</span>
              <span></span>
            </div>
            <div className="divide-y divide-slate-800/50">
              {filtered.map((scan) => (
                <div key={scan.id} className="group relative">
                  <div className={`grid ${MD_GRID_COLS} gap-2 md:gap-4 px-6 py-4 items-center hover:bg-slate-800/20 transition-all`}>
                    <input
                      type="checkbox"
                      aria-label={`Select ${scan.target}`}
                      checked={selectedIds.has(scan.id)}
                      onChange={() => toggleSelect(scan.id)}
                      onClick={(e) => e.stopPropagation()}
                      className="accent-brand-500 w-4 h-4 rounded hidden md:block"
                    />
                    <Link to={`/scans/${scan.id}`} className="min-w-0 flex items-center gap-3 col-start-1 md:col-start-2">
                      <div className="flex-1 min-w-0">
                        <p title={scan.target} className="text-sm font-medium text-slate-200 truncate group-hover:text-brand-400 transition-colors">{scan.target}</p>
                        <p className="text-xs text-slate-500 mt-0.5 md:hidden">
                          <span title={new Date(scan.created_at).toLocaleString()}>{timeAgo(scan.created_at)}</span>
                        </p>
                      </div>
                      <ChevronRightIcon className="w-4 h-4 text-slate-600 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity md:hidden" />
                    </Link>
                    <Link to={`/scans/${scan.id}`} className="hidden md:block">
                      <ScanStatusBadge status={scan.status} />
                    </Link>
                    <Link to={`/scans/${scan.id}`} className="hidden md:block overflow-hidden">
                      <SeverityBadges by_severity={scan.by_severity} />
                    </Link>
                    <Link to={`/scans/${scan.id}`} className="hidden md:block">
                      <span title={new Date(scan.created_at).toLocaleString()} className="text-xs text-slate-500 whitespace-nowrap">
                        {timeAgo(scan.created_at)}
                      </span>
                    </Link>
                    <span className="hidden md:block w-8" />
                  </div>
                  <button
                    onClick={(e) => { e.preventDefault(); e.stopPropagation(); setConfirmDeleteId(scan.id); }}
                    className="absolute right-4 top-1/2 -translate-y-1/2 p-2 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/5 transition-all opacity-0 group-hover:opacity-100 z-10"
                    title="Delete scan"
                    aria-label="Delete scan"
                  >
                    <DeleteIcon className="w-4 h-4" />
                  </button>
                  {/* Inline delete confirm */}
                  {confirmDeleteId === scan.id && (
                    <div className="px-6 py-3 bg-red-500/5 border-t border-red-500/20 flex items-center justify-between gap-3 animate-fade-in">
                      <p className="text-sm text-red-400">Delete this scan permanently?</p>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setConfirmDeleteId(null)}
                          className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 transition-all"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => handleDelete(scan.id)}
                          disabled={deleting === scan.id}
                          className="px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-red-600 hover:bg-red-500 disabled:opacity-50 transition-all flex items-center gap-1.5"
                        >
                          {deleting === scan.id ? (
                            <>
                              <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                              Deleting…
                            </>
                          ) : (
                            'Delete'
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
