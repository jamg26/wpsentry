import { useEffect, useState, useRef } from 'react';
import { api } from '../lib/api.ts';
import { CheckIcon } from './Icons.tsx';

interface ProgressEvent {
  module: string;
  status: 'ok' | 'error';
  findings: number;
  duration_ms: number;
  ts: number;
}

interface ProgressData {
  scan_id: string;
  total: number;
  completed: number | null;
  current_module: string | null;
  events: ProgressEvent[];
  status: string;
}

export function ScanProgress({ scanId, status }: { scanId: string; status: string }) {
  const [progress, setProgress] = useState<ProgressData | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchProgress = async () => {
    try {
      const data = await api.getScanProgress(scanId);
      setProgress(data);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    if (status !== 'queued' && status !== 'running') return;
    fetchProgress();
    intervalRef.current = setInterval(fetchProgress, 2000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [scanId, status]);

  if (!progress || (status !== 'queued' && status !== 'running')) return null;

  const pct = progress.total > 0 && progress.completed != null
    ? Math.round((progress.completed / progress.total) * 100)
    : 0;

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5 shadow-lg shadow-black/10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-3 h-3 rounded-full bg-blue-400 animate-pulse" />
            <div className="absolute inset-0 w-3 h-3 rounded-full bg-blue-400 animate-ping opacity-50" />
          </div>
          <span className="text-sm font-semibold text-white">
            {status === 'queued' ? 'Waiting in queue…' : 'Scan in progress'}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400">
            {progress.completed ?? 0} / {progress.total} modules
          </span>
          <span className="text-sm font-bold text-brand-400">{pct}%</span>
        </div>
      </div>

      {/* Progress bar */}
      <div className="space-y-2">
        <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-blue-500 to-brand-500 rounded-full transition-all duration-700 ease-out relative"
            style={{ width: `${pct}%` }}
          >
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent animate-pulse" />
          </div>
        </div>
        {progress.current_module && (
          <p className="text-xs text-slate-400">
            Currently scanning: <span className="text-blue-300 font-medium">{progress.current_module}</span>
          </p>
        )}
      </div>

      {/* Event log */}
      {progress.events.length > 0 && (
        <div className="space-y-1 max-h-52 overflow-y-auto">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2.5">Module Log</p>
          {[...progress.events].reverse().slice(0, 15).map((ev, i) => (
            <div key={i} className="flex items-center gap-3 text-xs py-1.5 border-b border-slate-800/30 last:border-0">
              <span className={`w-5 h-5 rounded-md flex items-center justify-center shrink-0 ${ev.status === 'ok' ? 'bg-brand-500/10 text-brand-400' : 'bg-red-500/10 text-red-400'}`}>
                {ev.status === 'ok' ? <CheckIcon className="w-3 h-3" /> : '✗'}
              </span>
              <span className="text-slate-300 flex-1 truncate">{ev.module}</span>
              {ev.findings > 0 && (
                <span className="text-orange-400 font-medium shrink-0 bg-orange-500/10 px-1.5 py-0.5 rounded text-[10px]">
                  {ev.findings} finding{ev.findings !== 1 ? 's' : ''}
                </span>
              )}
              <span className="text-slate-600 shrink-0 tabular-nums">{ev.duration_ms}ms</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
