interface ScanStatusBadgeProps {
  status: 'queued' | 'running' | 'completed' | 'failed';
}

export default function ScanStatusBadge({ status }: ScanStatusBadgeProps) {
  if (status === 'queued') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
        <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
        Queued
      </span>
    );
  }
  if (status === 'running') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
        <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
        Running
      </span>
    );
  }
  if (status === 'completed') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-brand-500/10 text-brand-400 border border-brand-500/20">
        <span className="w-1.5 h-1.5 rounded-full bg-brand-400" />
        Completed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
      <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
      Failed
    </span>
  );
}
