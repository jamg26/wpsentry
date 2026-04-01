import type { UsageStats } from '../lib/api.ts';

interface UsageBarProps {
  usage: UsageStats;
}

function formatResetTime(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = date.getTime() - now.getTime();
  if (diffMs <= 0) return 'soon';
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
  const diffMins = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
  if (diffHours > 0) return `${diffHours}h ${diffMins}m`;
  return `${diffMins}m`;
}

export default function UsageBar({ usage }: UsageBarProps) {
  const dailyPct = Math.min(100, (usage.daily_used / usage.daily_limit) * 100);
  const monthlyPct = Math.min(100, (usage.monthly_used / usage.monthly_limit) * 100);
  const dailyWarning = dailyPct >= 80;
  const monthlyWarning = monthlyPct >= 80;

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-5 shadow-lg shadow-black/10">
      <h3 className="text-sm font-semibold text-slate-300">Usage</h3>
      <div className="space-y-4">
        <div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-medium text-slate-400">Daily</span>
            <span className="text-xs text-slate-400">
              <span className={dailyWarning ? 'text-amber-400 font-medium' : ''}>{usage.daily_used}</span>/{usage.daily_limit}
              <span className="text-slate-600 ml-1.5">· resets in {formatResetTime(usage.reset_daily_at)}</span>
            </span>
          </div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ease-out ${dailyWarning ? 'bg-gradient-to-r from-amber-500 to-red-500' : 'bg-gradient-to-r from-brand-500 to-brand-400'}`}
              style={{ width: `${dailyPct}%` }}
            />
          </div>
        </div>
        <div>
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-medium text-slate-400">Monthly</span>
            <span className="text-xs text-slate-400">
              <span className={monthlyWarning ? 'text-amber-400 font-medium' : ''}>{usage.monthly_used}</span>/{usage.monthly_limit}
            </span>
          </div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ease-out ${monthlyWarning ? 'bg-gradient-to-r from-amber-500 to-red-500' : 'bg-gradient-to-r from-brand-500/70 to-brand-400/70'}`}
              style={{ width: `${monthlyPct}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
