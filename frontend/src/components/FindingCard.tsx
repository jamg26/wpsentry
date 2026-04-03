import { useState } from 'react';
import type { Finding } from '../lib/api.ts';
import { ChevronRightIcon, WarningIcon, InfoIcon, CriticalIcon, CopyIcon, CheckIcon, FlagIcon } from './Icons.tsx';
import { api } from '../lib/api.ts';
import { useToast } from './Toast.tsx';

interface FindingCardProps {
  finding: Finding;
  scanId?: string;
}

const severityConfig = {
  CRITICAL: {
    border: 'border-l-red-500',
    badge: 'bg-red-500/10 text-red-400 border-red-500/20',
    icon: <CriticalIcon className="w-3.5 h-3.5" />,
    label: 'Critical',
  },
  HIGH: {
    border: 'border-l-orange-500',
    badge: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    icon: <WarningIcon className="w-3.5 h-3.5" />,
    label: 'High',
  },
  MEDIUM: {
    border: 'border-l-yellow-500',
    badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    icon: <WarningIcon className="w-3.5 h-3.5" />,
    label: 'Medium',
  },
  LOW: {
    border: 'border-l-blue-500',
    badge: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    icon: <InfoIcon className="w-3.5 h-3.5" />,
    label: 'Low',
  },
  INFO: {
    border: 'border-l-slate-500',
    badge: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
    icon: <InfoIcon className="w-3.5 h-3.5" />,
    label: 'Info',
  },
};

const URL_RE = /(https?:\/\/[^\s<>"')\]]+)/g;
const CODE_HINT_RE = /curl\s|https?:\/\/|`[^`]+`|wget\s|--[a-z]/i;

function Linkified({ text }: { text: string }) {
  const parts = text.split(URL_RE);
  return (
    <>
      {parts.map((part, i) =>
        URL_RE.test(part) ? (
          <a
            key={i}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className="text-brand-400 hover:text-brand-300 hover:underline break-all"
            onClick={(e) => e.stopPropagation()}
          >
            {part}
          </a>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </>
  );
}

function StepContent({ text }: { text: string }) {
  if (CODE_HINT_RE.test(text)) {
    return (
      <span className="leading-relaxed">
        <code className="bg-slate-800/80 border border-slate-700 rounded px-1.5 py-0.5 font-mono text-xs text-slate-300">
          <Linkified text={text} />
        </code>
      </span>
    );
  }
  return (
    <span className="leading-relaxed">
      <Linkified text={text} />
    </span>
  );
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handleCopy}
      className={`${label ? 'flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs font-medium' : 'p-1.5 rounded-lg'} text-slate-500 hover:text-slate-300 hover:bg-slate-700/50 transition-all`}
      title="Copy to clipboard"
    >
      {copied ? <CheckIcon className="w-3.5 h-3.5 text-brand-400" /> : <CopyIcon className="w-3.5 h-3.5" />}
      {label && <span>{copied ? 'Copied' : label}</span>}
    </button>
  );
}

export default function FindingCard({ finding, scanId }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [showFpModal, setShowFpModal] = useState(false);
  const [fpReason, setFpReason] = useState('');
  const [fpSubmitting, setFpSubmitting] = useState(false);
  const [fpDone, setFpDone] = useState(false);
  const { toast } = useToast();
  const config = severityConfig[finding.severity];

  const handleReportFP = async () => {
    if (!scanId) return;
    setFpSubmitting(true);
    try {
      await api.reportFalsePositive(scanId, {
        finding_type: finding.type,
        finding_url: finding.url,
        finding_severity: finding.severity,
        reason: fpReason.trim() || undefined,
      });
      setFpDone(true);
      setShowFpModal(false);
      toast({ message: 'False positive reported — thank you!', type: 'success' });
    } catch {
      toast({ message: 'Failed to submit report', type: 'error' });
    } finally {
      setFpSubmitting(false);
    }
  };

  return (
    <div className={`bg-slate-900/60 border border-slate-800 border-l-4 ${config.border} rounded-r-xl rounded-l-none overflow-hidden shadow-sm shadow-black/5 hover:shadow-md hover:shadow-black/10 transition-all`}>
      {/* Header row — div instead of button to allow real link inside */}
      <div
        className="w-full px-5 py-4 flex items-start gap-3 text-left hover:bg-slate-800/30 transition-all cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(!expanded); } }}
        aria-expanded={expanded}
      >
        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${config.badge} shrink-0 mt-0.5`}>
          {config.icon}
          {config.label}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-200">{finding.type}</p>
          <a
            href={finding.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-brand-400 hover:text-brand-300 underline-offset-2 hover:underline mt-0.5 block break-all"
            onClick={(e) => e.stopPropagation()}
          >
            {finding.url}
          </a>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {/* FP report button — only when viewing own scan */}
          {scanId && (!fpDone ? (
            <button
              onClick={(e) => { e.stopPropagation(); setShowFpModal(true); }}
              title="Report false positive"
              aria-label="Report false positive"
              className="p-1.5 rounded-lg text-slate-600 hover:text-amber-400 hover:bg-amber-500/10 transition-all"
            >
              <FlagIcon className="w-3.5 h-3.5" />
            </button>
          ) : (
            <span className="p-1.5 text-amber-400" title="Reported">
              <FlagIcon className="w-3.5 h-3.5" />
            </span>
          ))}
          <ChevronRightIcon className={`w-4 h-4 text-slate-500 transition-transform duration-200 mt-0.5 ${expanded ? 'rotate-90' : ''}`} />
        </div>
      </div>

      {/* False positive modal */}
      {showFpModal && (
        <div className="px-5 pb-4 pt-3 border-t border-amber-500/20 bg-amber-500/5 animate-fade-in">
          <p className="text-xs font-semibold text-amber-400 mb-2">Report as False Positive</p>
          <p className="text-xs text-slate-500 mb-3">Tell us why this finding is incorrect (optional):</p>
          <textarea
            value={fpReason}
            onChange={(e) => setFpReason(e.target.value)}
            placeholder="e.g. This site uses Cloudflare Pages SPA, the path returns 200 for all routes..."
            rows={2}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500 resize-none mb-3"
          />
          <div className="flex items-center gap-2">
            <button
              onClick={handleReportFP}
              disabled={fpSubmitting}
              className="flex items-center gap-1.5 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 text-amber-400 text-xs font-medium px-3 py-1.5 rounded-lg transition-all disabled:opacity-50"
            >
              {fpSubmitting ? 'Submitting…' : 'Submit Report'}
            </button>
            <button
              onClick={(e) => { e.stopPropagation(); setShowFpModal(false); }}
              className="text-xs text-slate-500 hover:text-slate-300 px-3 py-1.5 rounded-lg hover:bg-slate-800 transition-all"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {expanded && (
        <div className="px-5 pb-5 space-y-4 border-t border-slate-800/50 animate-fade-in">
          <div className="pt-4">
            <p className="text-sm text-slate-300 leading-relaxed"><Linkified text={finding.description} /></p>
          </div>

          {finding.replication_steps && finding.replication_steps.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Replication Steps</h4>
                <CopyButton text={finding.replication_steps.map((s, i) => `${i + 1}. ${s}`).join('\n')} label="Copy steps" />
              </div>
              <p className="text-xs text-slate-500 mb-3">Follow these steps to verify this finding:</p>
              <ol className="space-y-2">
                {finding.replication_steps.map((step, i) => (
                  <li key={i} className="flex gap-3 text-sm text-slate-300">
                    <span className="w-5 h-5 rounded-md bg-slate-800 border border-slate-700 flex items-center justify-center text-xs text-slate-500 font-medium shrink-0">{i + 1}</span>
                    <StepContent text={step} />
                  </li>
                ))}
              </ol>
            </div>
          )}

          {finding.evidence && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Evidence</h4>
                <CopyButton text={finding.evidence} />
              </div>
              <pre className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 text-xs text-slate-300 overflow-x-auto font-mono whitespace-pre-wrap break-words leading-relaxed"><Linkified text={finding.evidence} /></pre>
            </div>
          )}

          {finding.remediation && (
            <div className="bg-brand-500/5 border border-brand-500/20 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <h4 className="text-xs font-semibold text-brand-400 uppercase tracking-wider">Remediation</h4>
                {finding.remediation_ai && (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium bg-violet-500/15 text-violet-400 border border-violet-500/20">
                    ✦ AI
                  </span>
                )}
              </div>
              <p className="text-sm text-slate-300 leading-relaxed"><Linkified text={finding.remediation} /></p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
