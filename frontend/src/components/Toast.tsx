import { createContext, useContext, useState, useCallback, useRef } from 'react';
import type { ReactNode } from 'react';
import { XIcon, CheckIcon, InfoIcon, WarningIcon, AlertTriangleIcon } from './Icons.tsx';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

interface ToastItem {
  id: number;
  message: string;
  type: ToastType;
}

interface ToastOptions {
  message: string;
  type: ToastType;
  duration?: number;
}

interface ToastContextValue {
  toast: (opts: ToastOptions) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const toastStyles: Record<ToastType, { bg: string; border: string; icon: string; iconComp: ReactNode }> = {
  success: {
    bg: 'bg-slate-900',
    border: 'border-green-500/30',
    icon: 'text-green-400',
    iconComp: <CheckIcon className="w-4 h-4" />,
  },
  error: {
    bg: 'bg-slate-900',
    border: 'border-red-500/30',
    icon: 'text-red-400',
    iconComp: <AlertTriangleIcon className="w-4 h-4" />,
  },
  info: {
    bg: 'bg-slate-900',
    border: 'border-blue-500/30',
    icon: 'text-blue-400',
    iconComp: <InfoIcon className="w-4 h-4" />,
  },
  warning: {
    bg: 'bg-slate-900',
    border: 'border-amber-500/30',
    icon: 'text-amber-400',
    iconComp: <WarningIcon className="w-4 h-4" />,
  },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const counterRef = useRef(0);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(({ message, type, duration = 3000 }: ToastOptions) => {
    const id = ++counterRef.current;
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => dismiss(id), duration);
  }, [dismiss]);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      {/* Toast container */}
      <div
        aria-live="polite"
        aria-atomic="false"
        className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none"
      >
        {toasts.map((t) => {
          const styles = toastStyles[t.type];
          return (
            <div
              key={t.id}
              className={`pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl border shadow-lg shadow-black/30 ${styles.bg} ${styles.border} animate-slide-in-right min-w-[260px] max-w-sm`}
              role="alert"
            >
              <span className={`shrink-0 ${styles.icon}`}>{styles.iconComp}</span>
              <p className="text-sm text-slate-200 flex-1">{t.message}</p>
              <button
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
                className="shrink-0 p-0.5 rounded text-slate-500 hover:text-slate-300 transition-colors"
              >
                <XIcon className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx;
}
