import { Component } from 'react';
import type { ReactNode, ErrorInfo } from 'react';
import { ShieldIcon } from './Icons.tsx';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center">
          <div className="text-center animate-fade-in-up max-w-md px-6">
            <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-6">
              <ShieldIcon className="w-8 h-8 text-red-400" />
            </div>
            <h1 className="text-2xl font-bold text-slate-100 mb-2">Something went wrong</h1>
            <p className="text-slate-400 text-sm mb-8 leading-relaxed">
              An unexpected error occurred. Please try reloading the page.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 bg-brand-600 hover:bg-brand-500 text-white font-semibold py-3 px-8 rounded-xl text-sm transition-all hover:shadow-lg hover:shadow-brand-500/20"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
