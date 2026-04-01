import { useSearchParams, Link } from 'react-router-dom';
import { ShieldIcon } from '../components/Icons.tsx';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const success = params.get('success') === '1';
  const error = params.get('error');
  const token = params.get('token');

  // If a token is present, redirect to the worker to process it
  if (token) {
    const apiBase = import.meta.env.VITE_API_URL ?? 'https://api.wpsentry.link';
    window.location.href = `${apiBase}/auth/verify?token=${token}`;
    return null;
  }

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
      <div className="max-w-md w-full">
        {/* Logo */}
        <div className="flex items-center justify-center gap-2.5 mb-8">
          <div className="w-9 h-9 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
            <ShieldIcon className="w-5 h-5 text-brand-400" />
          </div>
          <span className="text-lg font-bold text-slate-100">WPSentry</span>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center">
          {success ? (
            <>
              <div className="text-5xl mb-4">✅</div>
              <h1 className="text-xl font-bold text-slate-100 mb-2">Email verified!</h1>
              <p className="text-slate-400 text-sm mb-6">Your account is now active. You can start scanning WordPress sites.</p>
              <Link to="/scans/new" className="inline-flex items-center gap-2 bg-brand-500 hover:bg-brand-600 text-white font-semibold px-6 py-3 rounded-lg transition-colors text-sm">
                Start Your First Scan →
              </Link>
            </>
          ) : error ? (
            <>
              <div className="text-5xl mb-4">❌</div>
              <h1 className="text-xl font-bold text-slate-100 mb-2">Verification failed</h1>
              <p className="text-slate-400 text-sm mb-6">This link may have expired or already been used. Request a new verification email from your settings.</p>
              <Link to="/settings" className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold px-6 py-3 rounded-lg transition-colors text-sm">
                Go to Settings
              </Link>
            </>
          ) : (
            <>
              <div className="text-5xl mb-4">✉️</div>
              <h1 className="text-xl font-bold text-slate-100 mb-2">Check your email</h1>
              <p className="text-slate-400 text-sm mb-2">We sent a verification link to your email address.</p>
              <p className="text-slate-500 text-xs mb-6">Click the link in the email to activate your account and start scanning.</p>
              <Link to="/login" className="text-brand-400 hover:text-brand-300 text-sm transition-colors">
                Back to login
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
