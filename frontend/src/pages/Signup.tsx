import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth.tsx';
import { ShieldIcon, CheckIcon, WarningIcon } from '../components/Icons.tsx';

export default function Signup() {
  const { signup } = useAuth();
  const navigate = useNavigate();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setLoading(true);
    try {
      await signup(email, password, fullName.trim() || undefined);
      navigate('/dashboard');
    } catch (err: unknown) {
      const e = err as { message?: string };
      setError(e.message ?? 'Signup failed');
    } finally {
      setLoading(false);
    }
  };

  const features = [
    '100 security modules',
    'Free tier: 5 scans/day',
    'OWASP Top 10 coverage',
    'Full report export',
  ];

  return (
    <div className="min-h-screen flex">
      {/* Left panel */}
      <div className="hidden lg:flex w-1/2 bg-gradient-to-br from-slate-900 via-brand-950 to-slate-900 flex-col items-center justify-center p-12 relative overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-brand-500/10 via-transparent to-transparent" />
        <div className="absolute inset-0 bg-grid opacity-50" />
        <div className="relative z-10 max-w-md">
          <div className="w-16 h-16 rounded-2xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center mb-8 animate-shield-pulse">
            <ShieldIcon className="w-8 h-8 text-brand-400" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-3">WPSentry</h1>
          <p className="text-lg text-slate-400 mb-10">WordPress Security Intelligence Platform</p>
          <ul className="space-y-4">
            {features.map((f) => (
              <li key={f} className="flex items-center gap-3 text-slate-300">
                <span className="w-6 h-6 rounded-full bg-brand-500/10 border border-brand-500/20 flex items-center justify-center shrink-0">
                  <CheckIcon className="w-3.5 h-3.5 text-brand-400" />
                </span>
                <span className="text-sm">{f}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full lg:w-1/2 items-center justify-center bg-slate-950 px-8 py-12">
        <div className="w-full max-w-sm animate-fade-in-up">
          <div className="mb-8 lg:hidden flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
              <ShieldIcon className="w-5 h-5 text-brand-400" />
            </div>
            <span className="text-lg font-bold text-slate-100">WPSentry</span>
          </div>

          <Link
            to="/"
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors mb-6 inline-flex items-center gap-1"
          >
            ← Back to home
          </Link>

          <h2 className="text-2xl font-bold text-slate-100 mb-1">Create account</h2>
          <p className="text-slate-400 mb-8">Start scanning for free</p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Full Name <span className="text-slate-500 font-normal">(optional)</span></label>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
                placeholder="Jane Smith"
                autoComplete="name"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Email</label>
              <input
                data-testid="email-input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
                placeholder="you@example.com"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Password</label>
              <input
                data-testid="password-input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
                placeholder="••••••••"
              />
              <p className="mt-1.5 text-xs text-slate-500">Minimum 8 characters</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Confirm Password</label>
              <input
                data-testid="confirm-password-input"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
                placeholder="••••••••"
              />
            </div>

            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={agreedToTerms}
                onChange={(e) => setAgreedToTerms(e.target.checked)}
                className="accent-brand-500 mt-0.5 shrink-0"
              />
              <span className="text-xs text-slate-400 leading-relaxed">
                I agree to the{' '}
                <Link to="/terms" className="text-brand-400 hover:text-brand-300 transition-colors" target="_blank">
                  Terms of Service
                </Link>{' '}
                and{' '}
                <Link to="/privacy" className="text-brand-400 hover:text-brand-300 transition-colors" target="_blank">
                  Privacy Policy
                </Link>
              </span>
            </label>

            {error && (
              <div data-testid="error-message" className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 text-sm text-red-400 flex items-center gap-2.5 animate-fade-in">
                <WarningIcon className="w-4 h-4 shrink-0" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !agreedToTerms}
              className="w-full bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-3 px-4 rounded-xl text-sm transition-all hover:shadow-lg hover:shadow-brand-500/20 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </>
              ) : (
                'Create account'
              )}
            </button>
          </form>

          <p className="mt-8 text-sm text-slate-400 text-center">
            Already have an account?{' '}
            <Link to="/login" className="text-brand-400 hover:text-brand-300 font-medium transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
