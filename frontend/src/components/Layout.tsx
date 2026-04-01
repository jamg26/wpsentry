import { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../lib/auth.tsx';
import { api } from '../lib/api.ts';
import {
  ShieldIcon,
  DashboardIcon,
  HistoryIcon,
  SettingsIcon,
  LogoutIcon,
  PlusIcon,
  MenuIcon,
  CloseIcon,
  BellIcon,
  KeyboardIcon,
  XIcon,
} from './Icons.tsx';const navItems = [
  { to: '/dashboard', label: 'Dashboard', Icon: DashboardIcon },
  { to: '/scans/new', label: 'New Scan', Icon: PlusIcon },
  { to: '/history', label: 'History', Icon: HistoryIcon },
  { to: '/settings', label: 'Settings', Icon: SettingsIcon },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [showShortcutsModal, setShowShortcutsModal] = useState(false);
  const [isVerified, setIsVerified] = useState<boolean | null>(null);
  const [userFullName, setUserFullName] = useState<string | null>(null);

  useEffect(() => {
    api.getMe().then(me => {
      setIsVerified(me.is_verified === true);
      setUserFullName(me.full_name ?? null);
    }).catch(() => setIsVerified(null));
  }, []);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

const initials = userFullName
    ? userFullName.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()
    : (user?.email ?? '?')[0].toUpperCase();

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName.toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === 'n') { e.preventDefault(); navigate('/scans/new'); }
      else if (e.key === 'h') { e.preventDefault(); navigate('/history'); }
      else if (e.key === '?') { e.preventDefault(); setShowShortcutsModal(true); }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [navigate]);

  const sidebarContent = (
    <>
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-4 py-5 border-b border-slate-800">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-brand-500/20 to-brand-500/5 border border-brand-500/20 flex items-center justify-center">
          <ShieldIcon className="w-[18px] h-[18px] text-brand-400" />
        </div>
        <div>
          <p className="text-sm font-bold text-slate-100 leading-none">WPSentry</p>
          <p className="text-[10px] text-slate-500 leading-none mt-1 uppercase tracking-wider">Security Platform</p>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        <p className="text-[10px] font-semibold text-slate-600 uppercase tracking-wider px-3 mb-2">Navigation</p>
        {navItems.map(({ to, label, Icon }) => (
          <NavLink
            key={to}
            to={to}
            onClick={() => setMobileOpen(false)}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-brand-500/10 text-brand-400 border border-brand-500/20 shadow-sm shadow-brand-500/5'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 border border-transparent'
              }`
            }
          >
            <Icon className="w-[18px] h-[18px] shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User footer */}
      <div className="px-3 py-4 border-t border-slate-800">
        {/* Notification bell */}
        <div className="flex items-center justify-end px-1 mb-2">
          <div className="relative group">
            <button
              aria-label="Notifications"
              className="p-1.5 rounded-lg text-slate-600 hover:text-slate-400 hover:bg-slate-800 transition-colors"
            >
              <BellIcon className="w-4 h-4" />
            </button>
            <div className="absolute bottom-full right-0 mb-1.5 px-2 py-1 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-400 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
              No notifications
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl bg-slate-800/40 mb-2">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500 to-emerald-600 flex items-center justify-center shrink-0 text-white text-xs font-bold shadow-sm">
            {initials}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium text-slate-300 truncate">{userFullName || user?.email?.split('@')[0]}</p>
            <p
              data-testid="user-email"
              className="text-[10px] text-slate-500 truncate"
            >
              {user?.email}
            </p>
          </div>
        </div>
        <button
          data-testid="logout-btn"
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-sm text-slate-500 hover:text-red-400 hover:bg-red-500/5 transition-all duration-200 border border-transparent"
        >
          <LogoutIcon className="w-4 h-4 shrink-0" />
          Sign out
        </button>
      </div>
    </>
  );

  return (
    <div className="flex h-screen bg-slate-950">
      {/* Sidebar — desktop */}
      <aside className="hidden md:flex flex-col w-60 bg-slate-900/70 backdrop-blur-sm border-r border-slate-800 shrink-0">
        {sidebarContent}
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          <div
            className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="relative w-64 bg-slate-900 border-r border-slate-800 flex flex-col animate-slide-in-right">
            <button
              onClick={() => setMobileOpen(false)}
              className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <CloseIcon className="w-5 h-5" />
            </button>
            {sidebarContent}
          </aside>
        </div>
      )}

      {/* Mobile top bar */}
      <div className="md:hidden fixed top-0 left-0 right-0 z-40 bg-slate-900/95 backdrop-blur-xl border-b border-slate-800 px-4 py-3 flex items-center justify-between">
        <button
          onClick={() => setMobileOpen(true)}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          aria-label="Open menu"
        >
          <MenuIcon className="w-5 h-5" />
        </button>
        <div className="flex items-center gap-2">
          <ShieldIcon className="w-5 h-5 text-brand-400" />
          <span className="text-sm font-bold text-slate-100">WPSentry</span>
        </div>
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-brand-500 to-emerald-600 flex items-center justify-center text-white text-xs font-bold shadow-sm">
          {initials}
        </div>
      </div>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        {isVerified === false && (
          <div className="bg-amber-500/10 border-b border-amber-500/20 px-4 py-2.5 flex items-center justify-between gap-3">
            <p className="text-xs text-amber-400 flex items-center gap-2">
              <span>✉️</span>
              Please verify your email to start scanning.
              <button
                onClick={() => api.resendVerification().then(() => alert('Verification email sent!')).catch(() => {})}
                className="underline hover:text-amber-300 transition-colors"
              >
                Resend email
              </button>
            </p>
            <Link to="/verify-email" className="text-xs text-amber-400 hover:text-amber-300 transition-colors shrink-0">
              Learn more →
            </Link>
          </div>
        )}
        <div className="max-w-6xl mx-auto px-6 py-8 md:pt-8 pt-20">
          <Outlet />
        </div>
      </main>

      {/* Keyboard shortcuts modal */}
      {showShortcutsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl max-w-sm w-full mx-4 p-6 animate-fade-in-up">
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center">
                  <KeyboardIcon className="w-4 h-4 text-slate-400" />
                </div>
                <h3 className="text-sm font-semibold text-slate-200">Keyboard Shortcuts</h3>
              </div>
              <button
                onClick={() => setShowShortcutsModal(false)}
                aria-label="Close"
                className="p-1 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
              >
                <XIcon className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2">
              {[
                { key: 'N', description: 'New Scan' },
                { key: 'H', description: 'History' },
                { key: '?', description: 'Show this help' },
              ].map((s) => (
                <div key={s.key} className="flex items-center justify-between py-2 border-b border-slate-800/50 last:border-0">
                  <span className="text-sm text-slate-400">{s.description}</span>
                  <kbd className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300">{s.key}</kbd>
                </div>
              ))}
            </div>
            <p className="text-xs text-slate-600 mt-4">Shortcuts work when focus is not in an input field.</p>
          </div>
        </div>
      )}
    </div>
  );
}
