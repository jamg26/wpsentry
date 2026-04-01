import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import type { ReactNode } from 'react';
import { AuthProvider, useAuth } from './lib/auth.tsx';
import Layout from './components/Layout.tsx';
import Landing from './pages/Landing.tsx';
import Login from './pages/Login.tsx';
import Signup from './pages/Signup.tsx';
import Dashboard from './pages/Dashboard.tsx';
import History from './pages/History.tsx';
import NewScan from './pages/NewScan.tsx';
import ScanDetail from './pages/ScanDetail.tsx';
import Settings from './pages/Settings.tsx';
import Terms from './pages/Terms.tsx';
import Privacy from './pages/Privacy.tsx';
import ReportAbuse from './pages/ReportAbuse.tsx';
import PublicScan from './pages/PublicScan.tsx';
import VerifyEmail from './pages/VerifyEmail.tsx';
import AdminLogin from './pages/admin/AdminLogin.tsx';
import AdminLayout from './pages/admin/AdminLayout.tsx';
import AdminDashboard from './pages/admin/AdminDashboard.tsx';
import AdminUsers from './pages/admin/AdminUsers.tsx';
import AdminScans from './pages/admin/AdminScans.tsx';
import AdminConfig from './pages/admin/AdminConfig.tsx';
import AdminDB from './pages/admin/AdminDB.tsx';
import AdminRateLimits from './pages/admin/AdminRateLimits.tsx';
import AdminFPReports from './pages/admin/AdminFPReports.tsx';
import ErrorBoundary from './components/ErrorBoundary.tsx';
import CookieConsent from './components/CookieConsent.tsx';
import { ShieldIcon } from './components/Icons.tsx';
import { ToastProvider } from './components/Toast.tsx';

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-slate-400">Loading…</p>
        </div>
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function HomeRoute() {
  const { loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-slate-400">Loading…</p>
        </div>
      </div>
    );
  }
  return <Landing />;
}

function NotFound() {
  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center">
      <div className="text-center animate-fade-in-up">
        <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-6">
          <ShieldIcon className="w-8 h-8 text-slate-700" />
        </div>
        <h1 className="text-6xl font-bold text-slate-800 mb-3">404</h1>
        <p className="text-slate-400 mb-6">Page not found</p>
        <a href="/" className="text-brand-400 hover:text-brand-300 text-sm transition-colors">← Back to home</a>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<HomeRoute />} />
            <Route path="/login" element={<Login />} />
            <Route path="/signup" element={<Signup />} />
            <Route path="/terms" element={<Terms />} />
            <Route path="/privacy" element={<Privacy />} />
            <Route path="/report-abuse" element={<ReportAbuse />} />
            <Route path="/public/scans/:token" element={<PublicScan />} />
            <Route path="/verify-email" element={<VerifyEmail />} />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Dashboard />} />
          </Route>
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route path="scans/new" element={<NewScan />} />
            <Route path="scans/:id" element={<ScanDetail />} />
            <Route path="history" element={<History />} />
            <Route path="settings" element={<Settings />} />
          </Route>
          {/* Admin routes — separate from user auth */}
          <Route path="/admin" element={<AdminLogin />} />
          <Route path="/admin" element={<AdminLayout />}>
            <Route path="dashboard" element={<AdminDashboard />} />
            <Route path="users" element={<AdminUsers />} />
            <Route path="scans" element={<AdminScans />} />
            <Route path="config" element={<AdminConfig />} />
            <Route path="rate-limits" element={<AdminRateLimits />} />
            <Route path="fp-reports" element={<AdminFPReports />} />
            <Route path="db" element={<AdminDB />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
        <CookieConsent />
      </BrowserRouter>
    </AuthProvider>
    </ToastProvider>
    </ErrorBoundary>
  );
}
