import { useEffect, useState } from 'react';
import { useAuth } from '../lib/auth.tsx';
import { api } from '../lib/api.ts';
import type { UsageStats, ApiKey, Webhook, NotificationPrefs } from '../lib/api.ts';
import UsageBar from '../components/UsageBar.tsx';
import { UserIcon, WarningIcon, KeyIcon, AlertTriangleIcon, LockIcon, CheckIcon, BellIcon, WebhookIcon, TrashIcon, TerminalIcon, GithubIcon } from '../components/Icons.tsx';

const WORKER_URL = 'https://api.wpsentry.link';

// Feature flags — set to false to hide incomplete features from production UI
const FEATURES = {
  apiKeys: true,          // fixed and working
  notifications: true,    // email delivery via Resend
  webhooks: true,         // fully working
  scheduling: true,       // fully working
  publicSharing: true,    // fully working
  tags: true,             // fully working
  scanComparison: false,  // backend-only, no frontend UI yet
};

export default function Settings() {
  const { user, logout } = useAuth();
  const [usage, setUsage] = useState<UsageStats | null>(null);
  const [loadingUsage, setLoadingUsage] = useState(true);

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordMsg, setPasswordMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Delete account state
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  // API Keys state
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [loadingKeys, setLoadingKeys] = useState(true);
  const [newKeyName, setNewKeyName] = useState('');
  const [creatingKey, setCreatingKey] = useState(false);
  const [newKeyValue, setNewKeyValue] = useState('');
  const [keyCopied, setKeyCopied] = useState(false);
  const [deletingKeyId, setDeletingKeyId] = useState<string | null>(null);

  // Webhooks state
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loadingWebhooks, setLoadingWebhooks] = useState(true);
  const [newWebhookUrl, setNewWebhookUrl] = useState('');
  const [newWebhookEvents, setNewWebhookEvents] = useState<string[]>(['scan.completed', 'critical.found']);
  const [creatingWebhook, setCreatingWebhook] = useState(false);
  const [webhookMsg, setWebhookMsg] = useState('');
  const [deletingWebhookId, setDeletingWebhookId] = useState<string | null>(null);

  // Notification prefs state
  const [notifPrefs, setNotifPrefs] = useState<NotificationPrefs>({ scan_complete: true, critical_found: true, weekly_report: false });
  const [loadingNotif, setLoadingNotif] = useState(true);
  const [savingNotif, setSavingNotif] = useState(false);
  const [notifSaved, setNotifSaved] = useState(false);

  // Profile (full name) state
  const [fullName, setFullName] = useState('');
  const [editingName, setEditingName] = useState(false);
  const [savingName, setSavingName] = useState(false);
  const [nameSaved, setNameSaved] = useState(false);

  useEffect(() => {
    api.getUsage().then(setUsage).catch(console.error).finally(() => setLoadingUsage(false));
    api.getMe().then((me) => setFullName(me.full_name ?? '')).catch(console.error);
    api.listApiKeys().then((r) => setApiKeys(r.api_keys)).catch(console.error).finally(() => setLoadingKeys(false));
    api.listWebhooks().then((r) => setWebhooks(r.webhooks)).catch(console.error).finally(() => setLoadingWebhooks(false));
    api.getNotifications().then((r) => setNotifPrefs(r.notification_prefs)).catch(console.error).finally(() => setLoadingNotif(false));
  }, []);

  const formatDate = (iso: string | null | undefined) => {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  };

  const handleChangePassword = async () => {
    setPasswordMsg(null);
    if (newPassword !== confirmNewPassword) {
      setPasswordMsg({ type: 'error', text: 'New passwords do not match' });
      return;
    }
    if (newPassword.length < 8) {
      setPasswordMsg({ type: 'error', text: 'New password must be at least 8 characters' });
      return;
    }
    setPasswordLoading(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setPasswordMsg({ type: 'success', text: 'Password updated successfully' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNewPassword('');
    } catch (err: unknown) {
      const e = err as { message?: string };
      setPasswordMsg({ type: 'error', text: e.message ?? 'Failed to change password' });
    } finally {
      setPasswordLoading(false);
    }
  };

  const handleDeleteAccount = async () => {
    setDeleteError('');
    if (!deletePassword) {
      setDeleteError('Password is required');
      return;
    }
    setDeleteLoading(true);
    try {
      await api.deleteAccount(deletePassword);
      await logout();
      window.location.href = '/';
    } catch (err: unknown) {
      const e = err as { message?: string };
      setDeleteError(e.message ?? 'Failed to delete account');
    } finally {
      setDeleteLoading(false);
    }
  };

  const handleCreateApiKey = async () => {
    if (!newKeyName.trim()) return;
    setCreatingKey(true);
    try {
      const result = await api.createApiKey(newKeyName.trim());
      setNewKeyValue(result.key);
      setApiKeys((prev) => [...prev, { id: result.id, name: result.name, key_prefix: result.key_prefix, last_used_at: null, created_at: result.created_at, enabled: true }]);
      setNewKeyName('');
    } catch (err: unknown) {
      const e = err as { message?: string };
      alert(e.message ?? 'Failed to create API key');
    } finally {
      setCreatingKey(false);
    }
  };

  const handleDeleteApiKey = async (id: string) => {
    setDeletingKeyId(id);
    try {
      await api.deleteApiKey(id);
      setApiKeys((prev) => prev.filter((k) => k.id !== id));
    } catch (err: unknown) {
      const e = err as { message?: string };
      alert(e.message ?? 'Failed to delete key');
    } finally {
      setDeletingKeyId(null);
    }
  };

  const handleCreateWebhook = async () => {
    if (!newWebhookUrl.trim()) return;
    setCreatingWebhook(true);
    setWebhookMsg('');
    try {
      const hook = await api.createWebhook(newWebhookUrl.trim(), newWebhookEvents);
      setWebhooks((prev) => [...prev, hook]);
      setNewWebhookUrl('');
      setWebhookMsg(`Webhook created. Secret: ${(hook as Webhook & { secret: string }).secret}`);
    } catch (err: unknown) {
      const e = err as { message?: string };
      setWebhookMsg(e.message ?? 'Failed to create webhook');
    } finally {
      setCreatingWebhook(false);
    }
  };

  const handleDeleteWebhook = async (id: string) => {
    setDeletingWebhookId(id);
    try {
      await api.deleteWebhook(id);
      setWebhooks((prev) => prev.filter((w) => w.id !== id));
    } catch (err: unknown) {
      const e = err as { message?: string };
      alert(e.message ?? 'Failed to delete webhook');
    } finally {
      setDeletingWebhookId(null);
    }
  };

  const handleSaveName = async () => {
    setSavingName(true);
    try {
      await api.updateProfile(fullName);
      setNameSaved(true);
      setEditingName(false);
      setTimeout(() => setNameSaved(false), 2000);
    } catch {
      // keep editing open on error
    } finally {
      setSavingName(false);
    }
  };

  const handleSaveNotifications = async () => {
    setSavingNotif(true);
    try {
      await api.updateNotifications(notifPrefs);
      setNotifSaved(true);
      setTimeout(() => setNotifSaved(false), 2000);
    } catch (err: unknown) {
      const e = err as { message?: string };
      alert(e.message ?? 'Failed to save preferences');
    } finally {
      setSavingNotif(false);
    }
  };

  const tabs = [
    { id: 'profile' as const, label: 'Profile' },
    { id: 'notifications' as const, label: 'Notifications' },
    { id: 'integrations' as const, label: 'Integrations' },
    { id: 'danger' as const, label: 'Danger' },
  ];
  const [activeTab, setActiveTab] = useState<'profile' | 'notifications' | 'integrations' | 'danger'>('profile');

  return (
    <div className="max-w-2xl space-y-8">
      <div className="animate-fade-in-up">
        <h1 className="text-2xl font-bold text-slate-100">Settings</h1>
        <p className="text-slate-400 mt-1 text-sm">Manage your account and preferences</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-slate-800 -mb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === tab.id
                ? tab.id === 'danger'
                  ? 'text-red-400 border-red-500'
                  : 'text-slate-100 border-brand-500'
                : tab.id === 'danger'
                  ? 'text-slate-400 border-transparent hover:text-red-400'
                  : 'text-slate-400 border-transparent hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Profile tab ── */}
      {activeTab === 'profile' && <>

      {/* Account info */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center">
            <UserIcon className="w-[18px] h-[18px] text-slate-400" />
          </div>
          <h2 className="text-sm font-semibold text-slate-200">Account Information</h2>
        </div>
        <div className="px-6 py-5 space-y-0">
          <div className="flex items-center justify-between py-3.5 border-b border-slate-800/50">
            <span className="text-sm text-slate-500">Full Name</span>
            {editingName ? (
              <div className="flex items-center gap-2">
                <input
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleSaveName(); if (e.key === 'Escape') setEditingName(false); }}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:border-brand-500 w-44"
                  placeholder="Your name"
                  autoFocus
                />
                <button onClick={handleSaveName} disabled={savingName} className="text-xs bg-brand-600 hover:bg-brand-500 text-white px-3 py-1.5 rounded-lg transition-colors disabled:opacity-50">
                  {savingName ? '…' : 'Save'}
                </button>
                <button onClick={() => setEditingName(false)} className="text-xs text-slate-500 hover:text-slate-300 transition-colors">Cancel</button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <span className="text-sm text-slate-200 font-medium">{fullName || <span className="text-slate-500 italic">Not set</span>}</span>
                {nameSaved && <span className="text-xs text-green-400">✓ Saved</span>}
                <button onClick={() => setEditingName(true)} className="text-xs text-brand-400 hover:text-brand-300 transition-colors">Edit</button>
              </div>
            )}
          </div>
          <div className="flex items-center justify-between py-3.5 border-b border-slate-800/50">
            <span className="text-sm text-slate-500">Email</span>
            <span className="text-sm text-slate-200 font-medium">{user?.email}</span>
          </div>
          <div className="flex items-center justify-between py-3.5 border-b border-slate-800/50">
            <span className="text-sm text-slate-500">Member since</span>
            <span className="text-sm text-slate-200">{formatDate(user?.created_at)}</span>
          </div>
          <div className="flex items-center justify-between py-3.5">
            <span className="text-sm text-slate-500">Last login</span>
            <span className="text-sm text-slate-200">{formatDate(user?.last_login)}</span>
          </div>
        </div>
      </div>

      {/* Change Password */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '175ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center">
            <LockIcon className="w-[18px] h-[18px] text-slate-400" />
          </div>
          <h2 className="text-sm font-semibold text-slate-200">Change Password</h2>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
              placeholder="••••••••"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
              placeholder="••••••••"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Confirm New Password</label>
            <input
              type="password"
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
              placeholder="••••••••"
            />
          </div>
          {passwordMsg && (
            <div className={`flex items-center gap-2 text-sm rounded-xl px-4 py-2.5 animate-fade-in ${
              passwordMsg.type === 'success'
                ? 'bg-brand-500/10 border border-brand-500/20 text-brand-400'
                : 'bg-red-500/10 border border-red-500/20 text-red-400'
            }`}>
              {passwordMsg.type === 'success' ? <CheckIcon className="w-4 h-4 shrink-0" /> : <WarningIcon className="w-4 h-4 shrink-0" />}
              {passwordMsg.text}
            </div>
          )}
          <button
            onClick={handleChangePassword}
            disabled={passwordLoading || !currentPassword || !newPassword || !confirmNewPassword}
            className="bg-brand-600 hover:bg-brand-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-2.5 px-5 rounded-xl text-sm transition-all flex items-center gap-2"
          >
            {passwordLoading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Updating…
              </>
            ) : (
              'Update Password'
            )}
          </button>
        </div>
      </div>

      {/* Usage */}
      <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: '200ms' }}>
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-slate-200">Usage &amp; Limits</h2>
          <span className="text-xs px-2.5 py-0.5 rounded-full bg-brand-500/10 border border-brand-500/20 text-brand-400 font-medium">Free Tier</span>
        </div>
        {loadingUsage ? (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6">
            <div className="space-y-4">
              <div className="h-4 w-24 skeleton" />
              <div className="h-2 w-full skeleton" />
            </div>
          </div>
        ) : usage ? (
          <UsageBar usage={usage} />
        ) : (
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 text-sm text-slate-500">Could not load usage data</div>
        )}
      </div>

      {/* Free tier notice */}
      <div className="flex items-start gap-3 bg-amber-500/5 border border-amber-500/20 rounded-xl p-5 animate-fade-in-up" style={{ animationDelay: '250ms' }}>
        <WarningIcon className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-amber-400">Free Tier Limits</p>
          <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
            You are on the free tier with {usage ? usage.daily_limit : '…'} scans per day and {usage ? usage.monthly_limit : '…'} scans per month.
            All 100 security modules are available on the free tier.
          </p>
        </div>
      </div>

      </>}


      {/* ── Notifications tab ── */}
      {activeTab === 'notifications' && <>

      {/* Notifications */}
      {FEATURES.notifications && <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center">
            <BellIcon className="w-[18px] h-[18px] text-slate-400" />
          </div>
          <h2 className="text-sm font-semibold text-slate-200">Notification Preferences</h2>
          <span className="ml-auto text-xs text-green-400 flex items-center gap-1"><span>✓</span> Active</span>
        </div>
        <div className="px-6 py-5 space-y-4">
          {loadingNotif ? (
            <div className="space-y-3"><div className="h-8 skeleton rounded-xl" /><div className="h-8 skeleton rounded-xl" /></div>
          ) : (
            <div className="space-y-3">
              {([
                { key: 'scan_complete' as const, label: 'Scan completed', desc: 'When a scan finishes' },
                { key: 'critical_found' as const, label: 'Critical finding detected', desc: 'When a critical vulnerability is found' },
                { key: 'weekly_report' as const, label: 'Weekly summary', desc: 'Weekly digest of scan activity' },
              ] as const).map((item) => (
                <label key={item.key} className="flex items-center justify-between cursor-pointer group">
                  <div>
                    <p className="text-sm font-medium text-slate-200">{item.label}</p>
                    <p className="text-xs text-slate-500">{item.desc}</p>
                  </div>
                  <div
                    onClick={() => setNotifPrefs((p) => ({ ...p, [item.key]: !p[item.key] }))}
                    className={`relative w-10 h-5.5 rounded-full transition-colors cursor-pointer shrink-0 ${notifPrefs[item.key] ? 'bg-brand-600' : 'bg-slate-700'}`}
                    style={{ minWidth: '2.5rem', height: '1.375rem' }}
                  >
                    <span
                      className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${notifPrefs[item.key] ? 'translate-x-5' : 'translate-x-0.5'}`}
                    />
                  </div>
                </label>
              ))}
            </div>
          )}
          <button
            onClick={handleSaveNotifications}
            disabled={savingNotif || loadingNotif}
            className="flex items-center gap-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white font-medium py-2 px-4 rounded-xl text-sm transition-all"
          >
            {savingNotif ? (
              <><div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Saving…</>
            ) : notifSaved ? (
              <><CheckIcon className="w-4 h-4" />Saved</>
            ) : 'Save Preferences'}
          </button>
        </div>
      </div>}

      {/* Webhooks */}
      {FEATURES.webhooks && <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '130ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center">
            <WebhookIcon className="w-[18px] h-[18px] text-slate-400" />
          </div>
          <h2 className="text-sm font-semibold text-slate-200">Webhooks</h2>
        </div>
        <div className="px-6 py-5 space-y-4">
          <p className="text-sm text-slate-400">
            Receive HTTP POST requests when scan events occur. Requests are signed with <code className="bg-slate-800 px-1 py-0.5 rounded text-xs text-brand-400">X-JWP-Signature: sha256=...</code>
          </p>

          {webhookMsg && (
            <div className="bg-brand-500/5 border border-brand-500/20 rounded-xl px-4 py-3 text-xs text-slate-300 font-mono break-all animate-fade-in">
              {webhookMsg}
            </div>
          )}

          {loadingWebhooks ? (
            <div className="h-10 skeleton rounded-xl" />
          ) : webhooks.length > 0 ? (
            <div className="space-y-2">
              {webhooks.map((hook) => (
                <div key={hook.id} className="flex items-center justify-between bg-slate-800/60 border border-slate-700 rounded-xl px-4 py-3 gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-200 truncate">{hook.url}</p>
                    <p className="text-xs text-slate-500 mt-0.5">{hook.events.join(', ')}</p>
                  </div>
                  <button
                    onClick={() => handleDeleteWebhook(hook.id)}
                    disabled={deletingWebhookId === hook.id}
                    className="p-2 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/5 transition-all disabled:opacity-50 shrink-0"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-600">No webhooks configured</p>
          )}

          <div className="space-y-3 pt-2 border-t border-slate-800">
            <div className="flex items-center gap-2">
              <input
                type="url"
                value={newWebhookUrl}
                onChange={(e) => setNewWebhookUrl(e.target.value)}
                placeholder="https://your-server.com/webhook"
                className="flex-1 bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
              />
            </div>
            <div className="flex items-center gap-3">
              {['scan.completed', 'critical.found'].map((ev) => (
                <label key={ev} className="flex items-center gap-2 cursor-pointer text-xs text-slate-400">
                  <input
                    type="checkbox"
                    checked={newWebhookEvents.includes(ev)}
                    onChange={() => setNewWebhookEvents((prev) => prev.includes(ev) ? prev.filter((e) => e !== ev) : [...prev, ev])}
                    className="accent-brand-500"
                  />
                  {ev}
                </label>
              ))}
              <button
                onClick={handleCreateWebhook}
                disabled={creatingWebhook || !newWebhookUrl.trim() || newWebhookEvents.length === 0}
                className="ml-auto px-4 py-2 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white text-sm font-medium rounded-xl transition-all"
              >
                {creatingWebhook ? 'Adding…' : 'Add Webhook'}
              </button>
            </div>
          </div>
        </div>
      </div>}

      </>}

      {/* ── Integrations tab ── */}
      {activeTab === 'integrations' && <>

      {/* API Keys */}
      {FEATURES.apiKeys && <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '100ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center">
            <KeyIcon className="w-[18px] h-[18px] text-slate-400" />
          </div>
          <h2 className="text-sm font-semibold text-slate-200">API Keys</h2>
        </div>
        <div className="px-6 py-5 space-y-4">
          <p className="text-sm text-slate-400">
            Use API keys to authenticate programmatic requests. Keys grant the same access as your account.
            Use <code className="bg-slate-800 px-1 py-0.5 rounded text-brand-400 text-xs">Authorization: Bearer jwp_live_...</code>
          </p>

          {/* Show new key once */}
          {newKeyValue && (
            <div className="bg-brand-500/5 border border-brand-500/20 rounded-xl p-4 animate-fade-in">
              <p className="text-xs font-semibold text-brand-400 mb-2">⚠ Copy your key now — it won't be shown again</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 overflow-auto">{newKeyValue}</code>
                <button
                  onClick={async () => { await navigator.clipboard.writeText(newKeyValue); setKeyCopied(true); setTimeout(() => setKeyCopied(false), 2000); }}
                  className="px-3 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-xs font-medium transition-all shrink-0"
                >
                  {keyCopied ? 'Copied!' : 'Copy'}
                </button>
                <button
                  onClick={() => setNewKeyValue('')}
                  className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 text-xs font-medium transition-all shrink-0"
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}

          {/* Existing keys */}
          {loadingKeys ? (
            <div className="h-10 skeleton rounded-xl" />
          ) : apiKeys.length > 0 ? (
            <div className="space-y-2">
              {apiKeys.map((key) => (
                <div key={key.id} className="flex items-center justify-between bg-slate-800/60 border border-slate-700 rounded-xl px-4 py-3">
                  <div>
                    <p className="text-sm font-medium text-slate-200">{key.name}</p>
                    <p className="text-xs text-slate-500 font-mono mt-0.5">{key.key_prefix}…</p>
                    {key.last_used_at && (
                      <p className="text-xs text-slate-600 mt-0.5">Last used {formatDate(key.last_used_at)}</p>
                    )}
                  </div>
                  <button
                    onClick={() => handleDeleteApiKey(key.id)}
                    disabled={deletingKeyId === key.id}
                    className="p-2 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/5 transition-all disabled:opacity-50"
                  >
                    <TrashIcon className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-600">No API keys yet</p>
          )}

          {/* Create new key */}
          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="Key name (e.g. CI/CD pipeline)"
              className="flex-1 bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 transition-all"
              onKeyDown={(e) => e.key === 'Enter' && handleCreateApiKey()}
            />
            <button
              onClick={handleCreateApiKey}
              disabled={creatingKey || !newKeyName.trim()}
              className="px-4 py-2.5 bg-brand-600 hover:bg-brand-500 disabled:opacity-50 text-white text-sm font-medium rounded-xl transition-all shrink-0"
            >
              {creatingKey ? 'Creating…' : 'Create Key'}
            </button>
          </div>
        </div>
      </div>}

      {/* CI/CD Integration */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg shadow-black/10 animate-fade-in-up" style={{ animationDelay: '130ms' }}>
        <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center">
            <TerminalIcon className="w-[18px] h-[18px] text-slate-400" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-200">CI/CD Integration</h2>
            <p className="text-xs text-slate-500">Block deploys on critical vulnerabilities</p>
          </div>
        </div>
        <div className="px-6 py-5 space-y-4">
          {/* Step callouts */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { step: '1', label: 'Add secret', desc: 'Store your API key as JWP_API_KEY in your CI secrets' },
              { step: '2', label: 'Trigger scan', desc: 'POST /scans with your target URL after each deploy' },
              { step: '3', label: 'Gate on severity', desc: 'Exit 1 if critical_count > 0 to block the pipeline' },
            ].map(({ step, label, desc }) => (
              <div key={step} className="bg-slate-800/60 border border-slate-700 rounded-xl px-3 py-3">
                <div className="w-6 h-6 rounded-full bg-brand-600/20 text-brand-400 text-xs font-bold flex items-center justify-center mb-2">{step}</div>
                <p className="text-xs font-semibold text-slate-300">{label}</p>
                <p className="text-xs text-slate-500 mt-0.5">{desc}</p>
              </div>
            ))}
          </div>

          {/* GitHub Actions example */}
          <div className="bg-slate-800/60 border border-slate-700 rounded-xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-700 bg-slate-800/80">
              <GithubIcon className="w-4 h-4 text-slate-400" />
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">GitHub Actions</p>
              <span className="ml-auto text-xs text-slate-600">.github/workflows/security-scan.yml</span>
            </div>
            <pre className="text-xs font-mono text-slate-300 px-4 py-3 overflow-x-auto leading-relaxed whitespace-pre">{`name: Security Scan
on: [deployment]

jobs:
  jwp-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Trigger scan
        id: scan
        run: |
          SCAN_ID=$(curl -sf -X POST \\
            -H "Authorization: Bearer \${{ secrets.JWP_API_KEY }}" \\
            -H "Content-Type: application/json" \\
            -d '{"target":"https://your-site.com","tags":["branch:\${{ github.ref_name }}","sha:\${{ github.sha }}"]}' \\
            ${WORKER_URL}/scans | jq -r .id)
          echo "scan_id=$SCAN_ID" >> $GITHUB_OUTPUT

      - name: Wait for results
        run: |
          for i in \$(seq 1 30); do
            STATUS=\$(curl -sf \\
              -H "Authorization: Bearer \${{ secrets.JWP_API_KEY }}" \\
              ${WORKER_URL}/scans/\${{ steps.scan.outputs.scan_id }} | jq -r .status)
            [ "\$STATUS" = "completed" ] && break
            echo "[$i/30] Status: \$STATUS — waiting 10s…"
            sleep 10
          done

      - name: Check for critical vulnerabilities
        run: |
          RESULT=\$(curl -sf \\
            -H "Authorization: Bearer \${{ secrets.JWP_API_KEY }}" \\
            ${WORKER_URL}/scans/\${{ steps.scan.outputs.scan_id }})
          CRITICAL=\$(echo "\$RESULT" | jq .by_severity.critical)
          HIGH=\$(echo "\$RESULT" | jq .by_severity.high)
          echo "Critical: \$CRITICAL  High: \$HIGH"
          [ "\$CRITICAL" -gt 0 ] && exit 1 || exit 0`}</pre>
          </div>

          {/* Tagging tip */}
          <div className="flex items-start gap-3 bg-slate-800/40 border border-slate-700/60 rounded-xl px-4 py-3">
            <span className="text-base leading-none mt-0.5">💡</span>
            <div className="space-y-1">
              <p className="text-xs font-semibold text-slate-300">Tagging scans for traceability</p>
              <p className="text-xs text-slate-500">Pass <code className="bg-slate-700 px-1 rounded text-slate-300">"tags": ["branch:main", "sha:abc1234"]</code> in the POST body to link scans to git commits. Filter by tag on the History page.</p>
            </div>
          </div>

          <div className="flex items-start gap-3 bg-slate-800/40 border border-slate-700/60 rounded-xl px-4 py-3">
            <span className="text-base leading-none mt-0.5">⚡</span>
            <div className="space-y-1">
              <p className="text-xs font-semibold text-slate-300">Rate limits &amp; retries</p>
              <p className="text-xs text-slate-500">Free tier: <span className="text-slate-400 font-medium">5 scans/day · 50/month</span>. When exceeded, the API returns HTTP <code className="bg-slate-700 px-1 rounded text-slate-300">429</code> with a <code className="bg-slate-700 px-1 rounded text-slate-300">Retry-After</code> header and <code className="bg-slate-700 px-1 rounded text-slate-300">reset_daily_at</code> timestamp in the body.</p>
            </div>
          </div>
        </div>
      </div>

      </>}

      {/* ── Danger tab ── */}
      {activeTab === 'danger' && <>

      {/* Danger zone */}
      <div className="bg-red-500/5 border border-red-500/20 rounded-xl overflow-hidden animate-fade-in-up" style={{ animationDelay: '100ms' }}>
        <div className="px-6 py-4 border-b border-red-500/20 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
            <AlertTriangleIcon className="w-[18px] h-[18px] text-red-400" />
          </div>
          <h2 className="text-sm font-semibold text-red-400">Danger Zone</h2>
        </div>
        <div className="px-6 py-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-slate-300">Delete Account</p>
              <p className="text-xs text-slate-500 mt-0.5">Permanently delete your account and all scan data.</p>
            </div>
            <button
              onClick={() => setShowDeleteModal(true)}
              className="px-4 py-2 rounded-xl text-xs font-medium text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-all"
            >
              Delete Account
            </button>
          </div>
        </div>
      </div>

      </>}

      {/* Delete account modal */}
      {showDeleteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl max-w-md w-full mx-4 p-6 animate-fade-in-up">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                <AlertTriangleIcon className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-slate-100">Delete Account</h3>
                <p className="text-xs text-slate-500">This action cannot be undone</p>
              </div>
            </div>
            <p className="text-sm text-slate-400 mb-5 leading-relaxed">
              This will permanently delete your account, all scan history, reports, and associated data. Enter your password to confirm.
            </p>
            <input
              type="password"
              value={deletePassword}
              onChange={(e) => setDeletePassword(e.target.value)}
              placeholder="Enter your password"
              className="w-full bg-slate-800/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500 focus:ring-2 focus:ring-red-500/20 transition-all mb-4"
            />
            {deleteError && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-2.5 text-sm text-red-400 flex items-center gap-2 mb-4 animate-fade-in">
                <WarningIcon className="w-4 h-4 shrink-0" />
                {deleteError}
              </div>
            )}
            <div className="flex items-center gap-3 justify-end">
              <button
                onClick={() => { setShowDeleteModal(false); setDeletePassword(''); setDeleteError(''); }}
                className="px-4 py-2 rounded-xl text-sm font-medium text-slate-400 bg-slate-800 border border-slate-700 hover:bg-slate-700 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteAccount}
                disabled={deleteLoading || !deletePassword}
                className="px-4 py-2 rounded-xl text-sm font-medium text-white bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2"
              >
                {deleteLoading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Deleting…
                  </>
                ) : (
                  'Delete My Account'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
