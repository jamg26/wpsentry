import { useState, useEffect } from 'react';
import { getAdminConfig, updateAdminConfig, type AdminConfig } from '../../lib/adminApi';

export default function AdminConfigPage() {
  const [config, setConfig] = useState<AdminConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    getAdminConfig()
      .then(setConfig)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    setError('');
    setSuccess('');
    try {
      await updateAdminConfig(config);
      setSuccess('Configuration saved successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save config');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center py-20">
        <div className="w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!config) {
    return (
      <div className="px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm">
        Failed to load configuration
      </div>
    );
  }

  const fields = [
    {
      key: 'DAILY_SCAN_LIMIT' as keyof AdminConfig,
      label: 'Daily Scan Limit',
      description: 'Maximum scans a user can run per day',
      group: 'Scan Limits',
    },
    {
      key: 'MONTHLY_SCAN_LIMIT' as keyof AdminConfig,
      label: 'Monthly Scan Limit',
      description: 'Maximum scans a user can run per month',
      group: 'Scan Limits',
    },
    {
      key: 'AUTH_SIGNUP_MAX_ATTEMPTS' as keyof AdminConfig,
      label: 'Signup Max Attempts',
      description: 'Max signup attempts per IP before blocking',
      group: 'Rate Limiting',
    },
    {
      key: 'AUTH_SIGNUP_WINDOW_SECONDS' as keyof AdminConfig,
      label: 'Signup Window (seconds)',
      description: 'Time window for signup rate limit (e.g. 3600 = 1 hour)',
      group: 'Rate Limiting',
    },
    {
      key: 'AUTH_LOGIN_MAX_ATTEMPTS' as keyof AdminConfig,
      label: 'Login Max Attempts',
      description: 'Max login attempts per IP before blocking',
      group: 'Rate Limiting',
    },
    {
      key: 'AUTH_LOGIN_WINDOW_SECONDS' as keyof AdminConfig,
      label: 'Login Window (seconds)',
      description: 'Time window for login rate limit (e.g. 900 = 15 min)',
      group: 'Rate Limiting',
    },
  ];

  const groups = [...new Set(fields.map((f) => f.group))];

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">System Configuration</h1>
        <p className="text-sm text-slate-400 mt-1">
          These settings override the defaults from wrangler.toml at runtime.
        </p>
      </div>

      {error && (
        <div className="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
          {error}
        </div>
      )}

      {success && (
        <div className="mb-4 px-3 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">
          {success}
        </div>
      )}

      <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-6 space-y-8 max-w-lg">
        {groups.map((group) => (
          <div key={group}>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">{group}</h3>
            <div className="space-y-5">
              {fields.filter((f) => f.group === group).map((field) => (
                <div key={field.key}>
                  <label className="block text-sm font-medium text-slate-300 mb-1">
                    {field.label}
                  </label>
                  <p className="text-xs text-slate-500 mb-2">{field.description}</p>
                  <input
                    type="number"
                    value={config[field.key]}
                    onChange={(e) => setConfig({ ...config, [field.key]: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-700 text-white rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500"
                    min="0"
                  />
                </div>
              ))}
            </div>
          </div>
        ))}

        <button
          onClick={handleSave}
          disabled={saving}
          className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}
