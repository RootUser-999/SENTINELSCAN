import React, { useEffect, useState } from 'react';
import { KeyRound, Lock, Shield, Trash2, UserPlus } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { Asset, UserSession } from '../types/sentinel';
import { formatDateTime } from '../utils/formatters';

interface SettingsAuditViewProps {
  user: UserSession;
  assets: Asset[];
  onToast: (msg: string, type?: 'success' | 'error') => void;
  onUserUpdated: (user: UserSession) => void;
}

export const SettingsAuditView: React.FC<SettingsAuditViewProps> = ({
  user,
  assets,
  onToast,
  onUserUpdated,
}) => {
  const [members, setMembers] = useState<Array<{ id: string; email: string; full_name: string; role: string; created_at: string }>>([]);
  const [credentials, setCredentials] = useState<Array<{ id: string; label: string; auth_type: string; role_profile: string; expires_at: string; asset_name: string | null }>>([]);
  const [apiKeys, setApiKeys] = useState<Array<{ id: string; name: string; key_prefix: string; role: string; created_at: string; revoked_at: string | null }>>([]);
  const [auditLogs, setAuditLogs] = useState<Array<{ id: string; action: string; entity_type: string; user_email: string | null; details_json: string; created_at: string }>>([]);

  // Credential Vault form
  const [credLabel, setCredLabel] = useState('');
  const [credType, setCredType] = useState<'bearer_token' | 'cookie' | 'basic_header' | 'login_form'>('bearer_token');
  const [credRole, setCredRole] = useState<'authenticated_user' | 'administrator' | 'custom'>('authenticated_user');
  const [credAssetId, setCredAssetId] = useState('');
  const [credLoginUrl, setCredLoginUrl] = useState('/login');
  const [credUsernameHint, setCredUsernameHint] = useState('');
  const [credSecret, setCredSecret] = useState('');

  // Member invite form
  const [memberName, setMemberName] = useState('');
  const [memberEmail, setMemberEmail] = useState('');
  const [memberPassword, setMemberPassword] = useState('');
  const [memberRole, setMemberRole] = useState<'analyst' | 'viewer' | 'admin'>('analyst');

  // API Key form
  const [keyName, setKeyName] = useState('');
  const [newlyCreatedKey, setNewlyCreatedKey] = useState<string | null>(null);

  const loadAll = async () => {
    try {
      const [meRes, credRes, keyRes, auditRes] = await Promise.all([
        apiRequest<{ members: typeof members }>('/auth/me'),
        apiRequest<{ credentials: typeof credentials }>('/credentials'),
        apiRequest<{ keys: typeof apiKeys }>('/api-keys'),
        apiRequest<{ logs: typeof auditLogs }>('/audit-logs'),
      ]);
      setMembers(meRes.members);
      setCredentials(credRes.credentials);
      setApiKeys(keyRes.keys);
      setAuditLogs(auditRes.logs);
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to load workspace settings', 'error');
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleSaveCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiRequest('/credentials', {
        method: 'POST',
        body: JSON.stringify({
          label: credLabel,
          authType: credType,
          roleProfile: credRole,
          assetId: credAssetId || null,
          loginUrl: credType === 'login_form' ? credLoginUrl.trim() || '/login' : null,
          usernameHint: credType === 'login_form' ? credUsernameHint.trim() || null : null,
          secretValue: credSecret,
          ttlDays: 7,
        }),
      });
      setCredLabel('');
      setCredUsernameHint('');
      setCredSecret('');
      onToast('Credential encrypted (AES-256-GCM) and stored in vault.', 'success');
      loadAll();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to store credential', 'error');
    }
  };

  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiRequest('/auth/members', {
        method: 'POST',
        body: JSON.stringify({
          fullName: memberName,
          email: memberEmail,
          password: memberPassword,
          role: memberRole,
        }),
      });
      setMemberName('');
      setMemberEmail('');
      setMemberPassword('');
      onToast('Organization member created.', 'success');
      loadAll();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to add member', 'error');
    }
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiRequest<{ rawKey: string }>('/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name: keyName, role: 'analyst' }),
      });
      setNewlyCreatedKey(res.rawKey);
      setKeyName('');
      onToast('API key generated. Copy it now—it will not be shown again.', 'success');
      loadAll();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to create API key', 'error');
    }
  };

  const handleToggleMfa = async () => {
    try {
      const res = await apiRequest<{ mfaEnabled: boolean }>('/auth/mfa/toggle', { method: 'POST' });
      onUserUpdated({ ...user, mfaEnabled: res.mfaEnabled });
      onToast(`Account MFA protection ${res.mfaEnabled ? 'enabled' : 'disabled'}.`, 'success');
      loadAll();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'MFA toggle failed', 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Credential Vault */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-md p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Lock className="w-4 h-4 text-blue-400" aria-hidden="true" />
            <h2>Authenticated Scan Credential Vault</h2>
          </div>
          <p className="text-xs text-slate-400">
            Secrets are encrypted at rest with AES-256-GCM, automatically expire, and are redacted from scan logs and reports.
          </p>
          {(user.role === 'admin' || user.role === 'analyst') && (
            <form onSubmit={handleSaveCredential} className="space-y-3 text-xs">
              <div>
                <label htmlFor="cred-label" className="block text-slate-300 mb-1">Credential Label</label>
                <input
                  id="cred-label"
                  type="text"
                  required
                  value={credLabel}
                  onChange={(e) => setCredLabel(e.target.value)}
                  placeholder="Staging Test User JWT"
                  className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="cred-type" className="block text-slate-300 mb-1">Auth Type</label>
                  <select
                    id="cred-type"
                    value={credType}
                    onChange={(e) => setCredType(e.target.value as typeof credType)}
                    className="w-full px-2.5 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  >
                    <option value="bearer_token">Bearer Token</option>
                    <option value="cookie">Session Cookie</option>
                    <option value="basic_header">Custom Auth Header</option>
                    <option value="login_form">Login Form (Email + Password)</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="cred-role" className="block text-slate-300 mb-1">Role Profile</label>
                  <select
                    id="cred-role"
                    value={credRole}
                    onChange={(e) => setCredRole(e.target.value as typeof credRole)}
                    className="w-full px-2.5 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  >
                    <option value="authenticated_user">Authenticated User</option>
                    <option value="administrator">Test Administrator</option>
                    <option value="custom">Custom Test Role</option>
                  </select>
                </div>
              </div>
              <div>
                <label htmlFor="cred-asset" className="block text-slate-300 mb-1">Scoped Asset (Optional)</label>
                <select
                  id="cred-asset"
                  value={credAssetId}
                  onChange={(e) => setCredAssetId(e.target.value)}
                  className="w-full px-2.5 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                >
                  <option value="">Any verified organization asset</option>
                  {assets.map((a) => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
              </div>
              {credType === 'login_form' && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="cred-login-url" className="block text-slate-300 mb-1">Login Endpoint Path/URL</label>
                    <input
                      id="cred-login-url"
                      type="text"
                      value={credLoginUrl}
                      onChange={(e) => setCredLoginUrl(e.target.value)}
                      placeholder="/login"
                      className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                    />
                  </div>
                  <div>
                    <label htmlFor="cred-username" className="block text-slate-300 mb-1">Test Username / Email</label>
                    <input
                      id="cred-username"
                      type="text"
                      required
                      value={credUsernameHint}
                      onChange={(e) => setCredUsernameHint(e.target.value)}
                      placeholder="qa-user@example.test"
                      className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                    />
                  </div>
                </div>
              )}
              <div>
                <label htmlFor="cred-secret" className="block text-slate-300 mb-1">
                  {credType === 'login_form' ? 'Test Account Password' : 'Secret Token / Cookie Value'}
                </label>
                <input
                  id="cred-secret"
                  type="password"
                  required
                  value={credSecret}
                  onChange={(e) => setCredSecret(e.target.value)}
                  placeholder="Encrypted immediately on server"
                  className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
              </div>
              <button
                type="submit"
                className="w-full py-2 font-medium text-white bg-blue-600 hover:bg-blue-500 rounded"
              >
                Encrypt & Store Credential
              </button>
            </form>
          )}
        </div>

        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 text-sm font-semibold text-slate-100">
            Stored Credentials ({credentials.length})
          </div>
          {credentials.length === 0 ? (
            <div className="p-6 text-xs text-slate-500">No encrypted scan credentials stored.</div>
          ) : (
            <div className="divide-y divide-slate-800/80 text-xs">
              {credentials.map((c) => (
                <div key={c.id} className="px-5 py-3 flex items-center justify-between gap-4">
                  <div>
                    <div className="font-medium text-slate-200">{c.label}</div>
                    <div className="text-[11px] text-slate-500 font-mono">
                      {c.auth_type} · {c.role_profile} · Expires {formatDateTime(c.expires_at)}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={async () => {
                      await apiRequest(`/credentials/${c.id}`, { method: 'DELETE' });
                      loadAll();
                    }}
                    aria-label={`Delete credential ${c.label}`}
                    className="p-1.5 text-slate-500 hover:text-red-400"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* RBAC & API Keys */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <UserPlus className="w-4 h-4 text-blue-400" aria-hidden="true" />
              <h2>Organization Team & RBAC</h2>
            </div>
            <button
              type="button"
              onClick={handleToggleMfa}
              className="px-3 py-1 text-xs bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded text-slate-200"
            >
              MFA: {user.mfaEnabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          <div className="divide-y divide-slate-800/80 border border-slate-800 rounded bg-[#090D16] text-xs">
            {members.map((m) => (
              <div key={m.id} className="px-3.5 py-2.5 flex items-center justify-between">
                <div>
                  <div className="text-slate-200 font-medium">{m.full_name}</div>
                  <div className="text-[11px] text-slate-500">{m.email}</div>
                </div>
                <span className="font-mono text-blue-400 uppercase text-[11px]">{m.role}</span>
              </div>
            ))}
          </div>

          {user.role === 'admin' && (
            <form onSubmit={handleAddMember} className="pt-2 space-y-2.5 text-xs">
              <div className="font-medium text-slate-300">Provision Team Member</div>
              <div className="grid grid-cols-2 gap-2.5">
                <input
                  type="text"
                  required
                  value={memberName}
                  onChange={(e) => setMemberName(e.target.value)}
                  placeholder="Full Name"
                  className="px-3 py-1.5 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
                <input
                  type="email"
                  required
                  value={memberEmail}
                  onChange={(e) => setMemberEmail(e.target.value)}
                  placeholder="Email"
                  className="px-3 py-1.5 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
                <input
                  type="password"
                  required
                  minLength={8}
                  value={memberPassword}
                  onChange={(e) => setMemberPassword(e.target.value)}
                  placeholder="Initial Password (8+ chars)"
                  className="px-3 py-1.5 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
                <select
                  value={memberRole}
                  onChange={(e) => setMemberRole(e.target.value as typeof memberRole)}
                  className="px-3 py-1.5 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                >
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <button type="submit" className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium">
                Add Member
              </button>
            </form>
          )}
        </div>

        {/* API Keys */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <KeyRound className="w-4 h-4 text-blue-400" aria-hidden="true" />
            <h2>Programmatic CI/CD API Keys</h2>
          </div>

          {newlyCreatedKey && (
            <div className="p-3 bg-emerald-950/40 border border-emerald-700/50 rounded text-xs">
              <div className="text-emerald-300 font-medium">Copy your new API key (shown once):</div>
              <div className="mt-1 font-mono text-slate-100 break-all select-all">{newlyCreatedKey}</div>
            </div>
          )}

          {user.role === 'admin' && (
            <form onSubmit={handleCreateApiKey} className="flex gap-2 text-xs">
              <input
                type="text"
                required
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                placeholder="GitHub Actions Nightly Scanner"
                className="flex-1 px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
              />
              <button type="submit" className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium whitespace-nowrap">
                Generate Key
              </button>
            </form>
          )}

          <div className="divide-y divide-slate-800/80 border border-slate-800 rounded bg-[#090D16] text-xs">
            {apiKeys.length === 0 ? (
              <div className="p-4 text-slate-500">No API keys created yet.</div>
            ) : (
              apiKeys.map((k) => (
                <div key={k.id} className="px-3.5 py-2.5 flex items-center justify-between">
                  <div>
                    <div className="text-slate-200 font-medium">{k.name}</div>
                    <div className="text-[11px] font-mono text-slate-500">
                      {k.key_prefix}... · {k.role} · {k.revoked_at ? 'Revoked' : 'Active'}
                    </div>
                  </div>
                  {!k.revoked_at && user.role === 'admin' && (
                    <button
                      type="button"
                      onClick={async () => {
                        await apiRequest(`/api-keys/${k.id}`, { method: 'DELETE' });
                        loadAll();
                      }}
                      className="text-xs text-red-400 hover:underline"
                    >
                      Revoke
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Immutable Audit Trail */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Shield className="w-4 h-4 text-blue-400" aria-hidden="true" />
          <h2>Immutable Security Audit Log</h2>
        </div>
        <div className="overflow-x-auto max-h-80">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-[#0B111E] border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2.5 px-4 font-medium">Timestamp</th>
                <th className="py-2.5 px-4 font-medium">Actor</th>
                <th className="py-2.5 px-4 font-medium">Action</th>
                <th className="py-2.5 px-4 font-medium">Target / Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {auditLogs.map((l) => (
                <tr key={l.id}>
                  <td className="py-2 px-4 font-mono tabular-nums text-slate-400 whitespace-nowrap">{formatDateTime(l.created_at)}</td>
                  <td className="py-2 px-4 text-slate-300 whitespace-nowrap">{l.user_email || 'system'}</td>
                  <td className="py-2 px-4 font-mono text-blue-300 whitespace-nowrap">{l.action}</td>
                  <td className="py-2 px-4 font-mono text-[11px] text-slate-400 max-w-md truncate">{l.details_json}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
