import React, { useEffect, useState } from 'react';
import { KeyRound, Lock, Shield, Trash2, UserPlus } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { Asset, UserSession } from '../types/sentinel';
import { formatDateTime } from '../utils/formatters';
import { inputClassName, selectClassName } from './ui';

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
        <div className="lg:col-span-5 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#0F172A]">
            <Lock className="w-4 h-4 text-[#2563EB]" aria-hidden="true" />
            <h2>Authenticated Scan Credential Vault</h2>
          </div>
          <p className="text-xs text-[#64748B] leading-relaxed">
            Secrets are encrypted at rest with AES-256-GCM, automatically expire, and are redacted from scan logs and reports.
          </p>
          {(user.role === 'admin' || user.role === 'analyst') && (
            <form onSubmit={handleSaveCredential} className="space-y-3 text-xs">
              <div>
                <label htmlFor="cred-label" className="block font-medium text-[#334155] mb-1">
                  Credential Label
                </label>
                <input
                  id="cred-label"
                  type="text"
                  required
                  value={credLabel}
                  onChange={(e) => setCredLabel(e.target.value)}
                  placeholder="Staging Test User JWT"
                  className={inputClassName}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="cred-type" className="block font-medium text-[#334155] mb-1">
                    Auth Type
                  </label>
                  <select
                    id="cred-type"
                    value={credType}
                    onChange={(e) => setCredType(e.target.value as typeof credType)}
                    className={`${selectClassName} w-full`}
                  >
                    <option value="bearer_token">Bearer Token</option>
                    <option value="cookie">Session Cookie</option>
                    <option value="basic_header">Custom Auth Header</option>
                    <option value="login_form">Login Form (Email + Password)</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="cred-role" className="block font-medium text-[#334155] mb-1">
                    Role Profile
                  </label>
                  <select
                    id="cred-role"
                    value={credRole}
                    onChange={(e) => setCredRole(e.target.value as typeof credRole)}
                    className={`${selectClassName} w-full`}
                  >
                    <option value="authenticated_user">Authenticated User</option>
                    <option value="administrator">Test Administrator</option>
                    <option value="custom">Custom Test Role</option>
                  </select>
                </div>
              </div>
              <div>
                <label htmlFor="cred-asset" className="block font-medium text-[#334155] mb-1">
                  Scoped Asset (Optional)
                </label>
                <select
                  id="cred-asset"
                  value={credAssetId}
                  onChange={(e) => setCredAssetId(e.target.value)}
                  className={`${selectClassName} w-full`}
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
                    <label htmlFor="cred-login-url" className="block font-medium text-[#334155] mb-1">
                      Login Endpoint Path/URL
                    </label>
                    <input
                      id="cred-login-url"
                      type="text"
                      value={credLoginUrl}
                      onChange={(e) => setCredLoginUrl(e.target.value)}
                      placeholder="/login"
                      className={inputClassName}
                    />
                  </div>
                  <div>
                    <label htmlFor="cred-username" className="block font-medium text-[#334155] mb-1">
                      Test Username / Email
                    </label>
                    <input
                      id="cred-username"
                      type="text"
                      required
                      value={credUsernameHint}
                      onChange={(e) => setCredUsernameHint(e.target.value)}
                      placeholder="qa-user@example.test"
                      className={inputClassName}
                    />
                  </div>
                </div>
              )}
              <div>
                <label htmlFor="cred-secret" className="block font-medium text-[#334155] mb-1">
                  {credType === 'login_form' ? 'Test Account Password' : 'Secret Token / Cookie Value'}
                </label>
                <input
                  id="cred-secret"
                  type="password"
                  required
                  value={credSecret}
                  onChange={(e) => setCredSecret(e.target.value)}
                  placeholder="Encrypted immediately on server"
                  className={inputClassName}
                />
              </div>
              <button
                type="submit"
                className="w-full py-2 font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md shadow-xs"
              >
                Encrypt &amp; Store Credential
              </button>
            </form>
          )}
        </div>

        <div className="lg:col-span-7 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#E2E8F0] text-sm font-semibold text-[#0F172A]">
            Stored Credentials ({credentials.length})
          </div>
          {credentials.length === 0 ? (
            <div className="p-6 text-xs text-[#64748B]">No encrypted scan credentials stored.</div>
          ) : (
            <div className="divide-y divide-[#E2E8F0] text-xs">
              {credentials.map((c) => (
                <div key={c.id} className="px-5 py-3 flex items-center justify-between gap-4 hover:bg-[#F8FAFC]">
                  <div>
                    <div className="font-semibold text-[#0F172A]">{c.label}</div>
                    <div className="text-[11px] text-[#64748B] font-mono">
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
                    className="p-1.5 text-[#94A3B8] hover:text-[#DC2626] hover:bg-[#FEF2F2] rounded-md"
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
        <div className="min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#0F172A]">
              <UserPlus className="w-4 h-4 text-[#2563EB]" aria-hidden="true" />
              <h2>Organization Team &amp; RBAC</h2>
            </div>
            <button
              type="button"
              onClick={handleToggleMfa}
              className={`px-3 py-1 text-xs font-medium rounded-md border transition-colors ${
                user.mfaEnabled
                  ? 'bg-[#F0FDF4] border-[#BBF7D0] text-[#15803D]'
                  : 'bg-[#F8FAFC] border-[#CBD5E1] text-[#475569] hover:text-[#0F172A]'
              }`}
            >
              MFA: {user.mfaEnabled ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          <div className="divide-y divide-[#E2E8F0] border border-[#E2E8F0] rounded-md bg-[#F8FAFC] text-xs">
            {members.map((m) => (
              <div key={m.id} className="px-3.5 py-2.5 flex items-center justify-between">
                <div>
                  <div className="text-[#0F172A] font-semibold">{m.full_name}</div>
                  <div className="text-[11px] text-[#64748B]">{m.email}</div>
                </div>
                <span className="font-mono font-semibold text-[#2563EB] uppercase text-[11px]">{m.role}</span>
              </div>
            ))}
          </div>

          {user.role === 'admin' && (
            <form onSubmit={handleAddMember} className="pt-2 space-y-2.5 text-xs">
              <div className="font-semibold text-[#0F172A]">Provision Team Member</div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <input
                  type="text"
                  required
                  value={memberName}
                  onChange={(e) => setMemberName(e.target.value)}
                  placeholder="Full Name"
                  className={inputClassName}
                />
                <input
                  type="email"
                  required
                  value={memberEmail}
                  onChange={(e) => setMemberEmail(e.target.value)}
                  placeholder="Email"
                  className={inputClassName}
                />
                <input
                  type="password"
                  required
                  minLength={8}
                  value={memberPassword}
                  onChange={(e) => setMemberPassword(e.target.value)}
                  placeholder="Initial Password (8+ chars)"
                  className={inputClassName}
                />
                <select
                  value={memberRole}
                  onChange={(e) => setMemberRole(e.target.value as typeof memberRole)}
                  className={selectClassName}
                >
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <button
                type="submit"
                className="px-3.5 py-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-white rounded-md font-semibold shadow-xs"
              >
                Add Member
              </button>
            </form>
          )}
        </div>

        {/* API Keys */}
        <div className="min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-[#0F172A]">
            <KeyRound className="w-4 h-4 text-[#2563EB]" aria-hidden="true" />
            <h2>Programmatic CI/CD API Keys</h2>
          </div>

          {newlyCreatedKey && (
            <div className="p-3 bg-[#F0FDF4] border border-[#BBF7D0] rounded-md text-xs">
              <div className="text-[#15803D] font-semibold">Copy your new API key (shown once):</div>
              <div className="mt-1 font-mono text-[#0F172A] break-all select-all">{newlyCreatedKey}</div>
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
                className={`${inputClassName} flex-1`}
              />
              <button
                type="submit"
                className="px-4 py-2 bg-[#2563EB] hover:bg-[#1D4ED8] text-white rounded-md font-semibold whitespace-nowrap shadow-xs"
              >
                Generate Key
              </button>
            </form>
          )}

          <div className="divide-y divide-[#E2E8F0] border border-[#E2E8F0] rounded-md bg-[#F8FAFC] text-xs">
            {apiKeys.length === 0 ? (
              <div className="p-4 text-[#64748B]">No API keys created yet.</div>
            ) : (
              apiKeys.map((k) => (
                <div key={k.id} className="px-3.5 py-2.5 flex items-center justify-between">
                  <div>
                    <div className="text-[#0F172A] font-semibold">{k.name}</div>
                    <div className="text-[11px] font-mono text-[#64748B]">
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
                      className="text-xs font-medium text-[#DC2626] hover:underline"
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
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-[#E2E8F0] flex items-center gap-2 text-sm font-semibold text-[#0F172A]">
          <Shield className="w-4 h-4 text-[#2563EB]" aria-hidden="true" />
          <h2>Immutable Security Audit Log</h2>
        </div>
        <div className="overflow-x-auto max-h-80">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="sticky top-0 bg-[#F8FAFC] border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B]">
              <tr>
                <th className="py-2.5 px-4 font-semibold">Timestamp</th>
                <th className="py-2.5 px-4 font-semibold">Actor</th>
                <th className="py-2.5 px-4 font-semibold">Action</th>
                <th className="py-2.5 px-4 font-semibold">Target / Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8F0]">
              {auditLogs.map((l) => (
                <tr key={l.id} className="hover:bg-[#F8FAFC]">
                  <td className="py-2 px-4 font-mono tabular-nums text-[#64748B] whitespace-nowrap">
                    {formatDateTime(l.created_at)}
                  </td>
                  <td className="py-2 px-4 text-[#334155] whitespace-nowrap">{l.user_email || 'system'}</td>
                  <td className="py-2 px-4 font-mono font-medium text-[#2563EB] whitespace-nowrap">{l.action}</td>
                  <td className="py-2 px-4 font-mono text-[11px] text-[#475569] max-w-md truncate">{l.details_json}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
