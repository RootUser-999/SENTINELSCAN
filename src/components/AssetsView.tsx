import React, { useState } from 'react';
import { Plus, ShieldCheck, Trash2, Play, Search, CheckCircle2, AlertTriangle, FlaskConical } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { Asset, OwnershipVerification, UserRole } from '../types/sentinel';
import { formatDateTime } from '../utils/formatters';

// Controlled testing mode: set to true before public release to re-enforce DNS TXT verification
const REQUIRE_DNS_OWNERSHIP_VERIFICATION = false;

interface AssetsViewProps {
  assets: Asset[];
  verifications: OwnershipVerification[];
  userRole: UserRole;
  onRefresh: () => void;
  onLaunchScanForAsset: (assetId: string) => void;
  onToast: (msg: string, type?: 'success' | 'error') => void;
}

export const AssetsView: React.FC<AssetsViewProps> = ({
  assets,
  verifications,
  userRole,
  onRefresh,
  onLaunchScanForAsset,
  onToast,
}) => {
  const [search, setSearch] = useState('');
  const [envFilter, setEnvFilter] = useState<string>('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [verifyAsset, setVerifyAsset] = useState<Asset | null>(null);

  // Add asset form
  const [name, setName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [environment, setEnvironment] = useState<'production' | 'staging' | 'development' | 'practice_lab'>('production');
  const [criticality, setCriticality] = useState<'critical' | 'high' | 'medium' | 'low'>('high');
  const [scopeIncludePaths, setScopeIncludePaths] = useState('/');
  const [scopeExcludePaths, setScopeExcludePaths] = useState('/logout,/billing');
  const [submitting, setSubmitting] = useState(false);

  // Verify ownership form
  const [verifyMethod, setVerifyMethod] = useState<'dns_txt' | 'http_file' | 'html_meta' | 'practice_lab_attestation'>('dns_txt');
  const [authorizedBy, setAuthorizedBy] = useState('');
  const [authorizationNotes, setAuthorizationNotes] = useState('');
  const [confirmAuth, setConfirmAuth] = useState(false);
  const [verifying, setVerifying] = useState(false);

  const canEdit = userRole === 'admin' || userRole === 'analyst';

  const filtered = assets.filter((a) => {
    const matchesEnv = envFilter === 'all' || a.environment === envFilter;
    const q = search.trim().toLowerCase();
    const matchesSearch = !q || a.name.toLowerCase().includes(q) || a.target_url.toLowerCase().includes(q);
    return matchesEnv && matchesSearch;
  });

  const handleLoadPracticePreset = () => {
    setName('Practice Shop Lab (Controlled Target)');
    setTargetUrl('https://practice-shop.sentinel-lab.internal');
    setEnvironment('practice_lab');
    setCriticality('medium');
    setScopeIncludePaths('/');
    setScopeExcludePaths('');
  };

  const handleAddAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await apiRequest('/assets', {
        method: 'POST',
        body: JSON.stringify({
          name,
          targetUrl,
          environment,
          criticality,
          scopeIncludePaths,
          scopeExcludePaths,
        }),
      });
      onToast('Target asset added. Complete ownership verification before active scanning.', 'success');
      setShowAddModal(false);
      setName('');
      setTargetUrl('');
      onRefresh();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to add asset', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const openVerifyModal = (asset: Asset) => {
    setVerifyAsset(asset);
    setVerifyMethod(asset.is_practice_target ? 'practice_lab_attestation' : 'dns_txt');
    setAuthorizedBy(asset.authorization_signed_by || '');
    setAuthorizationNotes(
      asset.is_practice_target
        ? 'Authorized evaluation against isolated SentinelScan Practice Lab environment.'
        : ''
    );
    setConfirmAuth(false);
  };

  const handleVerifyOwnership = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifyAsset) return;
    setVerifying(true);
    try {
      await apiRequest(`/assets/${verifyAsset.id}/verify-ownership`, {
        method: 'POST',
        body: JSON.stringify({
          method: verifyMethod,
          authorizedBy,
          authorizationNotes,
          confirmExplicitAuthorization: confirmAuth,
        }),
      });
      onToast(`Ownership verified for ${verifyAsset.name}. Active scanning unlocked.`, 'success');
      setVerifyAsset(null);
      onRefresh();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Verification failed', 'error');
      onRefresh();
    } finally {
      setVerifying(false);
    }
  };

  const handleDeleteAsset = async (asset: Asset) => {
    try {
      await apiRequest(`/assets/${asset.id}`, { method: 'DELETE' });
      onToast(`Removed asset "${asset.name}".`, 'success');
      onRefresh();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Delete failed', 'error');
    }
  };

  const getTokenForAsset = (assetId: string) =>
    verifications.find((v) => v.asset_id === assetId)?.token || 'sentinel-verify-pending';

  return (
    <div className="space-y-5">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[260px]">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" aria-hidden="true" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets by name or URL..."
              aria-label="Search assets"
              className="w-full pl-9 pr-3 py-2 text-xs bg-[#0F172A] border border-slate-800 rounded text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            aria-label="Filter by environment"
            className="px-3 py-2 text-xs bg-[#0F172A] border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Environments</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
            <option value="practice_lab">Practice Lab</option>
          </select>
        </div>

        {canEdit && (
          <button
            type="button"
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded transition-colors whitespace-nowrap"
          >
            <Plus className="w-4 h-4" aria-hidden="true" />
            <span>Add Website / Asset</span>
          </button>
        )}
      </div>

      {/* Asset Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-10 text-center">
            <p className="text-sm text-slate-300 font-medium">No target websites match your filter</p>
            <p className="mt-1 text-xs text-slate-500">
              Add an owned domain or load the isolated Practice Lab target to test SentinelScan safely.
            </p>
            {canEdit && (
              <button
                type="button"
                onClick={() => {
                  handleLoadPracticePreset();
                  setShowAddModal(true);
                }}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded"
              >
                <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Add Isolated Practice Lab Target</span>
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-400 bg-[#0B111E]">
                  <th className="py-3 px-4 font-medium">Website / Target</th>
                  <th className="py-3 px-4 font-medium">Environment</th>
                  <th className="py-3 px-4 font-medium">Ownership</th>
                  <th className="py-3 px-4 font-medium text-right">Posture</th>
                  <th className="py-3 px-4 font-medium text-right">Open Findings</th>
                  <th className="py-3 px-4 font-medium text-right">Last Scanned</th>
                  <th className="py-3 px-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 text-xs">
                {filtered.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4">
                      <div className="font-medium text-slate-100">{a.name}</div>
                      <div className="text-[11px] text-slate-500 font-mono">{a.target_url}</div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {a.environment} · {a.criticality}
                    </td>
                    <td className="py-3 px-4">
                      {a.ownership_status === 'verified' ? (
                        <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Verified</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-amber-400 font-medium">
                          <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Pending Verification</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-200">
                      {a.latest_posture_score !== null ? `${a.latest_posture_score}/100` : '—'}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-200">
                      {a.open_findings ?? 0}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-400">
                      {formatDateTime(a.last_scanned_at)}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2">
                        {a.ownership_status !== 'verified' && canEdit && (
                          <button
                            type="button"
                            onClick={() => openVerifyModal(a)}
                            className="px-2.5 py-1 text-xs font-medium text-amber-300 bg-amber-950/50 border border-amber-700/50 hover:bg-amber-900/50 rounded"
                          >
                            Verify Ownership
                          </button>
                        )}
                        {a.ownership_status === 'verified' && canEdit && (
                          <button
                            type="button"
                            onClick={() => onLaunchScanForAsset(a.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-blue-300 bg-blue-950/60 border border-blue-700/50 hover:bg-blue-900/60 rounded"
                          >
                            <Play className="w-3 h-3" aria-hidden="true" />
                            <span>Scan</span>
                          </button>
                        )}
                        {canEdit && (
                          <button
                            type="button"
                            onClick={() => handleDeleteAsset(a)}
                            aria-label={`Delete asset ${a.name}`}
                            className="p-1.5 text-slate-500 hover:text-red-400 rounded"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Asset Modal */}
      {showAddModal && (
        <div role="dialog" aria-modal="true" aria-labelledby="add-asset-title" className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#0F172A] border border-slate-700 rounded-lg p-6">
            <div className="flex items-center justify-between gap-4">
              <h2 id="add-asset-title" className="text-base font-semibold text-slate-100">
                Register Target Website or Application
              </h2>
              <button
                type="button"
                onClick={handleLoadPracticePreset}
                className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 whitespace-nowrap"
              >
                <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Use Practice Lab Preset</span>
              </button>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              Private, loopback, and cloud metadata IPs are blocked automatically by SSRF scope controls.
            </p>

            <form onSubmit={handleAddAsset} className="mt-5 space-y-4">
              <div>
                <label htmlFor="asset-name" className="block text-xs font-medium text-slate-300 mb-1">
                  Application Name
                </label>
                <input
                  id="asset-name"
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Customer Portal Production"
                  className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label htmlFor="asset-url" className="block text-xs font-medium text-slate-300 mb-1">
                  Target Origin URL
                </label>
                <input
                  id="asset-url"
                  type="url"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://app.example.com"
                  className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="asset-env" className="block text-xs font-medium text-slate-300 mb-1">
                    Environment
                  </label>
                  <select
                    id="asset-env"
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value as typeof environment)}
                    className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="practice_lab">Practice Lab (Isolated)</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="asset-crit" className="block text-xs font-medium text-slate-300 mb-1">
                    Business Criticality
                  </label>
                  <select
                    id="asset-crit"
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value as typeof criticality)}
                    className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="asset-inc" className="block text-xs font-medium text-slate-300 mb-1">
                    Include Paths (comma-separated)
                  </label>
                  <input
                    id="asset-inc"
                    type="text"
                    value={scopeIncludePaths}
                    onChange={(e) => setScopeIncludePaths(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  />
                </div>
                <div>
                  <label htmlFor="asset-exc" className="block text-xs font-medium text-slate-300 mb-1">
                    Exclude Paths
                  </label>
                  <input
                    id="asset-exc"
                    type="text"
                    value={scopeExcludePaths}
                    onChange={(e) => setScopeExcludePaths(e.target.value)}
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  />
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded"
                >
                  {submitting ? 'Validating...' : 'Register Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Verify Ownership & Explicit Authorization Modal */}
      {verifyAsset && (
        <div role="dialog" aria-modal="true" aria-labelledby="verify-asset-title" className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-[#0F172A] border border-slate-700 rounded-lg p-6">
            <div className="flex items-center gap-2 text-slate-100 font-semibold text-base">
              <ShieldCheck className="w-5 h-5 text-blue-400" aria-hidden="true" />
              <h2 id="verify-asset-title">Verify Ownership & Written Authorization</h2>
            </div>
            <p className="mt-1 text-xs text-slate-400">
              Target: <span className="font-mono text-slate-200">{verifyAsset.target_url}</span>
            </p>

            <form onSubmit={handleVerifyOwnership} className="mt-4 space-y-4">
              <div>
                <label htmlFor="verify-method" className="block text-xs font-medium text-slate-300 mb-1">
                  Verification Mechanism
                </label>
                <select
                  id="verify-method"
                  value={verifyMethod}
                  onChange={(e) => setVerifyMethod(e.target.value as typeof verifyMethod)}
                  className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                >
                  {verifyAsset.is_practice_target ? (
                    <option value="practice_lab_attestation">Isolated Practice Lab Authorization</option>
                  ) : (
                    <>
                      <option value="dns_txt">
                        {REQUIRE_DNS_OWNERSHIP_VERIFICATION
                          ? `DNS TXT Record (_sentinelscan-verify.${verifyAsset.hostname})`
                          : 'Controlled Testing Authorization (DNS Verification Bypassed)'}
                      </option>
                      <option value="http_file">HTTP Well-Known File (/.well-known/sentinelscan-verification.txt)</option>
                      <option value="html_meta">HTML Meta Tag (&lt;meta name=&quot;sentinelscan-verification&quot;&gt;)</option>
                    </>
                  )}
                </select>
              </div>

              <div className="p-3 bg-[#090D16] border border-slate-800 rounded text-xs space-y-1.5">
                <div className="text-slate-400">Verification Token:</div>
                <div className="font-mono text-blue-300 select-all break-all">
                  {getTokenForAsset(verifyAsset.id)}
                </div>
                {!verifyAsset.is_practice_target && (
                  <div className="text-[11px] text-slate-500 pt-1">
                    {verifyMethod === 'dns_txt' &&
                      (REQUIRE_DNS_OWNERSHIP_VERIFICATION
                        ? `Publish TXT record at _sentinelscan-verify.${verifyAsset.hostname} containing the token above.`
                        : 'Controlled testing mode active: DNS TXT record verification is bypassed. Provide written authorization below to proceed to scan configuration.')}
                    {verifyMethod === 'http_file' && `Host plain text file at ${verifyAsset.target_url}/.well-known/sentinelscan-verification.txt with this token.`}
                    {verifyMethod === 'html_meta' && `Add <meta name="sentinelscan-verification" content="${getTokenForAsset(verifyAsset.id)}" /> to homepage <head>.`}
                  </div>
                )}
              </div>

              <div>
                <label htmlFor="auth-signatory" className="block text-xs font-medium text-slate-300 mb-1">
                  Authorized Signatory Name
                </label>
                <input
                  id="auth-signatory"
                  type="text"
                  required
                  value={authorizedBy}
                  onChange={(e) => setAuthorizedBy(e.target.value)}
                  placeholder="Jane Doe, VP Security"
                  className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
              </div>

              <div>
                <label htmlFor="auth-notes" className="block text-xs font-medium text-slate-300 mb-1">
                  Authorization Scope & Ticket / Engagement Reference
                </label>
                <textarea
                  id="auth-notes"
                  required
                  rows={2}
                  value={authorizationNotes}
                  onChange={(e) => setAuthorizationNotes(e.target.value)}
                  placeholder="SEC-2026-412: Authorized non-destructive assessment window"
                  className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                />
              </div>

              <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  required
                  checked={confirmAuth}
                  onChange={(e) => setConfirmAuth(e.target.checked)}
                  className="mt-0.5 rounded border-slate-600 bg-[#090D16]"
                />
                <span>
                  I confirm explicit written authorization to assess this target within its defined scope and rate limits.
                </span>
              </label>

              <div className="pt-2 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setVerifyAsset(null)}
                  className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={verifying || !confirmAuth}
                  className="px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded"
                >
                  {verifying ? 'Verifying...' : 'Verify & Authorize Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
