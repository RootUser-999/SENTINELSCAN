import React, { useState } from 'react';
import {
  Plus,
  ShieldCheck,
  Trash2,
  Play,
  Search,
  CheckCircle2,
  AlertTriangle,
  FlaskConical,
  Globe,
  X,
} from 'lucide-react';
import { apiRequest } from '../api/client';
import type { Asset, OwnershipVerification, UserRole } from '../types/sentinel';
import { formatDateTime } from '../utils/formatters';
import { EmptyState, inputClassName, selectClassName } from './ui';

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

  const authorizedCount = assets.filter((a) => a.ownership_status === 'verified').length;
  const totalOpenFindings = assets.reduce((acc, a) => acc + (a.open_findings || 0), 0);

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
      onToast('Target asset added. Authorize target scope before launching an assessment.', 'success');
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
      onToast(`Authorization confirmed for ${verifyAsset.name}. Active scanning unlocked.`, 'success');
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
      {/* Asset Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Registered Targets</div>
          <div className="mt-1.5 text-xl font-semibold font-mono tabular-nums text-[#0F172A]">
            {assets.length}
          </div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Authorized for Scanning</div>
          <div className="mt-1.5 text-xl font-semibold font-mono tabular-nums text-[#16A34A]">
            {authorizedCount}
          </div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Pending Authorization</div>
          <div className="mt-1.5 text-xl font-semibold font-mono tabular-nums text-[#D97706]">
            {assets.length - authorizedCount}
          </div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Open Findings Across Targets</div>
          <div className="mt-1.5 text-xl font-semibold font-mono tabular-nums text-[#0F172A]">
            {totalOpenFindings}
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-3.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3 flex-1 min-w-[260px]">
          <div className="relative flex-1 max-w-sm">
            <Search className="w-4 h-4 text-[#94A3B8] absolute left-3 top-2.5" aria-hidden="true" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search websites by name or URL..."
              aria-label="Search assets"
              className={`${inputClassName} pl-9`}
            />
          </div>
          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            aria-label="Filter by environment"
            className={selectClassName}
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
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md transition-colors whitespace-nowrap shadow-xs"
          >
            <Plus className="w-4 h-4" aria-hidden="true" />
            <span>Add Website / Asset</span>
          </button>
        )}
      </div>

      {/* Asset Table */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
        {filtered.length === 0 ? (
          <EmptyState
            icon={Globe}
            title="No target websites match your filter"
            description="Register an owned web application or load the isolated Practice Lab target to safely run end-to-end security assessments."
            action={
              canEdit ? (
                <button
                  type="button"
                  onClick={() => {
                    handleLoadPracticePreset();
                    setShowAddModal(true);
                  }}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md"
                >
                  <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Add Isolated Practice Lab Target</span>
                </button>
              ) : undefined
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B] bg-[#F8FAFC]">
                  <th className="py-3 px-4 font-semibold">Website / Target</th>
                  <th className="py-3 px-4 font-semibold">Environment</th>
                  <th className="py-3 px-4 font-semibold">Authorization</th>
                  <th className="py-3 px-4 font-semibold text-right">Posture</th>
                  <th className="py-3 px-4 font-semibold text-right">Open Findings</th>
                  <th className="py-3 px-4 font-semibold text-right">Last Scanned</th>
                  <th className="py-3 px-4 font-semibold text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E2E8F0] text-xs">
                {filtered.map((a) => (
                  <tr key={a.id} className="hover:bg-[#F8FAFC] transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-[#0F172A]">{a.name}</div>
                      <div className="text-[11px] text-[#64748B] font-mono">{a.target_url}</div>
                    </td>
                    <td className="py-3 px-4 text-[#475569] capitalize">
                      {a.environment.replace('_', ' ')} · {a.criticality}
                    </td>
                    <td className="py-3 px-4">
                      {a.ownership_status === 'verified' ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-[#BBF7D0] bg-[#F0FDF4] text-[#15803D] text-[11px] font-medium whitespace-nowrap">
                          <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Verified</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded border border-[#FDE68A] bg-[#FFFBEB] text-[#B45309] text-[11px] font-medium whitespace-nowrap">
                          <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
                          <span>Pending Verification</span>
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums font-medium text-[#0F172A]">
                      {a.latest_posture_score !== null ? `${a.latest_posture_score}/100` : '—'}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums font-medium text-[#0F172A]">
                      {a.open_findings ?? 0}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-[#64748B]">
                      {formatDateTime(a.last_scanned_at)}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-2">
                        {a.ownership_status !== 'verified' && canEdit && (
                          <button
                            type="button"
                            onClick={() => openVerifyModal(a)}
                            className="px-2.5 py-1 text-xs font-medium text-[#B45309] bg-[#FFFBEB] border border-[#FDE68A] hover:bg-[#FEF3C7] rounded-md transition-colors"
                          >
                            Verify Ownership
                          </button>
                        )}
                        {a.ownership_status === 'verified' && canEdit && (
                          <button
                            type="button"
                            onClick={() => onLaunchScanForAsset(a.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-[#1D4ED8] bg-[#EFF6FF] border border-[#BFDBFE] hover:bg-[#DBEAFE] rounded-md transition-colors"
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
                            className="p-1.5 text-[#94A3B8] hover:text-[#DC2626] hover:bg-[#FEF2F2] rounded-md transition-colors"
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
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="add-asset-title"
          className="fixed inset-0 z-50 bg-[#0F172A]/40 backdrop-blur-[1px] flex items-center justify-center p-4"
        >
          <div className="w-full max-w-lg bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl shadow-xl p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="add-asset-title" className="text-base font-semibold text-[#0F172A]">
                  Register Target Website or Application
                </h2>
                <p className="mt-1 text-xs text-[#64748B]">
                  Private, loopback, and cloud metadata IPs are blocked automatically by SSRF scope controls.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                aria-label="Close modal"
                className="p-1 text-[#64748B] hover:text-[#0F172A] rounded-md"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-3">
              <button
                type="button"
                onClick={handleLoadPracticePreset}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#1D4ED8] bg-[#EFF6FF] hover:bg-[#DBEAFE] border border-[#BFDBFE] rounded-md transition-colors"
              >
                <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Use Practice Lab Preset</span>
              </button>
            </div>

            <form onSubmit={handleAddAsset} className="mt-4 space-y-4">
              <div>
                <label htmlFor="asset-name" className="block text-xs font-medium text-[#334155] mb-1">
                  Application Name <span className="text-[#DC2626]">*</span>
                </label>
                <input
                  id="asset-name"
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Customer Portal Production"
                  className={inputClassName}
                />
              </div>

              <div>
                <label htmlFor="asset-url" className="block text-xs font-medium text-[#334155] mb-1">
                  Target Origin URL <span className="text-[#DC2626]">*</span>
                </label>
                <input
                  id="asset-url"
                  type="url"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://app.example.com"
                  className={`${inputClassName} font-mono`}
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="asset-env" className="block text-xs font-medium text-[#334155] mb-1">
                    Environment
                  </label>
                  <select
                    id="asset-env"
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value as typeof environment)}
                    className={`${selectClassName} w-full`}
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                    <option value="practice_lab">Practice Lab (Isolated)</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="asset-crit" className="block text-xs font-medium text-[#334155] mb-1">
                    Business Criticality
                  </label>
                  <select
                    id="asset-crit"
                    value={criticality}
                    onChange={(e) => setCriticality(e.target.value as typeof criticality)}
                    className={`${selectClassName} w-full`}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="asset-inc" className="block text-xs font-medium text-[#334155] mb-1">
                    Include Paths (comma-separated)
                  </label>
                  <input
                    id="asset-inc"
                    type="text"
                    value={scopeIncludePaths}
                    onChange={(e) => setScopeIncludePaths(e.target.value)}
                    className={`${inputClassName} font-mono`}
                  />
                </div>
                <div>
                  <label htmlFor="asset-exc" className="block text-xs font-medium text-[#334155] mb-1">
                    Exclude Paths
                  </label>
                  <input
                    id="asset-exc"
                    type="text"
                    value={scopeExcludePaths}
                    onChange={(e) => setScopeExcludePaths(e.target.value)}
                    className={`${inputClassName} font-mono`}
                  />
                </div>
              </div>

              <div className="pt-2 border-t border-[#E2E8F0] flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 text-xs font-medium text-[#475569] hover:text-[#0F172A] rounded-md"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 rounded-md shadow-xs"
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
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="verify-asset-title"
          className="fixed inset-0 z-50 bg-[#0F172A]/40 backdrop-blur-[1px] flex items-center justify-center p-4"
        >
          <div className="w-full max-w-xl bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl shadow-xl p-6">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 text-[#0F172A] font-semibold text-base">
                  <ShieldCheck className="w-5 h-5 text-[#2563EB]" aria-hidden="true" />
                  <h2 id="verify-asset-title">Verify Ownership &amp; Written Authorization</h2>
                </div>
                <p className="mt-1 text-xs text-[#64748B]">
                  Target: <span className="font-mono text-[#0F172A] font-medium">{verifyAsset.target_url}</span>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setVerifyAsset(null)}
                aria-label="Close authorization modal"
                className="p-1 text-[#64748B] hover:text-[#0F172A] rounded-md"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleVerifyOwnership} className="mt-4 space-y-4">
              <div>
                <label htmlFor="verify-method" className="block text-xs font-medium text-[#334155] mb-1">
                  Verification Mechanism
                </label>
                <select
                  id="verify-method"
                  value={verifyMethod}
                  onChange={(e) => setVerifyMethod(e.target.value as typeof verifyMethod)}
                  className={`${selectClassName} w-full`}
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

              <div className="p-3.5 bg-[#EFF6FF] border border-[#BFDBFE] rounded-md text-xs space-y-1.5">
                <div className="text-[#1E40AF] font-medium">Verification Token:</div>
                <div className="font-mono text-[#0F172A] bg-[#FFFFFF] border border-[#DBEAFE] px-2.5 py-1.5 rounded select-all break-all">
                  {getTokenForAsset(verifyAsset.id)}
                </div>
                {!verifyAsset.is_practice_target && (
                  <div className="text-[11px] text-[#1E40AF]/90 pt-0.5 leading-relaxed">
                    {verifyMethod === 'dns_txt' &&
                      (REQUIRE_DNS_OWNERSHIP_VERIFICATION
                        ? `Publish TXT record at _sentinelscan-verify.${verifyAsset.hostname} containing the token above.`
                        : 'Controlled testing mode active: DNS TXT record verification is bypassed. Provide written authorization below to proceed to scan configuration.')}
                    {verifyMethod === 'http_file' &&
                      `Host plain text file at ${verifyAsset.target_url}/.well-known/sentinelscan-verification.txt with this token.`}
                    {verifyMethod === 'html_meta' &&
                      `Add <meta name="sentinelscan-verification" content="${getTokenForAsset(verifyAsset.id)}" /> to homepage <head>.`}
                  </div>
                )}
              </div>

              <div>
                <label htmlFor="auth-signatory" className="block text-xs font-medium text-[#334155] mb-1">
                  Authorized Signatory Name <span className="text-[#DC2626]">*</span>
                </label>
                <input
                  id="auth-signatory"
                  type="text"
                  required
                  value={authorizedBy}
                  onChange={(e) => setAuthorizedBy(e.target.value)}
                  placeholder="Jane Doe, VP Security"
                  className={inputClassName}
                />
              </div>

              <div>
                <label htmlFor="auth-notes" className="block text-xs font-medium text-[#334155] mb-1">
                  Authorization Scope &amp; Ticket / Engagement Reference <span className="text-[#DC2626]">*</span>
                </label>
                <textarea
                  id="auth-notes"
                  required
                  rows={2}
                  value={authorizationNotes}
                  onChange={(e) => setAuthorizationNotes(e.target.value)}
                  placeholder="SEC-2026-412: Authorized non-destructive assessment window"
                  className={inputClassName}
                />
              </div>

              <label className="flex items-start gap-2.5 text-xs text-[#334155] cursor-pointer">
                <input
                  type="checkbox"
                  required
                  checked={confirmAuth}
                  onChange={(e) => setConfirmAuth(e.target.checked)}
                  className="mt-0.5 rounded border-[#CBD5E1] text-[#2563EB] focus:ring-[#2563EB]"
                />
                <span>
                  I confirm explicit written authorization to assess this target within its defined scope and rate limits.
                </span>
              </label>

              <div className="pt-2 border-t border-[#E2E8F0] flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setVerifyAsset(null)}
                  className="px-4 py-2 text-xs font-medium text-[#475569] hover:text-[#0F172A] rounded-md"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={verifying || !confirmAuth}
                  className="px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 rounded-md shadow-xs"
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
