import React, { useEffect, useState } from 'react';
import { Search, X, ExternalLink, ShieldAlert, ChevronRight } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { Asset, UserRole, Vulnerability } from '../types/sentinel';
import { formatDateTime, getVerificationStatusLabel } from '../utils/formatters';
import {
  CodeBlock,
  EmptyState,
  SeverityBadge,
  VerificationStatusBadge,
  inputClassName,
  selectClassName,
} from './ui';

interface FindingsViewProps {
  assets: Asset[];
  userRole: UserRole;
  initialSelectedFindingId: string | null;
  onClearInitialSelection: () => void;
  onRefreshParent: () => void;
  onToast: (msg: string, type?: 'success' | 'error') => void;
}

interface FindingDetailPayload {
  finding: Vulnerability;
  evidence: Array<{ id: string; evidence_type: string; summary: string; raw_excerpt: string; observed_at: string }>;
  history: Array<{ id: string; changed_by_name: string; previous_status: string; new_status: string; rationale: string; changed_at: string }>;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  assets,
  userRole,
  initialSelectedFindingId,
  onClearInitialSelection,
  onRefreshParent,
  onToast,
}) => {
  const [findings, setFindings] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [assetId, setAssetId] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 15;

  const [detail, setDetail] = useState<FindingDetailPayload | null>(null);
  const [nextStatus, setNextStatus] = useState('confirmed');
  const [rationale, setRationale] = useState('');
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const canTriage = userRole === 'admin' || userRole === 'analyst';

  const loadFindings = async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams();
      if (severity) qs.set('severity', severity);
      if (status) qs.set('status', status);
      if (assetId) qs.set('assetId', assetId);
      if (search.trim()) qs.set('search', search.trim());
      const res = await apiRequest<{ findings: Vulnerability[] }>(`/findings?${qs.toString()}`);
      setFindings(res.findings);
      setPage(1);
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to load findings', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [severity, status, assetId]);

  const openDetail = async (id: string) => {
    try {
      const res = await apiRequest<FindingDetailPayload>(`/findings/${id}`);
      setDetail(res);
      setNextStatus(res.finding.verification_status === 'open' ? 'confirmed' : res.finding.verification_status);
      setRationale('');
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to load finding details', 'error');
    }
  };

  useEffect(() => {
    if (initialSelectedFindingId) {
      openDetail(initialSelectedFindingId);
      onClearInitialSelection();
    }
  }, [initialSelectedFindingId]);

  const handleStatusUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!detail) return;
    setUpdatingStatus(true);
    try {
      await apiRequest(`/findings/${detail.finding.id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status: nextStatus, rationale }),
      });
      onToast(`Updated ${detail.finding.finding_code} status to ${getVerificationStatusLabel(nextStatus)}.`, 'success');
      await openDetail(detail.finding.id);
      await loadFindings();
      onRefreshParent();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to update status', 'error');
    } finally {
      setUpdatingStatus(false);
    }
  };

  const resetFilters = () => {
    setSeverity('');
    setStatus('');
    setAssetId('');
    setSearch('');
  };

  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const paged = findings.slice((page - 1) * pageSize, page * pageSize);

  const severityCounts = {
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    informational: findings.filter((f) => f.severity === 'informational').length,
  };

  return (
    <div className="space-y-5">
      {/* Severity Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg px-4 py-3">
          <div className="text-[11px] font-medium text-[#B91C1C]">Critical</div>
          <div className="mt-1 text-lg font-semibold font-mono tabular-nums text-[#DC2626]">{severityCounts.critical}</div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg px-4 py-3">
          <div className="text-[11px] font-medium text-[#C2410C]">High</div>
          <div className="mt-1 text-lg font-semibold font-mono tabular-nums text-[#EA580C]">{severityCounts.high}</div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg px-4 py-3">
          <div className="text-[11px] font-medium text-[#B45309]">Medium</div>
          <div className="mt-1 text-lg font-semibold font-mono tabular-nums text-[#D97706]">{severityCounts.medium}</div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg px-4 py-3">
          <div className="text-[11px] font-medium text-[#1D4ED8]">Low</div>
          <div className="mt-1 text-lg font-semibold font-mono tabular-nums text-[#2563EB]">{severityCounts.low}</div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg px-4 py-3 col-span-2 sm:col-span-1">
          <div className="text-[11px] font-medium text-[#64748B]">Informational</div>
          <div className="mt-1 text-lg font-semibold font-mono tabular-nums text-[#475569]">{severityCounts.informational}</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-3.5 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="w-4 h-4 text-[#94A3B8] absolute left-3 top-2.5" aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadFindings()}
            placeholder="Search by title, ID, URL, CWE, or CVE..."
            aria-label="Search vulnerabilities"
            className={`${inputClassName} pl-9`}
          />
        </div>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Filter by severity"
          className={selectClassName}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>

        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          aria-label="Filter by status"
          className={selectClassName}
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="confirmed">Confirmed</option>
          <option value="reopened">Reopened</option>
          <option value="remediated">Remediated</option>
          <option value="risk_accepted">Risk Accepted</option>
          <option value="false_positive">False Positive</option>
        </select>

        <select
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
          aria-label="Filter by asset"
          className={selectClassName}
        >
          <option value="">All Assets</option>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>

        <button
          type="button"
          onClick={loadFindings}
          className="px-3.5 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md transition-colors whitespace-nowrap"
        >
          Apply
        </button>

        {(severity || status || assetId || search) && (
          <button
            type="button"
            onClick={resetFilters}
            className="px-3 py-2 text-xs font-medium text-[#64748B] hover:text-[#0F172A] whitespace-nowrap"
          >
            Reset
          </button>
        )}
      </div>

      {/* Findings Data Table */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-3">
            {Array.from({ length: 5 }).map((_, idx) => (
              <div key={idx} className="h-12 bg-[#F8FAFC] border border-[#E2E8F0] rounded animate-pulse" />
            ))}
          </div>
        ) : paged.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No vulnerability findings match these filters"
            description="Adjust your severity, status, or target filters, or run a new security assessment on an authorized target."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B] bg-[#F8FAFC]">
                  <th className="py-3 px-4 font-semibold">Severity</th>
                  <th className="py-3 px-4 font-semibold">Finding &amp; Classification</th>
                  <th className="py-3 px-4 font-semibold">Affected Target</th>
                  <th className="py-3 px-4 font-semibold">Status</th>
                  <th className="py-3 px-4 font-semibold text-right">CVSS 4.0</th>
                  <th className="py-3 px-4 font-semibold text-right">Updated</th>
                  <th className="py-3 px-4 font-semibold text-right">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E2E8F0]">
                {paged.map((f) => (
                  <tr key={f.id} className="hover:bg-[#F8FAFC] transition-colors">
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3 px-4 max-w-md">
                      <button
                        type="button"
                        onClick={() => openDetail(f.id)}
                        className="text-left font-semibold text-[#0F172A] hover:text-[#2563EB] block"
                      >
                        {f.title}
                      </button>
                      <div className="mt-0.5 text-[11px] text-[#64748B] font-mono">
                        {f.finding_code} · {[f.cwe_id, f.cve_id, f.owasp_category, f.owasp_api_category].filter(Boolean).join(' · ')}
                      </div>
                    </td>
                    <td className="py-3 px-4 max-w-xs">
                      <div className="text-[#334155] font-medium truncate">{f.asset_name}</div>
                      <div className="text-[11px] text-[#64748B] font-mono truncate">
                        {f.http_method ? `${f.http_method} ` : ''}{f.affected_url}
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <VerificationStatusBadge status={f.verification_status} />
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums font-semibold text-[#0F172A]">
                      {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums text-[#64748B]">
                      {formatDateTime(f.updated_at)}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => openDetail(f.id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-[#2563EB] bg-[#EFF6FF] hover:bg-[#DBEAFE] border border-[#BFDBFE] rounded transition-colors"
                      >
                        <span>Details</span>
                        <ChevronRight className="w-3 h-3" aria-hidden="true" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {findings.length > pageSize && (
          <div className="px-4 py-3 border-t border-[#E2E8F0] bg-[#F8FAFC] flex items-center justify-between text-xs text-[#64748B]">
            <span className="font-mono tabular-nums">
              Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, findings.length)} of {findings.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="px-3 py-1 bg-[#FFFFFF] border border-[#CBD5E1] text-[#0F172A] hover:bg-[#F1F5F9] rounded-md disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
                className="px-3 py-1 bg-[#FFFFFF] border border-[#CBD5E1] text-[#0F172A] hover:bg-[#F1F5F9] rounded-md disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Finding Technical Evidence Slide-Over */}
      {detail && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="finding-detail-title"
          className="fixed inset-0 z-50 bg-[#0F172A]/40 backdrop-blur-[1px] flex justify-end"
        >
          <div className="w-full max-w-2xl bg-[#FFFFFF] border-l border-[#E2E8F0] shadow-2xl h-full overflow-y-auto p-6 space-y-6">
            <div className="flex items-start justify-between gap-4 border-b border-[#E2E8F0] pb-4">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={detail.finding.severity} />
                  <VerificationStatusBadge status={detail.finding.verification_status} />
                  <span className="text-xs font-mono text-[#64748B]">
                    {detail.finding.finding_code} · {detail.finding.scanner_module} · Confidence: {detail.finding.confidence}
                  </span>
                </div>
                <h2 id="finding-detail-title" className="mt-2 text-lg font-semibold text-[#0F172A] leading-snug">
                  {detail.finding.title}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setDetail(null)}
                aria-label="Close finding details"
                className="p-1.5 text-[#64748B] hover:text-[#0F172A] hover:bg-[#F1F5F9] rounded-md border border-[#E2E8F0]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-md">
                <div className="text-[#64748B]">Severity</div>
                <div className="mt-1 font-semibold capitalize text-[#0F172A]">{detail.finding.severity}</div>
              </div>
              <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-md">
                <div className="text-[#64748B]">CVSS 4.0</div>
                <div className="mt-1 font-mono tabular-nums font-semibold text-[#0F172A]">
                  {detail.finding.cvss_score !== null ? detail.finding.cvss_score.toFixed(1) : 'Not scored'}
                </div>
              </div>
              <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-md">
                <div className="text-[#64748B]">CWE / CVE</div>
                <div className="mt-1 font-mono text-[#0F172A] truncate">
                  {detail.finding.cve_id || detail.finding.cwe_id || '—'}
                </div>
              </div>
              <div className="p-3 bg-[#F8FAFC] border border-[#E2E8F0] rounded-md">
                <div className="text-[#64748B]">OWASP</div>
                <div className="mt-1 font-mono text-[#0F172A] truncate">
                  {detail.finding.owasp_api_category || detail.finding.owasp_category || '—'}
                </div>
              </div>
            </div>

            <div className="space-y-5 text-xs">
              <div>
                <h3 className="font-semibold text-[#0F172A] mb-1.5">Affected Component</h3>
                <CodeBlock
                  label="Target Endpoint & Parameter"
                  content={`${detail.finding.http_method ? `${detail.finding.http_method} ` : ''}${detail.finding.affected_url}${
                    detail.finding.parameter_name ? `\nParameter: ${detail.finding.parameter_name}` : ''
                  }`}
                />
              </div>

              <div>
                <h3 className="font-semibold text-[#0F172A] mb-1.5">Description &amp; Technical Explanation</h3>
                <p className="text-[#334155] leading-relaxed">{detail.finding.description}</p>
                <p className="mt-2 text-[#475569] leading-relaxed">{detail.finding.technical_explanation}</p>
                {detail.finding.detection_technique && (
                  <div className="mt-2 px-3 py-2 bg-[#EFF6FF] border border-[#BFDBFE] rounded-md text-[11px] text-[#1E40AF] font-mono">
                    Detection Technique: {detail.finding.detection_technique}
                  </div>
                )}
                <p className="mt-2 text-[11px] text-[#64748B]">
                  CVSS Rationale: {detail.finding.cvss_rationale}
                  {detail.finding.cvss_vector ? ` (${detail.finding.cvss_vector})` : ''}
                </p>
              </div>

              {/* Evidence Viewer */}
              <div>
                <h3 className="font-semibold text-[#0F172A] mb-2">Collected Technical Evidence</h3>
                <div className="space-y-2.5">
                  {detail.evidence.map((ev) => (
                    <CodeBlock
                      key={ev.id}
                      label={`${ev.evidence_type} · ${ev.summary}`}
                      content={ev.raw_excerpt}
                    />
                  ))}
                </div>
              </div>

              <div>
                <h3 className="font-semibold text-[#0F172A] mb-1.5">Business Impact &amp; Remediation</h3>
                <p className="text-[#475569] leading-relaxed">{detail.finding.business_impact}</p>
                <div className="mt-2.5 p-3.5 bg-[#EFF6FF] border border-[#BFDBFE] rounded-md text-[#1E3A8A] leading-relaxed">
                  {detail.finding.remediation_instructions}
                </div>
              </div>

              {detail.finding.references && detail.finding.references.length > 0 && (
                <div>
                  <h3 className="font-semibold text-[#0F172A] mb-1.5">References</h3>
                  <div className="flex flex-wrap gap-3">
                    {detail.finding.references.map((ref) => (
                      <a
                        key={ref}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-[#2563EB] hover:text-[#1E40AF] hover:underline"
                      >
                        <span>{ref}</span>
                        <ExternalLink className="w-3 h-3" aria-hidden="true" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Remediation & Verification Workflow */}
              {canTriage && (
                <form onSubmit={handleStatusUpdate} className="pt-4 border-t border-[#E2E8F0] space-y-3">
                  <h3 className="font-semibold text-[#0F172A]">Update Verification Status</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <select
                      value={nextStatus}
                      onChange={(e) => setNextStatus(e.target.value)}
                      aria-label="New verification status"
                      className={selectClassName}
                    >
                      <option value="open">Open</option>
                      <option value="confirmed">Confirmed</option>
                      <option value="remediated">Remediated</option>
                      <option value="risk_accepted">Risk Accepted</option>
                      <option value="false_positive">False Positive</option>
                      <option value="reopened">Reopened</option>
                    </select>
                    <input
                      type="text"
                      required
                      value={rationale}
                      onChange={(e) => setRationale(e.target.value)}
                      placeholder="Rationale (e.g. Patched CSP header in Nginx)"
                      className={`${inputClassName} sm:col-span-2`}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={updatingStatus}
                    className="px-4 py-2 font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 rounded-md shadow-xs"
                  >
                    {updatingStatus ? 'Saving...' : 'Save Status Change'}
                  </button>
                </form>
              )}

              {/* Status Audit History */}
              <div className="pt-4 border-t border-[#E2E8F0]">
                <h3 className="font-semibold text-[#0F172A] mb-2">Status Audit History</h3>
                <div className="space-y-1.5">
                  {detail.history.map((h) => (
                    <div key={h.id} className="text-[11px] text-[#64748B] bg-[#F8FAFC] border border-[#E2E8F0] rounded px-3 py-2">
                      <span className="font-mono text-[#64748B]">{formatDateTime(h.changed_at)}</span> ·{' '}
                      <span className="font-medium text-[#0F172A]">{h.changed_by_name}</span>{' '}
                      <span>changed </span>
                      <span className="font-mono text-[#475569]">{h.previous_status}</span> →{' '}
                      <span className="font-mono font-semibold text-[#2563EB]">{h.new_status}</span>: {h.rationale}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
