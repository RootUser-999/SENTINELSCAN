import React, { useEffect, useState } from 'react';
import { Search, X, ExternalLink } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { Asset, UserRole, Vulnerability } from '../types/sentinel';
import { formatDateTime, getSeverityStyle, getVerificationStatusLabel } from '../utils/formatters';

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

  const totalPages = Math.max(1, Math.ceil(findings.length / pageSize));
  const paged = findings.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="space-y-5">
      {/* Filter Bar */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && loadFindings()}
            placeholder="Search by title, ID, URL, CWE, or CVE..."
            aria-label="Search vulnerabilities"
            className="w-full pl-9 pr-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100 placeholder-slate-500"
          />
        </div>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Filter by severity"
          className="px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-200"
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
          className="px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-200"
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
          className="px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-200"
        >
          <option value="">All Assets</option>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>

        <button
          type="button"
          onClick={loadFindings}
          className="px-3.5 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded"
        >
          Apply
        </button>
      </div>

      {/* Findings Data Table */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
        {loading ? (
          <div className="p-8 text-xs text-slate-400">Loading findings...</div>
        ) : paged.length === 0 ? (
          <div className="p-10 text-center text-xs text-slate-400">
            No findings match the current filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 bg-[#0B111E]">
                  <th className="py-3 px-4 font-medium">Severity</th>
                  <th className="py-3 px-4 font-medium">Finding & Classification</th>
                  <th className="py-3 px-4 font-medium">Affected Target</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium text-right">CVSS 4.0</th>
                  <th className="py-3 px-4 font-medium text-right">Updated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {paged.map((f) => {
                  const sev = getSeverityStyle(f.severity);
                  return (
                    <tr key={f.id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`inline-block px-2 py-0.5 rounded border text-[11px] font-medium ${sev.text} ${sev.border} ${sev.bg}`}>
                          {sev.label}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-md">
                        <button
                          type="button"
                          onClick={() => openDetail(f.id)}
                          className="text-left font-medium text-slate-100 hover:text-blue-400 block"
                        >
                          {f.title}
                        </button>
                        <div className="mt-0.5 text-[11px] text-slate-500 font-mono">
                          {f.finding_code} · {[f.cwe_id, f.cve_id, f.owasp_category, f.owasp_api_category].filter(Boolean).join(' · ')}
                        </div>
                      </td>
                      <td className="py-3 px-4 max-w-xs">
                        <div className="text-slate-300 truncate">{f.asset_name}</div>
                        <div className="text-[11px] text-slate-500 font-mono truncate">{f.affected_url}</div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                        {getVerificationStatusLabel(f.verification_status)}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-200">
                        {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums text-slate-400">
                        {formatDateTime(f.updated_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {findings.length > pageSize && (
          <div className="px-4 py-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span className="font-mono tabular-nums">
              Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, findings.length)} of {findings.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="px-3 py-1 bg-slate-800 rounded disabled:opacity-40"
              >
                Previous
              </button>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
                className="px-3 py-1 bg-slate-800 rounded disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Finding Detail Slide-Over */}
      {detail && (
        <div role="dialog" aria-modal="true" aria-labelledby="finding-detail-title" className="fixed inset-0 z-50 bg-black/70 flex justify-end">
          <div className="w-full max-w-2xl bg-[#0F172A] border-l border-slate-800 h-full overflow-y-auto p-6 space-y-6">
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <div className="text-xs font-mono text-slate-400">
                  {detail.finding.finding_code} · {detail.finding.scanner_module} · Confidence: {detail.finding.confidence}
                </div>
                <h2 id="finding-detail-title" className="mt-1 text-lg font-semibold text-slate-100">
                  {detail.finding.title}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setDetail(null)}
                aria-label="Close finding details"
                className="p-1.5 text-slate-400 hover:text-white rounded border border-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="text-slate-500">Severity</div>
                <div className="mt-1 font-semibold capitalize text-slate-100">{detail.finding.severity}</div>
              </div>
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="text-slate-500">CVSS 4.0</div>
                <div className="mt-1 font-mono font-semibold text-slate-100">
                  {detail.finding.cvss_score !== null ? detail.finding.cvss_score.toFixed(1) : 'Not scored'}
                </div>
              </div>
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="text-slate-500">CWE / CVE</div>
                <div className="mt-1 font-mono text-slate-200 truncate">
                  {detail.finding.cve_id || detail.finding.cwe_id || '—'}
                </div>
              </div>
              <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                <div className="text-slate-500">OWASP</div>
                <div className="mt-1 font-mono text-slate-200 truncate">
                  {detail.finding.owasp_api_category || detail.finding.owasp_category || '—'}
                </div>
              </div>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <h3 className="font-semibold text-slate-200 mb-1">Affected Component</h3>
                <div className="p-2.5 bg-[#090D16] border border-slate-800 rounded font-mono text-slate-300 break-all">
                  {detail.finding.http_method ? `${detail.finding.http_method} ` : ''}{detail.finding.affected_url}
                  {detail.finding.parameter_name ? ` (parameter: ${detail.finding.parameter_name})` : ''}
                </div>
              </div>

              <div>
                <h3 className="font-semibold text-slate-200 mb-1">Description & Technical Explanation</h3>
                <p className="text-slate-300 leading-relaxed">{detail.finding.description}</p>
                <p className="mt-1.5 text-slate-400 leading-relaxed">{detail.finding.technical_explanation}</p>
                {detail.finding.detection_technique && (
                  <p className="mt-1.5 text-[11px] text-blue-300 font-mono">
                    Detection Technique: {detail.finding.detection_technique}
                  </p>
                )}
                <p className="mt-1.5 text-[11px] text-slate-500">
                  CVSS Rationale: {detail.finding.cvss_rationale}
                  {detail.finding.cvss_vector ? ` (${detail.finding.cvss_vector})` : ''}
                </p>
              </div>

              {/* Evidence Viewer */}
              <div>
                <h3 className="font-semibold text-slate-200 mb-1.5">Collected Technical Evidence</h3>
                <div className="space-y-2">
                  {detail.evidence.map((ev) => (
                    <div key={ev.id} className="bg-[#090D16] border border-slate-800 rounded p-3">
                      <div className="text-[11px] text-blue-400 font-medium mb-1">
                        {ev.evidence_type} · {ev.summary}
                      </div>
                      <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-all">
                        {ev.raw_excerpt}
                      </pre>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="font-semibold text-slate-200 mb-1">Business Impact & Remediation</h3>
                <p className="text-slate-400">{detail.finding.business_impact}</p>
                <div className="mt-2 p-3 bg-blue-950/20 border border-blue-900/50 rounded text-slate-200 leading-relaxed">
                  {detail.finding.remediation_instructions}
                </div>
              </div>

              {detail.finding.references && detail.finding.references.length > 0 && (
                <div>
                  <h3 className="font-semibold text-slate-200 mb-1">References</h3>
                  <div className="space-y-1">
                    {detail.finding.references.map((ref) => (
                      <a
                        key={ref}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-400 hover:underline mr-4"
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
                <form onSubmit={handleStatusUpdate} className="pt-4 border-t border-slate-800 space-y-3">
                  <h3 className="font-semibold text-slate-200">Update Verification Status</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <select
                      value={nextStatus}
                      onChange={(e) => setNextStatus(e.target.value)}
                      aria-label="New verification status"
                      className="px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
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
                      className="sm:col-span-2 px-3 py-2 bg-[#090D16] border border-slate-700 rounded text-slate-100"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={updatingStatus}
                    className="px-4 py-2 font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded"
                  >
                    {updatingStatus ? 'Saving...' : 'Save Status Change'}
                  </button>
                </form>
              )}

              {/* Status Audit History */}
              <div className="pt-3 border-t border-slate-800">
                <h3 className="font-semibold text-slate-200 mb-2">Status Audit History</h3>
                <div className="space-y-1.5">
                  {detail.history.map((h) => (
                    <div key={h.id} className="text-[11px] text-slate-400">
                      <span className="font-mono text-slate-500">{formatDateTime(h.changed_at)}</span> ·{' '}
                      <span className="text-slate-200">{h.changed_by_name}</span>{' '}
                      <span>changed </span>
                      <span className="font-mono">{h.previous_status}</span> →{' '}
                      <span className="font-mono text-blue-400">{h.new_status}</span>: {h.rationale}
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
