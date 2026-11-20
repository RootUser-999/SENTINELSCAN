import React, { useEffect, useState } from 'react';
import { Code2, Search } from 'lucide-react';
import { apiRequest } from '../api/client';
import type { EndpointRow, ScanRecord, Vulnerability } from '../types/sentinel';
import { EmptyState, MethodBadge, SeverityBadge, inputClassName, selectClassName } from './ui';

interface ApiCodeSecurityViewProps {
  scans: ScanRecord[];
  onSelectFinding: (id: string) => void;
}

export const ApiCodeSecurityView: React.FC<ApiCodeSecurityViewProps> = ({ scans, onSelectFinding }) => {
  const completedScans = scans.filter((s) => s.status === 'completed');
  const [selectedScanId, setSelectedScanId] = useState(completedScans[0]?.id || '');
  const [endpoints, setEndpoints] = useState<EndpointRow[]>([]);
  const [scaFindings, setScaFindings] = useState<Vulnerability[]>([]);
  const [sastFindings, setSastFindings] = useState<Vulnerability[]>([]);
  const [endpointSearch, setEndpointSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState('ALL');

  useEffect(() => {
    if (!selectedScanId && completedScans.length > 0) {
      setSelectedScanId(completedScans[0].id);
    }
  }, [completedScans, selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) return;
    apiRequest<{ endpoints: EndpointRow[]; findings: Vulnerability[] }>(`/scans/${selectedScanId}`)
      .then((res) => {
        setEndpoints(res.endpoints || []);
        setScaFindings((res.findings || []).filter((f) => f.scanner_module === 'dependency-sca'));
        setSastFindings((res.findings || []).filter((f) => f.scanner_module === 'static-code-sast'));
      })
      .catch(() => {
        // handled cleanly by empty state
      });
  }, [selectedScanId]);

  const filteredEndpoints = endpoints.filter((ep) => {
    const matchesMethod = methodFilter === 'ALL' || ep.method.toUpperCase() === methodFilter;
    const q = endpointSearch.trim().toLowerCase();
    const matchesQ =
      !q ||
      ep.path.toLowerCase().includes(q) ||
      ep.source.toLowerCase().includes(q) ||
      ep.auth_required.toLowerCase().includes(q);
    return matchesMethod && matchesQ;
  });

  return (
    <div className="space-y-6">
      {/* Header & Scan Selector */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-[#0F172A]">Attack Surface Inventory, SCA Dependencies &amp; SAST Findings</h2>
          <p className="mt-0.5 text-xs text-[#64748B]">
            Inspect discovered endpoints, OpenAPI routes, OSV dependency CVEs, and static analysis findings.
          </p>
        </div>
        {completedScans.length > 0 && (
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            aria-label="Select assessment scan"
            className={`${selectClassName} min-w-[260px]`}
          >
            {completedScans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.asset_name} · {s.profile} ({new Date(s.created_at).toLocaleDateString()})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Summary Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Discovered Endpoints</div>
          <div className="mt-1.5 text-2xl font-semibold font-mono tabular-nums text-[#2563EB]">
            {endpoints.length}
          </div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Dependency CVEs (OSV SCA)</div>
          <div className="mt-1.5 text-2xl font-semibold font-mono tabular-nums text-[#0F172A]">
            {scaFindings.length}
          </div>
        </div>
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Static Code Issues (SAST)</div>
          <div className="mt-1.5 text-2xl font-semibold font-mono tabular-nums text-[#0F172A]">
            {sastFindings.length}
          </div>
        </div>
      </div>

      {/* API Endpoint Inventory */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-[#E2E8F0] flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-[#0F172A]">
            API &amp; Application Endpoint Inventory ({filteredEndpoints.length})
          </h3>
          {endpoints.length > 0 && (
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-[#94A3B8] absolute left-2.5 top-2" aria-hidden="true" />
                <input
                  type="search"
                  value={endpointSearch}
                  onChange={(e) => setEndpointSearch(e.target.value)}
                  placeholder="Search path or source..."
                  aria-label="Search API endpoints"
                  className={`${inputClassName} pl-8 py-1 w-48`}
                />
              </div>
              <select
                value={methodFilter}
                onChange={(e) => setMethodFilter(e.target.value)}
                aria-label="Filter by HTTP method"
                className={`${selectClassName} py-1`}
              >
                <option value="ALL">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
          )}
        </div>

        {filteredEndpoints.length === 0 ? (
          <EmptyState
            icon={Code2}
            title="No endpoints inventoried for this scan"
            description="Run a Standard or Comprehensive scan (with optional OpenAPI spec) to populate discovered routes, forms, and API endpoints."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B] bg-[#F8FAFC]">
                  <th className="py-2.5 px-4 font-semibold">Method</th>
                  <th className="py-2.5 px-4 font-semibold">Path</th>
                  <th className="py-2.5 px-4 font-semibold">Source</th>
                  <th className="py-2.5 px-4 font-semibold">Auth Scheme</th>
                  <th className="py-2.5 px-4 font-semibold">Parameters</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E2E8F0]">
                {filteredEndpoints.map((ep) => {
                  let params: string[] = [];
                  try {
                    params = JSON.parse(ep.parameters_json || '[]') as string[];
                  } catch {
                    params = [];
                  }
                  return (
                    <tr key={ep.id} className="hover:bg-[#F8FAFC] transition-colors">
                      <td className="py-2.5 px-4">
                        <MethodBadge method={ep.method} />
                      </td>
                      <td className="py-2.5 px-4 font-mono text-[#0F172A]">{ep.path}</td>
                      <td className="py-2.5 px-4 text-[#64748B]">{ep.source}</td>
                      <td className="py-2.5 px-4 text-[#334155]">{ep.auth_required}</td>
                      <td className="py-2.5 px-4 font-mono text-[11px] text-[#64748B]">
                        {params.join(', ') || '—'}
                      </td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums font-medium text-[#0F172A]">
                        {ep.status_code ?? '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SCA & SAST Grids */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#E2E8F0]">
            <h3 className="text-sm font-semibold text-[#0F172A]">
              Dependency Vulnerabilities — SCA ({scaFindings.length})
            </h3>
          </div>
          {scaFindings.length === 0 ? (
            <div className="p-6 text-xs text-[#64748B]">
              No vulnerable dependencies reported for this scan. Attach a package.json, lockfile, or requirements.txt during scan launch to run OSV CVE checks.
            </div>
          ) : (
            <div className="divide-y divide-[#E2E8F0]">
              {scaFindings.map((f) => (
                <div key={f.id} className="p-4 hover:bg-[#F8FAFC] transition-colors">
                  <div className="flex items-center justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => onSelectFinding(f.id)}
                      className="text-xs font-semibold text-[#0F172A] hover:text-[#2563EB] text-left"
                    >
                      {f.title}
                    </button>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <div className="mt-1 text-[11px] font-mono text-[#64748B]">
                    {f.cve_id || f.finding_code} · {f.affected_url}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#E2E8F0]">
            <h3 className="text-sm font-semibold text-[#0F172A]">
              Static Code Findings — SAST ({sastFindings.length})
            </h3>
          </div>
          {sastFindings.length === 0 ? (
            <div className="p-6 text-xs text-[#64748B]">
              No static analysis findings for this scan. Submit authorized source code in Scan Configuration to inspect secrets, crypto, and injection sinks.
            </div>
          ) : (
            <div className="divide-y divide-[#E2E8F0]">
              {sastFindings.map((f) => (
                <div key={f.id} className="p-4 hover:bg-[#F8FAFC] transition-colors">
                  <div className="flex items-center justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => onSelectFinding(f.id)}
                      className="text-xs font-semibold text-[#0F172A] hover:text-[#2563EB] text-left"
                    >
                      {f.title}
                    </button>
                    <SeverityBadge severity={f.severity} />
                  </div>
                  <div className="mt-1 text-[11px] font-mono text-[#64748B]">
                    {f.cwe_id} · {f.affected_url}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
