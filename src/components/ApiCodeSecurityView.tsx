import React, { useEffect, useState } from 'react';
import { apiRequest } from '../api/client';
import type { EndpointRow, ScanRecord, Vulnerability } from '../types/sentinel';
import { getSeverityStyle } from '../utils/formatters';

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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#0F172A] border border-slate-800 rounded-md p-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">API Inventory, SCA Dependencies & SAST Code Findings</h2>
          <p className="text-xs text-slate-400">Inspect discovered endpoints, OpenAPI routes, OSV dependency CVEs, and static analysis findings.</p>
        </div>
        {completedScans.length > 0 && (
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            aria-label="Select assessment scan"
            className="px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
          >
            {completedScans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.asset_name} · {s.profile} ({new Date(s.created_at).toLocaleDateString()})
              </option>
            ))}
          </select>
        )}
      </div>

      {/* API Endpoint Inventory */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-100">API & Application Endpoint Inventory ({endpoints.length})</h3>
        </div>
        {endpoints.length === 0 ? (
          <div className="p-6 text-xs text-slate-500">
            No endpoints inventoried for this scan yet. Run a Standard or Comprehensive scan (with optional OpenAPI spec) to populate endpoint discovery.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 bg-[#0B111E]">
                  <th className="py-2.5 px-4 font-medium">Method</th>
                  <th className="py-2.5 px-4 font-medium">Path</th>
                  <th className="py-2.5 px-4 font-medium">Source</th>
                  <th className="py-2.5 px-4 font-medium">Auth Scheme</th>
                  <th className="py-2.5 px-4 font-medium text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 font-mono font-semibold text-blue-400">{ep.method}</td>
                    <td className="py-2.5 px-4 font-mono text-slate-200">{ep.path}</td>
                    <td className="py-2.5 px-4 text-slate-400">{ep.source}</td>
                    <td className="py-2.5 px-4 text-slate-300">{ep.auth_required}</td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-300">
                      {ep.status_code ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* SCA & SAST Grids */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">Dependency Vulnerabilities — SCA ({scaFindings.length})</h3>
          </div>
          {scaFindings.length === 0 ? (
            <div className="p-6 text-xs text-slate-500">
              No vulnerable dependencies reported for this scan. Attach a package.json, lockfile, or requirements.txt during scan launch to run OSV CVE checks.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {scaFindings.map((f) => {
                const sev = getSeverityStyle(f.severity);
                return (
                  <div key={f.id} className="p-4 hover:bg-slate-800/30">
                    <div className="flex items-center justify-between gap-2">
                      <button type="button" onClick={() => onSelectFinding(f.id)} className="text-xs font-medium text-slate-100 hover:text-blue-400 text-left">
                        {f.title}
                      </button>
                      <span className={`text-[11px] font-medium ${sev.text}`}>{sev.label}</span>
                    </div>
                    <div className="mt-1 text-[11px] font-mono text-slate-400">{f.cve_id || f.finding_code} · {f.affected_url}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-100">Static Code Findings — SAST ({sastFindings.length})</h3>
          </div>
          {sastFindings.length === 0 ? (
            <div className="p-6 text-xs text-slate-500">
              No static analysis findings for this scan. Submit authorized source code in Scan Configuration to inspect secrets, crypto, and injection sinks.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {sastFindings.map((f) => {
                const sev = getSeverityStyle(f.severity);
                return (
                  <div key={f.id} className="p-4 hover:bg-slate-800/30">
                    <div className="flex items-center justify-between gap-2">
                      <button type="button" onClick={() => onSelectFinding(f.id)} className="text-xs font-medium text-slate-100 hover:text-blue-400 text-left">
                        {f.title}
                      </button>
                      <span className={`text-[11px] font-medium ${sev.text}`}>{sev.label}</span>
                    </div>
                    <div className="mt-1 text-[11px] font-mono text-slate-400">{f.cwe_id} · {f.affected_url}</div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
