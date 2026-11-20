import React, { useEffect, useState } from 'react';
import { FileDown, FileSpreadsheet, FileJson, Info } from 'lucide-react';
import { apiRequest, downloadAuthenticatedBlob } from '../api/client';
import type { ScanRecord } from '../types/sentinel';
import { formatBytes, formatDateTime } from '../utils/formatters';

interface ComplianceReportsViewProps {
  scans: ScanRecord[];
  onToast: (msg: string, type?: 'success' | 'error') => void;
}

interface FrameworkRow {
  id: string;
  code: string;
  name: string;
  version: string;
  description: string;
}

interface ControlRow {
  id: string;
  framework_id: string;
  control_code: string;
  title: string;
  category: string;
  evidence_required: string;
}

interface MappingRow {
  framework_id: string;
  control_id: string;
  status: 'passed' | 'failed' | 'not_assessed' | 'partial';
  notes: string;
}

interface ReportHistoryRow {
  id: string;
  asset_name: string;
  profile: string;
  format: string;
  export_scope: string;
  filename: string;
  file_size_bytes: number;
  generated_by_name: string;
  created_at: string;
}

const CSV_SCOPES = [
  { id: 'all-findings', label: 'All Findings' },
  { id: 'passed-checks', label: 'Passed Checks' },
  { id: 'failed-checks', label: 'Failed Checks' },
  { id: 'vulnerability-inventory', label: 'Vulnerability Inventory' },
  { id: 'endpoint-inventory', label: 'Endpoint Inventory' },
  { id: 'security-headers', label: 'Security Headers' },
  { id: 'compliance-mapping', label: 'Compliance Mapping' },
];

export const ComplianceReportsView: React.FC<ComplianceReportsViewProps> = ({ scans, onToast }) => {
  const completedScans = scans.filter((s) => s.status === 'completed');
  const [selectedScanId, setSelectedScanId] = useState(completedScans[0]?.id || '');
  const [csvScope, setCsvScope] = useState('all-findings');
  const [downloading, setDownloading] = useState<string | null>(null);

  const [frameworks, setFrameworks] = useState<FrameworkRow[]>([]);
  const [controls, setControls] = useState<ControlRow[]>([]);
  const [mappings, setMappings] = useState<MappingRow[]>([]);
  const [notice, setNotice] = useState('');
  const [activeFrameworkId, setActiveFrameworkId] = useState('fw-owasp-top10');
  const [reportHistory, setReportHistory] = useState<ReportHistoryRow[]>([]);

  useEffect(() => {
    if (!selectedScanId && completedScans.length > 0) {
      setSelectedScanId(completedScans[0].id);
    }
  }, [completedScans, selectedScanId]);

  const loadComplianceAndHistory = async () => {
    try {
      const [compRes, repRes] = await Promise.all([
        apiRequest<{
          frameworks: FrameworkRow[];
          controls: ControlRow[];
          mappings: MappingRow[];
          nonCertificationNotice: string;
        }>(`/compliance${selectedScanId ? `?scanId=${encodeURIComponent(selectedScanId)}` : ''}`),
        apiRequest<{ reports: ReportHistoryRow[] }>('/reports'),
      ]);
      setFrameworks(compRes.frameworks);
      setControls(compRes.controls);
      setMappings(compRes.mappings);
      setNotice(compRes.nonCertificationNotice);
      setReportHistory(repRes.reports);
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to load compliance data', 'error');
    }
  };

  useEffect(() => {
    loadComplianceAndHistory();
  }, [selectedScanId]);

  const handleExport = async (kind: 'pdf' | 'csv' | 'json') => {
    if (!selectedScanId) {
      onToast('Complete an assessment scan before generating a report.', 'error');
      return;
    }
    setDownloading(kind);
    try {
      if (kind === 'pdf') {
        await downloadAuthenticatedBlob(`/reports/${selectedScanId}/pdf`, `sentinelscan-report.pdf`);
      } else if (kind === 'csv') {
        await downloadAuthenticatedBlob(`/reports/${selectedScanId}/csv?scope=${csvScope}`, `sentinelscan-${csvScope}.csv`);
      } else {
        await downloadAuthenticatedBlob(`/reports/${selectedScanId}/json`, `sentinelscan-report.json`);
      }
      onToast(`Generated and downloaded ${kind.toUpperCase()} report.`, 'success');
      loadComplianceAndHistory();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Report export failed', 'error');
    } finally {
      setDownloading(null);
    }
  };

  const activeControls = controls.filter((c) => c.framework_id === activeFrameworkId);
  const mappingByControl = new Map(mappings.map((m) => [m.control_id, m]));

  return (
    <div className="space-y-6">
      {/* Report Export Panel */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">Security Assessment Report Generator</h2>
            <p className="text-xs text-slate-400">Export verified scan evidence, charts, header tables, and remediation roadmaps in PDF, CSV, or JSON.</p>
          </div>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            aria-label="Select completed scan for export"
            className="px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100 min-w-[260px]"
          >
            {completedScans.length === 0 ? (
              <option value="">No completed scans available</option>
            ) : (
              completedScans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.asset_name} · {s.profile} · {formatDateTime(s.completed_at)}
                </option>
              ))
            )}
          </select>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-[#090D16] border border-slate-800 rounded flex flex-col justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-100">Executive & Technical PDF Report</div>
              <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
                Multi-page consulting report with cover page, severity charts, technical findings, headers, compliance matrix, and roadmap.
              </p>
            </div>
            <button
              type="button"
              disabled={!selectedScanId || downloading !== null}
              onClick={() => handleExport('pdf')}
              className="mt-4 inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-40 rounded"
            >
              <FileDown className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{downloading === 'pdf' ? 'Rendering PDF...' : 'Download PDF Report'}</span>
            </button>
          </div>

          <div className="p-4 bg-[#090D16] border border-slate-800 rounded flex flex-col justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-100">Scoped CSV Inventory Export</div>
              <label htmlFor="csv-scope-select" className="block mt-2 text-[11px] text-slate-400 mb-1">
                Export Dataset Scope
              </label>
              <select
                id="csv-scope-select"
                value={csvScope}
                onChange={(e) => setCsvScope(e.target.value)}
                className="w-full px-2.5 py-1.5 text-xs bg-[#0F172A] border border-slate-700 rounded text-slate-200"
              >
                {CSV_SCOPES.map((sc) => (
                  <option key={sc.id} value={sc.id}>{sc.label}</option>
                ))}
              </select>
            </div>
            <button
              type="button"
              disabled={!selectedScanId || downloading !== null}
              onClick={() => handleExport('csv')}
              className="mt-4 inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-40 rounded"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{downloading === 'csv' ? 'Exporting CSV...' : 'Download CSV'}</span>
            </button>
          </div>

          <div className="p-4 bg-[#090D16] border border-slate-800 rounded flex flex-col justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-100">Structured JSON Telemetry Bundle</div>
              <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
                Complete machine-readable dataset for SIEM ingestion, CI/CD gates, and archival diffing.
              </p>
            </div>
            <button
              type="button"
              disabled={!selectedScanId || downloading !== null}
              onClick={() => handleExport('json')}
              className="mt-4 inline-flex items-center justify-center gap-2 px-4 py-2 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 disabled:opacity-40 rounded"
            >
              <FileJson className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{downloading === 'json' ? 'Exporting JSON...' : 'Download JSON'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Compliance Framework Mapping */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
        <div className="p-5 border-b border-slate-800 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <h2 className="text-sm font-semibold text-slate-100">Compliance & Security Framework Coverage</h2>
          </div>
          {notice && (
            <div className="flex items-start gap-2 p-3 bg-[#090D16] border border-slate-800 rounded text-xs text-slate-300">
              <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" aria-hidden="true" />
              <span>{notice}</span>
            </div>
          )}
          <div className="flex flex-wrap gap-1.5 pt-1">
            {frameworks.map((fw) => (
              <button
                key={fw.id}
                type="button"
                onClick={() => setActiveFrameworkId(fw.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded border transition-colors whitespace-nowrap ${
                  activeFrameworkId === fw.id
                    ? 'bg-slate-800 border-slate-600 text-slate-100'
                    : 'bg-[#090D16] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {fw.name}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 bg-[#0B111E]">
                <th className="py-2.5 px-4 font-medium">Control</th>
                <th className="py-2.5 px-4 font-medium">Title & Category</th>
                <th className="py-2.5 px-4 font-medium">Assessed Status</th>
                <th className="py-2.5 px-4 font-medium">Evidence & Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {activeControls.map((c) => {
                const m = mappingByControl.get(c.id);
                const status = m?.status || 'not_assessed';
                const statusColor =
                  status === 'passed'
                    ? 'text-emerald-400'
                    : status === 'failed'
                      ? 'text-red-400'
                      : status === 'partial'
                        ? 'text-amber-400'
                        : 'text-slate-500';
                return (
                  <tr key={c.id} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 font-mono text-slate-200 whitespace-nowrap">{c.control_code}</td>
                    <td className="py-2.5 px-4">
                      <div className="font-medium text-slate-100">{c.title}</div>
                      <div className="text-[11px] text-slate-500">{c.category}</div>
                    </td>
                    <td className={`py-2.5 px-4 font-mono whitespace-nowrap capitalize ${statusColor}`}>
                      {status.replace('_', ' ')}
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 max-w-md">
                      {m?.notes || `Requires: ${c.evidence_required}`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Report History */}
      {reportHistory.length > 0 && (
        <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 text-sm font-semibold text-slate-100">
            Generated Report Archive
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 bg-[#0B111E]">
                  <th className="py-2.5 px-4 font-medium">Filename</th>
                  <th className="py-2.5 px-4 font-medium">Target</th>
                  <th className="py-2.5 px-4 font-medium">Format / Scope</th>
                  <th className="py-2.5 px-4 font-medium text-right">Size</th>
                  <th className="py-2.5 px-4 font-medium text-right">Generated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {reportHistory.map((r) => (
                  <tr key={r.id}>
                    <td className="py-2.5 px-4 font-mono text-slate-200">{r.filename}</td>
                    <td className="py-2.5 px-4 text-slate-300">{r.asset_name}</td>
                    <td className="py-2.5 px-4 uppercase font-mono text-slate-400">{r.format} · {r.export_scope}</td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-400">{formatBytes(r.file_size_bytes)}</td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-400">{formatDateTime(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
