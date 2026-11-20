import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar,
  Cell,
  CartesianGrid,
} from 'recharts';
import { Globe, Play, ArrowUpRight, ShieldAlert, Activity, ShieldCheck } from 'lucide-react';
import type { DashboardSummary, NavTab } from '../types/sentinel';
import { formatDateTime, formatDurationMs } from '../utils/formatters';
import { ScanStatusBadge, SeverityBadge } from './ui';

interface OverviewDashboardProps {
  summary: DashboardSummary | null;
  loading: boolean;
  onNavigate: (tab: NavTab) => void;
  onOpenScanDetail: (scanId: string) => void;
  onSelectFinding: (findingId: string) => void;
  onOpenAddAsset: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  summary,
  loading,
  onNavigate,
  onOpenScanDetail,
  onSelectFinding,
  onOpenAddAsset,
}) => {
  if (loading && !summary) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
          {Array.from({ length: 7 }).map((_, idx) => (
            <div key={idx} className="h-24 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 h-72 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg animate-pulse" />
          <div className="lg:col-span-5 h-72 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg animate-pulse" />
        </div>
      </div>
    );
  }

  if (!summary || (summary.metrics.totalAssets === 0 && summary.metrics.totalScans === 0)) {
    return (
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-xl p-8 sm:p-10 max-w-3xl shadow-xs">
        <div className="w-11 h-11 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] flex items-center justify-center text-[#2563EB]">
          <ShieldCheck className="w-5 h-5" aria-hidden="true" />
        </div>
        <h2 className="mt-4 text-lg font-semibold text-[#0F172A] tracking-tight">
          Begin Your First Authorized Security Assessment
        </h2>
        <p className="mt-2 text-sm text-[#64748B] leading-relaxed max-w-2xl">
          SentinelScan executes real TLS, HTTP security header, DNS, recursive attack-surface crawling, OWASP probes, OpenAPI, dependency (OSV), and static code checks. No synthetic vulnerability counts or mock scan results are populated in advance.
        </p>
        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={onOpenAddAsset}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md transition-colors shadow-xs"
          >
            <Globe className="w-4 h-4" aria-hidden="true" />
            <span>Add Website or Practice Lab Target</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('assets')}
            className="px-4 py-2 text-xs font-medium text-[#334155] bg-[#FFFFFF] hover:bg-[#F8FAFC] border border-[#CBD5E1] rounded-md transition-colors"
          >
            Open Asset Inventory
          </button>
        </div>
      </div>
    );
  }

  const { metrics, postureTrend, recentScans, mostVulnerableAssets, recentFindings } = summary;

  const distributionData = [
    { name: 'Critical', count: metrics.critical, color: '#DC2626' },
    { name: 'High', count: metrics.high, color: '#EA580C' },
    { name: 'Medium', count: metrics.medium, color: '#D97706' },
    { name: 'Low', count: metrics.low, color: '#2563EB' },
    { name: 'Info', count: metrics.informational, color: '#64748B' },
  ];

  const trendData = postureTrend.map((t, idx) => ({
    label: `#${idx + 1} ${t.asset_name.slice(0, 14)}`,
    score: t.posture_score,
    passed: t.passed_checks,
    failed: t.failed_checks,
  }));

  return (
    <div className="space-y-6">
      {/* Top 7-KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Websites Monitored</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#0F172A]">
            {metrics.totalAssets}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B] font-mono tabular-nums">
            {metrics.verifiedAssets} authorized
          </div>
        </div>

        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#64748B]">Total Assessments</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#0F172A]">
            {metrics.totalScans}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B]">All profiles</div>
        </div>

        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#2563EB]">Active Scans</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#2563EB]">
            {metrics.activeScans}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B]">Queued / running</div>
        </div>

        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#B91C1C]">Critical</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#DC2626]">
            {metrics.critical}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B]">Open findings</div>
        </div>

        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#C2410C]">High</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#EA580C]">
            {metrics.high}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B]">Open findings</div>
        </div>

        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#B45309]">Medium</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#D97706]">
            {metrics.medium}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B]">Open findings</div>
        </div>

        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-4">
          <div className="text-xs font-medium text-[#1D4ED8]">Low</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-[#2563EB]">
            {metrics.low}
          </div>
          <div className="mt-1 text-[11px] text-[#64748B]">Open findings</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-[#0F172A]">Security Posture Trend</h2>
              <p className="text-xs text-[#64748B]">
                Calculated from executed check pass ratio &amp; active severity penalties
              </p>
            </div>
            <span className="text-[11px] text-[#475569] font-mono tabular-nums whitespace-nowrap">
              {trendData.length > 0
                ? `Latest: ${trendData[trendData.length - 1].score}/100`
                : '0–100 scale'}
            </span>
          </div>
          {trendData.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-xs text-[#64748B] bg-[#F8FAFC] border border-dashed border-[#CBD5E1] rounded-md">
              Complete at least one assessment to plot posture history.
            </div>
          ) : (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="postureFillBlue" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#2563EB" stopOpacity={0.18} />
                      <stop offset="95%" stopColor="#2563EB" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#E2E8F0" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#64748B', fontSize: 11 }} axisLine={{ stroke: '#E2E8F0' }} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fill: '#64748B', fontSize: 11 }} axisLine={{ stroke: '#E2E8F0' }} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      border: '1px solid #E2E8F0',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#0F172A',
                      boxShadow: '0 4px 12px rgba(15, 23, 42, 0.08)',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    name="Posture Score"
                    stroke="#2563EB"
                    strokeWidth={2}
                    fill="url(#postureFillBlue)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="lg:col-span-5 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-[#0F172A]">Active Vulnerability Distribution</h2>
              <p className="text-xs text-[#64748B]">Open, confirmed &amp; reopened findings</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="text-xs font-medium text-[#2563EB] hover:text-[#1E40AF] inline-flex items-center gap-1 whitespace-nowrap"
            >
              <span>All findings</span>
              <ArrowUpRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={distributionData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="#E2E8F0" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#64748B', fontSize: 11 }} axisLine={{ stroke: '#E2E8F0' }} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#64748B', fontSize: 11 }} axisLine={{ stroke: '#E2E8F0' }} tickLine={false} />
                <Tooltip
                  cursor={{ fill: '#F8FAFC' }}
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    border: '1px solid #E2E8F0',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#0F172A',
                    boxShadow: '0 4px 12px rgba(15, 23, 42, 0.08)',
                  }}
                />
                <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]}>
                  {distributionData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Panels: Most Vulnerable Assets & Recently Discovered Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#E2E8F0] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[#0F172A]">Most Vulnerable Assets</h2>
            <button
              type="button"
              onClick={() => onNavigate('assets')}
              className="text-xs font-medium text-[#2563EB] hover:text-[#1E40AF] whitespace-nowrap"
            >
              Manage assets
            </button>
          </div>
          <div className="divide-y divide-[#E2E8F0]">
            {mostVulnerableAssets.length === 0 ? (
              <div className="p-6 text-xs text-[#64748B]">No assets registered yet.</div>
            ) : (
              mostVulnerableAssets.map((asset) => (
                <div key={asset.id} className="px-5 py-3 flex items-center justify-between gap-4 hover:bg-[#F8FAFC] transition-colors">
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-[#0F172A] truncate">{asset.name}</div>
                    <div className="text-[11px] text-[#64748B] truncate font-mono">{asset.target_url}</div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 text-xs font-mono tabular-nums">
                    <span className="text-[#DC2626] font-semibold">{asset.critical_count || 0}C</span>
                    <span className="text-[#EA580C] font-semibold">{asset.high_count || 0}H</span>
                    <span className="text-[#64748B]">{asset.total_open_findings || 0} open</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="lg:col-span-7 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-[#E2E8F0] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-[#0F172A]">Recently Discovered Findings</h2>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="text-xs font-medium text-[#2563EB] hover:text-[#1E40AF] whitespace-nowrap"
            >
              Triage queue
            </button>
          </div>
          {recentFindings.length === 0 ? (
            <div className="p-6 text-xs text-[#64748B] flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#94A3B8]" aria-hidden="true" />
              <span>No findings recorded yet. Run an assessment on an authorized asset.</span>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B] bg-[#F8FAFC]">
                    <th className="py-2.5 px-4 font-semibold">Severity</th>
                    <th className="py-2.5 px-4 font-semibold">Finding</th>
                    <th className="py-2.5 px-4 font-semibold">Asset</th>
                    <th className="py-2.5 px-4 font-semibold text-right">CVSS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#E2E8F0] text-xs">
                  {recentFindings.map((f) => (
                    <tr key={f.id} className="hover:bg-[#F8FAFC] transition-colors">
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-2.5 px-4 max-w-xs">
                        <button
                          type="button"
                          onClick={() => onSelectFinding(f.id)}
                          className="text-left text-[#0F172A] hover:text-[#2563EB] font-medium truncate block w-full"
                        >
                          {f.title}
                        </button>
                        <div className="text-[11px] text-[#64748B] font-mono">
                          {f.finding_code} · {f.cwe_id || f.category}
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-[#475569] max-w-[140px] truncate">{f.asset_name}</td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums font-medium text-[#0F172A] whitespace-nowrap">
                        {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Recent Assessments */}
      <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-[#E2E8F0] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#2563EB]" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-[#0F172A]">Recent Assessments</h2>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('scans')}
            className="text-xs font-medium text-[#2563EB] hover:text-[#1E40AF] inline-flex items-center gap-1 whitespace-nowrap"
          >
            <Play className="w-3 h-3" aria-hidden="true" />
            <span>Scan history</span>
          </button>
        </div>
        {recentScans.length === 0 ? (
          <div className="p-6 text-xs text-[#64748B]">No assessments executed yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B] bg-[#F8FAFC]">
                  <th className="py-2.5 px-4 font-semibold">Target</th>
                  <th className="py-2.5 px-4 font-semibold">Profile</th>
                  <th className="py-2.5 px-4 font-semibold">Status</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Posture</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Passed / Failed</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Duration</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Timestamp</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E2E8F0] text-xs">
                {recentScans.map((s) => (
                  <tr key={s.id} className="hover:bg-[#F8FAFC] transition-colors">
                    <td className="py-2.5 px-4">
                      <button
                        type="button"
                        onClick={() => onOpenScanDetail(s.id)}
                        className="text-left font-semibold text-[#0F172A] hover:text-[#2563EB]"
                      >
                        {s.asset_name}
                      </button>
                      <div className="text-[11px] text-[#64748B] font-mono">{s.target_url}</div>
                    </td>
                    <td className="py-2.5 px-4 text-[#334155] capitalize">{s.profile}</td>
                    <td className="py-2.5 px-4">
                      <ScanStatusBadge status={s.status} progressPct={s.progress_pct} />
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums font-semibold text-[#0F172A]">
                      {s.posture_score !== null ? `${s.posture_score}/100` : '—'}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums">
                      <span className="text-[#16A34A] font-semibold">{s.passed_checks}</span>
                      <span className="text-[#CBD5E1] mx-1">/</span>
                      <span className="text-[#DC2626] font-semibold">{s.failed_checks}</span>
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-[#64748B]">
                      {formatDurationMs(s.duration_ms)}
                    </td>
                    <td className="py-2.5 px-4 text-right font-mono tabular-nums text-[#64748B]">
                      {formatDateTime(s.created_at)}
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onOpenScanDetail(s.id)}
                        className="px-2.5 py-1 text-[11px] font-medium text-[#2563EB] bg-[#EFF6FF] hover:bg-[#DBEAFE] border border-[#BFDBFE] rounded transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
