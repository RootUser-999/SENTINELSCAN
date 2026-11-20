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
import { Globe, Play, ArrowUpRight, ShieldAlert } from 'lucide-react';
import type { DashboardSummary, NavTab } from '../types/sentinel';
import { formatDateTime, formatDurationMs, getSeverityStyle } from '../utils/formatters';

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
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
          {Array.from({ length: 7 }).map((_, idx) => (
            <div key={idx} className="h-24 bg-[#0F172A] border border-slate-800 rounded-md animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 h-72 bg-[#0F172A] border border-slate-800 rounded-md animate-pulse" />
          <div className="lg:col-span-5 h-72 bg-[#0F172A] border border-slate-800 rounded-md animate-pulse" />
        </div>
      </div>
    );
  }

  if (!summary || (summary.metrics.totalAssets === 0 && summary.metrics.totalScans === 0)) {
    return (
      <div className="bg-[#0F172A] border border-slate-800 rounded-md p-10 max-w-3xl">
        <div className="flex items-center gap-2.5 text-slate-200 font-semibold text-lg">
          <Globe className="w-5 h-5 text-blue-400" aria-hidden="true" />
          <h2>Begin Your First Authorized Security Assessment</h2>
        </div>
        <p className="mt-2.5 text-sm text-slate-400 leading-relaxed max-w-2xl">
          SentinelScan executes real TLS, HTTP security header, DNS, surface exposure, OpenAPI, dependency (OSV), and static code checks. No synthetic vulnerability counts or mock scan results are populated in advance.
        </p>
        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={onOpenAddAsset}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 rounded transition-colors"
          >
            <Globe className="w-4 h-4" aria-hidden="true" />
            <span>Add Website or Practice Lab Target</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('assets')}
            className="px-4 py-2 text-sm font-medium text-slate-300 bg-slate-800/70 hover:bg-slate-800 border border-slate-700 rounded transition-colors"
          >
            Open Asset Inventory
          </button>
        </div>
      </div>
    );
  }

  const { metrics, postureTrend, recentScans, mostVulnerableAssets, recentFindings } = summary;

  const distributionData = [
    { name: 'Critical', count: metrics.critical, color: '#EF4444' },
    { name: 'High', count: metrics.high, color: '#F97316' },
    { name: 'Medium', count: metrics.medium, color: '#F59E0B' },
    { name: 'Low', count: metrics.low, color: '#38BDF8' },
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
        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-slate-400">Websites Monitored</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-100">
            {metrics.totalAssets}
          </div>
          <div className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
            {metrics.verifiedAssets} verified
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-slate-400">Total Scans</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-slate-100">
            {metrics.totalScans}
          </div>
          <div className="mt-1 text-xs text-slate-500">All profiles</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-slate-400">Active Scans</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-blue-400">
            {metrics.activeScans}
          </div>
          <div className="mt-1 text-xs text-slate-500">Queued / running</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-red-400">Critical</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-red-400">
            {metrics.critical}
          </div>
          <div className="mt-1 text-xs text-slate-500">Open findings</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-orange-400">High</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-orange-400">
            {metrics.high}
          </div>
          <div className="mt-1 text-xs text-slate-500">Open findings</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-amber-400">Medium</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-amber-400">
            {metrics.medium}
          </div>
          <div className="mt-1 text-xs text-slate-500">Open findings</div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-4">
          <div className="text-xs text-sky-400">Low</div>
          <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-sky-400">
            {metrics.low}
          </div>
          <div className="mt-1 text-xs text-slate-500">Open findings</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-md p-5">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Security Posture Trend</h2>
              <p className="text-xs text-slate-400">Calculated from executed pass ratio & active severity penalties</p>
            </div>
            <span className="text-xs text-slate-500 font-mono">0–100 scale</span>
          </div>
          {trendData.length === 0 ? (
            <div className="h-56 flex items-center justify-center text-xs text-slate-500 border border-dashed border-slate-800 rounded">
              Complete at least one assessment to plot posture history.
            </div>
          ) : (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: '#94A3B8', fontSize: 11 }} axisLine={{ stroke: '#1E293B' }} />
                  <YAxis domain={[0, 100]} tick={{ fill: '#94A3B8', fontSize: 11 }} axisLine={{ stroke: '#1E293B' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0B111E',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      fontSize: '12px',
                      color: '#F1F5F9',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    name="Posture Score"
                    stroke="#3B82F6"
                    strokeWidth={2}
                    fill="#3B82F6"
                    fillOpacity={0.14}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-md p-5">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Active Vulnerability Distribution</h2>
              <p className="text-xs text-slate-400">Open, confirmed & reopened findings</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 whitespace-nowrap"
            >
              <span>All findings</span>
              <ArrowUpRight className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={distributionData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="#1E293B" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" tick={{ fill: '#94A3B8', fontSize: 11 }} axisLine={{ stroke: '#1E293B' }} />
                <YAxis allowDecimals={false} tick={{ fill: '#94A3B8', fontSize: 11 }} axisLine={{ stroke: '#1E293B' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0B111E',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    fontSize: '12px',
                    color: '#F1F5F9',
                  }}
                />
                <Bar dataKey="count" name="Findings" radius={[3, 3, 0, 0]}>
                  {distributionData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom Tables: Most Vulnerable Assets & Recent Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-5 bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">Most Vulnerable Assets</h2>
            <button
              type="button"
              onClick={() => onNavigate('assets')}
              className="text-xs text-blue-400 hover:text-blue-300 whitespace-nowrap"
            >
              Manage assets
            </button>
          </div>
          <div className="divide-y divide-slate-800/80">
            {mostVulnerableAssets.length === 0 ? (
              <div className="p-6 text-xs text-slate-500">No assets registered yet.</div>
            ) : (
              mostVulnerableAssets.map((asset) => (
                <div key={asset.id} className="px-5 py-3 flex items-center justify-between gap-4 hover:bg-slate-800/30">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-slate-200 truncate">{asset.name}</div>
                    <div className="text-xs text-slate-500 truncate font-mono">{asset.target_url}</div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 text-xs font-mono tabular-nums">
                    <span className="text-red-400">{asset.critical_count || 0}C</span>
                    <span className="text-orange-400">{asset.high_count || 0}H</span>
                    <span className="text-slate-400">{asset.total_open_findings || 0} open</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="lg:col-span-7 bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">Recently Discovered Findings</h2>
            <button
              type="button"
              onClick={() => onNavigate('findings')}
              className="text-xs text-blue-400 hover:text-blue-300 whitespace-nowrap"
            >
              Triage queue
            </button>
          </div>
          {recentFindings.length === 0 ? (
            <div className="p-6 text-xs text-slate-500 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-slate-600" aria-hidden="true" />
              <span>No findings recorded yet. Run an assessment on a verified asset.</span>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-400 bg-[#0B111E]">
                    <th className="py-2.5 px-4 font-medium">Severity</th>
                    <th className="py-2.5 px-4 font-medium">Finding</th>
                    <th className="py-2.5 px-4 font-medium">Asset</th>
                    <th className="py-2.5 px-4 font-medium text-right">CVSS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-xs">
                  {recentFindings.map((f) => {
                    const sev = getSeverityStyle(f.severity);
                    return (
                      <tr key={f.id} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span className={`inline-block px-2 py-0.5 rounded border text-[11px] font-medium ${sev.text} ${sev.border} ${sev.bg}`}>
                            {sev.label}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 max-w-xs">
                          <button
                            type="button"
                            onClick={() => onSelectFinding(f.id)}
                            className="text-left text-slate-200 hover:text-blue-400 font-medium truncate block w-full"
                          >
                            {f.title}
                          </button>
                          <div className="text-[11px] text-slate-500 font-mono">{f.finding_code} · {f.cwe_id || f.category}</div>
                        </td>
                        <td className="py-2.5 px-4 text-slate-400 max-w-[140px] truncate">{f.asset_name}</td>
                        <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-300 whitespace-nowrap">
                          {f.cvss_score !== null ? f.cvss_score.toFixed(1) : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scan Activity */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-100">Recent Scan Activity</h2>
          <button
            type="button"
            onClick={() => onNavigate('scans')}
            className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 whitespace-nowrap"
          >
            <Play className="w-3 h-3" aria-hidden="true" />
            <span>Scan console</span>
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-400 bg-[#0B111E]">
                <th className="py-2.5 px-4 font-medium">Target</th>
                <th className="py-2.5 px-4 font-medium">Profile</th>
                <th className="py-2.5 px-4 font-medium">Status</th>
                <th className="py-2.5 px-4 font-medium text-right">Posture</th>
                <th className="py-2.5 px-4 font-medium text-right">Passed / Failed</th>
                <th className="py-2.5 px-4 font-medium text-right">Duration</th>
                <th className="py-2.5 px-4 font-medium text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-xs">
              {recentScans.map((s) => (
                <tr key={s.id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 px-4">
                    <button
                      type="button"
                      onClick={() => onOpenScanDetail(s.id)}
                      className="text-left font-medium text-slate-200 hover:text-blue-400"
                    >
                      {s.asset_name}
                    </button>
                    <div className="text-[11px] text-slate-500 font-mono">{s.target_url}</div>
                  </td>
                  <td className="py-2.5 px-4 text-slate-300 capitalize">{s.profile}</td>
                  <td className="py-2.5 px-4">
                    <span className={`font-mono text-xs ${s.status === 'completed' ? 'text-emerald-400' : s.status === 'failed' ? 'text-red-400' : 'text-blue-400'}`}>
                      {s.status} ({s.progress_pct}%)
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-200">
                    {s.posture_score !== null ? `${s.posture_score}` : '—'}
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums">
                    <span className="text-emerald-400">{s.passed_checks}</span>
                    <span className="text-slate-600 mx-1">/</span>
                    <span className="text-red-400">{s.failed_checks}</span>
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-400">
                    {formatDurationMs(s.duration_ms)}
                  </td>
                  <td className="py-2.5 px-4 text-right font-mono tabular-nums text-slate-400">
                    {formatDateTime(s.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
