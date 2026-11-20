import React, { useEffect, useState } from 'react';
import {
  Play,
  Square,
  GitCompare,
  FlaskConical,
  CheckCircle2,
  XCircle,
  Clock,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Search,
  Activity,
} from 'lucide-react';
import { apiRequest } from '../api/client';
import type {
  Asset,
  EndpointRow,
  NavTab,
  ScanRecord,
  ScannerModuleMeta,
  SecurityCheckRow,
  UserRole,
} from '../types/sentinel';
import { formatDateTime, formatDurationMs } from '../utils/formatters';
import {
  EmptyState,
  MethodBadge,
  OutcomeBadge,
  ScanStatusBadge,
  inputClassName,
  selectClassName,
} from './ui';

interface ScansViewProps {
  assets: Asset[];
  scans: ScanRecord[];
  modules: ScannerModuleMeta[];
  userRole: UserRole;
  preselectedAssetId: string | null;
  selectedScanId: string | null;
  initialMode?: 'console' | 'launch';
  onNavigateTab?: (tab: NavTab) => void;
  onSelectScanId: (id: string | null) => void;
  onRefresh: () => void;
  onToast: (msg: string, type?: 'success' | 'error') => void;
}

interface ScanDetailPayload {
  scan: ScanRecord;
  executions: Array<{
    id: string;
    module_id: string;
    module_name: string;
    module_version: string;
    status: string;
    duration_ms: number | null;
    checks_executed: number;
    findings_created: number;
    error_message: string | null;
  }>;
  logs: Array<{ id: string; timestamp: string; level: string; module_id: string | null; message: string }>;
  checks: SecurityCheckRow[];
  endpoints: EndpointRow[];
}

interface CompareResult {
  baseline: ScanRecord;
  target: ScanRecord;
  postureDelta: number | null;
  passedDelta: number;
  failedDelta: number;
  checkDiffs: Array<{ checkKey: string; title: string; baselineStatus: string; targetStatus: string }>;
}

interface VaultCredentialMeta {
  id: string;
  label: string;
  auth_type: string;
  role_profile: string;
}

const PROFILE_INFO: Record<
  'quick' | 'standard' | 'comprehensive' | 'custom',
  { title: string; impact: string; description: string }
> = {
  quick: {
    title: 'Quick Assessment',
    impact: 'Minimal traffic (~10–25 requests). Safe for production.',
    description: 'Evaluates HTTPS/TLS transport, 10 security headers + CORS, DNS SPF/DMARC/CAA, and basic sensitive file probes.',
  },
  standard: {
    title: 'Standard Assessment',
    impact: 'Controlled scoped crawl + non-destructive OWASP/API probes.',
    description: 'Includes Quick checks plus recursive crawling, OWASP active probes (SQLi, XSS, CSRF, IDOR, traversal, redirect), cookies, and API/GraphQL checks.',
  },
  comprehensive: {
    title: 'Comprehensive Assessment',
    impact: 'Deep scoped crawl + full OWASP probes + multi-role auth testing.',
    description: 'Runs all 10 modules including deep crawling, OWASP probes, API/JWT/GraphQL security, OSV SCA, multi-file SAST, and role boundary verification.',
  },
  custom: {
    title: 'Custom Assessment',
    impact: 'User-defined modules, crawl depth, URL/request budget, and concurrency.',
    description: 'Select specific scanner modules and configure custom crawl caps, credentials, OpenAPI, dependency manifests, or source files.',
  },
};

export const ScansView: React.FC<ScansViewProps> = ({
  assets,
  scans,
  modules,
  userRole,
  preselectedAssetId,
  selectedScanId,
  initialMode = 'console',
  onNavigateTab,
  onSelectScanId,
  onRefresh,
  onToast,
}) => {
  const verifiedAssets = assets.filter((a) => a.ownership_status === 'verified');
  const [subView, setSubView] = useState<'console' | 'launch' | 'compare'>(
    preselectedAssetId || initialMode === 'launch' ? 'launch' : 'console'
  );
  const [advancedOpen, setAdvancedOpen] = useState(false);

  // Launch form state
  const [assetId, setAssetId] = useState(preselectedAssetId || verifiedAssets[0]?.id || '');
  const [profile, setProfile] = useState<'quick' | 'standard' | 'comprehensive' | 'custom'>('standard');
  const [selectedModules, setSelectedModules] = useState<string[]>(modules.map((m) => m.id));
  const [rateLimitRps, setRateLimitRps] = useState(5);
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxUrls, setMaxUrls] = useState(60);
  const [maxRequests, setMaxRequests] = useState(250);
  const [concurrencyLimit, setConcurrencyLimit] = useState(3);
  const [requestTimeoutMs, setRequestTimeoutMs] = useState(10000);

  // Authenticated & multi-role testing state
  const [credentials, setCredentials] = useState<VaultCredentialMeta[]>([]);
  const [allowAuthenticated, setAllowAuthenticated] = useState(false);
  const [credentialId, setCredentialId] = useState('');
  const [secondaryCredentialId, setSecondaryCredentialId] = useState('');
  const [customHeadersText, setCustomHeadersText] = useState('');

  // Optional API / SCA / SAST inputs
  const [openapiSpecRaw, setOpenapiSpecRaw] = useState('');
  const [scaManifestName, setScaManifestName] = useState('package.json');
  const [scaManifestRaw, setScaManifestRaw] = useState('');
  const [sastFilename, setSastFilename] = useState('checkout.ts');
  const [sastCodeRaw, setSastCodeRaw] = useState('');
  const [sastFiles, setSastFiles] = useState<Array<{ filename: string; content: string }>>([]);
  const [launching, setLaunching] = useState(false);

  // Scan History search / filter / sort
  const [historySearch, setHistorySearch] = useState('');
  const [historyStatus, setHistoryStatus] = useState('all');
  const [historySort, setHistorySort] = useState<'newest' | 'oldest' | 'score_desc' | 'score_asc'>('newest');

  // Detail polling & result filters
  const [detail, setDetail] = useState<ScanDetailPayload | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [endpointSearch, setEndpointSearch] = useState('');
  const [endpointMethodFilter, setEndpointMethodFilter] = useState('ALL');
  const [checkOutcomeFilter, setCheckOutcomeFilter] = useState('ALL');
  const [checkSearch, setCheckSearch] = useState('');

  // Comparison state
  const completedScans = scans.filter((s) => s.status === 'completed');
  const [baselineId, setBaselineId] = useState(completedScans[1]?.id || completedScans[0]?.id || '');
  const [targetId, setTargetId] = useState(completedScans[0]?.id || '');
  const [compareData, setCompareData] = useState<CompareResult | null>(null);

  const canLaunch = userRole === 'admin' || userRole === 'analyst';

  useEffect(() => {
    if (initialMode === 'launch' && canLaunch) {
      setSubView('launch');
    } else if (initialMode === 'console' && subView === 'launch' && !preselectedAssetId) {
      setSubView('console');
    }
  }, [initialMode, canLaunch, preselectedAssetId]);

  useEffect(() => {
    if (subView === 'launch' && canLaunch) {
      apiRequest<{ credentials: VaultCredentialMeta[] }>('/credentials')
        .then((res) => setCredentials(res.credentials || []))
        .catch(() => {});
    }
  }, [subView, canLaunch]);

  useEffect(() => {
    if (preselectedAssetId) {
      setAssetId(preselectedAssetId);
      setSubView('launch');
    }
  }, [preselectedAssetId]);

  useEffect(() => {
    if (!assetId && verifiedAssets.length > 0) {
      setAssetId(verifiedAssets[0].id);
    }
  }, [verifiedAssets, assetId]);

  useEffect(() => {
    if (selectedModules.length === 0 && modules.length > 0) {
      setSelectedModules(modules.map((m) => m.id));
    }
  }, [modules, selectedModules.length]);

  useEffect(() => {
    if (completedScans.length >= 2) {
      if (!targetId || !completedScans.some((s) => s.id === targetId)) {
        setTargetId(completedScans[0].id);
      }
      if (!baselineId || !completedScans.some((s) => s.id === baselineId) || baselineId === completedScans[0].id) {
        setBaselineId(completedScans[1].id);
      }
    }
  }, [completedScans.length]);

  useEffect(() => {
    const activeId = selectedScanId || scans[0]?.id || null;
    if (!activeId || subView !== 'console') return;

    let cancelled = false;
    let isTerminal = false;
    setDetail(null);
    setDetailLoading(true);

    const fetchDetail = async () => {
      try {
        const data = await apiRequest<ScanDetailPayload>(`/scans/${activeId}`);
        if (!cancelled) {
          setDetail(data);
          setDetailLoading(false);
          if (data.scan.status === 'completed' || data.scan.status === 'failed' || data.scan.status === 'cancelled') {
            isTerminal = true;
            onRefresh();
          }
        }
      } catch {
        if (!cancelled) setDetailLoading(false);
      }
    };

    fetchDetail();

    const timer = setInterval(() => {
      if (!isTerminal) {
        fetchDetail();
      }
    }, 1000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [selectedScanId, scans.length, subView]);

  const handleLoadPracticeSamples = async () => {
    try {
      const res = await apiRequest<{ openapiSpec: string; packageJson: string; sastSnippet: string }>('/practice-samples');
      setOpenapiSpecRaw(res.openapiSpec);
      setScaManifestName('package.json');
      setScaManifestRaw(res.packageJson);
      setSastFilename('checkoutHandler.ts');
      setSastCodeRaw(res.sastSnippet);
      setProfile('comprehensive');
      setMaxDepth(3);
      setMaxUrls(80);
      setMaxRequests(350);
      setAdvancedOpen(true);
      onToast('Loaded Practice Lab OpenAPI, package.json, and SAST review sample.', 'success');
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to load samples', 'error');
    }
  };

  const handleMultiSastUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []).slice(0, 15);
    if (files.length === 0) return;
    const loaded: Array<{ filename: string; content: string }> = [];
    for (const f of files) {
      const text = await f.text();
      loaded.push({ filename: f.name, content: text.slice(0, 250_000) });
    }
    setSastFiles(loaded);
    if (loaded.length === 1) {
      setSastFilename(loaded[0].filename);
      setSastCodeRaw(loaded[0].content);
    }
    onToast(`Loaded ${loaded.length} authorized source file(s) for SAST.`, 'success');
  };

  const parseCustomHeaders = (): Record<string, string> => {
    const map: Record<string, string> = {};
    for (const line of customHeadersText.split(/\r?\n/)) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        if (k && v) map[k] = v;
      }
    }
    return map;
  };

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assetId) {
      onToast('Select a verified asset before launching an assessment.', 'error');
      return;
    }
    setLaunching(true);
    try {
      const res = await apiRequest<{ id: string }>('/scans', {
        method: 'POST',
        body: JSON.stringify({
          assetId,
          profile,
          selectedModules: profile === 'custom' ? selectedModules : undefined,
          maxDepth,
          maxUrls,
          maxRequests,
          concurrencyLimit,
          requestTimeoutMs,
          rateLimitRps,
          allowAuthenticated,
          credentialId: allowAuthenticated && credentialId ? credentialId : null,
          secondaryCredentialId: allowAuthenticated && secondaryCredentialId ? secondaryCredentialId : null,
          customHeaders: parseCustomHeaders(),
          openapiSpecRaw: openapiSpecRaw.trim() || null,
          scaManifestName: scaManifestRaw.trim() ? scaManifestName : null,
          scaManifestRaw: scaManifestRaw.trim() || null,
          sastFilename: sastCodeRaw.trim() ? sastFilename : null,
          sastCodeRaw: sastCodeRaw.trim() || null,
          sastFiles,
        }),
      });
      onToast('Security assessment queued and running.', 'success');
      onSelectScanId(res.id);
      setSubView('console');
      if (onNavigateTab) onNavigateTab('scans');
      onRefresh();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Failed to launch scan', 'error');
    } finally {
      setLaunching(false);
    }
  };

  const handleCancelScan = async (id: string) => {
    try {
      await apiRequest(`/scans/${id}/cancel`, { method: 'POST' });
      onToast('Scan cancellation requested.', 'success');
      onRefresh();
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Cancel failed', 'error');
    }
  };

  const handleCompare = async () => {
    if (!baselineId || !targetId) return;
    try {
      const res = await apiRequest<CompareResult>(
        `/scans/compare?baselineId=${encodeURIComponent(baselineId)}&targetId=${encodeURIComponent(targetId)}`
      );
      setCompareData(res);
    } catch (err) {
      onToast(err instanceof Error ? err.message : 'Comparison failed', 'error');
    }
  };

  const filteredScans = scans
    .filter((s) => {
      const matchesStatus = historyStatus === 'all' || s.status === historyStatus;
      const q = historySearch.trim().toLowerCase();
      const matchesQ =
        !q ||
        s.asset_name.toLowerCase().includes(q) ||
        s.target_url.toLowerCase().includes(q) ||
        s.profile.toLowerCase().includes(q);
      return matchesStatus && matchesQ;
    })
    .slice()
    .sort((a, b) => {
      if (historySort === 'oldest') {
        return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      }
      if (historySort === 'score_desc') {
        return (b.posture_score ?? -1) - (a.posture_score ?? -1);
      }
      if (historySort === 'score_asc') {
        return (a.posture_score ?? 999) - (b.posture_score ?? 999);
      }
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

  const filteredEndpoints = (detail?.endpoints || []).filter((ep) => {
    const matchesMethod = endpointMethodFilter === 'ALL' || ep.method.toUpperCase() === endpointMethodFilter;
    const q = endpointSearch.trim().toLowerCase();
    const matchesQ =
      !q ||
      ep.path.toLowerCase().includes(q) ||
      ep.source.toLowerCase().includes(q) ||
      ep.parameters_json.toLowerCase().includes(q);
    return matchesMethod && matchesQ;
  });

  const filteredChecks = (detail?.checks || []).filter((c) => {
    const norm = (c.normalized_status || c.status).toUpperCase();
    const matchesOutcome = checkOutcomeFilter === 'ALL' || norm === checkOutcomeFilter;
    const q = checkSearch.trim().toLowerCase();
    const matchesQ =
      !q ||
      c.title.toLowerCase().includes(q) ||
      c.explanation.toLowerCase().includes(q) ||
      (c.observed_value || '').toLowerCase().includes(q);
    return matchesOutcome && matchesQ;
  });

  const switchSubView = (mode: 'console' | 'launch' | 'compare') => {
    setSubView(mode);
    if (onNavigateTab) {
      if (mode === 'launch') onNavigateTab('new-assessment');
      else onNavigateTab('scans');
    }
  };

  return (
    <div className="space-y-5">
      {/* Sub-navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="inline-flex flex-wrap items-center gap-1 p-1 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg shadow-2xs max-w-full">
          <button
            type="button"
            onClick={() => switchSubView('console')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              subView === 'console'
                ? 'bg-[#EFF6FF] text-[#1E40AF] font-semibold'
                : 'text-[#64748B] hover:text-[#0F172A]'
            }`}
          >
            Live Console &amp; History
          </button>
          {canLaunch && (
            <button
              type="button"
              onClick={() => switchSubView('launch')}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                subView === 'launch'
                  ? 'bg-[#EFF6FF] text-[#1E40AF] font-semibold'
                  : 'text-[#64748B] hover:text-[#0F172A]'
              }`}
            >
              Configure &amp; Launch Scan
            </button>
          )}
          <button
            type="button"
            onClick={() => switchSubView('compare')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
              subView === 'compare'
                ? 'bg-[#EFF6FF] text-[#1E40AF] font-semibold'
                : 'text-[#64748B] hover:text-[#0F172A]'
            }`}
          >
            Compare Scans
          </button>
        </div>
      </div>

      {/* NEW ASSESSMENT CONFIGURATION */}
      {subView === 'launch' && (
        <form onSubmit={handleLaunchScan} className="space-y-5">
          <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-6 space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#E2E8F0] pb-4">
              <div>
                <h2 className="text-base font-semibold text-[#0F172A]">Configure Security Assessment</h2>
                <p className="mt-0.5 text-xs text-[#64748B]">
                  Select an authorized target, choose an assessment profile, and tune crawl limits or optional artifacts.
                </p>
              </div>
              <button
                type="button"
                onClick={handleLoadPracticeSamples}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#1D4ED8] bg-[#EFF6FF] border border-[#BFDBFE] hover:bg-[#DBEAFE] rounded-md transition-colors whitespace-nowrap"
              >
                <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Attach Practice Lab API/SCA/SAST Artifacts</span>
              </button>
            </div>

            {verifiedAssets.length === 0 ? (
              <div className="p-4 bg-[#FFFBEB] border border-[#FDE68A] rounded-md text-xs text-[#92400E]">
                No authorized assets are available yet. Register and authorize an asset in Websites &amp; Assets first.
              </div>
            ) : (
              <>
                {/* Section 1: Target Information & Scope */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-[#475569]">
                      1. Target Information &amp; Scope Limits
                    </h3>
                    <span className="text-[11px] text-[#64748B]">
                      <span className="text-[#DC2626]">*</span> Required field
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
                    <div className="lg:col-span-2">
                      <label htmlFor="scan-asset" className="block text-xs font-medium text-[#334155] mb-1.5">
                        Target Asset (Authorized) <span className="text-[#DC2626]">*</span>
                      </label>
                      <select
                        id="scan-asset"
                        value={assetId}
                        onChange={(e) => setAssetId(e.target.value)}
                        className={`${selectClassName} w-full`}
                      >
                        {verifiedAssets.map((a) => (
                          <option key={a.id} value={a.id}>
                            {a.name} ({a.target_url})
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label htmlFor="scan-depth" className="block text-xs font-medium text-[#334155] mb-1.5">
                        Crawl Depth
                      </label>
                      <input
                        id="scan-depth"
                        type="number"
                        min={1}
                        max={5}
                        value={maxDepth}
                        onChange={(e) => setMaxDepth(Number(e.target.value))}
                        className={`${inputClassName} font-mono`}
                      />
                    </div>

                    <div>
                      <label htmlFor="scan-max-urls" className="block text-xs font-medium text-[#334155] mb-1.5">
                        URL Limit
                      </label>
                      <input
                        id="scan-max-urls"
                        type="number"
                        min={5}
                        max={250}
                        value={maxUrls}
                        onChange={(e) => setMaxUrls(Number(e.target.value))}
                        className={`${inputClassName} font-mono`}
                      />
                    </div>

                    <div>
                      <label htmlFor="scan-max-requests" className="block text-xs font-medium text-[#334155] mb-1.5">
                        Request Limit
                      </label>
                      <input
                        id="scan-max-requests"
                        type="number"
                        min={20}
                        max={1500}
                        value={maxRequests}
                        onChange={(e) => setMaxRequests(Number(e.target.value))}
                        className={`${inputClassName} font-mono`}
                      />
                    </div>

                    <div>
                      <label htmlFor="scan-rps" className="block text-xs font-medium text-[#334155] mb-1.5">
                        Rate (RPS) / Workers
                      </label>
                      <div className="flex gap-2">
                        <input
                          id="scan-rps"
                          type="number"
                          min={1}
                          max={20}
                          value={rateLimitRps}
                          onChange={(e) => setRateLimitRps(Number(e.target.value))}
                          aria-label="Rate limit requests per second"
                          className={`${inputClassName} w-1/2 font-mono px-2`}
                        />
                        <input
                          id="scan-concurrency"
                          type="number"
                          min={1}
                          max={6}
                          value={concurrencyLimit}
                          onChange={(e) => setConcurrencyLimit(Number(e.target.value))}
                          aria-label="Worker concurrency"
                          className={`${inputClassName} w-1/2 font-mono px-2`}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Section 2: Assessment Type */}
                <div className="pt-4 border-t border-[#E2E8F0]">
                  <div className="text-xs font-semibold uppercase tracking-wider text-[#475569] mb-2.5">
                    2. Assessment Type <span className="text-[#DC2626]">*</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                    {(['quick', 'standard', 'comprehensive', 'custom'] as const).map((p) => {
                      const info = PROFILE_INFO[p];
                      const active = profile === p;
                      return (
                        <button
                          key={p}
                          type="button"
                          onClick={() => setProfile(p)}
                          className={`text-left p-4 rounded-lg border transition-colors ${
                            active
                              ? 'bg-[#EFF6FF] border-[#2563EB] ring-1 ring-[#2563EB]'
                              : 'bg-[#FFFFFF] border-[#E2E8F0] hover:border-[#CBD5E1] hover:bg-[#F8FAFC]'
                          }`}
                        >
                          <div className={`text-xs font-semibold ${active ? 'text-[#1E40AF]' : 'text-[#0F172A]'}`}>
                            {info.title}
                          </div>
                          <div className="mt-1.5 text-[11px] text-[#64748B] leading-relaxed">{info.description}</div>
                          <div className="mt-2.5 text-[11px] font-medium text-[#2563EB]">{info.impact}</div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Custom Module Selector */}
                {profile === 'custom' && (
                  <div className="pt-4 border-t border-[#E2E8F0]">
                    <div className="flex items-center justify-between mb-2.5">
                      <div className="text-xs font-semibold uppercase tracking-wider text-[#475569]">
                        Scan Modules ({selectedModules.length} selected)
                      </div>
                      <div className="flex items-center gap-3 text-xs">
                        <button
                          type="button"
                          onClick={() => setSelectedModules(modules.map((m) => m.id))}
                          className="text-[#2563EB] hover:underline font-medium"
                        >
                          Select all
                        </button>
                        <button
                          type="button"
                          onClick={() => setSelectedModules([])}
                          className="text-[#64748B] hover:text-[#0F172A]"
                        >
                          Clear
                        </button>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                      {modules.map((m) => {
                        const checked = selectedModules.includes(m.id);
                        return (
                          <label
                            key={m.id}
                            className={`flex items-start gap-2.5 p-3 rounded-md border text-xs cursor-pointer transition-colors ${
                              checked
                                ? 'bg-[#EFF6FF]/60 border-[#BFDBFE]'
                                : 'bg-[#F8FAFC] border-[#E2E8F0]'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={(e) => {
                                if (e.target.checked) setSelectedModules([...selectedModules, m.id]);
                                else setSelectedModules(selectedModules.filter((id) => id !== m.id));
                              }}
                              className="mt-0.5 rounded border-[#CBD5E1] text-[#2563EB]"
                            />
                            <div>
                              <div className="font-semibold text-[#0F172A]">{m.name}</div>
                              <div className="text-[11px] text-[#64748B]">v{m.version} · {m.category}</div>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Section 3: Collapsible Advanced Configuration */}
                <div className="pt-4 border-t border-[#E2E8F0]">
                  <button
                    type="button"
                    aria-expanded={advancedOpen}
                    onClick={() => setAdvancedOpen((prev) => !prev)}
                    className="w-full flex items-center justify-between px-4 py-3 bg-[#F8FAFC] hover:bg-[#F1F5F9] border border-[#E2E8F0] rounded-lg text-left transition-colors"
                  >
                    <div>
                      <div className="text-xs font-semibold text-[#0F172A]">
                        3. Advanced Configuration (Optional)
                      </div>
                      <div className="text-[11px] text-[#64748B]">
                        Authentication credentials, multi-role testing, OpenAPI specification, SCA manifest, and SAST source files
                      </div>
                    </div>
                    {advancedOpen ? (
                      <ChevronUp className="w-4 h-4 text-[#64748B] shrink-0" aria-hidden="true" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-[#64748B] shrink-0" aria-hidden="true" />
                    )}
                  </button>

                  {advancedOpen && (
                    <div className="mt-4 space-y-5 p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                      {/* Authenticated Testing & Role Comparison */}
                      <div className="p-4 bg-[#FFFFFF] border border-[#E2E8F0] rounded-md space-y-3">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <label className="inline-flex items-center gap-2 text-xs font-semibold text-[#0F172A] cursor-pointer">
                            <input
                              type="checkbox"
                              checked={allowAuthenticated}
                              onChange={(e) => setAllowAuthenticated(e.target.checked)}
                              className="rounded border-[#CBD5E1] text-[#2563EB]"
                            />
                            <span>Enable Authorized Authenticated Testing &amp; Role Comparison</span>
                          </label>
                          <div className="flex items-center gap-2 text-xs">
                            <label htmlFor="scan-timeout" className="text-[#64748B]">Request Timeout (ms):</label>
                            <input
                              id="scan-timeout"
                              type="number"
                              min={2000}
                              max={25000}
                              step={500}
                              value={requestTimeoutMs}
                              onChange={(e) => setRequestTimeoutMs(Number(e.target.value))}
                              className={`${inputClassName} w-24 py-1 font-mono`}
                            />
                          </div>
                        </div>

                        {allowAuthenticated && (
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-3 border-t border-[#E2E8F0] text-xs">
                            <div>
                              <label htmlFor="scan-cred-1" className="block font-medium text-[#334155] mb-1">
                                Primary Role Credential
                              </label>
                              <select
                                id="scan-cred-1"
                                value={credentialId}
                                onChange={(e) => setCredentialId(e.target.value)}
                                className={`${selectClassName} w-full`}
                              >
                                <option value="">Select vault credential...</option>
                                {credentials.map((c) => (
                                  <option key={c.id} value={c.id}>
                                    {c.label} ({c.role_profile} · {c.auth_type})
                                  </option>
                                ))}
                              </select>
                            </div>
                            <div>
                              <label htmlFor="scan-cred-2" className="block font-medium text-[#334155] mb-1">
                                Secondary Role (Optional Comparison)
                              </label>
                              <select
                                id="scan-cred-2"
                                value={secondaryCredentialId}
                                onChange={(e) => setSecondaryCredentialId(e.target.value)}
                                className={`${selectClassName} w-full`}
                              >
                                <option value="">None</option>
                                {credentials.map((c) => (
                                  <option key={c.id} value={c.id}>
                                    {c.label} ({c.role_profile} · {c.auth_type})
                                  </option>
                                ))}
                              </select>
                            </div>
                            <div>
                              <label htmlFor="scan-custom-hdrs" className="block font-medium text-[#334155] mb-1">
                                Custom Auth Headers (Header: Value)
                              </label>
                              <textarea
                                id="scan-custom-hdrs"
                                rows={2}
                                value={customHeadersText}
                                onChange={(e) => setCustomHeadersText(e.target.value)}
                                placeholder="X-Tenant-Id: staging-101"
                                className={`${inputClassName} font-mono py-1.5`}
                              />
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Optional API / SCA / SAST Inputs */}
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-md p-3.5">
                          <label htmlFor="scan-openapi" className="block text-xs font-semibold text-[#0F172A] mb-1.5">
                            API Specification (OpenAPI 3.x / Swagger)
                          </label>
                          <textarea
                            id="scan-openapi"
                            rows={5}
                            value={openapiSpecRaw}
                            onChange={(e) => setOpenapiSpecRaw(e.target.value)}
                            placeholder='{"openapi":"3.0.3","paths":{...}}'
                            className={`${inputClassName} font-mono`}
                          />
                        </div>

                        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-md p-3.5">
                          <div className="flex items-center justify-between gap-2 mb-1.5">
                            <label htmlFor="scan-sca" className="text-xs font-semibold text-[#0F172A]">
                              Dependency Manifest (SCA)
                            </label>
                            <select
                              value={scaManifestName}
                              onChange={(e) => setScaManifestName(e.target.value)}
                              aria-label="Dependency manifest type"
                              className="text-[11px] bg-[#F8FAFC] border border-[#CBD5E1] rounded px-1.5 py-0.5 text-[#334155]"
                            >
                              <option value="package.json">package.json</option>
                              <option value="package-lock.json">package-lock.json</option>
                              <option value="requirements.txt">requirements.txt</option>
                              <option value="pyproject.toml">pyproject.toml</option>
                              <option value="go.mod">go.mod</option>
                              <option value="Cargo.toml">Cargo.toml</option>
                              <option value="pom.xml">pom.xml</option>
                              <option value="composer.lock">composer.lock</option>
                              <option value="Gemfile.lock">Gemfile.lock</option>
                            </select>
                          </div>
                          <textarea
                            id="scan-sca"
                            rows={5}
                            value={scaManifestRaw}
                            onChange={(e) => setScaManifestRaw(e.target.value)}
                            placeholder='{"dependencies":{"express":"4.18.2"}}'
                            className={`${inputClassName} font-mono`}
                          />
                        </div>

                        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-md p-3.5">
                          <div className="flex items-center justify-between gap-2 mb-1.5">
                            <label htmlFor="scan-sast" className="text-xs font-semibold text-[#0F172A] truncate">
                              Source Code Analysis (SAST)
                            </label>
                            <div className="flex items-center gap-2 shrink-0">
                              <label className="text-[11px] font-medium text-[#2563EB] hover:underline cursor-pointer whitespace-nowrap">
                                Upload files
                                <input
                                  type="file"
                                  multiple
                                  onChange={handleMultiSastUpload}
                                  className="sr-only"
                                />
                              </label>
                              <input
                                type="text"
                                value={sastFilename}
                                onChange={(e) => setSastFilename(e.target.value)}
                                aria-label="SAST filename"
                                className="w-24 text-[11px] font-mono bg-[#F8FAFC] border border-[#CBD5E1] rounded px-1.5 py-0.5 text-[#334155]"
                              />
                            </div>
                          </div>
                          <textarea
                            id="scan-sast"
                            rows={5}
                            value={sastCodeRaw}
                            onChange={(e) => setSastCodeRaw(e.target.value)}
                            placeholder={
                              sastFiles.length > 0
                                ? `${sastFiles.length} source file(s) attached: ${sastFiles.map((f) => f.filename).join(', ')}`
                                : 'Paste authorized application source file or upload multiple files for static security checks...'
                            }
                            className={`${inputClassName} font-mono`}
                          />
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-[#E2E8F0] flex justify-end">
                  <button
                    type="submit"
                    disabled={launching}
                    className="inline-flex items-center gap-2 px-5 py-2.5 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] disabled:opacity-50 rounded-md transition-colors shadow-xs"
                  >
                    <Play className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>{launching ? 'Queuing Scan...' : 'Launch Security Assessment'}</span>
                  </button>
                </div>
              </>
            )}
          </div>
        </form>
      )}

      {/* LIVE CONSOLE & SCAN HISTORY */}
      {subView === 'console' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Scan History Sidebar */}
          <div className="lg:col-span-4 min-w-0 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden flex flex-col">
            <div className="p-4 border-b border-[#E2E8F0] space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-[#475569]">
                  Scan History ({filteredScans.length})
                </h2>
              </div>
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-[#94A3B8] absolute left-2.5 top-2.5" aria-hidden="true" />
                <input
                  type="search"
                  value={historySearch}
                  onChange={(e) => setHistorySearch(e.target.value)}
                  placeholder="Filter by target or profile..."
                  aria-label="Filter scan history"
                  className={`${inputClassName} pl-8 py-1.5`}
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <select
                  value={historyStatus}
                  onChange={(e) => setHistoryStatus(e.target.value)}
                  aria-label="Filter scans by status"
                  className={`${selectClassName} py-1.5`}
                >
                  <option value="all">All Statuses</option>
                  <option value="completed">Completed</option>
                  <option value="running">Running</option>
                  <option value="failed">Failed</option>
                  <option value="cancelled">Cancelled</option>
                </select>
                <select
                  value={historySort}
                  onChange={(e) => setHistorySort(e.target.value as typeof historySort)}
                  aria-label="Sort scans"
                  className={`${selectClassName} py-1.5`}
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                  <option value="score_desc">Highest Score</option>
                  <option value="score_asc">Lowest Score</option>
                </select>
              </div>
            </div>

            <div className="divide-y divide-[#E2E8F0] max-h-[680px] overflow-y-auto">
              {filteredScans.length === 0 ? (
                <div className="p-6 text-xs text-[#64748B]">No matching scans recorded yet.</div>
              ) : (
                filteredScans.map((s) => {
                  const active = (selectedScanId || scans[0]?.id) === s.id;
                  return (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => onSelectScanId(s.id)}
                      className={`w-full text-left px-4 py-3 transition-colors border-l-2 ${
                        active
                          ? 'bg-[#EFF6FF] border-[#2563EB]'
                          : 'border-transparent hover:bg-[#F8FAFC]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className={`text-xs font-semibold truncate ${active ? 'text-[#1E40AF]' : 'text-[#0F172A]'}`}>
                          {s.asset_name}
                        </span>
                        <ScanStatusBadge status={s.status} progressPct={s.progress_pct} />
                      </div>
                      <div className="mt-1.5 flex items-center justify-between text-[11px] text-[#64748B] font-mono">
                        <span>{s.profile} · {formatDateTime(s.created_at)}</span>
                        <span className="font-semibold text-[#0F172A]">
                          {s.posture_score !== null ? `${s.posture_score}/100` : `${s.progress_pct}%`}
                        </span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Active Assessment Results Detail */}
          <div className="lg:col-span-8 min-w-0 space-y-5">
            {detailLoading && !detail ? (
              <div className="h-64 bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg animate-pulse" />
            ) : !detail ? (
              <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg">
                <EmptyState
                  icon={Activity}
                  title="Select an assessment to inspect results"
                  description="Choose a scan from the history panel or configure a new assessment to inspect live module execution, checks, and attack-surface endpoints."
                  action={
                    canLaunch ? (
                      <button
                        type="button"
                        onClick={() => switchSubView('launch')}
                        className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md"
                      >
                        <Play className="w-3.5 h-3.5" aria-hidden="true" />
                        <span>New Assessment</span>
                      </button>
                    ) : undefined
                  }
                />
              </div>
            ) : (
              <>
                {/* Assessment Summary Card */}
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-5">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <div className="flex flex-wrap items-center gap-2.5">
                        <h2 className="text-base font-semibold text-[#0F172A]">{detail.scan.asset_name}</h2>
                        <ScanStatusBadge status={detail.scan.status} progressPct={detail.scan.progress_pct} />
                      </div>
                      <div className="mt-1 text-xs text-[#64748B] font-mono">
                        {detail.scan.target_url} · {detail.scan.profile} · Duration {formatDurationMs(detail.scan.duration_ms)}
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      {detail.scan.posture_score !== null && (
                        <div className="px-3.5 py-2 bg-[#EFF6FF] border border-[#BFDBFE] rounded-md text-right">
                          <div className="text-[10px] font-semibold uppercase tracking-wider text-[#1E40AF]">
                            Posture Score
                          </div>
                          <div className="text-lg font-mono font-bold tabular-nums text-[#1E40AF]">
                            {detail.scan.posture_score}/100
                          </div>
                        </div>
                      )}
                      {(detail.scan.status === 'queued' || detail.scan.status === 'running') && canLaunch && (
                        <button
                          type="button"
                          onClick={() => handleCancelScan(detail.scan.id)}
                          className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-[#B91C1C] bg-[#FEF2F2] border border-[#FECACA] hover:bg-[#FEE2E2] rounded-md"
                        >
                          <Square className="w-3 h-3" aria-hidden="true" />
                          <span>Cancel Scan</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Progress Bar */}
                  <div className="mt-4">
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className="text-[#475569] font-medium">
                        {detail.scan.current_module ? `Running: ${detail.scan.current_module}` : `Status: ${detail.scan.status}`}
                      </span>
                      <span className="font-mono tabular-nums font-semibold text-[#0F172A]">
                        {detail.scan.progress_pct}%
                      </span>
                    </div>
                    <div className="w-full h-2 bg-[#F1F5F9] rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${
                          detail.scan.status === 'failed'
                            ? 'bg-[#DC2626]'
                            : detail.scan.status === 'completed'
                              ? 'bg-[#16A34A]'
                              : 'bg-[#2563EB]'
                        }`}
                        style={{ width: `${detail.scan.progress_pct}%` }}
                      />
                    </div>
                  </div>

                  {/* Normalized 7-Outcome Check Summary */}
                  <div className="mt-4 pt-4 border-t border-[#E2E8F0] grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2 text-center">
                    {[
                      ['TOTAL', detail.scan.total_checks, 'text-[#0F172A]', 'bg-[#F8FAFC] border-[#E2E8F0]'],
                      ['PASS', detail.scan.passed_checks, 'text-[#16A34A]', 'bg-[#F0FDF4] border-[#BBF7D0]'],
                      ['FAIL', detail.scan.failed_checks, 'text-[#DC2626]', 'bg-[#FEF2F2] border-[#FECACA]'],
                      ['POTENTIAL', detail.scan.potential_checks, 'text-[#D97706]', 'bg-[#FFFBEB] border-[#FDE68A]'],
                      ['INFO', detail.scan.informational_checks, 'text-[#475569]', 'bg-[#F8FAFC] border-[#E2E8F0]'],
                      ['MANUAL', detail.scan.manual_required_checks, 'text-[#B45309]', 'bg-[#FFFBEB] border-[#FDE68A]'],
                      ['NOT_PERF', detail.scan.not_performed_checks, 'text-[#64748B]', 'bg-[#F8FAFC] border-[#E2E8F0]'],
                      ['N/A', detail.scan.not_applicable_checks, 'text-[#64748B]', 'bg-[#F8FAFC] border-[#E2E8F0]'],
                    ].map(([label, val, cls, box]) => (
                      <div key={String(label)} className={`border rounded-md p-2 ${box}`}>
                        <div className="text-[10px] font-mono font-medium text-[#64748B] truncate">{label}</div>
                        <div className={`mt-0.5 text-sm font-mono font-bold tabular-nums ${cls}`}>{val}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Module Execution Table */}
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
                  <div className="px-4 py-3 border-b border-[#E2E8F0] text-xs font-semibold text-[#0F172A]">
                    Scanner Modules ({detail.executions.length})
                  </div>
                  <div className="divide-y divide-[#E2E8F0]">
                    {detail.executions.map((ex) => (
                      <div key={ex.id} className="px-4 py-2.5 flex items-center justify-between gap-4 text-xs hover:bg-[#F8FAFC]">
                        <div className="flex items-center gap-2.5 min-w-0">
                          {ex.status === 'completed' ? (
                            <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0" aria-hidden="true" />
                          ) : ex.status === 'failed' ? (
                            <XCircle className="w-4 h-4 text-[#DC2626] shrink-0" aria-hidden="true" />
                          ) : ex.status === 'running' ? (
                            <Clock className="w-4 h-4 text-[#2563EB] shrink-0" aria-hidden="true" />
                          ) : (
                            <AlertCircle className="w-4 h-4 text-[#94A3B8] shrink-0" aria-hidden="true" />
                          )}
                          <div className="min-w-0">
                            <div className="font-medium text-[#0F172A] truncate">{ex.module_name}</div>
                            {ex.error_message && <div className="text-[11px] text-[#DC2626]">{ex.error_message}</div>}
                          </div>
                        </div>
                        <div className="text-right font-mono tabular-nums text-[11px] text-[#64748B] shrink-0">
                          {ex.checks_executed} {ex.checks_executed === 1 ? 'check' : 'checks'} ·{' '}
                          {ex.findings_created} {ex.findings_created === 1 ? 'finding' : 'findings'} ·{' '}
                          {formatDurationMs(ex.duration_ms)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Discovered Attack Surface Endpoints */}
                {detail.endpoints.length > 0 && (
                  <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
                    <div className="px-4 py-3 border-b border-[#E2E8F0] flex flex-wrap items-center justify-between gap-3">
                      <div className="text-xs font-semibold text-[#0F172A]">
                        Discovered Attack Surface Endpoints ({filteredEndpoints.length} of {detail.endpoints.length})
                      </div>
                      <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                        <input
                          type="search"
                          value={endpointSearch}
                          onChange={(e) => setEndpointSearch(e.target.value)}
                          placeholder="Search endpoints..."
                          aria-label="Search discovered endpoints"
                          className={`${inputClassName} flex-1 sm:w-44 min-w-[140px] py-1`}
                        />
                        <select
                          value={endpointMethodFilter}
                          onChange={(e) => setEndpointMethodFilter(e.target.value)}
                          aria-label="Filter endpoints by HTTP method"
                          className={`${selectClassName} py-1`}
                        >
                          <option value="ALL">All Methods</option>
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="DELETE">DELETE</option>
                        </select>
                      </div>
                    </div>
                    <div className="overflow-x-auto max-h-64">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead className="sticky top-0 bg-[#F8FAFC] border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B]">
                          <tr>
                            <th className="py-2 px-4 font-semibold">Method</th>
                            <th className="py-2 px-4 font-semibold">Path</th>
                            <th className="py-2 px-4 font-semibold">Source</th>
                            <th className="py-2 px-4 font-semibold">Parameters</th>
                            <th className="py-2 px-4 font-semibold text-right">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#E2E8F0]">
                          {filteredEndpoints.slice(0, 60).map((ep) => {
                            let params: string[] = [];
                            try {
                              params = JSON.parse(ep.parameters_json || '[]') as string[];
                            } catch {
                              params = [];
                            }
                            return (
                              <tr key={ep.id} className="hover:bg-[#F8FAFC]">
                                <td className="py-2 px-4">
                                  <MethodBadge method={ep.method} />
                                </td>
                                <td className="py-2 px-4 font-mono text-[#0F172A]">{ep.path}</td>
                                <td className="py-2 px-4 text-[#64748B]">{ep.source}</td>
                                <td className="py-2 px-4 font-mono text-[11px] text-[#475569]">{params.join(', ') || '—'}</td>
                                <td className="py-2 px-4 text-right font-mono tabular-nums text-[#334155]">
                                  {ep.status_code ?? '—'}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Security Checks Ledger */}
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
                  <div className="px-4 py-3 border-b border-[#E2E8F0] flex flex-wrap items-center justify-between gap-3">
                    <div className="text-xs font-semibold text-[#0F172A]">
                      Executed Security Checks ({filteredChecks.length} of {detail.checks.length})
                    </div>
                    <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                      <input
                        type="search"
                        value={checkSearch}
                        onChange={(e) => setCheckSearch(e.target.value)}
                        placeholder="Search checks..."
                        aria-label="Search security checks"
                        className={`${inputClassName} flex-1 sm:w-44 min-w-[140px] py-1`}
                      />
                      <select
                        value={checkOutcomeFilter}
                        onChange={(e) => setCheckOutcomeFilter(e.target.value)}
                        aria-label="Filter checks by outcome"
                        className={`${selectClassName} py-1`}
                      >
                        <option value="ALL">All Outcomes</option>
                        <option value="FAIL">FAIL</option>
                        <option value="POTENTIAL">POTENTIAL</option>
                        <option value="PASS">PASS</option>
                        <option value="INFORMATIONAL">INFORMATIONAL</option>
                        <option value="MANUAL_REQUIRED">MANUAL_REQUIRED</option>
                        <option value="NOT_PERFORMED">NOT_PERFORMED</option>
                        <option value="NOT_APPLICABLE">NOT_APPLICABLE</option>
                      </select>
                    </div>
                  </div>
                  <div className="overflow-x-auto max-h-96">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead className="sticky top-0 bg-[#F8FAFC] border-b border-[#E2E8F0] text-[11px] uppercase tracking-wider text-[#64748B]">
                        <tr>
                          <th className="py-2 px-4 font-semibold">Outcome</th>
                          <th className="py-2 px-4 font-semibold">Check</th>
                          <th className="py-2 px-4 font-semibold">Observed Evidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#E2E8F0]">
                        {filteredChecks.map((c) => (
                          <tr key={c.id} className="hover:bg-[#F8FAFC]">
                            <td className="py-2.5 px-4 whitespace-nowrap">
                              <OutcomeBadge status={c.normalized_status || c.status} />
                            </td>
                            <td className="py-2.5 px-4">
                              <div className="font-medium text-[#0F172A]">{c.title}</div>
                              <div className="text-[11px] text-[#64748B] mt-0.5">{c.explanation}</div>
                            </td>
                            <td className="py-2.5 px-4 font-mono text-[11px] text-[#334155] max-w-xs break-words">
                              {c.observed_value || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Structured Execution Log */}
                <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg overflow-hidden">
                  <div className="px-4 py-3 border-b border-[#E2E8F0] text-xs font-semibold text-[#0F172A]">
                    Execution Log ({detail.logs.length})
                  </div>
                  <div className="p-3 bg-[#F8FAFC] max-h-48 overflow-y-auto space-y-1 font-mono text-[11px]">
                    {detail.logs.map((l) => (
                      <div
                        key={l.id}
                        className={
                          l.level === 'error'
                            ? 'text-[#DC2626]'
                            : l.level === 'warn'
                              ? 'text-[#B45309]'
                              : 'text-[#334155]'
                        }
                      >
                        <span className="text-[#94A3B8]">[{new Date(l.timestamp).toLocaleTimeString()}]</span>{' '}
                        {l.module_id ? <span className="text-[#2563EB] font-medium">[{l.module_id}] </span> : null}
                        <span>{l.message}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* SCAN COMPARISON */}
      {subView === 'compare' && (
        <div className="bg-[#FFFFFF] border border-[#E2E8F0] rounded-lg p-6 space-y-5">
          <div>
            <h2 className="text-base font-semibold text-[#0F172A]">Compare Assessment Runs</h2>
            <p className="mt-0.5 text-xs text-[#64748B]">Verify remediation progress across historical assessments.</p>
          </div>
          {completedScans.length < 2 ? (
            <div className="text-xs text-[#64748B] p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-md">
              At least two completed scans are required to compare security posture deltas.
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-end gap-4">
                <div className="flex-1 min-w-[220px]">
                  <label htmlFor="cmp-base" className="block text-xs font-medium text-[#334155] mb-1">
                    Baseline Scan
                  </label>
                  <select
                    id="cmp-base"
                    value={baselineId}
                    onChange={(e) => setBaselineId(e.target.value)}
                    className={`${selectClassName} w-full`}
                  >
                    {completedScans.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.asset_name} · {s.profile} · {formatDateTime(s.completed_at)} ({s.posture_score ?? 'N/A'})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex-1 min-w-[220px]">
                  <label htmlFor="cmp-target" className="block text-xs font-medium text-[#334155] mb-1">
                    Comparison Scan
                  </label>
                  <select
                    id="cmp-target"
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    className={`${selectClassName} w-full`}
                  >
                    {completedScans.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.asset_name} · {s.profile} · {formatDateTime(s.completed_at)} ({s.posture_score ?? 'N/A'})
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  onClick={handleCompare}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md shadow-xs"
                >
                  <GitCompare className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Compare Results</span>
                </button>
              </div>

              {compareData && (
                <div className="space-y-4 pt-4 border-t border-[#E2E8F0]">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-center">
                    <div className="p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                      <div className="text-xs font-medium text-[#64748B]">Posture Delta</div>
                      <div
                        className={`mt-1 text-xl font-mono font-bold tabular-nums ${
                          (compareData.postureDelta ?? 0) >= 0 ? 'text-[#16A34A]' : 'text-[#DC2626]'
                        }`}
                      >
                        {compareData.postureDelta !== null
                          ? `${compareData.postureDelta > 0 ? '+' : ''}${compareData.postureDelta}`
                          : '—'}
                      </div>
                    </div>
                    <div className="p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                      <div className="text-xs font-medium text-[#64748B]">Passed Checks Delta</div>
                      <div className="mt-1 text-xl font-mono font-bold tabular-nums text-[#0F172A]">
                        {compareData.passedDelta > 0 ? `+${compareData.passedDelta}` : compareData.passedDelta}
                      </div>
                    </div>
                    <div className="p-4 bg-[#F8FAFC] border border-[#E2E8F0] rounded-lg">
                      <div className="text-xs font-medium text-[#64748B]">Failed Checks Delta</div>
                      <div className="mt-1 text-xl font-mono font-bold tabular-nums text-[#0F172A]">
                        {compareData.failedDelta > 0 ? `+${compareData.failedDelta}` : compareData.failedDelta}
                      </div>
                    </div>
                  </div>

                  {compareData.checkDiffs.length === 0 ? (
                    <div className="text-xs text-[#64748B]">No check status changes between these two scans.</div>
                  ) : (
                    <div className="overflow-x-auto border border-[#E2E8F0] rounded-lg">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead>
                          <tr className="border-b border-[#E2E8F0] bg-[#F8FAFC] text-[11px] uppercase tracking-wider text-[#64748B]">
                            <th className="py-2.5 px-4 font-semibold">Check</th>
                            <th className="py-2.5 px-4 font-semibold">Baseline</th>
                            <th className="py-2.5 px-4 font-semibold">Comparison</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#E2E8F0]">
                          {compareData.checkDiffs.map((d) => (
                            <tr key={d.checkKey} className="hover:bg-[#F8FAFC]">
                              <td className="py-2.5 px-4 font-medium text-[#0F172A]">{d.title}</td>
                              <td className="py-2.5 px-4">
                                <OutcomeBadge status={d.baselineStatus} />
                              </td>
                              <td className="py-2.5 px-4">
                                <OutcomeBadge status={d.targetStatus} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};
