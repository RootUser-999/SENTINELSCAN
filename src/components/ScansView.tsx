import React, { useEffect, useState } from 'react';
import { Play, Square, GitCompare, FlaskConical, CheckCircle2, XCircle, Clock, AlertCircle } from 'lucide-react';
import { apiRequest } from '../api/client';
import type {
  Asset,
  EndpointRow,
  ScanRecord,
  ScannerModuleMeta,
  SecurityCheckRow,
  UserRole,
} from '../types/sentinel';
import { formatDateTime, formatDurationMs, getCheckOutcomeLabel } from '../utils/formatters';

interface ScansViewProps {
  assets: Asset[];
  scans: ScanRecord[];
  modules: ScannerModuleMeta[];
  userRole: UserRole;
  preselectedAssetId: string | null;
  selectedScanId: string | null;
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
  onSelectScanId,
  onRefresh,
  onToast,
}) => {
  const verifiedAssets = assets.filter((a) => a.ownership_status === 'verified');
  const [subView, setSubView] = useState<'console' | 'launch' | 'compare'>(
    preselectedAssetId ? 'launch' : 'console'
  );

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

  // Detail polling state
  const [detail, setDetail] = useState<ScanDetailPayload | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Comparison state
  const completedScans = scans.filter((s) => s.status === 'completed');
  const [baselineId, setBaselineId] = useState(completedScans[1]?.id || completedScans[0]?.id || '');
  const [targetId, setTargetId] = useState(completedScans[0]?.id || '');
  const [compareData, setCompareData] = useState<CompareResult | null>(null);

  const canLaunch = userRole === 'admin' || userRole === 'analyst';

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

  return (
    <div className="space-y-5">
      {/* Sub-navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-1 p-1 bg-[#0F172A] border border-slate-800 rounded-md">
          <button
            type="button"
            onClick={() => setSubView('console')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              subView === 'console' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Live Console & History
          </button>
          {canLaunch && (
            <button
              type="button"
              onClick={() => setSubView('launch')}
              className={`px-3.5 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                subView === 'launch' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Configure & Launch Scan
            </button>
          )}
          <button
            type="button"
            onClick={() => setSubView('compare')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              subView === 'compare' ? 'bg-slate-800 text-slate-100' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Compare Scans
          </button>
        </div>
      </div>

      {/* LAUNCH WIZARD */}
      {subView === 'launch' && (
        <form onSubmit={handleLaunchScan} className="bg-[#0F172A] border border-slate-800 rounded-md p-6 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100">Configure Security Assessment</h2>
              <p className="text-xs text-slate-400">Configure crawl scope, concurrency, authenticated test roles, and artifact inputs.</p>
            </div>
            <button
              type="button"
              onClick={handleLoadPracticeSamples}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-300 bg-blue-950/50 border border-blue-800/60 hover:bg-blue-900/50 rounded"
            >
              <FlaskConical className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Attach Practice Lab API/SCA/SAST Artifacts</span>
            </button>
          </div>

          {verifiedAssets.length === 0 ? (
            <div className="p-4 bg-amber-950/30 border border-amber-800/50 rounded text-xs text-amber-200">
              No authorized assets are available yet. Register an asset in the Websites & Assets tab first.
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-4">
                <div className="lg:col-span-2">
                  <label htmlFor="scan-asset" className="block text-xs font-medium text-slate-300 mb-1.5">
                    Target Asset (Authorized)
                  </label>
                  <select
                    id="scan-asset"
                    value={assetId}
                    onChange={(e) => setAssetId(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  >
                    {verifiedAssets.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.name} ({a.target_url})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="scan-depth" className="block text-xs font-medium text-slate-300 mb-1.5">
                    Crawl Depth
                  </label>
                  <input
                    id="scan-depth"
                    type="number"
                    min={1}
                    max={5}
                    value={maxDepth}
                    onChange={(e) => setMaxDepth(Number(e.target.value))}
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  />
                </div>

                <div>
                  <label htmlFor="scan-max-urls" className="block text-xs font-medium text-slate-300 mb-1.5">
                    URL Limit
                  </label>
                  <input
                    id="scan-max-urls"
                    type="number"
                    min={5}
                    max={250}
                    value={maxUrls}
                    onChange={(e) => setMaxUrls(Number(e.target.value))}
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  />
                </div>

                <div>
                  <label htmlFor="scan-max-requests" className="block text-xs font-medium text-slate-300 mb-1.5">
                    Request Limit
                  </label>
                  <input
                    id="scan-max-requests"
                    type="number"
                    min={20}
                    max={1500}
                    value={maxRequests}
                    onChange={(e) => setMaxRequests(Number(e.target.value))}
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  />
                </div>

                <div>
                  <label htmlFor="scan-rps" className="block text-xs font-medium text-slate-300 mb-1.5">
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
                      className="w-1/2 px-2 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                    />
                    <input
                      id="scan-concurrency"
                      type="number"
                      min={1}
                      max={6}
                      value={concurrencyLimit}
                      onChange={(e) => setConcurrencyLimit(Number(e.target.value))}
                      aria-label="Worker concurrency"
                      className="w-1/2 px-2 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-100"
                    />
                  </div>
                </div>
              </div>

              {/* Scan Profile Selector */}
              <div>
                <div className="text-xs font-medium text-slate-300 mb-2">Assessment Profile</div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  {(['quick', 'standard', 'comprehensive', 'custom'] as const).map((p) => {
                    const info = PROFILE_INFO[p];
                    const active = profile === p;
                    return (
                      <button
                        key={p}
                        type="button"
                        onClick={() => setProfile(p)}
                        className={`text-left p-3.5 rounded border transition-colors ${
                          active
                            ? 'bg-blue-950/30 border-blue-500 text-slate-100'
                            : 'bg-[#090D16] border-slate-800 text-slate-300 hover:border-slate-700'
                        }`}
                      >
                        <div className="text-xs font-semibold">{info.title}</div>
                        <div className="mt-1 text-[11px] text-slate-400 leading-relaxed">{info.description}</div>
                        <div className="mt-2 text-[11px] text-blue-300/90">{info.impact}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Custom Module Selector */}
              {profile === 'custom' && (
                <div>
                  <div className="text-xs font-medium text-slate-300 mb-2">Select Scanner Modules</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {modules.map((m) => {
                      const checked = selectedModules.includes(m.id);
                      return (
                        <label
                          key={m.id}
                          className="flex items-start gap-2.5 p-3 bg-[#090D16] border border-slate-800 rounded text-xs cursor-pointer"
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={(e) => {
                              if (e.target.checked) setSelectedModules([...selectedModules, m.id]);
                              else setSelectedModules(selectedModules.filter((id) => id !== m.id));
                            }}
                            className="mt-0.5"
                          />
                          <div>
                            <div className="font-medium text-slate-200">{m.name}</div>
                            <div className="text-[11px] text-slate-500">v{m.version} · {m.category}</div>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Authenticated Testing & Role Comparison */}
              <div className="p-4 bg-[#090D16] border border-slate-800 rounded space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-200 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={allowAuthenticated}
                      onChange={(e) => setAllowAuthenticated(e.target.checked)}
                    />
                    <span>Enable Authorized Authenticated Testing & Role Comparison</span>
                  </label>
                  <div className="flex items-center gap-2 text-xs">
                    <label htmlFor="scan-timeout" className="text-slate-400">Request Timeout (ms):</label>
                    <input
                      id="scan-timeout"
                      type="number"
                      min={2000}
                      max={25000}
                      step={500}
                      value={requestTimeoutMs}
                      onChange={(e) => setRequestTimeoutMs(Number(e.target.value))}
                      className="w-24 px-2 py-1 font-mono bg-[#0F172A] border border-slate-700 rounded text-slate-200"
                    />
                  </div>
                </div>

                {allowAuthenticated && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 border-t border-slate-800/80 text-xs">
                    <div>
                      <label htmlFor="scan-cred-1" className="block text-slate-300 mb-1">Primary Role Credential</label>
                      <select
                        id="scan-cred-1"
                        value={credentialId}
                        onChange={(e) => setCredentialId(e.target.value)}
                        className="w-full px-2.5 py-2 bg-[#0F172A] border border-slate-700 rounded text-slate-100"
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
                      <label htmlFor="scan-cred-2" className="block text-slate-300 mb-1">Secondary Role (Optional Comparison)</label>
                      <select
                        id="scan-cred-2"
                        value={secondaryCredentialId}
                        onChange={(e) => setSecondaryCredentialId(e.target.value)}
                        className="w-full px-2.5 py-2 bg-[#0F172A] border border-slate-700 rounded text-slate-100"
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
                      <label htmlFor="scan-custom-hdrs" className="block text-slate-300 mb-1">Custom Auth Headers (Header: Value)</label>
                      <textarea
                        id="scan-custom-hdrs"
                        rows={2}
                        value={customHeadersText}
                        onChange={(e) => setCustomHeadersText(e.target.value)}
                        placeholder="X-Tenant-Id: staging-101"
                        className="w-full px-2.5 py-1.5 font-mono bg-[#0F172A] border border-slate-700 rounded text-slate-200"
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Optional API / SCA / SAST Inputs */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 pt-2 border-t border-slate-800">
                <div>
                  <label htmlFor="scan-openapi" className="block text-xs font-medium text-slate-300 mb-1">
                    OpenAPI 3.x / Swagger Spec (Optional JSON/YAML)
                  </label>
                  <textarea
                    id="scan-openapi"
                    rows={5}
                    value={openapiSpecRaw}
                    onChange={(e) => setOpenapiSpecRaw(e.target.value)}
                    placeholder='{"openapi":"3.0.3","paths":{...}}'
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-200"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label htmlFor="scan-sca" className="text-xs font-medium text-slate-300">
                      Dependency Manifest (SCA via OSV)
                    </label>
                    <select
                      value={scaManifestName}
                      onChange={(e) => setScaManifestName(e.target.value)}
                      aria-label="Dependency manifest type"
                      className="text-[11px] bg-[#090D16] border border-slate-700 rounded px-1.5 py-0.5 text-slate-300"
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
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-200"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <label htmlFor="scan-sast" className="text-xs font-medium text-slate-300 truncate">
                      Authorized Source Code (SAST)
                    </label>
                    <div className="flex items-center gap-2 shrink-0">
                      <label className="text-[11px] text-blue-400 hover:underline cursor-pointer whitespace-nowrap">
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
                        className="w-24 text-[11px] font-mono bg-[#090D16] border border-slate-700 rounded px-1.5 py-0.5 text-slate-300"
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
                    className="w-full px-3 py-2 text-xs font-mono bg-[#090D16] border border-slate-700 rounded text-slate-200"
                  />
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={launching}
                  className="inline-flex items-center gap-2 px-5 py-2.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded transition-colors"
                >
                  <Play className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>{launching ? 'Queuing Scan...' : 'Launch Security Assessment'}</span>
                </button>
              </div>
            </>
          )}
        </form>
      )}

      {/* LIVE CONSOLE & HISTORY */}
      {subView === 'console' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Scan List */}
          <div className="lg:col-span-4 bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 text-xs font-semibold text-slate-200">
              Scan History ({scans.length})
            </div>
            <div className="divide-y divide-slate-800/80 max-h-[600px] overflow-y-auto">
              {scans.length === 0 ? (
                <div className="p-6 text-xs text-slate-500">No scans executed yet.</div>
              ) : (
                scans.map((s) => {
                  const active = (selectedScanId || scans[0]?.id) === s.id;
                  return (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => onSelectScanId(s.id)}
                      className={`w-full text-left px-4 py-3 transition-colors ${
                        active ? 'bg-slate-800/80' : 'hover:bg-slate-800/30'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-medium text-slate-100 truncate">{s.asset_name}</span>
                        <span className={`text-[11px] font-mono ${s.status === 'completed' ? 'text-emerald-400' : s.status === 'failed' ? 'text-red-400' : 'text-blue-400'}`}>
                          {s.status}
                        </span>
                      </div>
                      <div className="mt-1 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                        <span>{s.profile} · {formatDateTime(s.created_at)}</span>
                        <span>{s.posture_score !== null ? `${s.posture_score}/100` : `${s.progress_pct}%`}</span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>

          {/* Active Scan Detail */}
          <div className="lg:col-span-8 space-y-5">
            {detailLoading && !detail ? (
              <div className="h-64 bg-[#0F172A] border border-slate-800 rounded-md animate-pulse" />
            ) : !detail ? (
              <div className="bg-[#0F172A] border border-slate-800 rounded-md p-8 text-xs text-slate-400">
                Select a scan or launch a new assessment to inspect live module progress, checks, and logs.
              </div>
            ) : (
              <>
                <div className="bg-[#0F172A] border border-slate-800 rounded-md p-5">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <h2 className="text-base font-semibold text-slate-100">{detail.scan.asset_name}</h2>
                      <div className="mt-0.5 text-xs text-slate-400 font-mono">
                        {detail.scan.target_url} · {detail.scan.profile} · Duration {formatDurationMs(detail.scan.duration_ms)}
                      </div>
                    </div>
                    {(detail.scan.status === 'queued' || detail.scan.status === 'running') && canLaunch && (
                      <button
                        type="button"
                        onClick={() => handleCancelScan(detail.scan.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-300 bg-red-950/50 border border-red-800/60 hover:bg-red-900/50 rounded"
                      >
                        <Square className="w-3 h-3" aria-hidden="true" />
                        <span>Cancel Scan</span>
                      </button>
                    )}
                  </div>

                  {/* Progress Bar */}
                  <div className="mt-4">
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className="text-slate-300">
                        {detail.scan.current_module ? `Running: ${detail.scan.current_module}` : `Status: ${detail.scan.status}`}
                      </span>
                      <span className="font-mono tabular-nums text-slate-300">{detail.scan.progress_pct}%</span>
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${
                          detail.scan.status === 'failed' ? 'bg-red-500' : detail.scan.status === 'completed' ? 'bg-emerald-500' : 'bg-blue-500'
                        }`}
                        style={{ width: `${detail.scan.progress_pct}%` }}
                      />
                    </div>
                  </div>

                  {/* Normalized Check Taxonomy Summary */}
                  <div className="mt-4 pt-4 border-t border-slate-800 grid grid-cols-4 sm:grid-cols-8 gap-2 text-center">
                    {[
                      ['TOTAL', detail.scan.total_checks, 'text-slate-100'],
                      ['PASS', detail.scan.passed_checks, 'text-emerald-400'],
                      ['FAIL', detail.scan.failed_checks, 'text-red-400'],
                      ['POTENTIAL', detail.scan.potential_checks, 'text-amber-400'],
                      ['INFO', detail.scan.informational_checks, 'text-slate-400'],
                      ['MANUAL', detail.scan.manual_required_checks, 'text-amber-300'],
                      ['NOT_PERF', detail.scan.not_performed_checks, 'text-slate-500'],
                      ['N/A', detail.scan.not_applicable_checks, 'text-slate-500'],
                    ].map(([label, val, cls]) => (
                      <div key={String(label)} className="bg-[#090D16] border border-slate-800 rounded p-2">
                        <div className="text-[10px] font-mono text-slate-500 truncate">{label}</div>
                        <div className={`text-sm font-mono font-semibold tabular-nums ${cls}`}>{val}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Module Execution Table */}
                <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 text-xs font-semibold text-slate-200">
                    Scanner Modules ({detail.executions.length})
                  </div>
                  <div className="divide-y divide-slate-800/80">
                    {detail.executions.map((ex) => (
                      <div key={ex.id} className="px-4 py-2.5 flex items-center justify-between gap-4 text-xs">
                        <div className="flex items-center gap-2.5 min-w-0">
                          {ex.status === 'completed' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
                          ) : ex.status === 'failed' ? (
                            <XCircle className="w-4 h-4 text-red-400 shrink-0" aria-hidden="true" />
                          ) : ex.status === 'running' ? (
                            <Clock className="w-4 h-4 text-blue-400 shrink-0" aria-hidden="true" />
                          ) : (
                            <AlertCircle className="w-4 h-4 text-slate-500 shrink-0" aria-hidden="true" />
                          )}
                          <div className="min-w-0">
                            <div className="font-medium text-slate-200 truncate">{ex.module_name}</div>
                            {ex.error_message && <div className="text-[11px] text-red-400">{ex.error_message}</div>}
                          </div>
                        </div>
                        <div className="text-right font-mono tabular-nums text-[11px] text-slate-400 shrink-0">
                          {ex.checks_executed} checks · {ex.findings_created} findings · {formatDurationMs(ex.duration_ms)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Discovered Attack Surface Endpoints */}
                {detail.endpoints.length > 0 && (
                  <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
                    <div className="px-4 py-3 border-b border-slate-800 text-xs font-semibold text-slate-200">
                      Discovered Attack Surface Endpoints ({detail.endpoints.length})
                    </div>
                    <div className="overflow-x-auto max-h-60">
                      <table className="w-full text-left border-collapse text-xs">
                        <thead className="sticky top-0 bg-[#0B111E] border-b border-slate-800 text-slate-400">
                          <tr>
                            <th className="py-2 px-4 font-medium">Method</th>
                            <th className="py-2 px-4 font-medium">Path</th>
                            <th className="py-2 px-4 font-medium">Source</th>
                            <th className="py-2 px-4 font-medium">Parameters</th>
                            <th className="py-2 px-4 font-medium text-right">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {detail.endpoints.slice(0, 60).map((ep) => {
                            let params: string[] = [];
                            try {
                              params = JSON.parse(ep.parameters_json || '[]') as string[];
                            } catch {
                              params = [];
                            }
                            return (
                              <tr key={ep.id} className="hover:bg-slate-800/30">
                                <td className="py-2 px-4 font-mono text-blue-300">{ep.method}</td>
                                <td className="py-2 px-4 font-mono text-slate-200">{ep.path}</td>
                                <td className="py-2 px-4 text-slate-400">{ep.source}</td>
                                <td className="py-2 px-4 font-mono text-[11px] text-slate-400">{params.join(', ') || '—'}</td>
                                <td className="py-2 px-4 text-right font-mono text-slate-300">{ep.status_code ?? '—'}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Security Checks Ledger */}
                <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 text-xs font-semibold text-slate-200">
                    Executed Security Checks ({detail.checks.length})
                  </div>
                  <div className="overflow-x-auto max-h-96">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead className="sticky top-0 bg-[#0B111E] border-b border-slate-800 text-slate-400">
                        <tr>
                          <th className="py-2 px-4 font-medium">Outcome</th>
                          <th className="py-2 px-4 font-medium">Check</th>
                          <th className="py-2 px-4 font-medium">Observed Evidence</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {detail.checks.map((c) => {
                          const out = getCheckOutcomeLabel(c.normalized_status || c.status);
                          return (
                            <tr key={c.id} className="hover:bg-slate-800/30">
                              <td className={`py-2.5 px-4 whitespace-nowrap font-mono text-[11px] font-medium ${out.colorClass}`}>
                                {out.label}
                              </td>
                              <td className="py-2.5 px-4">
                                <div className="font-medium text-slate-200">{c.title}</div>
                                <div className="text-[11px] text-slate-500">{c.explanation}</div>
                              </td>
                              <td className="py-2.5 px-4 font-mono text-[11px] text-slate-300 max-w-xs break-words">
                                {c.observed_value || '—'}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Structured Scan Logs */}
                <div className="bg-[#0F172A] border border-slate-800 rounded-md overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 text-xs font-semibold text-slate-200">
                    Execution Log
                  </div>
                  <div className="p-3 bg-[#090D16] max-h-48 overflow-y-auto space-y-1 font-mono text-[11px]">
                    {detail.logs.map((l) => (
                      <div key={l.id} className={l.level === 'error' ? 'text-red-400' : l.level === 'warn' ? 'text-amber-300' : 'text-slate-400'}>
                        <span className="text-slate-600">[{new Date(l.timestamp).toLocaleTimeString()}]</span>{' '}
                        {l.module_id ? <span className="text-blue-400">[{l.module_id}] </span> : null}
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
        <div className="bg-[#0F172A] border border-slate-800 rounded-md p-6 space-y-5">
          <div>
            <h2 className="text-base font-semibold text-slate-100">Compare Assessment Runs</h2>
            <p className="text-xs text-slate-400">Verify remediation progress across historical scans.</p>
          </div>
          {completedScans.length < 2 ? (
            <div className="text-xs text-slate-400 p-4 bg-[#090D16] border border-slate-800 rounded">
              At least two completed scans are required to compare security posture deltas.
            </div>
          ) : (
            <>
              <div className="flex flex-wrap items-end gap-4">
                <div className="flex-1 min-w-[220px]">
                  <label htmlFor="cmp-base" className="block text-xs text-slate-400 mb-1">Baseline Scan</label>
                  <select
                    id="cmp-base"
                    value={baselineId}
                    onChange={(e) => setBaselineId(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
                  >
                    {completedScans.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.asset_name} · {s.profile} · {formatDateTime(s.completed_at)} ({s.posture_score ?? 'N/A'})
                      </option>
                    ))}
                  </select>
                </div>
                <div className="flex-1 min-w-[220px]">
                  <label htmlFor="cmp-target" className="block text-xs text-slate-400 mb-1">Comparison Scan</label>
                  <select
                    id="cmp-target"
                    value={targetId}
                    onChange={(e) => setTargetId(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[#090D16] border border-slate-700 rounded text-slate-100"
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
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded"
                >
                  <GitCompare className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Compare Results</span>
                </button>
              </div>

              {compareData && (
                <div className="space-y-4 pt-3 border-t border-slate-800">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                      <div className="text-xs text-slate-400">Posture Delta</div>
                      <div className={`mt-1 text-xl font-mono font-semibold ${(compareData.postureDelta ?? 0) >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                        {compareData.postureDelta !== null ? `${compareData.postureDelta > 0 ? '+' : ''}${compareData.postureDelta}` : '—'}
                      </div>
                    </div>
                    <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                      <div className="text-xs text-slate-400">Passed Checks Delta</div>
                      <div className="mt-1 text-xl font-mono font-semibold text-slate-100">
                        {compareData.passedDelta > 0 ? `+${compareData.passedDelta}` : compareData.passedDelta}
                      </div>
                    </div>
                    <div className="p-3 bg-[#090D16] border border-slate-800 rounded">
                      <div className="text-xs text-slate-400">Failed Checks Delta</div>
                      <div className="mt-1 text-xl font-mono font-semibold text-slate-100">
                        {compareData.failedDelta > 0 ? `+${compareData.failedDelta}` : compareData.failedDelta}
                      </div>
                    </div>
                  </div>

                  {compareData.checkDiffs.length === 0 ? (
                    <div className="text-xs text-slate-400">No check status changes between these two scans.</div>
                  ) : (
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 px-3">Check</th>
                          <th className="py-2 px-3">Baseline</th>
                          <th className="py-2 px-3">Comparison</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {compareData.checkDiffs.map((d) => (
                          <tr key={d.checkKey}>
                            <td className="py-2 px-3 text-slate-200">{d.title}</td>
                            <td className="py-2 px-3 font-mono text-slate-400">{d.baselineStatus}</td>
                            <td className="py-2 px-3 font-mono text-blue-400">{d.targetStatus}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
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
