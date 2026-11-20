import { useCallback, useEffect, useState } from 'react';
import { apiRequest, setAuthToken } from './api/client';
import { ApiCodeSecurityView } from './components/ApiCodeSecurityView';
import { AssetsView } from './components/AssetsView';
import { AuthScreen } from './components/AuthScreen';
import { ComplianceReportsView } from './components/ComplianceReportsView';
import { FindingsView } from './components/FindingsView';
import { OverviewDashboard } from './components/OverviewDashboard';
import { ScansView } from './components/ScansView';
import { SettingsAuditView } from './components/SettingsAuditView';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import type {
  Asset,
  DashboardSummary,
  NavTab,
  OwnershipVerification,
  ScanRecord,
  ScannerModuleMeta,
  UserSession,
} from './types/sentinel';

interface ToastMessage {
  id: string;
  message: string;
  type: 'success' | 'error';
}

export default function App() {
  const [user, setUser] = useState<UserSession | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [verifications, setVerifications] = useState<OwnershipVerification[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [modules, setModules] = useState<ScannerModuleMeta[]>([]);
  const [loading, setLoading] = useState(false);

  const [preselectedAssetId, setPreselectedAssetId] = useState<string | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const addToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev.slice(-3), { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  const refreshWorkspaceData = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      const [sumRes, assetRes, scanRes, modRes] = await Promise.all([
        apiRequest<DashboardSummary>('/dashboard/summary'),
        apiRequest<{ assets: Asset[]; verifications: OwnershipVerification[] }>('/assets'),
        apiRequest<{ scans: ScanRecord[] }>('/scans'),
        apiRequest<{ modules: ScannerModuleMeta[] }>('/scans/modules'),
      ]);
      setSummary(sumRes);
      setAssets(assetRes.assets);
      setVerifications(assetRes.verifications);
      setScans(scanRes.scans);
      setModules(modRes.modules);
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to refresh workspace data', 'error');
    } finally {
      setLoading(false);
    }
  }, [user, addToast]);

  useEffect(() => {
    if (user) {
      refreshWorkspaceData();
    }
  }, [user, refreshWorkspaceData]);

  const handleLogout = () => {
    setAuthToken(null);
    setUser(null);
    setSummary(null);
    setAssets([]);
    setScans([]);
    setActiveTab('overview');
  };

  if (!user) {
    return <AuthScreen onAuthenticated={(u) => setUser(u)} />;
  }

  const openFindingsCount =
    (summary?.metrics.critical || 0) +
    (summary?.metrics.high || 0) +
    (summary?.metrics.medium || 0) +
    (summary?.metrics.low || 0);

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-[#0F172A] flex">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={(tab) => {
          setPreselectedAssetId(null);
          setActiveTab(tab);
        }}
        user={user}
        activeScansCount={summary?.metrics.activeScans || 0}
        openFindingsCount={openFindingsCount}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((c) => !c)}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar
          activeTab={activeTab}
          organizationName={user.organizationName}
          user={user}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          canLaunch={user.role === 'admin' || user.role === 'analyst'}
          onLaunchAssessmentClick={() => {
            const firstVerified = assets.find((a) => a.ownership_status === 'verified');
            if (!firstVerified) {
              setActiveTab('assets');
              addToast('Register and authorize a target asset before launching an assessment.', 'error');
              return;
            }
            setPreselectedAssetId(firstVerified.id);
            setActiveTab('new-assessment');
          }}
        />

        <main className="flex-1 min-w-0 p-4 sm:p-6 max-w-[1440px] w-full mx-auto">
          {activeTab === 'overview' && (
            <OverviewDashboard
              summary={summary}
              loading={loading}
              onNavigate={(tab) => setActiveTab(tab)}
              onOpenScanDetail={(scanId) => {
                setSelectedScanId(scanId);
                setActiveTab('scans');
              }}
              onSelectFinding={(fid) => {
                setSelectedFindingId(fid);
                setActiveTab('findings');
              }}
              onOpenAddAsset={() => setActiveTab('assets')}
            />
          )}

          {activeTab === 'assets' && (
            <AssetsView
              assets={assets}
              verifications={verifications}
              userRole={user.role}
              onRefresh={refreshWorkspaceData}
              onLaunchScanForAsset={(aid) => {
                setPreselectedAssetId(aid);
                setActiveTab('new-assessment');
              }}
              onToast={addToast}
            />
          )}

          {(activeTab === 'scans' || activeTab === 'new-assessment') && (
            <ScansView
              assets={assets}
              scans={scans}
              modules={modules}
              userRole={user.role}
              preselectedAssetId={preselectedAssetId}
              selectedScanId={selectedScanId}
              initialMode={activeTab === 'new-assessment' ? 'launch' : 'console'}
              onNavigateTab={(tab) => setActiveTab(tab)}
              onSelectScanId={setSelectedScanId}
              onRefresh={refreshWorkspaceData}
              onToast={addToast}
            />
          )}

          {activeTab === 'findings' && (
            <FindingsView
              assets={assets}
              userRole={user.role}
              initialSelectedFindingId={selectedFindingId}
              onClearInitialSelection={() => setSelectedFindingId(null)}
              onRefreshParent={refreshWorkspaceData}
              onToast={addToast}
            />
          )}

          {activeTab === 'api-code' && (
            <ApiCodeSecurityView
              scans={scans}
              onSelectFinding={(fid) => {
                setSelectedFindingId(fid);
                setActiveTab('findings');
              }}
            />
          )}

          {activeTab === 'compliance' && (
            <ComplianceReportsView scans={scans} onToast={addToast} />
          )}

          {activeTab === 'settings' && (
            <SettingsAuditView
              user={user}
              assets={assets}
              onToast={addToast}
              onUserUpdated={(updated) => setUser(updated)}
            />
          )}
        </main>
      </div>

      {/* Toast Notifications */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`px-4 py-2.5 rounded-lg border text-xs font-medium shadow-md ${
              t.type === 'error'
                ? 'bg-[#FEF2F2] border-[#FECACA] text-[#B91C1C]'
                : 'bg-[#FFFFFF] border-[#CBD5E1] text-[#0F172A]'
            }`}
          >
            {t.message}
          </div>
        ))}
      </div>
    </div>
  );
}
