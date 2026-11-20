import React from 'react';
import {
  LayoutDashboard,
  Globe,
  Activity,
  ShieldAlert,
  Code2,
  FileCheck2,
  Settings,
  Shield,
  LogOut,
} from 'lucide-react';
import type { NavTab, UserSession } from '../types/sentinel';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  user: UserSession;
  activeScansCount: number;
  openFindingsCount: number;
  onLogout: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

const NAV_ITEMS: Array<{ id: NavTab; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'assets', label: 'Websites & Assets', icon: Globe },
  { id: 'scans', label: 'Scans & Engine', icon: Activity },
  { id: 'findings', label: 'Vulnerabilities', icon: ShieldAlert },
  { id: 'api-code', label: 'API, SCA & SAST', icon: Code2 },
  { id: 'compliance', label: 'Compliance & Reports', icon: FileCheck2 },
  { id: 'settings', label: 'Vault, RBAC & Audit', icon: Settings },
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  user,
  activeScansCount,
  openFindingsCount,
  onLogout,
  mobileOpen,
  onCloseMobile,
}) => {
  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}
      <aside
        aria-label="Primary Sidebar Navigation"
        className={`fixed inset-y-0 left-0 z-40 w-64 bg-[#0B111E] border-r border-slate-800/90 flex flex-col transition-transform duration-200 lg:static lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Zone */}
        <div className="h-14 px-5 border-b border-slate-800/90 flex items-center gap-2.5 shrink-0">
          <Shield className="w-5 h-5 text-blue-500 shrink-0" aria-hidden="true" />
          <span className="text-base font-semibold tracking-tight text-slate-100 whitespace-nowrap">
            SentinelScan
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  onSelectTab(item.id);
                  onCloseMobile();
                }}
                aria-current={isActive ? 'page' : undefined}
                className={`w-full flex items-center justify-between px-3 py-2 text-sm font-medium rounded-md transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-slate-800/90 text-slate-100'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} aria-hidden="true" />
                  <span className="truncate">{item.label}</span>
                </span>
                {item.id === 'scans' && activeScansCount > 0 && (
                  <span className="text-xs font-mono tabular-nums text-blue-400">
                    {activeScansCount}
                  </span>
                )}
                {item.id === 'findings' && openFindingsCount > 0 && (
                  <span className="text-xs font-mono tabular-nums text-slate-400">
                    {openFindingsCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Organization & Account Footer */}
        <div className="p-4 border-t border-slate-800/90 bg-[#090D16]/60">
          <div className="text-xs font-medium text-slate-200 truncate">{user.fullName}</div>
          <div className="mt-0.5 text-xs text-slate-400 truncate">
            {user.organizationName} · {user.role}
          </div>
          <button
            type="button"
            onClick={onLogout}
            className="mt-3 w-full flex items-center gap-2 px-2.5 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 rounded transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>
    </>
  );
};
