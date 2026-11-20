import React from 'react';
import {
  LayoutDashboard,
  Globe,
  PlayCircle,
  History,
  ShieldAlert,
  Code2,
  FileCheck2,
  Settings,
  Shield,
  LogOut,
  PanelLeftClose,
  PanelLeftOpen,
  X,
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
  collapsed: boolean;
  onToggleCollapse: () => void;
}

interface NavGroup {
  label: string;
  items: Array<{
    id: NavTab;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    roles?: Array<'admin' | 'analyst' | 'viewer'>;
  }>;
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Monitor',
    items: [
      { id: 'overview', label: 'Overview', icon: LayoutDashboard },
      { id: 'assets', label: 'Websites & Assets', icon: Globe },
    ],
  },
  {
    label: 'Assessments',
    items: [
      { id: 'new-assessment', label: 'New Assessment', icon: PlayCircle, roles: ['admin', 'analyst'] },
      { id: 'scans', label: 'Scan History & Results', icon: History },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'findings', label: 'Vulnerability Findings', icon: ShieldAlert },
      { id: 'api-code', label: 'Attack Surface & Code', icon: Code2 },
    ],
  },
  {
    label: 'Governance',
    items: [
      { id: 'compliance', label: 'Compliance & Reports', icon: FileCheck2 },
      { id: 'settings', label: 'Vault, RBAC & Settings', icon: Settings },
    ],
  },
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
  collapsed,
  onToggleCollapse,
}) => {
  const initials = user.fullName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || '')
    .join('') || 'U';

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-[#0F172A]/40 backdrop-blur-[1px] lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}
      <aside
        aria-label="Primary Sidebar Navigation"
        className={`fixed inset-y-0 left-0 z-40 bg-[#FFFFFF] border-r border-[#E2E8F0] flex flex-col transition-all duration-200 lg:static lg:translate-x-0 ${
          collapsed ? 'lg:w-[72px]' : 'lg:w-64'
        } w-64 ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}
      >
        {/* Brand Header */}
        <div className="h-14 px-4 border-b border-[#E2E8F0] flex items-center justify-between gap-2 shrink-0">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-[#2563EB] flex items-center justify-center shrink-0">
              <Shield className="w-4 h-4 text-white" aria-hidden="true" />
            </div>
            {!collapsed && (
              <span className="text-[15px] font-semibold tracking-tight text-[#0F172A] whitespace-nowrap truncate">
                SentinelScan
              </span>
            )}
          </div>

          <button
            type="button"
            onClick={onToggleCollapse}
            aria-label={collapsed ? 'Expand sidebar navigation' : 'Collapse sidebar navigation'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="hidden lg:inline-flex p-1.5 text-[#64748B] hover:text-[#0F172A] hover:bg-[#F1F5F9] rounded-md transition-colors"
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
          </button>

          <button
            type="button"
            onClick={onCloseMobile}
            aria-label="Close navigation menu"
            className="lg:hidden p-1.5 text-[#64748B] hover:text-[#0F172A] hover:bg-[#F1F5F9] rounded-md"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Grouped Navigation */}
        <nav className="flex-1 px-2.5 py-4 space-y-5 overflow-y-auto">
          {NAV_GROUPS.map((group) => {
            const visibleItems = group.items.filter(
              (item) => !item.roles || item.roles.includes(user.role)
            );
            if (visibleItems.length === 0) return null;

            return (
              <div key={group.label}>
                {!collapsed && (
                  <div className="px-2.5 mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#94A3B8]">
                    {group.label}
                  </div>
                )}
                <div className="space-y-0.5">
                  {visibleItems.map((item) => {
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
                        title={collapsed ? item.label : undefined}
                        aria-label={collapsed ? item.label : undefined}
                        aria-current={isActive ? 'page' : undefined}
                        className={`w-full flex items-center ${
                          collapsed ? 'justify-center px-2' : 'justify-between px-2.5'
                        } py-2 text-[13px] font-medium rounded-md transition-colors whitespace-nowrap ${
                          isActive
                            ? 'bg-[#EFF6FF] text-[#1E40AF] font-semibold'
                            : 'text-[#475569] hover:text-[#0F172A] hover:bg-[#F8FAFC]'
                        }`}
                      >
                        <span className="flex items-center gap-2.5 min-w-0">
                          <Icon
                            className={`w-4 h-4 shrink-0 ${
                              isActive ? 'text-[#2563EB]' : 'text-[#64748B]'
                            }`}
                            aria-hidden="true"
                          />
                          {!collapsed && <span className="truncate">{item.label}</span>}
                        </span>

                        {!collapsed && item.id === 'scans' && activeScansCount > 0 && (
                          <span className="text-[11px] font-mono tabular-nums font-semibold px-1.5 py-0.5 rounded bg-[#EFF6FF] text-[#2563EB] border border-[#BFDBFE]">
                            {activeScansCount}
                          </span>
                        )}

                        {!collapsed && item.id === 'findings' && openFindingsCount > 0 && (
                          <span className="text-[11px] font-mono tabular-nums font-medium text-[#64748B]">
                            {openFindingsCount}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>

        {/* Organization & Account Footer */}
        <div className="p-3 border-t border-[#E2E8F0] bg-[#F8FAFC]">
          <div className={`flex items-center ${collapsed ? 'justify-center' : 'gap-2.5'}`}>
            <div
              className="w-8 h-8 rounded-full bg-[#EFF6FF] border border-[#BFDBFE] text-[#1E40AF] text-xs font-semibold flex items-center justify-center shrink-0"
              aria-hidden="true"
            >
              {initials}
            </div>
            {!collapsed && (
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-[#0F172A] truncate">{user.fullName}</div>
                <div className="text-[11px] text-[#64748B] truncate">
                  {user.organizationName} · {user.role}
                </div>
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onLogout}
            title={collapsed ? 'Sign Out' : undefined}
            aria-label="Sign Out"
            className={`mt-2.5 w-full flex items-center ${
              collapsed ? 'justify-center px-2' : 'gap-2 px-2.5'
            } py-1.5 text-xs font-medium text-[#64748B] hover:text-[#DC2626] hover:bg-[#FEF2F2] rounded-md transition-colors`}
          >
            <LogOut className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            {!collapsed && <span>Sign Out</span>}
          </button>
        </div>
      </aside>
    </>
  );
};
