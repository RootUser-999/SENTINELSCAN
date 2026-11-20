import React from 'react';
import { Menu, Play } from 'lucide-react';
import type { NavTab, UserSession } from '../types/sentinel';

interface TopBarProps {
  activeTab: NavTab;
  organizationName: string;
  user: UserSession;
  onOpenMobileMenu: () => void;
  onLaunchAssessmentClick: () => void;
  canLaunch: boolean;
}

const TAB_TITLES: Record<NavTab, { section: string; title: string }> = {
  overview: { section: 'Monitor', title: 'Security Posture Overview' },
  assets: { section: 'Monitor', title: 'Websites & Target Assets' },
  'new-assessment': { section: 'Assessments', title: 'New Security Assessment' },
  scans: { section: 'Assessments', title: 'Scan History & Results' },
  findings: { section: 'Intelligence', title: 'Vulnerability Findings' },
  'api-code': { section: 'Intelligence', title: 'Attack Surface, API & Code' },
  compliance: { section: 'Governance', title: 'Compliance & Reports' },
  settings: { section: 'Governance', title: 'Vault, RBAC & Settings' },
};

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  organizationName,
  user,
  onOpenMobileMenu,
  onLaunchAssessmentClick,
  canLaunch,
}) => {
  const meta = TAB_TITLES[activeTab];

  return (
    <header className="h-14 px-4 lg:px-6 border-b border-[#E2E8F0] bg-[#FFFFFF] flex items-center justify-between gap-4 shrink-0">
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="lg:hidden p-2 text-[#64748B] hover:text-[#0F172A] hover:bg-[#F8FAFC] rounded-md border border-[#E2E8F0]"
        >
          <Menu className="w-4 h-4" />
        </button>
        <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-sm min-w-0 truncate">
          <span className="text-[#64748B] whitespace-nowrap hidden sm:inline truncate max-w-[160px]">
            {organizationName}
          </span>
          <span className="text-[#CBD5E1] hidden sm:inline" aria-hidden="true">/</span>
          <span className="text-[#64748B] whitespace-nowrap hidden md:inline">{meta.section}</span>
          <span className="text-[#CBD5E1] hidden md:inline" aria-hidden="true">/</span>
          <h1 className="font-semibold text-[#0F172A] truncate">{meta.title}</h1>
        </nav>
      </div>

      <div className="flex items-center gap-3 shrink-0">
        <span className="hidden xl:inline-flex items-center text-xs text-[#64748B] whitespace-nowrap">
          {user.email}
        </span>

        {canLaunch && activeTab !== 'new-assessment' && (
          <button
            type="button"
            onClick={onLaunchAssessmentClick}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-white bg-[#2563EB] hover:bg-[#1D4ED8] rounded-md transition-colors whitespace-nowrap shrink-0 shadow-xs"
          >
            <Play className="w-3.5 h-3.5" aria-hidden="true" />
            <span>New Assessment</span>
          </button>
        )}
      </div>
    </header>
  );
};
