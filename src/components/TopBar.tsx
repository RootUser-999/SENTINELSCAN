import React from 'react';
import { Menu, Play } from 'lucide-react';
import type { NavTab } from '../types/sentinel';

interface TopBarProps {
  activeTab: NavTab;
  organizationName: string;
  onOpenMobileMenu: () => void;
  onLaunchAssessmentClick: () => void;
  canLaunch: boolean;
}

const TAB_TITLES: Record<NavTab, string> = {
  overview: 'Security Posture Overview',
  assets: 'Assets & Ownership Verification',
  scans: 'Assessments & Scanning Engine',
  findings: 'Vulnerability Intelligence',
  'api-code': 'API Inventory, SCA & SAST',
  compliance: 'Compliance & Assessment Reports',
  settings: 'Credential Vault, RBAC & Audit Log',
};

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  organizationName,
  onOpenMobileMenu,
  onLaunchAssessmentClick,
  canLaunch,
}) => {
  return (
    <header className="h-14 px-4 lg:px-6 border-b border-slate-800/90 bg-[#0B111E] flex items-center justify-between gap-8 shrink-0">
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="lg:hidden p-2 text-slate-400 hover:text-slate-100 rounded border border-slate-800"
        >
          <Menu className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2 text-sm min-w-0 truncate">
          <span className="text-slate-400 whitespace-nowrap hidden sm:inline">{organizationName}</span>
          <span className="text-slate-600 hidden sm:inline" aria-hidden="true">/</span>
          <h1 className="font-semibold text-slate-100 truncate">{TAB_TITLES[activeTab]}</h1>
        </div>
      </div>

      {canLaunch && (
        <div className="shrink-0">
          <button
            type="button"
            onClick={onLaunchAssessmentClick}
            className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded transition-colors whitespace-nowrap shrink-0"
          >
            <Play className="w-3.5 h-3.5" aria-hidden="true" />
            <span>New Assessment</span>
          </button>
        </div>
      )}
    </header>
  );
};
