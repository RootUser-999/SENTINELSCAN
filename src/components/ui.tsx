import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import {
  getCheckOutcomeLabel,
  getMethodBadgeStyle,
  getScanStatusStyle,
  getSeverityStyle,
  getVerificationStatusLabel,
  getVerificationStatusStyle,
} from '../utils/formatters';

export const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const s = getSeverityStyle(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] font-semibold whitespace-nowrap ${s.text} ${s.border} ${s.bg}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} aria-hidden="true" />
      <span>{s.label}</span>
    </span>
  );
};

export const OutcomeBadge: React.FC<{ status: string }> = ({ status }) => {
  const out = getCheckOutcomeLabel(status);
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded border font-mono text-[11px] font-semibold whitespace-nowrap ${out.badgeClass}`}
    >
      {out.label}
    </span>
  );
};

export const MethodBadge: React.FC<{ method: string }> = ({ method }) => (
  <span
    className={`inline-flex items-center px-2 py-0.5 rounded border font-mono text-[11px] font-semibold whitespace-nowrap ${getMethodBadgeStyle(
      method
    )}`}
  >
    {method.toUpperCase()}
  </span>
);

export const ScanStatusBadge: React.FC<{ status: string; progressPct?: number }> = ({
  status,
  progressPct,
}) => {
  const st = getScanStatusStyle(status);
  const isActive = status === 'running' || status === 'queued';
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] font-medium whitespace-nowrap ${st.text} ${st.bg} ${st.border}`}
    >
      {isActive && (
        <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] animate-pulse" aria-hidden="true" />
      )}
      <span>
        {st.label}
        {isActive && typeof progressPct === 'number' ? ` (${progressPct}%)` : ''}
      </span>
    </span>
  );
};

export const VerificationStatusBadge: React.FC<{ status: string }> = ({ status }) => (
  <span
    className={`inline-flex items-center px-2 py-0.5 rounded border text-[11px] font-medium whitespace-nowrap ${getVerificationStatusStyle(
      status
    )}`}
  >
    {getVerificationStatusLabel(status)}
  </span>
);

export const CodeBlock: React.FC<{
  content: string;
  label?: string;
  className?: string;
}> = ({ content, label, className = '' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // ignore clipboard errors in restricted frames
    }
  };

  return (
    <div className={`bg-[#F8FAFC] border border-[#E2E8F0] rounded-md overflow-hidden ${className}`}>
      <div className="px-3 py-1.5 bg-[#F1F5F9]/70 border-b border-[#E2E8F0] flex items-center justify-between gap-2">
        <span className="text-[11px] font-medium text-[#475569] truncate">
          {label || 'Technical Evidence'}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          aria-label={`Copy ${label || 'code block'}`}
          className="inline-flex items-center gap-1 text-[11px] font-medium text-[#64748B] hover:text-[#0F172A] transition-colors whitespace-nowrap"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-[#16A34A]" aria-hidden="true" />
              <span className="text-[#16A34A]">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" aria-hidden="true" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3 text-[11px] leading-relaxed font-mono text-[#0F172A] whitespace-pre-wrap break-all overflow-x-auto">
        {content}
      </pre>
    </div>
  );
};

export const EmptyState: React.FC<{
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  action?: React.ReactNode;
}> = ({ icon: Icon, title, description, action }) => (
  <div className="p-10 text-center flex flex-col items-center justify-center">
    <div className="w-10 h-10 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] flex items-center justify-center text-[#2563EB]">
      <Icon className="w-5 h-5" aria-hidden="true" />
    </div>
    <h3 className="mt-3 text-sm font-semibold text-[#0F172A]">{title}</h3>
    <p className="mt-1 text-xs text-[#64748B] max-w-md leading-relaxed">{description}</p>
    {action && <div className="mt-4">{action}</div>}
  </div>
);

export const inputClassName =
  'w-full px-3 py-2 text-xs bg-[#FFFFFF] border border-[#CBD5E1] rounded-md text-[#0F172A] placeholder-[#94A3B8] focus:outline-none focus:border-[#2563EB] focus:ring-2 focus:ring-[#2563EB]/15 transition-colors';

export const selectClassName =
  'px-3 py-2 text-xs bg-[#FFFFFF] border border-[#CBD5E1] rounded-md text-[#0F172A] focus:outline-none focus:border-[#2563EB] focus:ring-2 focus:ring-[#2563EB]/15 transition-colors';
