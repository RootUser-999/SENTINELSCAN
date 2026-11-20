export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function getSeverityStyle(severity: string): { text: string; border: string; bg: string; label: string } {
  switch (severity) {
    case 'critical':
      return { text: 'text-red-400', border: 'border-red-500/40', bg: 'bg-red-500/10', label: 'Critical' };
    case 'high':
      return { text: 'text-orange-400', border: 'border-orange-500/40', bg: 'bg-orange-500/10', label: 'High' };
    case 'medium':
      return { text: 'text-amber-400', border: 'border-amber-500/40', bg: 'bg-amber-500/10', label: 'Medium' };
    case 'low':
      return { text: 'text-sky-400', border: 'border-sky-500/40', bg: 'bg-sky-500/10', label: 'Low' };
    default:
      return { text: 'text-slate-400', border: 'border-slate-700', bg: 'bg-slate-800/60', label: 'Info' };
  }
}

export function getCheckOutcomeLabel(status: string): { label: string; colorClass: string } {
  switch (status) {
    case 'passed':
      return { label: 'Passed', colorClass: 'text-emerald-400' };
    case 'failed':
      return { label: 'Failed', colorClass: 'text-red-400' };
    case 'potential':
      return { label: 'Potential', colorClass: 'text-amber-400' };
    case 'informational':
      return { label: 'Informational', colorClass: 'text-slate-400' };
    case 'manual_required':
      return { label: 'Manual Required', colorClass: 'text-amber-300' };
    case 'not_applicable':
      return { label: 'Not Applicable', colorClass: 'text-slate-500' };
    default:
      return { label: 'Not Performed', colorClass: 'text-slate-500' };
  }
}

export function getVerificationStatusLabel(status: string): string {
  switch (status) {
    case 'open':
      return 'Open';
    case 'confirmed':
      return 'Confirmed';
    case 'false_positive':
      return 'False Positive';
    case 'risk_accepted':
      return 'Risk Accepted';
    case 'remediated':
      return 'Remediated';
    case 'reopened':
      return 'Reopened';
    default:
      return status;
  }
}
