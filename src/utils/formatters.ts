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

export function getSeverityStyle(severity: string): {
  text: string;
  border: string;
  bg: string;
  dot: string;
  label: string;
} {
  switch (severity) {
    case 'critical':
      return {
        text: 'text-[#B91C1C]',
        border: 'border-[#FECACA]',
        bg: 'bg-[#FEF2F2]',
        dot: 'bg-[#DC2626]',
        label: 'Critical',
      };
    case 'high':
      return {
        text: 'text-[#C2410C]',
        border: 'border-[#FED7AA]',
        bg: 'bg-[#FFF7ED]',
        dot: 'bg-[#EA580C]',
        label: 'High',
      };
    case 'medium':
      return {
        text: 'text-[#B45309]',
        border: 'border-[#FDE68A]',
        bg: 'bg-[#FFFBEB]',
        dot: 'bg-[#D97706]',
        label: 'Medium',
      };
    case 'low':
      return {
        text: 'text-[#1D4ED8]',
        border: 'border-[#BFDBFE]',
        bg: 'bg-[#EFF6FF]',
        dot: 'bg-[#2563EB]',
        label: 'Low',
      };
    default:
      return {
        text: 'text-[#475569]',
        border: 'border-[#E2E8F0]',
        bg: 'bg-[#F8FAFC]',
        dot: 'bg-[#64748B]',
        label: 'Info',
      };
  }
}

export function getCheckOutcomeLabel(status: string): {
  label: string;
  colorClass: string;
  badgeClass: string;
} {
  const upper = status.toUpperCase();
  switch (upper) {
    case 'PASSED':
    case 'PASS':
      return {
        label: 'PASS',
        colorClass: 'text-[#16A34A]',
        badgeClass: 'text-[#15803D] bg-[#F0FDF4] border-[#BBF7D0]',
      };
    case 'FAILED':
    case 'FAIL':
      return {
        label: 'FAIL',
        colorClass: 'text-[#DC2626]',
        badgeClass: 'text-[#B91C1C] bg-[#FEF2F2] border-[#FECACA]',
      };
    case 'POTENTIAL':
      return {
        label: 'POTENTIAL',
        colorClass: 'text-[#D97706]',
        badgeClass: 'text-[#B45309] bg-[#FFFBEB] border-[#FDE68A]',
      };
    case 'INFORMATIONAL':
      return {
        label: 'INFORMATIONAL',
        colorClass: 'text-[#475569]',
        badgeClass: 'text-[#475569] bg-[#F8FAFC] border-[#E2E8F0]',
      };
    case 'MANUAL_REQUIRED':
      return {
        label: 'MANUAL_REQUIRED',
        colorClass: 'text-[#B45309]',
        badgeClass: 'text-[#92400E] bg-[#FFFBEB] border-[#FDE68A]',
      };
    case 'NOT_APPLICABLE':
      return {
        label: 'NOT_APPLICABLE',
        colorClass: 'text-[#64748B]',
        badgeClass: 'text-[#64748B] bg-[#F8FAFC] border-[#E2E8F0]',
      };
    default:
      return {
        label: 'NOT_PERFORMED',
        colorClass: 'text-[#64748B]',
        badgeClass: 'text-[#64748B] bg-[#F8FAFC] border-[#E2E8F0]',
      };
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

export function getVerificationStatusStyle(status: string): string {
  switch (status) {
    case 'open':
      return 'text-[#B91C1C] bg-[#FEF2F2] border-[#FECACA]';
    case 'confirmed':
      return 'text-[#C2410C] bg-[#FFF7ED] border-[#FED7AA]';
    case 'reopened':
      return 'text-[#B45309] bg-[#FFFBEB] border-[#FDE68A]';
    case 'remediated':
      return 'text-[#15803D] bg-[#F0FDF4] border-[#BBF7D0]';
    case 'risk_accepted':
      return 'text-[#1D4ED8] bg-[#EFF6FF] border-[#BFDBFE]';
    case 'false_positive':
    default:
      return 'text-[#475569] bg-[#F8FAFC] border-[#E2E8F0]';
  }
}

export function getMethodBadgeStyle(method: string): string {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'text-[#1D4ED8] bg-[#EFF6FF] border-[#BFDBFE]';
    case 'POST':
      return 'text-[#15803D] bg-[#F0FDF4] border-[#BBF7D0]';
    case 'PUT':
    case 'PATCH':
      return 'text-[#B45309] bg-[#FFFBEB] border-[#FDE68A]';
    case 'DELETE':
      return 'text-[#B91C1C] bg-[#FEF2F2] border-[#FECACA]';
    default:
      return 'text-[#475569] bg-[#F8FAFC] border-[#E2E8F0]';
  }
}

export function getScanStatusStyle(status: string): {
  text: string;
  bg: string;
  border: string;
  label: string;
} {
  switch (status) {
    case 'completed':
      return {
        text: 'text-[#15803D]',
        bg: 'bg-[#F0FDF4]',
        border: 'border-[#BBF7D0]',
        label: 'Completed',
      };
    case 'failed':
      return {
        text: 'text-[#B91C1C]',
        bg: 'bg-[#FEF2F2]',
        border: 'border-[#FECACA]',
        label: 'Failed',
      };
    case 'cancelled':
      return {
        text: 'text-[#475569]',
        bg: 'bg-[#F8FAFC]',
        border: 'border-[#E2E8F0]',
        label: 'Cancelled',
      };
    case 'running':
      return {
        text: 'text-[#1D4ED8]',
        bg: 'bg-[#EFF6FF]',
        border: 'border-[#BFDBFE]',
        label: 'Running',
      };
    default:
      return {
        text: 'text-[#1D4ED8]',
        bg: 'bg-[#EFF6FF]',
        border: 'border-[#BFDBFE]',
        label: 'Queued',
      };
  }
}
