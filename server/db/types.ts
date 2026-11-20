export type UserRole = 'admin' | 'analyst' | 'viewer';

export type AssetEnvironment = 'production' | 'staging' | 'development' | 'practice_lab';
export type AssetCriticality = 'critical' | 'high' | 'medium' | 'low';
export type OwnershipStatus = 'unverified' | 'pending' | 'verified';
export type VerificationMethod = 'dns_txt' | 'http_file' | 'html_meta' | 'practice_lab_attestation';

export type ScanProfile = 'quick' | 'standard' | 'comprehensive' | 'custom';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type CheckOutcome =
  | 'passed'
  | 'failed'
  | 'potential'
  | 'informational'
  | 'not_applicable'
  | 'not_performed'
  | 'manual_required';

export type NormalizedCheckOutcome =
  | 'PASS'
  | 'FAIL'
  | 'POTENTIAL'
  | 'INFORMATIONAL'
  | 'MANUAL_REQUIRED'
  | 'NOT_PERFORMED'
  | 'NOT_APPLICABLE';

export function normalizeCheckOutcome(status: string): NormalizedCheckOutcome {
  switch (status) {
    case 'passed':
    case 'PASS':
      return 'PASS';
    case 'failed':
    case 'FAIL':
      return 'FAIL';
    case 'potential':
    case 'POTENTIAL':
      return 'POTENTIAL';
    case 'informational':
    case 'INFORMATIONAL':
      return 'INFORMATIONAL';
    case 'manual_required':
    case 'MANUAL_REQUIRED':
      return 'MANUAL_REQUIRED';
    case 'not_applicable':
    case 'NOT_APPLICABLE':
      return 'NOT_APPLICABLE';
    default:
      return 'NOT_PERFORMED';
  }
}

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type VerificationStatus =
  | 'open'
  | 'confirmed'
  | 'false_positive'
  | 'risk_accepted'
  | 'remediated'
  | 'reopened';

export interface AuthUser {
  id: string;
  email: string;
  fullName: string;
  organizationId: string;
  organizationName: string;
  role: UserRole;
  mfaEnabled: boolean;
}
