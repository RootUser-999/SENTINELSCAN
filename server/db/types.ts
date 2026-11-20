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
