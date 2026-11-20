export type NavTab =
  | 'overview'
  | 'assets'
  | 'scans'
  | 'findings'
  | 'api-code'
  | 'compliance'
  | 'settings';

export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface UserSession {
  id: string;
  email: string;
  fullName: string;
  organizationId: string;
  organizationName: string;
  role: UserRole;
  mfaEnabled: boolean;
}

export interface Asset {
  id: string;
  organization_id: string;
  name: string;
  target_url: string;
  hostname: string;
  environment: 'production' | 'staging' | 'development' | 'practice_lab';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  scope_include_paths: string;
  scope_exclude_paths: string;
  max_requests_per_sec: number;
  is_practice_target: number;
  ownership_status: 'unverified' | 'pending' | 'verified';
  authorization_signed_by: string | null;
  authorization_signed_at: string | null;
  authorization_notes: string | null;
  latest_posture_score: number | null;
  last_scanned_at: string | null;
  total_scans: number;
  open_findings: number;
  created_at: string;
}

export interface OwnershipVerification {
  id: string;
  asset_id: string;
  method: string;
  token: string;
  target_location: string;
  status: string;
  checked_at: string | null;
  failure_reason: string | null;
  created_at: string;
}

export interface ScanRecord {
  id: string;
  asset_id: string;
  asset_name: string;
  target_url: string;
  environment?: string;
  initiated_by_name?: string;
  profile: 'quick' | 'standard' | 'comprehensive' | 'custom';
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress_pct: number;
  current_module: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  posture_score: number | null;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  potential_checks: number;
  informational_checks: number;
  not_applicable_checks: number;
  not_performed_checks: number;
  manual_required_checks: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string | null;
  created_at: string;
}

export interface ScannerModuleMeta {
  id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  default_timeout_ms: number;
}

export interface Vulnerability {
  id: string;
  asset_id: string;
  asset_name?: string;
  target_url?: string;
  finding_code: string;
  title: string;
  category: string;
  description: string;
  technical_explanation: string;
  affected_url: string;
  http_method: string | null;
  parameter_name: string | null;
  scanner_module: string;
  confidence: 'high' | 'medium' | 'low';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  cvss_version: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_rationale: string;
  cwe_id: string | null;
  cve_id: string | null;
  owasp_category: string | null;
  owasp_api_category: string | null;
  business_impact: string;
  exploitation_prerequisites: string;
  remediation_instructions: string;
  references?: string[];
  verification_status: 'open' | 'confirmed' | 'false_positive' | 'risk_accepted' | 'remediated' | 'reopened';
  detected_at: string;
  updated_at: string;
}

export interface SecurityCheckRow {
  id: string;
  module_id: string;
  check_key: string;
  title: string;
  category: string;
  status: 'passed' | 'failed' | 'potential' | 'informational' | 'not_applicable' | 'not_performed' | 'manual_required';
  observed_value: string | null;
  expected_value: string | null;
  explanation: string;
  remediation: string | null;
  cwe_id: string | null;
  owasp_category: string | null;
}

export interface EndpointRow {
  id: string;
  url: string;
  path: string;
  method: string;
  source: string;
  auth_required: string;
  status_code: number | null;
  content_type: string | null;
  parameters_json: string;
  notes: string | null;
}

export interface DashboardSummary {
  metrics: {
    totalAssets: number;
    verifiedAssets: number;
    totalScans: number;
    activeScans: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
  postureTrend: Array<{
    id: string;
    completed_at: string;
    posture_score: number;
    passed_checks: number;
    failed_checks: number;
    asset_name: string;
  }>;
  recentScans: ScanRecord[];
  mostVulnerableAssets: Array<{
    id: string;
    name: string;
    target_url: string;
    environment: string;
    criticality: string;
    critical_count: number;
    high_count: number;
    total_open_findings: number;
  }>;
  recentFindings: Vulnerability[];
}
