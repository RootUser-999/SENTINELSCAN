import type {
  CheckOutcome,
  ConfidenceLevel,
  ScanProfile,
  SeverityLevel,
} from '../db/types.ts';

export interface HttpResponseSnapshot {
  url: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  bodyText: string;
  redirectChain: Array<{ from: string; to: string; status: number }>;
  durationMs: number;
}

export interface SecurityCheckCandidate {
  checkKey: string;
  title: string;
  category: string;
  status: CheckOutcome;
  observedValue: string | null;
  expectedValue: string | null;
  explanation: string;
  remediation: string | null;
  cweId: string | null;
  owaspCategory: string | null;
}

export interface FindingEvidenceCandidate {
  evidenceType:
    | 'http_header'
    | 'http_response'
    | 'tls_cert'
    | 'dns_record'
    | 'dependency_advisory'
    | 'code_snippet'
    | 'api_spec'
    | 'auth_diff';
  summary: string;
  rawExcerpt: string;
}

export interface FindingCandidate {
  ruleId: string;
  title: string;
  category: string;
  description: string;
  technicalExplanation: string;
  affectedUrl: string;
  httpMethod: string | null;
  parameterName: string | null;
  confidence: ConfidenceLevel;
  severity: SeverityLevel;
  cvssVersion: '4.0' | null;
  cvssScore: number | null;
  cvssVector: string | null;
  cvssRationale: string;
  cweId: string | null;
  cveId: string | null;
  owaspCategory: string | null;
  owaspApiCategory: string | null;
  businessImpact: string;
  exploitationPrerequisites: string;
  remediationInstructions: string;
  references: string[];
  evidence: FindingEvidenceCandidate[];
}

export interface DiscoveredEndpointCandidate {
  url: string;
  path: string;
  method: string;
  source: 'crawl' | 'openapi' | 'probe';
  authRequired: 'required' | 'optional' | 'none_detected' | 'unknown';
  statusCode: number | null;
  contentType: string | null;
  parameters: string[];
  notes: string | null;
}

export interface ModuleExecutionResult {
  checks: SecurityCheckCandidate[];
  findings: FindingCandidate[];
  endpoints: DiscoveredEndpointCandidate[];
  logs: Array<{ level: 'info' | 'warn' | 'error'; message: string }>;
}

export interface ScanContext {
  scanId: string;
  organizationId: string;
  assetId: string;
  targetUrl: string;
  hostname: string;
  isPracticeTarget: boolean;
  profile: ScanProfile;
  maxDepth: number;
  requestTimeoutMs: number;
  rateLimitRps: number;
  scopeIncludePaths: string[];
  scopeExcludePaths: string[];
  allowAuthenticated: boolean;
  authHeaders: Record<string, string>;
  authRoleProfile: string | null;
  secretValuesToRedact: string[];
  openapiSpecRaw: string | null;
  scaManifestName: string | null;
  scaManifestRaw: string | null;
  sastFilename: string | null;
  sastCodeRaw: string | null;
  isCancelled: () => boolean;
  httpFetch: (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }) => Promise<HttpResponseSnapshot>;
  log: (level: 'info' | 'warn' | 'error', message: string) => void;
  sharedState: {
    homepageResponse?: HttpResponseSnapshot;
    discoveredUrls: Set<string>;
  };
}

export interface ScannerModule {
  id: string;
  name: string;
  version: string;
  category: string;
  description: string;
  supportedProfiles: ScanProfile[];
  defaultTimeoutMs: number;
  execute(ctx: ScanContext): Promise<ModuleExecutionResult>;
}
