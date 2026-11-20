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
  detectionTechnique?: string | null;
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

export interface CrawledPage {
  url: string;
  finalUrl: string;
  path: string;
  depth: number;
  status: number;
  contentType: string | null;
  headers: Record<string, string>;
  setCookies: string[];
  bodyText: string;
  queryParams: string[];
}

export interface DiscoveredForm {
  pageUrl: string;
  actionUrl: string;
  method: string;
  enctype: string;
  fields: Array<{ name: string; type: string }>;
  hasCsrfField: boolean;
  hasPasswordField: boolean;
  hasFileInput: boolean;
}

export interface DiscoveredJsResource {
  url: string;
  extractedApiRoutes: string[];
  domXssMatches: string[];
  secretMatches: string[];
}

export interface CrawlResult {
  pages: CrawledPage[];
  forms: DiscoveredForm[];
  parameterizedUrls: Array<{ url: string; path: string; method: string; params: string[] }>;
  jsResources: DiscoveredJsResource[];
  discoveredApiRoutes: string[];
  loginPages: string[];
  uploadEndpoints: Array<{ pageUrl: string; actionUrl: string; fieldNames: string[] }>;
  endpoints: DiscoveredEndpointCandidate[];
  stats: {
    pagesCrawled: number;
    maxDepthReached: number;
    formsFound: number;
    paramsFound: number;
    jsFilesFetched: number;
    apiRoutesFromJs: number;
    stoppedReason: 'completed' | 'url_limit' | 'request_budget' | 'cancelled';
  };
}

export interface SastSourceFile {
  filename: string;
  content: string;
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
  maxUrls: number;
  maxRequests: number;
  concurrencyLimit: number;
  requestTimeoutMs: number;
  rateLimitRps: number;
  scopeIncludePaths: string[];
  scopeExcludePaths: string[];
  allowAuthenticated: boolean;
  authHeaders: Record<string, string>;
  authRoleProfile: string | null;
  secondaryAuthHeaders: Record<string, string>;
  secondaryAuthRoleProfile: string | null;
  customHeaders: Record<string, string>;
  secretValuesToRedact: string[];
  openapiSpecRaw: string | null;
  scaManifestName: string | null;
  scaManifestRaw: string | null;
  sastFilename: string | null;
  sastCodeRaw: string | null;
  sastFiles: SastSourceFile[];
  isCancelled: () => boolean;
  httpFetch: (
    url: string,
    init?: { method?: string; headers?: Record<string, string>; body?: string; followRedirects?: boolean }
  ) => Promise<HttpResponseSnapshot>;
  getHttpStats?: () => { requestsSent: number; retries: number; errors: number; budgetRemaining: number };
  log: (level: 'info' | 'warn' | 'error', message: string) => void;
  sharedState: {
    homepageResponse?: HttpResponseSnapshot;
    discoveredUrls: Set<string>;
    crawlResult?: CrawlResult;
    discoveredTokens?: string[];
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
