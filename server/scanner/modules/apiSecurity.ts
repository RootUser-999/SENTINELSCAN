import * as yaml from 'js-yaml';
import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import { crawlTargetSurface } from '../crawler.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

interface ParsedOpenApi {
  info?: { title?: string; version?: string };
  security?: Array<Record<string, string[]>>;
  paths?: Record<string, Record<string, {
    summary?: string;
    security?: Array<Record<string, string[]>>;
    parameters?: Array<{ name?: string; in?: string }>;
    requestBody?: unknown;
  }>>;
  components?: { securitySchemes?: Record<string, unknown> };
  securityDefinitions?: Record<string, unknown>;
}

function parseOpenApiDoc(raw: string): ParsedOpenApi | null {
  try {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    if (trimmed.startsWith('{')) {
      return JSON.parse(trimmed) as ParsedOpenApi;
    }
    return yaml.load(trimmed) as ParsedOpenApi;
  } catch {
    return null;
  }
}

interface JwtInspectionIssue {
  issue: string;
  headerAlg: string;
  hasExp: boolean;
  sensitiveKeys: string[];
}

function inspectJwtString(token: string): JwtInspectionIssue | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const hdr = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as { alg?: string };
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
    const alg = String(hdr.alg || 'unknown');
    const hasExp = typeof payload.exp === 'number';
    const sensitiveKeys = Object.keys(payload).filter((k) =>
      /(?:password|secret|private|ssn|token|pin)/i.test(k)
    );
    const issues: string[] = [];
    if (alg.toLowerCase() === 'none') issues.push('uses insecure alg="none"');
    if (!hasExp) issues.push('omits "exp" expiration claim');
    if (sensitiveKeys.length > 0) issues.push(`contains sensitive claim key(s): ${sensitiveKeys.join(', ')}`);
    if (issues.length === 0) return null;
    return {
      issue: issues.join('; '),
      headerAlg: alg,
      hasExp,
      sensitiveKeys,
    };
  } catch {
    return null;
  }
}

export const apiSecurityModule: ScannerModule = {
  id: 'api-security-openapi',
  name: 'REST & GraphQL API Security Analyzer',
  version: '2.0.0',
  category: 'API Security Assessment',
  description:
    'Discovers REST routes from crawl/JS/OpenAPI, audits GraphQL introspection/suggestions/batching, inspects JWT headers/claims, checks sensitive JSON fields, and evaluates API rate-limiting posture.',
  supportedProfiles: ['standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 45000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const endpoints: ModuleExecutionResult['endpoints'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const crawl = await crawlTargetSurface(ctx);
    const origin = new URL(crawl.pages[0]?.finalUrl || ctx.targetUrl).origin;

    const observedResponses: Array<{ url: string; body: string }> = [];
    const seenObservedUrls = new Set<string>();
    for (const p of crawl.pages) {
      if (!seenObservedUrls.has(p.finalUrl)) {
        seenObservedUrls.add(p.finalUrl);
        observedResponses.push({ url: p.finalUrl, body: p.bodyText });
      }
    }

    // 1. Probe OpenAPI / Swagger exposure
    const docPaths = ['/openapi.json', '/swagger.json', '/v3/api-docs'];
    let discoveredSpec: ParsedOpenApi | null = null;
    let exposedSpecUrl: string | null = null;

    for (const docPath of docPaths) {
      if (ctx.isCancelled()) break;
      const url = `${origin}${docPath}`;
      try {
        const res = await ctx.httpFetch(url, { followRedirects: false });
        if (res.status === 200 && /openapi|swagger|paths/i.test(res.bodyText)) {
          const parsed = parseOpenApiDoc(res.bodyText);
          if (parsed && parsed.paths) {
            discoveredSpec = parsed;
            exposedSpecUrl = url;
            endpoints.push({
              url,
              path: docPath,
              method: 'GET',
              source: 'probe',
              authRequired: 'none_detected',
              statusCode: res.status,
              contentType: res.headers['content-type'] || null,
              parameters: [],
              notes: 'Publicly accessible OpenAPI/Swagger specification',
            });
            break;
          }
        }
      } catch {
        // Ignore non-existent spec path
      }
    }

    checks.push({
      checkKey: 'api.openapi_exposure',
      title: 'Public OpenAPI / Swagger Specification Exposure',
      category: 'API Security',
      status: exposedSpecUrl ? 'failed' : 'passed',
      observedValue: exposedSpecUrl ? `Publicly readable at ${exposedSpecUrl}` : 'No unauthenticated OpenAPI/Swagger spec exposed on common paths',
      expectedValue: 'Restrict interactive API docs in production or require authentication',
      explanation: exposedSpecUrl
        ? `OpenAPI schema is publicly downloadable at ${exposedSpecUrl}, exposing full endpoint routes and data models.`
        : 'Common OpenAPI/Swagger documentation paths did not return public schemas.',
      remediation: exposedSpecUrl ? 'Restrict Swagger/OpenAPI JSON endpoints to authenticated internal/developer roles in production.' : null,
      cweId: 'CWE-200',
      owaspCategory: 'A05:2021',
    });

    if (exposedSpecUrl) {
      findings.push({
        ruleId: 'API_SWAGGER_PUBLIC_EXPOSURE',
        title: 'Unauthenticated OpenAPI / Swagger Specification Exposed',
        category: 'API Security Assessment',
        description: 'The full OpenAPI specification is accessible without authentication.',
        technicalExplanation: `GET ${exposedSpecUrl} returned HTTP 200 containing ${Object.keys(discoveredSpec?.paths || {}).length} documented route(s).`,
        detectionTechnique: 'OpenAPI/Swagger specification endpoint discovery',
        affectedUrl: exposedSpecUrl,
        httpMethod: 'GET',
        parameterName: null,
        confidence: 'high',
        severity: 'low',
        cvssVersion: null,
        cvssScore: null,
        cvssVector: null,
        cvssRationale: 'API documentation exposure is informational/low risk depending on whether internal/admin routes are disclosed.',
        cweId: 'CWE-200',
        cveId: null,
        owaspCategory: 'A05:2021',
        owaspApiCategory: 'API8:2023',
        businessImpact: 'Reduces reconnaissance effort for attackers by enumerating every API route, parameter, and schema.',
        exploitationPrerequisites: 'Unauthenticated GET access.',
        remediationInstructions: 'Disable public OpenAPI endpoints in production or place them behind VPN/authentication.',
        references: ['https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/'],
        evidence: [
          {
            evidenceType: 'api_spec',
            summary: 'Discovered OpenAPI info header',
            rawExcerpt: JSON.stringify(discoveredSpec?.info || {}, null, 2),
          },
        ],
      });
    }

    // 2. GraphQL Introspection, Field Suggestions & Batching
    try {
      const gqlUrl = `${origin}/graphql`;
      const gqlRes = await ctx.httpFetch(gqlUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
      });
      const introspectionOpen = gqlRes.status === 200 && /"__schema"\s*:/.test(gqlRes.bodyText);
      if (introspectionOpen) {
        endpoints.push({
          url: gqlUrl,
          path: '/graphql',
          method: 'POST',
          source: 'probe',
          authRequired: 'none_detected',
          statusCode: gqlRes.status,
          contentType: gqlRes.headers['content-type'] || null,
          parameters: ['query'],
          notes: 'GraphQL endpoint with introspection enabled',
        });

        checks.push({
          checkKey: 'api.graphql_introspection',
          title: 'GraphQL Introspection Exposure',
          category: 'API Security',
          status: 'failed',
          observedValue: `Introspection enabled at ${gqlUrl}`,
          expectedValue: 'Introspection disabled in production environments',
          explanation: 'GraphQL __schema introspection query succeeded without authentication.',
          remediation: 'Disable GraphQL introspection in production.',
          cweId: 'CWE-200',
          owaspCategory: 'A05:2021',
        });

        findings.push({
          ruleId: 'API_GRAPHQL_INTROSPECTION',
          title: 'GraphQL Introspection Enabled Without Authentication',
          category: 'API Security Assessment',
          description: 'The GraphQL endpoint allows unauthenticated __schema introspection queries.',
          technicalExplanation: `POST ${gqlUrl} with __schema query returned schema type metadata.`,
          detectionTechnique: 'GraphQL __schema introspection query probe',
          affectedUrl: gqlUrl,
          httpMethod: 'POST',
          parameterName: 'query',
          confidence: 'high',
          severity: 'medium',
          cvssVersion: null,
          cvssScore: null,
          cvssVector: null,
          cvssRationale: 'Schema introspection increases attack surface visibility without directly leaking user records.',
          cweId: 'CWE-200',
          cveId: null,
          owaspCategory: 'A05:2021',
          owaspApiCategory: 'API8:2023',
          businessImpact: 'Exposes full GraphQL queries, mutations, and internal object types.',
          exploitationPrerequisites: 'HTTP POST access to /graphql.',
          remediationInstructions: 'Disable introspection in production GraphQL server configuration.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
          evidence: [
            {
              evidenceType: 'http_response',
              summary: 'GraphQL __schema response excerpt',
              rawExcerpt: gqlRes.bodyText.slice(0, 240),
            },
          ],
        });

        // Probe GraphQL field suggestions & array batching
        try {
          const suggestRes = await ctx.httpFetch(gqlUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: '{ __typoSentinel }' }),
          });
          const hasSuggestions = /Did you mean/i.test(suggestRes.bodyText);

          const batchRes = await ctx.httpFetch(gqlUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify([{ query: '{ __typename }' }, { query: '{ __typename }' }]),
          });
          const batchSupported = batchRes.status === 200 && batchRes.bodyText.trim().startsWith('[');

          checks.push({
            checkKey: 'api.graphql_hardening',
            title: 'GraphQL Field Suggestions & Query Batching Controls',
            category: 'API Security',
            status: hasSuggestions || batchSupported ? 'potential' : 'passed',
            observedValue: `Field suggestions: ${hasSuggestions ? 'enabled' : 'disabled'}; Array batching: ${batchSupported ? 'allowed' : 'blocked'}`,
            expectedValue: 'Disable production field suggestions and cap query batching/depth',
            explanation: hasSuggestions || batchSupported
              ? 'GraphQL server leaks schema names via Did-you-mean suggestions or accepts unthrottled batched arrays.'
              : 'Field suggestion leaks and unguarded array batching were not observed.',
            remediation: hasSuggestions || batchSupported ? 'Disable GraphQL field suggestions and restrict batch size and query depth.' : null,
            cweId: 'CWE-200',
            owaspCategory: 'A05:2021',
          });
        } catch {
          // ignore
        }
      } else {
        checks.push({
          checkKey: 'api.graphql_introspection',
          title: 'GraphQL Introspection Exposure',
          category: 'API Security',
          status: 'not_applicable',
          observedValue: `POST /graphql returned HTTP ${gqlRes.status}`,
          expectedValue: 'Introspection disabled or GraphQL absent',
          explanation: 'No open GraphQL introspection endpoint detected at /graphql.',
          remediation: null,
          cweId: null,
          owaspCategory: 'A05:2021',
        });
      }
    } catch {
      logs.push({ level: 'info', message: 'GraphQL probe skipped or endpoint absent.' });
    }

    // 3. Analyze imported or discovered OpenAPI specification + JS-extracted REST routes
    const activeSpec = ctx.openapiSpecRaw ? parseOpenApiDoc(ctx.openapiSpecRaw) : discoveredSpec;
    if (ctx.openapiSpecRaw && !activeSpec) {
      logs.push({ level: 'warn', message: 'Imported OpenAPI specification could not be parsed as valid JSON or YAML.' });
    }

    const rateLimitCheckUrls: string[] = [];

    if (activeSpec && activeSpec.paths) {
      const globalSecurity = Array.isArray(activeSpec.security) && activeSpec.security.length > 0;
      let unprotectedRoutes = 0;
      let bolaRiskRoutes = 0;

      for (const [apiPath, methodsObj] of Object.entries(activeSpec.paths)) {
        if (!methodsObj || typeof methodsObj !== 'object') continue;
        for (const [methodKey, op] of Object.entries(methodsObj)) {
          const upperMethod = methodKey.toUpperCase();
          if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].includes(upperMethod)) continue;

          const hasOpSecurity = Array.isArray(op?.security) ? op.security.length > 0 : globalSecurity;
          const params = Array.isArray(op?.parameters) ? op.parameters.map((p) => p.name || '').filter(Boolean) : [];
          const hasObjectParam = /\{[^}]*id[^}]*\}/i.test(apiPath) || params.some((p) => /id$/i.test(p));

          endpoints.push({
            url: `${origin}${apiPath}`,
            path: apiPath,
            method: upperMethod,
            source: 'openapi',
            authRequired: hasOpSecurity ? 'required' : 'none_detected',
            statusCode: null,
            contentType: 'application/json',
            parameters: params,
            notes: op?.summary || null,
          });

          if (!hasOpSecurity) unprotectedRoutes += 1;
          if (hasObjectParam && !hasOpSecurity) bolaRiskRoutes += 1;

          if (upperMethod === 'GET' && !apiPath.includes('{')) {
            try {
              const targetUrl = `${origin}${apiPath}`;
              const liveGet = await ctx.httpFetch(targetUrl);
              if (!seenObservedUrls.has(targetUrl)) {
                seenObservedUrls.add(targetUrl);
                observedResponses.push({ url: targetUrl, body: liveGet.bodyText });
              }
              if (rateLimitCheckUrls.length < 2) rateLimitCheckUrls.push(targetUrl);

              if (liveGet.status === 200 && !hasOpSecurity && /users|orders|accounts|admin|profile/i.test(apiPath)) {
                const cvss = evaluateCvss4(
                  { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
                  'high',
                  `Unauthenticated GET ${apiPath} returned HTTP 200 with JSON payload.`
                );
                findings.push({
                  ruleId: `API_UNAUTHENTICATED_SENSITIVE_GET_${apiPath.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
                  title: `Unauthenticated Sensitive API Endpoint: ${apiPath}`,
                  category: 'Broken Access Control',
                  description: `API route GET ${apiPath} is documented without security requirements and returned HTTP 200 unauthenticated.`,
                  technicalExplanation: `OpenAPI specification omits security scheme for ${apiPath}, and live unauthenticated GET returned HTTP 200.`,
                  detectionTechnique: 'OpenAPI operation audit + unauthenticated live GET verification',
                  affectedUrl: targetUrl,
                  httpMethod: 'GET',
                  parameterName: null,
                  confidence: 'high',
                  severity: cvss.severity,
                  cvssVersion: cvss.version,
                  cvssScore: cvss.score,
                  cvssVector: cvss.vector,
                  cvssRationale: cvss.rationale,
                  cweId: 'CWE-306',
                  cveId: null,
                  owaspCategory: 'A01:2021',
                  owaspApiCategory: 'API2:2023',
                  businessImpact: 'Unauthorized users can query user/account records directly from the API.',
                  exploitationPrerequisites: 'Direct HTTP GET request.',
                  remediationInstructions: 'Enforce authentication middleware and declare security requirements in the OpenAPI schema.',
                  references: ['https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/'],
                  evidence: [
                    {
                      evidenceType: 'http_response',
                      summary: `Unauthenticated HTTP 200 response on ${apiPath}`,
                      rawExcerpt: liveGet.bodyText.slice(0, 260),
                    },
                  ],
                });
              }
            } catch {
              // Ignore unreachable API path
            }
          }
        }
      }

      checks.push({
        checkKey: 'api.openapi_security_schemes',
        title: 'OpenAPI Operation Security Coverage (OWASP API2)',
        category: 'API Security',
        status: unprotectedRoutes > 0 ? 'failed' : 'passed',
        observedValue: `${unprotectedRoutes} route(s) lack OpenAPI security schemes; ${bolaRiskRoutes} ID-parameterized route(s) unguarded (BOLA risk)`,
        expectedValue: 'All non-public API routes enforce authentication and object-level authorization',
        explanation:
          unprotectedRoutes > 0
            ? `Analyzed OpenAPI spec: ${unprotectedRoutes} operation(s) lack security definitions.`
            : 'All analyzed OpenAPI operations define security schemes.',
        remediation:
          unprotectedRoutes > 0 ? 'Define global or per-operation security schemes and enforce server-side object ownership checks (API1 BOLA).' : null,
        cweId: 'CWE-306',
        owaspCategory: 'A01:2021',
      });

      if (bolaRiskRoutes > 0) {
        findings.push({
          ruleId: 'API_BOLA_INDICATOR',
          title: 'Potential Broken Object Level Authorization (BOLA) on Object-ID Routes',
          category: 'API Security Assessment',
          description: `${bolaRiskRoutes} object-ID parameterized route(s) in the OpenAPI spec lack declared authentication/security schemes.`,
          technicalExplanation: 'Endpoints accepting resource identifiers (e.g., {orderId}, {userId}) without security definitions require explicit object-ownership verification.',
          detectionTechnique: 'OpenAPI object-ID parameter security scheme analysis',
          affectedUrl: exposedSpecUrl || ctx.targetUrl,
          httpMethod: 'GET',
          parameterName: 'objectId',
          confidence: 'medium',
          severity: 'high',
          cvssVersion: null,
          cvssScore: null,
          cvssVector: null,
          cvssRationale: 'OpenAPI metadata alone indicates missing auth schema; runtime BOLA requires authenticated cross-tenant test accounts.',
          cweId: 'CWE-639',
          cveId: null,
          owaspCategory: 'A01:2021',
          owaspApiCategory: 'API1:2023',
          businessImpact: 'Attackers may enumerate or access other users’ records by substituting object IDs.',
          exploitationPrerequisites: 'Unprotected or non-tenant-scoped object lookup.',
          remediationInstructions: 'Enforce authentication and verify resource ownership (user.id === resource.ownerId) on every object route.',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
          evidence: [
            {
              evidenceType: 'api_spec',
              summary: 'OpenAPI routes with ID parameters lacking security definitions',
              rawExcerpt: Object.keys(activeSpec.paths).filter((p) => /\{[^}]*id[^}]*\}/i.test(p)).join('\n'),
            },
          ],
        });
      }
    } else {
      checks.push({
        checkKey: 'api.openapi_security_schemes',
        title: 'OpenAPI Specification Security Audit',
        category: 'API Security',
        status: 'not_performed',
        observedValue: 'No OpenAPI specification supplied or discovered',
        expectedValue: 'Imported OpenAPI 3.x / Swagger 2.0 JSON or YAML',
        explanation: 'Upload or paste an OpenAPI specification in Scan Configuration to inventory and audit API routes.',
        remediation: null,
        cweId: null,
        owaspCategory: null,
      });
    }

    // 4. Sensitive property leakage inspection across JSON API responses
    let sensitiveFieldHits = 0;
    for (const obs of observedResponses) {
      const m = obs.body.match(/"(passwordHash|password_hash|privateKey|secretKey|ssn|creditCard)"\s*:/i);
      if (m) {
        sensitiveFieldHits += 1;
        findings.push({
          ruleId: `API_EXCESSIVE_DATA_EXPOSURE_${new URL(obs.url).pathname.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
          title: `Excessive Data Exposure: Sensitive Field "${m[1]}" in API Response`,
          category: 'API Security Assessment',
          description: `API response returned sensitive internal property "${m[1]}" in JSON payload.`,
          technicalExplanation: `GET ${obs.url} serialized sensitive field "${m[1]}" to the HTTP client.`,
          detectionTechnique: 'API response JSON schema & sensitive property inspection',
          affectedUrl: obs.url,
          httpMethod: 'GET',
          parameterName: m[1],
          confidence: 'high',
          severity: 'high',
          cvssVersion: null,
          cvssScore: null,
          cvssVector: null,
          cvssRationale: 'Excessive data exposure leaks sensitive backend properties (OWASP API3:2023).',
          cweId: 'CWE-213',
          cveId: null,
          owaspCategory: 'A01:2021',
          owaspApiCategory: 'API3:2023',
          businessImpact: 'Sensitive internal fields such as password hashes or secrets are exposed to API consumers.',
          exploitationPrerequisites: 'HTTP access to the API endpoint.',
          remediationInstructions: 'Use explicit DTO response serializers / allowlists and exclude internal credential or secret fields from API payloads.',
          references: ['https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/'],
          evidence: [
            {
              evidenceType: 'http_response',
              summary: `Sensitive JSON key "${m[1]}" observed`,
              rawExcerpt: obs.body.slice(0, 220),
            },
          ],
        });
      }
    }

    checks.push({
      checkKey: 'api.excessive_data_exposure',
      title: 'API Excessive Property Exposure (OWASP API3)',
      category: 'API Security',
      status: observedResponses.length === 0 ? 'not_performed' : sensitiveFieldHits > 0 ? 'failed' : 'passed',
      observedValue:
        sensitiveFieldHits > 0
          ? `${sensitiveFieldHits} API response(s) exposed sensitive property keys`
          : `Inspected ${observedResponses.length} response(s); no passwordHash/secret/privateKey properties exposed`,
      expectedValue: 'Strict response DTO allowlists omitting hashes, secrets, and PII',
      explanation: sensitiveFieldHits > 0 ? 'Response JSON included sensitive internal fields.' : 'No excessive sensitive fields matched.',
      remediation: sensitiveFieldHits > 0 ? 'Strip sensitive properties via response DTO projection.' : null,
      cweId: 'CWE-213',
      owaspCategory: 'A01:2021',
    });

    // 5. JWT Configuration & Claim Analysis (inspects JWTs from authHeaders or API responses)
    const jwtCandidates: Array<{ source: string; token: string }> = [];
    const seenJwtTokens = new Set<string>();
    const addJwtCandidate = (source: string, token: string) => {
      if (!seenJwtTokens.has(token)) {
        seenJwtTokens.add(token);
        jwtCandidates.push({ source, token });
      }
    };
    const authHdr = ctx.authHeaders['Authorization'] || ctx.authHeaders['authorization'] || '';
    const bearerMatch = authHdr.match(/^Bearer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)$/i);
    if (bearerMatch) addJwtCandidate('Configured Scan Authorization Header', bearerMatch[1]);
    for (const obs of observedResponses) {
      const m = obs.body.match(/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g);
      if (m) {
        for (const tok of m.slice(0, 2)) addJwtCandidate(obs.url, tok);
      }
    }

    let weakJwtHits = 0;
    for (const item of jwtCandidates.slice(0, 5)) {
      const issue = inspectJwtString(item.token);
      if (issue) {
        weakJwtHits += 1;
        const isAlgNone = issue.headerAlg.toLowerCase() === 'none';
        const cvss = evaluateCvss4(
          isAlgNone
            ? { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'H', VA: 'N', SC: 'N', SI: 'N', SA: 'N' }
            : { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'N', VC: 'L', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
          isAlgNone ? 'critical' : 'medium',
          `JWT inspection identified ${issue.issue}.`
        );
        const sourceSlug = (item.source.startsWith('http') ? new URL(item.source).pathname : 'header')
          .replace(/[^A-Za-z0-9]/g, '_')
          .toUpperCase();
        findings.push({
          ruleId: `API_WEAK_JWT_${sourceSlug}_${issue.headerAlg.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
          title: `Insecure JWT Configuration (${issue.issue})`,
          category: 'API Security Assessment',
          description: `Observed JSON Web Token ${issue.issue}.`,
          technicalExplanation: `JWT observed at ${item.source} decodes to alg="${issue.headerAlg}", hasExp=${issue.hasExp}.`,
          detectionTechnique: 'JWT header/claim base64url structure & algorithm analysis',
          affectedUrl: item.source.startsWith('http') ? item.source : ctx.targetUrl,
          httpMethod: 'GET',
          parameterName: 'JWT',
          confidence: 'high',
          severity: cvss.severity,
          cvssVersion: cvss.version,
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
          cvssRationale: cvss.rationale,
          cweId: 'CWE-347',
          cveId: null,
          owaspCategory: 'A07:2021',
          owaspApiCategory: 'API2:2023',
          businessImpact: isAlgNone
            ? 'Unsigned alg=none tokens allow attackers to forge arbitrary user roles and identities.'
            : 'Missing token expiration or sensitive claims increases exposure window if intercepted.',
          exploitationPrerequisites: 'Server accepts tokens without strict algorithm allowlist or claim validation.',
          remediationInstructions: 'Reject alg="none", enforce explicit asymmetric/strong HMAC algorithm verification (RS256/EdDSA), require short-lived "exp" claims, and keep sensitive attributes out of JWT payloads.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'],
          evidence: [
            {
              evidenceType: 'api_spec',
              summary: 'JWT decoded metadata (signature/secret redacted)',
              rawExcerpt: `Source: ${item.source}\nHeader alg: ${issue.headerAlg}\nhasExp: ${issue.hasExp}\nIssues: ${issue.issue}`,
            },
          ],
        });
      }
    }

    checks.push({
      checkKey: 'api.jwt_configuration',
      title: 'JWT Algorithm & Expiration Claim Posture',
      category: 'API Security',
      status: jwtCandidates.length === 0 ? 'not_applicable' : weakJwtHits > 0 ? 'failed' : 'passed',
      observedValue:
        jwtCandidates.length === 0
          ? 'No JWT tokens observed in API responses or credentials'
          : weakJwtHits > 0
            ? `${weakJwtHits} JWT(s) exhibited weak algorithm or missing expiration claim`
            : `Analyzed ${jwtCandidates.length} JWT(s); strong algorithm and exp claim present`,
      expectedValue: 'Explicitly verified signature algorithm (no alg=none) and bounded exp claim',
      explanation: jwtCandidates.length === 0 ? 'No JWT tokens observed.' : weakJwtHits > 0 ? 'Detected weak JWT configuration.' : 'Observed JWTs enforce strong headers and exp.',
      remediation: weakJwtHits > 0 ? 'Enforce strict algorithm allowlisting and mandatory short-lived exp claims.' : null,
      cweId: 'CWE-347',
      owaspCategory: 'A07:2021',
    });

    // 6. Non-DoS API Rate-Limit Header Posture Check (max 3 safe GET requests)
    const rateTarget =
      rateLimitCheckUrls[0] ||
      (crawl.discoveredApiRoutes[0] ? `${origin}${crawl.discoveredApiRoutes[0]}` : null);
    if (rateTarget) {
      try {
        let sawRateHeaders = false;
        let saw429 = false;
        for (let i = 0; i < 3; i++) {
          const r = await ctx.httpFetch(rateTarget, { followRedirects: false });
          if (r.status === 429) saw429 = true;
          if (
            r.headers['x-ratelimit-limit'] ||
            r.headers['ratelimit-limit'] ||
            r.headers['retry-after'] ||
            r.headers['x-ratelimit-remaining']
          ) {
            sawRateHeaders = true;
          }
        }
        checks.push({
          checkKey: 'api.rate_limiting',
          title: 'API Rate-Limiting Headers & Throttling Posture',
          category: 'API Security',
          status: sawRateHeaders || saw429 ? 'passed' : 'informational',
          observedValue: sawRateHeaders || saw429
            ? `Rate-limit controls advertised on ${new URL(rateTarget).pathname}`
            : `No X-RateLimit-* / RateLimit-* headers observed on ${new URL(rateTarget).pathname} (low-rate probe only)`,
          expectedValue: 'RateLimit-* headers and server-side throttling (HTTP 429) on API endpoints',
          explanation: 'Safe non-DoS probe checks standard rate-limit headers without flooding the target.',
          remediation: sawRateHeaders ? null : 'Implement per-IP/per-token API rate limiting and emit standard RateLimit-* headers.',
          cweId: 'CWE-770',
          owaspCategory: 'A04:2021',
        });
      } catch {
        // ignore
      }
    }

    return { checks, findings, endpoints, logs };
  },
};
