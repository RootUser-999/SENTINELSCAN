import * as yaml from 'js-yaml';
import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
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

export const apiSecurityModule: ScannerModule = {
  id: 'api-security-openapi',
  name: 'REST & GraphQL API Security Analyzer',
  version: '1.3.0',
  category: 'API Security Assessment',
  description: 'Discovers OpenAPI/Swagger & GraphQL endpoints, parses imported OpenAPI specs, builds endpoint inventory, and evaluates OWASP API Security Top 10 (2023) indicators.',
  supportedProfiles: ['standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 12000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const endpoints: ModuleExecutionResult['endpoints'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const baseRes = ctx.sharedState.homepageResponse || (await ctx.httpFetch(ctx.targetUrl));
    const origin = new URL(baseRes.finalUrl).origin;

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

    // 2. GraphQL Introspection probe
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

    // 3. Analyze imported or discovered OpenAPI specification
    const activeSpec = ctx.openapiSpecRaw ? parseOpenApiDoc(ctx.openapiSpecRaw) : discoveredSpec;
    if (ctx.openapiSpecRaw && !activeSpec) {
      logs.push({ level: 'warn', message: 'Imported OpenAPI specification could not be parsed as valid JSON or YAML.' });
    }

    if (activeSpec && activeSpec.paths) {
      const globalSecurity = Array.isArray(activeSpec.security) && activeSpec.security.length > 0;
      let unprotectedRoutes = 0;
      let bolaRiskRoutes = 0;

      for (const [apiPath, methodsObj] of Object.entries(activeSpec.paths)) {
        if (!methodsObj || typeof methodsObj !== 'object') continue;
        for (const [methodKey, op] of Object.entries(methodsObj)) {
          const upperMethod = methodKey.toUpperCase();
          if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'].includes(upperMethod)) continue;

          const hasOpSecurity = Array.isArray(op?.security)
            ? op.security.length > 0
            : globalSecurity;
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

          if (!hasOpSecurity) {
            unprotectedRoutes += 1;
          }
          if (hasObjectParam && !hasOpSecurity) {
            bolaRiskRoutes += 1;
          }

          // Safe unauthenticated GET check on non-parameterized paths
          if (upperMethod === 'GET' && !apiPath.includes('{')) {
            try {
              const liveGet = await ctx.httpFetch(`${origin}${apiPath}`);
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
                  affectedUrl: `${origin}${apiPath}`,
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

    return { checks, findings, endpoints, logs };
  },
};
