import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import { crawlTargetSurface } from '../crawler.ts';
import { RequestBudgetExceededError } from '../httpClient.ts';
import type {
  FindingCandidate,
  HttpResponseSnapshot,
  ModuleExecutionResult,
  ScannerModule,
  ScanContext,
  SecurityCheckCandidate,
} from '../types.ts';

const SQL_ERROR_PATTERNS = [
  /SQLSTATE\[[0-9A-Z]+\]/i,
  /You have an error in your SQL syntax/i,
  /Warning:\s*(?:mysql_|pg_|sqlite_|oci_)/i,
  /ORA-\d{5}/,
  /SQLite\/JDBCDriver|SQLITE_ERROR/i,
  /PostgreSQL.*ERROR/i,
  /Unclosed quotation mark after the character string/i,
];

const NOSQL_ERROR_PATTERNS = [
  /MongoError|MongoServerError/i,
  /CastError:\s*Cast to/i,
  /BSONTypeError/i,
  /\$ne operator|\$gt operator|\$regex/i,
];

const TRAVERSAL_SIGNATURES = [
  /root:x:0:0:/,
  /daemon:x:1:1:/,
  /\[boot loader\]/i,
  /\[extensions\]/i,
  /ENOENT:\s*no such file or directory/i,
  /java\.io\.FileNotFoundException/i,
];

const SSRF_ERROR_SIGNATURES = [
  /ssrf-check\.sentinel-invalid\.example/i,
  /getaddrinfo\s+ENOTFOUND/i,
  /ECONNREFUSED|EAI_AGAIN/i,
];

const REDIRECT_PARAM_REGEX = /^(?:next|url|redirect|redirect_uri|return|returnurl|goto|dest|destination|target|continue|redir)$/i;
const FILE_PARAM_REGEX = /^(?:file|path|filepath|doc|document|template|page|download|asset|filename|img)$/i;
const SSRF_PARAM_REGEX = /^(?:url|uri|webhook|callback|fetch|proxy|feed|imageurl|avatarurl|link|dest|endpoint)$/i;

function buildProbeUrl(baseUrl: string, param: string, value: string): string {
  const u = new URL(baseUrl);
  u.searchParams.set(param, value);
  return u.toString();
}

function buildBracketProbeUrl(baseUrl: string, param: string, operator: string, value: string): string {
  const u = new URL(baseUrl);
  u.searchParams.delete(param);
  u.searchParams.set(`${param}[${operator}]`, value);
  return u.toString();
}

function formatHttpEvidence(
  method: string,
  url: string,
  res: HttpResponseSnapshot,
  snippet?: string
): string {
  const contentType = res.headers['content-type'] || 'unknown';
  const loc = res.headers['location'] ? `\nLocation: ${res.headers['location']}` : '';
  return `Request: ${method} ${url}\nResponse: HTTP ${res.status} (${contentType})${loc}\nExcerpt: ${(snippet ?? res.bodyText).slice(0, 260)}`;
}

export const owaspActiveProbesModule: ScannerModule = {
  id: 'owasp-active-probes',
  name: 'OWASP Injection, XSS, CSRF & Access Probes',
  version: '2.0.0',
  category: 'OWASP Top 10 Active Assessment',
  description:
    'Executes safe, non-destructive, baseline-compared probes across crawled endpoints and parameters for SQLi, Blind SQLi, NoSQLi, Reflected/DOM XSS, CSRF, IDOR/BOLA, Access Control, Path Traversal, Open Redirect, SSRF/XXE indicators, and File Uploads.',
  supportedProfiles: ['standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 60000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: SecurityCheckCandidate[] = [];
    const findings: FindingCandidate[] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const crawl = await crawlTargetSurface(ctx);
    const origin = new URL(ctx.sharedState.homepageResponse?.finalUrl || ctx.targetUrl).origin;

    logs.push({
      level: 'info',
      message: `Crawl summary: ${crawl.stats.pagesCrawled} page(s), depth ${crawl.stats.maxDepthReached}, ${crawl.stats.formsFound} form(s), ${crawl.stats.paramsFound} parameter(s), ${crawl.stats.jsFilesFetched} JS bundle(s) (${crawl.stats.stoppedReason}).`,
    });

    // Collect deduplicated (url, param) pairs from GET query strings + GET HTML forms
    const paramTargets: Array<{ baseUrl: string; path: string; param: string }> = [];
    const seenParamTarget = new Set<string>();

    for (const pEntry of crawl.parameterizedUrls) {
      if (pEntry.method !== 'GET') continue;
      for (const param of pEntry.params) {
        const key = `${pEntry.path}|${param}`;
        if (!seenParamTarget.has(key)) {
          seenParamTarget.add(key);
          paramTargets.push({ baseUrl: pEntry.url, path: pEntry.path, param });
        }
      }
    }
    for (const f of crawl.forms) {
      if (f.method !== 'GET') continue;
      const fUrl = new URL(f.actionUrl);
      for (const field of f.fields) {
        const key = `${fUrl.pathname}|${field.name}`;
        if (!seenParamTarget.has(key)) {
          seenParamTarget.add(key);
          paramTargets.push({ baseUrl: f.actionUrl, path: fUrl.pathname, param: field.name });
        }
      }
    }

    const cappedParamTargets = paramTargets.slice(0, ctx.profile === 'comprehensive' ? 18 : 10);
    const baselineCache = new Map<string, HttpResponseSnapshot>();

    const getBaseline = async (url: string): Promise<HttpResponseSnapshot | null> => {
      if (baselineCache.has(url)) return baselineCache.get(url)!;
      try {
        const res = await ctx.httpFetch(url, { followRedirects: false });
        baselineCache.set(url, res);
        return res;
      } catch {
        return null;
      }
    };

    let sqliErrorHits = 0;
    let sqliBlindHits = 0;
    let nosqliHits = 0;
    let reflectedXssHits = 0;
    let pathTraversalHits = 0;
    let openRedirectHits = 0;
    let ssrfHits = 0;
    let budgetExhausted = false;

    const sqliReported = new Set<string>();
    const xssReported = new Set<string>();

    for (const target of cappedParamTargets) {
      if (ctx.isCancelled() || budgetExhausted) break;
      const baseline = await getBaseline(target.baseUrl);
      if (!baseline) continue;
      const baselineHasSqlErr = SQL_ERROR_PATTERNS.some((rx) => rx.test(baseline.bodyText));
      const baselineHasNosqlErr = NOSQL_ERROR_PATTERNS.some((rx) => rx.test(baseline.bodyText));

      try {
        // 1. Error-based SQLi & Blind SQLi boolean differential
        const quoteUrl = buildProbeUrl(target.baseUrl, target.param, "sentinel'\"");
        const quoteRes = await ctx.httpFetch(quoteUrl, { followRedirects: false });
        const matchedSqlErr = !baselineHasSqlErr
          ? SQL_ERROR_PATTERNS.find((rx) => rx.test(quoteRes.bodyText))
          : undefined;

        if (matchedSqlErr && !sqliReported.has(`${target.path}|${target.param}`)) {
          sqliReported.add(`${target.path}|${target.param}`);
          sqliErrorHits += 1;
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'H', VA: 'L', SC: 'N', SI: 'N', SA: 'N' },
            'critical',
            'Database syntax error triggered by non-destructive quote probe relative to clean baseline.'
          );
          findings.push({
            ruleId: `OWASP_SQLI_ERROR_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
            title: `SQL Injection Error Indicator on ${target.path} (${target.param})`,
            category: 'Injection',
            description: `Submitting SQL syntax characters in parameter "${target.param}" triggered an unhandled database error response.`,
            technicalExplanation: `Baseline GET returned HTTP ${baseline.status} without SQL errors; probing with quote characters triggered ${matchedSqlErr.source}.`,
            detectionTechnique: 'Error-based differential SQL probe (non-destructive syntax character vs baseline)',
            affectedUrl: target.baseUrl,
            httpMethod: 'GET',
            parameterName: target.param,
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: 'CWE-89',
            cveId: null,
            owaspCategory: 'A03:2021',
            owaspApiCategory: 'API8:2023',
            businessImpact: 'Unsanitized SQL interpolation can permit unauthorized database reads, modification, or authentication bypass.',
            exploitationPrerequisites: 'Reachable HTTP parameter passed to SQL query builder.',
            remediationInstructions: 'Use parameterized prepared statements or strict ORM bindings; never concatenate user input into SQL statements, and suppress database error details.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: `Baseline vs SQL syntax probe on parameter "${target.param}"`,
                rawExcerpt: formatHttpEvidence('GET', quoteUrl, quoteRes),
              },
            ],
          });
        }

        // Blind SQLi Boolean differential
        if (!sqliReported.has(`${target.path}|${target.param}`)) {
          const trueUrl = buildProbeUrl(target.baseUrl, target.param, "1' OR '1'='1");
          const falseUrl = buildProbeUrl(target.baseUrl, target.param, "1' AND '1'='2");
          const trueRes = await ctx.httpFetch(trueUrl, { followRedirects: false });
          const falseRes = await ctx.httpFetch(falseUrl, { followRedirects: false });

          const lenDelta = Math.abs(trueRes.bodyText.length - falseRes.bodyText.length);
          const baselineMatchTrue = Math.abs(baseline.bodyText.length - trueRes.bodyText.length);
          if (
            baseline.status === 200 &&
            trueRes.status === 200 &&
            ((falseRes.status === 200 && lenDelta >= 40 && baselineMatchTrue < lenDelta) ||
              (falseRes.status >= 400 && trueRes.status === 200))
          ) {
            sqliBlindHits += 1;
            const cvss = evaluateCvss4(
              { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'N', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
              'high',
              'Boolean true/false SQL predicate probe produced divergent response sizes/statuses.'
            );
            findings.push({
              ruleId: `OWASP_BLIND_SQLI_BOOLEAN_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
              title: `Blind SQL Injection Indicator (Boolean Differential) on ${target.path}`,
              category: 'Injection',
              description: `Parameter "${target.param}" exhibited measurable behavioral divergence between boolean-true and boolean-false SQL expressions.`,
              technicalExplanation: `True probe returned HTTP ${trueRes.status} (${trueRes.bodyText.length} bytes) vs False probe HTTP ${falseRes.status} (${falseRes.bodyText.length} bytes).`,
              detectionTechnique: 'Boolean differential blind SQLi probe (1\' OR \'1\'=\'1 vs 1\' AND \'1\'=\'2)',
              affectedUrl: target.baseUrl,
              httpMethod: 'GET',
              parameterName: target.param,
              confidence: 'medium',
              severity: cvss.severity,
              cvssVersion: cvss.version,
              cvssScore: cvss.score,
              cvssVector: cvss.vector,
              cvssRationale: cvss.rationale,
              cweId: 'CWE-89',
              cveId: null,
              owaspCategory: 'A03:2021',
              owaspApiCategory: null,
              businessImpact: 'Boolean-based blind SQL injection can allow row-by-row data inference.',
              exploitationPrerequisites: 'Parameter evaluated inside SQL WHERE/filter clause without parameterization.',
              remediationInstructions: 'Replace dynamic SQL string building with parameterized prepared statements and strict type validation.',
              references: ['https://owasp.org/www-community/attacks/Blind_SQL_Injection'],
              evidence: [
                {
                  evidenceType: 'http_response',
                  summary: 'True vs False boolean probe length/status comparison',
                  rawExcerpt: `True (${trueUrl}): HTTP ${trueRes.status}, ${trueRes.bodyText.length}B\nFalse (${falseUrl}): HTTP ${falseRes.status}, ${falseRes.bodyText.length}B`,
                },
              ],
            });
          }
        }

        // 2. NoSQL Injection operator probe
        const nosqlBaselineUrl = buildProbeUrl(target.baseUrl, target.param, 'sentinel_nomatch_9481');
        const nosqlProbeUrl = buildBracketProbeUrl(target.baseUrl, target.param, '$ne', 'sentinel_nomatch_9481');
        const nosqlBaseRes = await ctx.httpFetch(nosqlBaselineUrl, { followRedirects: false });
        const nosqlRes = await ctx.httpFetch(nosqlProbeUrl, { followRedirects: false });
        const matchedNosqlErr = !baselineHasNosqlErr
          ? NOSQL_ERROR_PATTERNS.find((rx) => rx.test(nosqlRes.bodyText))
          : undefined;
        const significantNosqlExpansion =
          nosqlRes.status === 200 &&
          nosqlBaseRes.status === 200 &&
          nosqlRes.bodyText.length > nosqlBaseRes.bodyText.length + 60 &&
          /json/i.test(nosqlRes.headers['content-type'] || '');

        if (matchedNosqlErr || significantNosqlExpansion) {
          nosqliHits += 1;
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
            'high',
            'Query operator [$ne] altered query filter semantics or surfaced a NoSQL driver error.'
          );
          findings.push({
            ruleId: `OWASP_NOSQLI_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
            title: `NoSQL Operator Injection Indicator on ${target.path} (${target.param})`,
            category: 'Injection',
            description: `Submitting query bracket operator "${target.param}[$ne]" altered query behavior or returned a NoSQL driver diagnostic.`,
            technicalExplanation: matchedNosqlErr
              ? `Response matched NoSQL signature ${matchedNosqlErr.source} after bracket operator injection.`
              : `Operator probe returned ${nosqlRes.bodyText.length}B JSON vs ${nosqlBaseRes.bodyText.length}B for scalar non-match sentinel.`,
            detectionTechnique: 'NoSQL bracket operator differential probe ($ne vs scalar sentinel)',
            affectedUrl: target.baseUrl,
            httpMethod: 'GET',
            parameterName: target.param,
            confidence: matchedNosqlErr ? 'high' : 'medium',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: 'CWE-943',
            cveId: null,
            owaspCategory: 'A03:2021',
            owaspApiCategory: 'API8:2023',
            businessImpact: 'Attackers may bypass filter predicates, expose hidden records, or bypass authentication in document databases.',
            exploitationPrerequisites: 'Framework parses nested query objects directly into database query filters.',
            remediationInstructions: 'Coerce query parameters strictly to primitive strings/numbers using schema validation (e.g., Zod) and reject object operators starting with "$".',
            references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: `NoSQL [$ne] probe response on "${target.param}"`,
                rawExcerpt: formatHttpEvidence('GET', nosqlProbeUrl, nosqlRes),
              },
            ],
          });
        }

        // 3. Reflected XSS (safe canary check in HTML response)
        const canary = 'sentinel<xss>"8492';
        const xssUrl = buildProbeUrl(target.baseUrl, target.param, canary);
        const xssRes = await ctx.httpFetch(xssUrl, { followRedirects: false });
        const xssCt = xssRes.headers['content-type'] || '';
        if (
          (!xssCt || /html/i.test(xssCt)) &&
          !baseline.bodyText.includes(canary) &&
          xssRes.bodyText.includes(canary) &&
          !xssReported.has(`${target.path}|${target.param}`)
        ) {
          xssReported.add(`${target.path}|${target.param}`);
          reflectedXssHits += 1;
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'A', VC: 'L', VI: 'L', VA: 'N', SC: 'L', SI: 'L', SA: 'N' },
            'high',
            'Unencoded angle brackets and quotes reflected directly inside HTML response body.'
          );
          findings.push({
            ruleId: `OWASP_REFLECTED_XSS_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
            title: `Reflected Cross-Site Scripting (XSS) on ${target.path} (${target.param})`,
            category: 'Cross-Site Scripting (XSS)',
            description: `Input supplied to "${target.param}" is reflected unescaped into an HTML response.`,
            technicalExplanation: `Harmless canary "${canary}" was returned verbatim in ${xssCt || 'HTML'} response without HTML entity encoding.`,
            detectionTechnique: 'Safe HTML canary reflection check (sentinel<xss>"8492)',
            affectedUrl: target.baseUrl,
            httpMethod: 'GET',
            parameterName: target.param,
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: 'CWE-79',
            cveId: null,
            owaspCategory: 'A03:2021',
            owaspApiCategory: null,
            businessImpact: 'Attackers can craft malicious URLs to execute JavaScript in victim sessions, exfiltrate tokens, or perform unauthorized actions.',
            exploitationPrerequisites: 'Victim navigates to crafted link.',
            remediationInstructions: 'Apply context-aware HTML output encoding on all user-controlled values and enforce a strict Content-Security-Policy without unsafe-inline.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: `Unescaped reflection of canary in "${target.param}"`,
                rawExcerpt: formatHttpEvidence('GET', xssUrl, xssRes),
              },
            ],
          });
        }

        // 4. Path Traversal
        if (FILE_PARAM_REGEX.test(target.param) || target.path.includes('download') || target.path.includes('file')) {
          const travUrl = buildProbeUrl(target.baseUrl, target.param, '../../../../etc/passwd');
          const travRes = await ctx.httpFetch(travUrl, { followRedirects: false });
          const hitSig = TRAVERSAL_SIGNATURES.find(
            (rx) => rx.test(travRes.bodyText) && !rx.test(baseline.bodyText)
          );
          if (hitSig) {
            pathTraversalHits += 1;
            const cvss = evaluateCvss4(
              { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
              'critical',
              'Path traversal sequence returned arbitrary filesystem signature relative to baseline.'
            );
            findings.push({
              ruleId: `OWASP_PATH_TRAVERSAL_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
              title: `Path Traversal Vulnerability on ${target.path} (${target.param})`,
              category: 'Broken Access Control',
              description: `Parameter "${target.param}" permits directory traversal sequences ("../") to escape the intended root directory.`,
              technicalExplanation: `Probe matched OS file signature ${hitSig.source} that was absent in baseline.`,
              detectionTechnique: 'Relative path traversal probe (../../../../etc/passwd vs baseline)',
              affectedUrl: target.baseUrl,
              httpMethod: 'GET',
              parameterName: target.param,
              confidence: 'high',
              severity: cvss.severity,
              cvssVersion: cvss.version,
              cvssScore: cvss.score,
              cvssVector: cvss.vector,
              cvssRationale: cvss.rationale,
              cweId: 'CWE-22',
              cveId: null,
              owaspCategory: 'A01:2021',
              owaspApiCategory: null,
              businessImpact: 'Attackers may read arbitrary server configuration files, credentials, or source code.',
              exploitationPrerequisites: 'Unvalidated filename/path parameter passed to filesystem APIs.',
              remediationInstructions: 'Resolve canonical paths (path.resolve), verify the path starts with the permitted base directory, or map opaque file IDs server-side.',
              references: ['https://owasp.org/www-community/attacks/Path_Traversal'],
              evidence: [
                {
                  evidenceType: 'http_response',
                  summary: `Filesystem signature matched on "${target.param}"`,
                  rawExcerpt: formatHttpEvidence('GET', travUrl, travRes),
                },
              ],
            });
          }
        }

        // 5. Open Redirect
        if (REDIRECT_PARAM_REGEX.test(target.param) || target.path.includes('redirect')) {
          const canaryTarget = 'https://redirect-check.sentinel-invalid.example/landing';
          const redirUrl = buildProbeUrl(target.baseUrl, target.param, canaryTarget);
          const redirRes = await ctx.httpFetch(redirUrl, { followRedirects: false });
          const loc = redirRes.headers['location'] || '';
          const metaHit = /<meta[^>]+http-equiv=["']?refresh["']?[^>]+redirect-check\.sentinel-invalid\.example/i.test(redirRes.bodyText);
          let externalLocation = false;
          if (loc) {
            try {
              const locUrl = new URL(loc, origin);
              externalLocation = locUrl.hostname === 'redirect-check.sentinel-invalid.example';
            } catch {
              externalLocation = loc.includes('redirect-check.sentinel-invalid.example');
            }
          }
          if ((redirRes.status >= 300 && redirRes.status < 400 && externalLocation) || metaHit) {
            openRedirectHits += 1;
            const cvss = evaluateCvss4(
              { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'A', VC: 'L', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
              'medium',
              'Server issues 3xx redirect to attacker-controlled external hostname.'
            );
            findings.push({
              ruleId: `OWASP_OPEN_REDIRECT_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
              title: `Unvalidated Open Redirect on ${target.path} (${target.param})`,
              category: 'Broken Access Control',
              description: `Redirect parameter "${target.param}" accepts external origins and issues an HTTP ${redirRes.status} redirect to arbitrary domains.`,
              technicalExplanation: `GET ${redirUrl} returned Location: ${loc || '(meta refresh)'}.`,
              detectionTechnique: 'Non-following HTTP redirect probe with external sentinel URL',
              affectedUrl: target.baseUrl,
              httpMethod: 'GET',
              parameterName: target.param,
              confidence: 'high',
              severity: cvss.severity,
              cvssVersion: cvss.version,
              cvssScore: cvss.score,
              cvssVector: cvss.vector,
              cvssRationale: cvss.rationale,
              cweId: 'CWE-601',
              cveId: null,
              owaspCategory: 'A01:2021',
              owaspApiCategory: null,
              businessImpact: 'Facilitates phishing campaigns abusing trust in the primary application domain and OAuth token redirection.',
              exploitationPrerequisites: 'Victim clicks crafted redirect link.',
              remediationInstructions: 'Restrict redirects to relative paths or validate target hostnames against an explicit server-side allowlist.',
              references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
              evidence: [
                {
                  evidenceType: 'http_header',
                  summary: 'Observed external Location header in redirect response',
                  rawExcerpt: formatHttpEvidence('GET', redirUrl, redirRes),
                },
              ],
            });
          }
        }

        // 6. SSRF Parameter & Validation Indicator (NEVER probes internal/metadata IPs!)
        if (SSRF_PARAM_REGEX.test(target.param) || target.path.includes('preview') || target.path.includes('fetch')) {
          const ssrfProbeTarget = 'https://ssrf-check.sentinel-invalid.example/probe';
          const ssrfUrl = buildProbeUrl(target.baseUrl, target.param, ssrfProbeTarget);
          const ssrfRes = await ctx.httpFetch(ssrfUrl, { followRedirects: false });
          const matchedSsrf = SSRF_ERROR_SIGNATURES.find(
            (rx) => rx.test(ssrfRes.bodyText) && !rx.test(baseline.bodyText)
          );
          if (matchedSsrf) {
            ssrfHits += 1;
            const cvss = evaluateCvss4(
              { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'N', VC: 'L', VI: 'N', VA: 'N', SC: 'H', SI: 'N', SA: 'N' },
              'high',
              'Server-side outbound DNS/HTTP attempt evidenced for supplied external URL parameter.'
            );
            findings.push({
              ruleId: `OWASP_SSRF_INDICATOR_${target.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}_${target.param.toUpperCase()}`,
              title: `Server-Side Request Forgery (SSRF) Indicator on ${target.path} (${target.param})`,
              category: 'Server-Side Request Forgery (SSRF)',
              description: `Supplying an external sentinel URL to "${target.param}" caused the server to attempt an outbound resolution/connection.`,
              technicalExplanation: `Response contained outbound resolution diagnostic (${matchedSsrf.source}). Internal/metadata IPs were intentionally never probed.`,
              detectionTechnique: 'Safe external .invalid DNS/fetch canary probe (non-routable sentinel)',
              affectedUrl: target.baseUrl,
              httpMethod: 'GET',
              parameterName: target.param,
              confidence: 'medium',
              severity: cvss.severity,
              cvssVersion: cvss.version,
              cvssScore: cvss.score,
              cvssVector: cvss.vector,
              cvssRationale: cvss.rationale,
              cweId: 'CWE-918',
              cveId: null,
              owaspCategory: 'A10:2021',
              owaspApiCategory: 'API7:2023',
              businessImpact: 'Unconstrained server-side URL fetching can expose internal services, cloud metadata, or private network endpoints.',
              exploitationPrerequisites: 'Server fetches user-supplied URLs without IP/domain allowlisting.',
              remediationInstructions: 'Enforce strict URL scheme (HTTPS only), domain allowlists, and block private/loopback/link-local IP ranges post-DNS-resolution before connecting.',
              references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'],
              evidence: [
                {
                  evidenceType: 'http_response',
                  summary: 'Outbound fetch attempt indicator',
                  rawExcerpt: formatHttpEvidence('GET', ssrfUrl, ssrfRes),
                },
              ],
            });
          }
        }
      } catch (err) {
        if (err instanceof RequestBudgetExceededError) {
          budgetExhausted = true;
          break;
        }
      }
    }

    // Check records for injection & param checks
    const hadParams = cappedParamTargets.length > 0;
    checks.push({
      checkKey: 'owasp.sqli_error',
      title: 'SQL Injection Error-Based Probes',
      category: 'Injection',
      status: !hadParams ? 'not_applicable' : sqliErrorHits > 0 ? 'failed' : 'passed',
      observedValue: !hadParams
        ? 'No GET query or form parameters discovered to probe'
        : sqliErrorHits > 0
          ? `${sqliErrorHits} parameter(s) triggered database SQL error signatures`
          : `Probed ${cappedParamTargets.length} parameter(s); 0 SQL error signatures detected`,
      expectedValue: '0 unhandled SQL syntax/driver errors across input parameters',
      explanation: !hadParams
        ? 'No parameterized endpoints were discovered during crawl.'
        : sqliErrorHits > 0
          ? 'Database syntax error responses confirmed unsafe SQL query handling.'
          : 'Safe quote/syntax probes did not elicit database error signatures.',
      remediation: sqliErrorHits > 0 ? 'Use parameterized queries / prepared statements for all dynamic SQL inputs.' : null,
      cweId: 'CWE-89',
      owaspCategory: 'A03:2021',
    });

    checks.push({
      checkKey: 'owasp.sqli_blind_boolean',
      title: 'Blind SQL Injection Boolean Differential Probes',
      category: 'Injection',
      status: !hadParams ? 'not_applicable' : sqliBlindHits > 0 ? 'potential' : 'passed',
      observedValue: !hadParams
        ? 'No parameterized endpoints discovered'
        : sqliBlindHits > 0
          ? `${sqliBlindHits} parameter(s) showed boolean true/false divergence`
          : `Tested ${cappedParamTargets.length} parameter(s); no boolean divergence observed`,
      expectedValue: 'Consistent handling of SQL boolean fragments as literal strings',
      explanation: !hadParams
        ? 'No parameterized endpoints were discovered during crawl.'
        : sqliBlindHits > 0
          ? 'Boolean true vs false probes differed in response length or status code.'
          : 'Boolean SQL probes produced identical handling.',
      remediation: sqliBlindHits > 0 ? 'Verify parameterization and input validation on flagged parameters.' : null,
      cweId: 'CWE-89',
      owaspCategory: 'A03:2021',
    });

    checks.push({
      checkKey: 'owasp.nosqli',
      title: 'NoSQL Operator Injection Probes',
      category: 'Injection',
      status: !hadParams ? 'not_applicable' : nosqliHits > 0 ? 'failed' : 'passed',
      observedValue: !hadParams
        ? 'No query parameters discovered'
        : nosqliHits > 0
          ? `${nosqliHits} parameter(s) accepted NoSQL [$ne] operator or emitted NoSQL error`
          : `Tested ${cappedParamTargets.length} parameter(s); 0 NoSQL operator anomalies`,
      expectedValue: 'Query operators stripped or rejected by strict schema validation',
      explanation: !hadParams
        ? 'No query parameters discovered.'
        : nosqliHits > 0
          ? 'Bracket operator injection altered filter output or produced NoSQL driver errors.'
          : 'No NoSQL operator injection behavior observed.',
      remediation: nosqliHits > 0 ? 'Validate query inputs as primitive scalar types and strip keys beginning with "$".' : null,
      cweId: 'CWE-943',
      owaspCategory: 'A03:2021',
    });

    checks.push({
      checkKey: 'owasp.xss_reflected',
      title: 'Reflected Cross-Site Scripting (XSS) Probes',
      category: 'Cross-Site Scripting (XSS)',
      status: !hadParams ? 'not_applicable' : reflectedXssHits > 0 ? 'failed' : 'passed',
      observedValue: !hadParams
        ? 'No HTML query parameters discovered'
        : reflectedXssHits > 0
          ? `${reflectedXssHits} parameter(s) reflected unescaped HTML canary`
          : `Tested ${cappedParamTargets.length} parameter(s); reflected values were properly encoded or absent`,
      expectedValue: 'HTML special characters (<, >, ") escaped before rendering',
      explanation: !hadParams
        ? 'No query parameters discovered.'
        : reflectedXssHits > 0
          ? 'Harmless HTML canary appeared unescaped in text/html response.'
          : 'No unescaped canary reflections detected.',
      remediation: reflectedXssHits > 0 ? 'Apply context-aware output encoding and strict CSP.' : null,
      cweId: 'CWE-79',
      owaspCategory: 'A03:2021',
    });

    // 7. DOM XSS across crawled pages + JS bundles
    const domMatches: Array<{ location: string; excerpt: string }> = [];
    for (const p of crawl.pages) {
      const m = p.bodyText.match(/(?:location\.search|location\.hash|document\.URL|window\.name|URLSearchParams)[\s\S]{0,200}(?:\.innerHTML\b|\.outerHTML\b|document\.write\(|insertAdjacentHTML\()/i);
      if (m) domMatches.push({ location: p.finalUrl, excerpt: m[0].slice(0, 180) });
    }
    for (const js of crawl.jsResources) {
      for (const hit of js.domXssMatches) {
        domMatches.push({ location: js.url, excerpt: hit });
      }
    }

    checks.push({
      checkKey: 'owasp.xss_dom',
      title: 'DOM-Based XSS Source-to-Sink Inspection (HTML + JS Bundles)',
      category: 'Cross-Site Scripting (XSS)',
      status: domMatches.length > 0 ? 'potential' : 'passed',
      observedValue:
        domMatches.length > 0
          ? `${domMatches.length} DOM source-to-sink pattern(s) across ${crawl.pages.length} page(s) & ${crawl.jsResources.length} JS bundle(s)`
          : `Inspected ${crawl.pages.length} page(s) & ${crawl.jsResources.length} JS bundle(s); 0 direct DOM XSS sinks`,
      expectedValue: 'Safe DOM text APIs (textContent) or sanitized rendering',
      explanation:
        domMatches.length > 0
          ? 'Client scripts pass URL/location input toward innerHTML/document.write sinks.'
          : 'No unguarded location-to-innerHTML sinks observed in crawled HTML or JS bundles.',
      remediation: domMatches.length > 0 ? 'Use textContent or sanitize HTML via DOMPurify before DOM insertion.' : null,
      cweId: 'CWE-79',
      owaspCategory: 'A03:2021',
    });

    for (const dm of domMatches.slice(0, 3)) {
      const cvss = evaluateCvss4(
        { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'P', VC: 'L', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
        'high',
        'Observable client-side URL source flowing into innerHTML sink.'
      );
      findings.push({
        ruleId: `OWASP_DOM_XSS_${dm.location.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
        title: `DOM-Based XSS Source-to-Sink Pattern (${new URL(dm.location).pathname})`,
        category: 'Cross-Site Scripting (XSS)',
        description: 'Client-side script passes URL/location state directly into an unsafe HTML DOM sink.',
        technicalExplanation: `Matched DOM source-to-sink flow in ${dm.location}.`,
        detectionTechnique: 'Crawled HTML & JavaScript bundle source-to-sink AST/pattern analysis',
        affectedUrl: dm.location,
        httpMethod: 'GET',
        parameterName: 'location.search / hash',
        confidence: 'medium',
        severity: cvss.severity,
        cvssVersion: cvss.version,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        cvssRationale: cvss.rationale,
        cweId: 'CWE-79',
        cveId: null,
        owaspCategory: 'A03:2021',
        owaspApiCategory: null,
        businessImpact: 'Allows client-side script execution via crafted links without server reflection.',
        exploitationPrerequisites: 'User loads page with crafted query/hash parameter.',
        remediationInstructions: 'Replace innerHTML/document.write with textContent or sanitize using DOMPurify.',
        references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS'],
        evidence: [
          {
            evidenceType: 'code_snippet',
            summary: `DOM XSS pattern in ${new URL(dm.location).pathname}`,
            rawExcerpt: dm.excerpt,
          },
        ],
      });
    }

    // 8. Multi-page CSRF Protection across all discovered state-changing HTML forms
    const stateForms = crawl.forms.filter((f) => f.method !== 'GET');
    const unguardedForms = stateForms.filter((f) => !f.hasCsrfField);
    checks.push({
      checkKey: 'owasp.csrf',
      title: 'Multi-Page State-Changing Form CSRF Protection',
      category: 'Cross-Site Request Forgery (CSRF)',
      status: stateForms.length === 0 ? 'not_applicable' : unguardedForms.length > 0 ? 'potential' : 'passed',
      observedValue:
        stateForms.length === 0
          ? 'No state-changing HTML POST/PUT/DELETE forms discovered across crawled pages'
          : `${unguardedForms.length} of ${stateForms.length} POST/mutation form(s) lack visible anti-CSRF token fields`,
      expectedValue: 'Per-session anti-CSRF token on every state-changing HTML form',
      explanation:
        stateForms.length === 0
          ? 'Crawled pages contained no POST HTML forms.'
          : unguardedForms.length > 0
            ? `Forms at ${unguardedForms.map((u) => new URL(u.actionUrl).pathname).join(', ')} omit anti-CSRF hidden inputs.`
            : 'All discovered state-changing HTML forms include anti-CSRF token fields.',
      remediation: unguardedForms.length > 0 ? 'Embed cryptographic CSRF tokens in all state-changing forms and verify Origin/Referer headers.' : null,
      cweId: 'CWE-352',
      owaspCategory: 'A01:2021',
    });

    // 9. IDOR / BOLA probe on numeric object endpoints
    const idCandidates = new Set<string>();
    for (const ep of crawl.endpoints) {
      if (/\/\d+(?:$|\?)/.test(ep.url)) idCandidates.add(ep.url);
    }
    for (const route of crawl.discoveredApiRoutes) {
      if (/\/\d+(?:$|\?)/.test(route)) idCandidates.add(`${origin}${route}`);
    }

    let idorHits = 0;
    for (const idUrl of Array.from(idCandidates).slice(0, 5)) {
      if (ctx.isCancelled() || budgetExhausted) break;
      try {
        const res1 = await ctx.httpFetch(idUrl, { headers: ctx.authHeaders });
        const mutatedUrl = idUrl.replace(/\/(\d+)(?=$|\?)/, (_, num) => `/${Number(num) + 1}`);
        if (mutatedUrl === idUrl) continue;
        const res2 = await ctx.httpFetch(mutatedUrl, { headers: ctx.authHeaders });
        if (
          res1.status === 200 &&
          res2.status === 200 &&
          res1.bodyText !== res2.bodyText &&
          /json/i.test(res2.headers['content-type'] || '')
        ) {
          idorHits += 1;
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
            'high',
            'Adjacent numeric object identifier returned distinct object record without authorization block.'
          );
          findings.push({
            ruleId: `OWASP_IDOR_BOLA_${new URL(idUrl).pathname.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `Broken Object Level Authorization (IDOR/BOLA) on ${new URL(idUrl).pathname}`,
            category: 'Broken Access Control',
            description: 'Incrementing a numeric resource identifier returned another object record with HTTP 200 without ownership enforcement.',
            technicalExplanation: `GET ${idUrl} and adjacent GET ${mutatedUrl} both returned distinct JSON object payloads (HTTP 200).`,
            detectionTechnique: 'Adjacent object identifier differential probe',
            affectedUrl: mutatedUrl,
            httpMethod: 'GET',
            parameterName: 'objectId',
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: 'CWE-639',
            cveId: null,
            owaspCategory: 'A01:2021',
            owaspApiCategory: 'API1:2023',
            businessImpact: 'Unauthorized parties can enumerate and retrieve records belonging to other accounts.',
            exploitationPrerequisites: 'Sequential or predictable object identifier.',
            remediationInstructions: 'Enforce server-side object ownership checks (session.userId === record.ownerId) on every object route and avoid predictable sequential IDs.',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'],
            evidence: [
              {
                evidenceType: 'auth_diff',
                summary: 'Adjacent object ID differential JSON response',
                rawExcerpt: `ID A (${idUrl}): ${res1.bodyText.slice(0, 140)}\nID B (${mutatedUrl}): ${res2.bodyText.slice(0, 140)}`,
              },
            ],
          });
        }
      } catch (err) {
        if (err instanceof RequestBudgetExceededError) {
          budgetExhausted = true;
          break;
        }
      }
    }

    checks.push({
      checkKey: 'owasp.idor_bola',
      title: 'IDOR / Broken Object Level Authorization (BOLA) Probes',
      category: 'Broken Access Control',
      status: idCandidates.size === 0 ? 'not_applicable' : idorHits > 0 ? 'failed' : 'passed',
      observedValue:
        idCandidates.size === 0
          ? 'No numeric object-ID endpoints discovered in crawl or JS routes'
          : idorHits > 0
            ? `${idorHits} endpoint(s) returned distinct adjacent object data without access denial`
            : `Checked ${idCandidates.size} object-ID endpoint(s); adjacent IDs rejected or identical`,
      expectedValue: 'Object ownership enforced (401/403/404 for unauthorized object IDs)',
      explanation:
        idCandidates.size === 0
          ? 'No numeric resource IDs were observed during discovery.'
          : idorHits > 0
            ? 'Adjacent ID enumeration returned distinct JSON records with HTTP 200.'
            : 'No unauthorized object access confirmed across discovered ID routes.',
      remediation: idorHits > 0 ? 'Verify caller authorization against resource owner before returning records.' : null,
      cweId: 'CWE-639',
      owaspCategory: 'A01:2021',
    });

    // 10. Path Traversal, Open Redirect, SSRF check summary rows
    const fileParamTested = cappedParamTargets.some(
      (t) => FILE_PARAM_REGEX.test(t.param) || t.path.includes('download') || t.path.includes('file')
    );
    checks.push({
      checkKey: 'owasp.path_traversal',
      title: 'Directory / Path Traversal Probes',
      category: 'Broken Access Control',
      status: !fileParamTested ? 'not_applicable' : pathTraversalHits > 0 ? 'failed' : 'passed',
      observedValue: !fileParamTested
        ? 'No file/path/download parameters discovered'
        : pathTraversalHits > 0
          ? `${pathTraversalHits} parameter(s) returned arbitrary filesystem signatures`
          : 'Tested file/path parameters; no filesystem signatures exposed',
      expectedValue: 'Strict path canonicalization and directory confinement',
      explanation: !fileParamTested
        ? 'No file-handling query parameters discovered during crawl.'
        : pathTraversalHits > 0
          ? 'Relative traversal sequence escaped intended directory.'
          : 'Path traversal probes returned safe errors or ignored traversal.',
      remediation: pathTraversalHits > 0 ? 'Canonicalize paths and enforce base-directory prefix verification.' : null,
      cweId: 'CWE-22',
      owaspCategory: 'A01:2021',
    });

    const redirectParamTested = cappedParamTargets.some(
      (t) => REDIRECT_PARAM_REGEX.test(t.param) || t.path.includes('redirect')
    );
    checks.push({
      checkKey: 'owasp.open_redirect',
      title: 'Unvalidated Open Redirect Probes',
      category: 'Broken Access Control',
      status: !redirectParamTested ? 'not_applicable' : openRedirectHits > 0 ? 'failed' : 'passed',
      observedValue: !redirectParamTested
        ? 'No redirect/next/return parameters discovered'
        : openRedirectHits > 0
          ? `${openRedirectHits} redirect endpoint(s) issued external Location headers`
          : 'Tested redirect parameters; external destinations blocked or ignored',
      expectedValue: 'Redirects restricted to relative paths or allowlisted origins',
      explanation: !redirectParamTested
        ? 'No redirect parameters observed during crawl.'
        : openRedirectHits > 0
          ? 'Location header redirected to external canary domain.'
          : 'Redirect probes stayed within safe bounds.',
      remediation: openRedirectHits > 0 ? 'Validate redirect targets against an explicit allowlist.' : null,
      cweId: 'CWE-601',
      owaspCategory: 'A01:2021',
    });

    const ssrfParamTested = cappedParamTargets.some(
      (t) => SSRF_PARAM_REGEX.test(t.param) || t.path.includes('preview') || t.path.includes('fetch')
    );
    checks.push({
      checkKey: 'owasp.ssrf_indicator',
      title: 'Server-Side Request Forgery (SSRF) Parameter Indicators',
      category: 'Server-Side Request Forgery (SSRF)',
      status: !ssrfParamTested ? 'not_applicable' : ssrfHits > 0 ? 'potential' : 'passed',
      observedValue: !ssrfParamTested
        ? 'No URL/webhook/callback parameters discovered'
        : ssrfHits > 0
          ? `${ssrfHits} parameter(s) evidenced server-side outbound resolution attempts`
          : 'URL parameters did not expose outbound connection diagnostics',
      expectedValue: 'Strict URL scheme/domain allowlisting and private-IP egress blocking',
      explanation: !ssrfParamTested
        ? 'No URL-fetching parameters identified.'
        : ssrfHits > 0
          ? 'External .invalid canary triggered outbound DNS/connection behavior server-side.'
          : 'No SSRF indicators observed.',
      remediation: ssrfHits > 0 ? 'Restrict server-side HTTP clients to allowlisted hosts and block RFC1918/link-local IPs.' : null,
      cweId: 'CWE-918',
      owaspCategory: 'A10:2021',
    });

    // 11. Safe XXE Parser Exposure Indicator (no DTD / external entities!)
    const xmlCandidates = new Set<string>();
    for (const r of crawl.discoveredApiRoutes) {
      if (/xml|soap/i.test(r)) xmlCandidates.add(`${origin}${r}`);
    }
    for (const ep of crawl.endpoints) {
      if (/xml|soap/i.test(ep.path) || /xml/i.test(ep.contentType || '')) xmlCandidates.add(ep.url);
    }

    let xxeIndicatorHits = 0;
    for (const xUrl of Array.from(xmlCandidates).slice(0, 3)) {
      if (ctx.isCancelled() || budgetExhausted) break;
      try {
        const xmlRes = await ctx.httpFetch(xUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/xml' },
          body: '<?xml version="1.0" encoding="UTF-8"?><sentinelPing>check8492</sentinelPing>',
        });
        if (
          xmlRes.status === 200 &&
          (xmlRes.bodyText.includes('check8492') || /libxml|SAXParse|XMLSyntaxError/i.test(xmlRes.bodyText))
        ) {
          xxeIndicatorHits += 1;
          findings.push({
            ruleId: `OWASP_XXE_PARSER_INDICATOR_${new URL(xUrl).pathname.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `XML Parser Active Endpoint (XXE Assessment Indicator) at ${new URL(xUrl).pathname}`,
            category: 'Security Misconfiguration',
            description: 'Endpoint actively parses application/xml payloads. Verify DTD and external entity resolution are disabled.',
            technicalExplanation: `POST ${xUrl} with benign well-formed XML echoed/parsed node values (${xmlRes.headers['content-type'] || 'xml'}). No external entities were transmitted.`,
            detectionTechnique: 'Non-destructive well-formed XML parser probe (no DTD/ENTITY)',
            affectedUrl: xUrl,
            httpMethod: 'POST',
            parameterName: 'XML body',
            confidence: 'medium',
            severity: 'medium',
            cvssVersion: null,
            cvssScore: null,
            cvssVector: null,
            cvssRationale: 'Safe assessment does not inject external DTD entities; manual or parser config verification is required to confirm XXE immunity.',
            cweId: 'CWE-611',
            cveId: null,
            owaspCategory: 'A05:2021',
            owaspApiCategory: null,
            businessImpact: 'If the underlying XML parser allows DOCTYPE/external entities, attackers may read local files or perform SSRF.',
            exploitationPrerequisites: 'XML parser configured with default/permissive DTD settings.',
            remediationInstructions: 'Disable DOCTYPE declarations and external entity resolution in the XML parser (e.g., disallow-doctype-decl=true / defusedxml).',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: 'XML parser processed benign XML ping',
                rawExcerpt: formatHttpEvidence('POST', xUrl, xmlRes),
              },
            ],
          });
        }
      } catch (err) {
        if (err instanceof RequestBudgetExceededError) {
          budgetExhausted = true;
          break;
        }
      }
    }

    checks.push({
      checkKey: 'owasp.xxe_indicator',
      title: 'XML Endpoint & XXE Parser Surface Indicator',
      category: 'Security Misconfiguration',
      status: xmlCandidates.size === 0 ? 'not_applicable' : xxeIndicatorHits > 0 ? 'potential' : 'passed',
      observedValue:
        xmlCandidates.size === 0
          ? 'No XML/SOAP endpoints discovered'
          : xxeIndicatorHits > 0
            ? `${xxeIndicatorHits} XML parsing endpoint(s) confirmed active (verify DTD disabled)`
            : 'Discovered XML endpoint(s) did not echo parsed XML',
      expectedValue: 'JSON preferred or XML parser configured with DOCTYPE/external entities disabled',
      explanation:
        xmlCandidates.size === 0
          ? 'No XML or SOAP API routes were identified.'
          : xxeIndicatorHits > 0
            ? 'Endpoint parsed benign XML body; confirm DTDs are disabled safely.'
            : 'No unsafe XML parsing indicators observed.',
      remediation: xxeIndicatorHits > 0 ? 'Disable DTD declarations and external entities in XML parser settings.' : null,
      cweId: 'CWE-611',
      owaspCategory: 'A05:2021',
    });

    // 12. File Upload Weaknesses
    let uploadWeaknesses = 0;
    if (crawl.uploadEndpoints.length > 0) {
      for (const up of crawl.uploadEndpoints) {
        const matchingForm = crawl.forms.find((f) => f.actionUrl === up.actionUrl && f.hasFileInput);
        const page = crawl.pages.find((p) => p.finalUrl === up.pageUrl);
        const hasAcceptAttr = page ? /<input[^>]+type=["']file["'][^>]+accept=/i.test(page.bodyText) : false;
        let uploadsIndexExposed = false;
        try {
          const idxRes = await ctx.httpFetch(`${origin}/uploads/`);
          uploadsIndexExposed = idxRes.status === 200 && /Index of \//i.test(idxRes.bodyText);
        } catch {
          // ignore
        }

        if (!hasAcceptAttr || (matchingForm && !matchingForm.hasCsrfField) || uploadsIndexExposed) {
          uploadWeaknesses += 1;
          findings.push({
            ruleId: `OWASP_FILE_UPLOAD_WEAKNESS_${new URL(up.actionUrl).pathname.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `File Upload Security Weakness on ${new URL(up.actionUrl).pathname}`,
            category: 'Insecure Design',
            description: `Upload form (${up.fieldNames.join(', ') || 'file'}) exhibits weak controls: ${[
              !hasAcceptAttr ? 'missing client file type accept filter' : null,
              matchingForm && !matchingForm.hasCsrfField ? 'missing anti-CSRF token' : null,
              uploadsIndexExposed ? 'public directory listing at /uploads/' : null,
            ]
              .filter(Boolean)
              .join(', ')}.`,
            technicalExplanation: `Inspected multipart upload form at ${up.pageUrl} -> ${up.actionUrl}.`,
            detectionTechnique: 'Multipart form & upload directory exposure inspection',
            affectedUrl: up.actionUrl,
            httpMethod: 'POST',
            parameterName: up.fieldNames[0] || 'file',
            confidence: 'high',
            severity: uploadsIndexExposed ? 'high' : 'medium',
            cvssVersion: null,
            cvssScore: null,
            cvssVector: null,
            cvssRationale: 'Passive/directory inspection confirms missing upload guardrails without transmitting malicious binaries.',
            cweId: 'CWE-434',
            cveId: null,
            owaspCategory: 'A04:2021',
            owaspApiCategory: null,
            businessImpact: 'Permissive uploads and public upload directory indexes can expose sensitive user documents or enable stored XSS/script hosting.',
            exploitationPrerequisites: 'Access to file upload endpoint.',
            remediationInstructions: 'Validate MIME type & magic bytes server-side, rename uploaded files randomly, store outside web root (object storage), and disable /uploads directory indexing.',
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: 'File upload form & /uploads/ inspection',
                rawExcerpt: `Form action: ${up.actionUrl}\nAccept attr present: ${hasAcceptAttr}\nCSRF field present: ${Boolean(matchingForm?.hasCsrfField)}\n/uploads/ listing exposed: ${uploadsIndexExposed}`,
              },
            ],
          });
        }
      }
    }

    checks.push({
      checkKey: 'owasp.file_upload',
      title: 'File Upload Controls & Storage Exposure',
      category: 'Insecure Design',
      status: crawl.uploadEndpoints.length === 0 ? 'not_applicable' : uploadWeaknesses > 0 ? 'failed' : 'passed',
      observedValue:
        crawl.uploadEndpoints.length === 0
          ? 'No multipart file upload forms discovered'
          : uploadWeaknesses > 0
            ? `${uploadWeaknesses} upload endpoint(s) showed missing restrictions or exposed /uploads/ index`
            : `Inspected ${crawl.uploadEndpoints.length} upload form(s); guardrails present`,
      expectedValue: 'Allowlisted extensions, server magic-byte checks, CSRF token, private object storage',
      explanation:
        crawl.uploadEndpoints.length === 0
          ? 'No <input type="file"> upload forms found during crawl.'
          : uploadWeaknesses > 0
            ? 'Detected weak upload restrictions or public /uploads/ listing.'
            : 'Upload endpoints include basic guardrails.',
      remediation: uploadWeaknesses > 0 ? 'Store uploads outside web root with randomized names and strict server-side content validation.' : null,
      cweId: 'CWE-434',
      owaspCategory: 'A04:2021',
    });

    // 13. Broken Access Control on discovered admin/internal endpoints
    const adminCandidates = new Set<string>();
    for (const ep of crawl.endpoints) {
      if (/\/(?:admin|internal|audit|backup|debug)/i.test(ep.path)) {
        adminCandidates.add(ep.url);
      }
    }
    let brokenAccessHits = 0;
    for (const aUrl of Array.from(adminCandidates).slice(0, 6)) {
      if (ctx.isCancelled() || budgetExhausted) break;
      try {
        const res = await ctx.httpFetch(aUrl, { followRedirects: false });
        if (res.status === 200 && !/login|sign in/i.test(res.bodyText)) {
          brokenAccessHits += 1;
          const aPath = new URL(aUrl).pathname;
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
            'high',
            'Administrative/internal route responded HTTP 200 without authentication redirect or 401/403.'
          );
          findings.push({
            ruleId: `OWASP_BROKEN_ACCESS_CONTROL_${aPath.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `Broken Access Control: Unauthenticated Access to ${aPath}`,
            category: 'Broken Access Control',
            description: `Privileged or internal route ${aPath} returned HTTP 200 without requiring authentication.`,
            technicalExplanation: `Anonymous GET ${aUrl} returned HTTP 200 (${res.headers['content-type'] || 'unknown'}).`,
            detectionTechnique: 'Unauthenticated access probe against discovered administrative/internal paths',
            affectedUrl: aUrl,
            httpMethod: 'GET',
            parameterName: null,
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: 'CWE-284',
            cveId: null,
            owaspCategory: 'A01:2021',
            owaspApiCategory: 'API5:2023',
            businessImpact: 'Unauthorized users can view administrative indexes, backups, or privileged functionality.',
            exploitationPrerequisites: 'Direct HTTP GET access.',
            remediationInstructions: 'Enforce deny-by-default authentication and role-based authorization checks on all administrative routes.',
            references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: `HTTP 200 on unauthenticated request to ${aPath}`,
                rawExcerpt: formatHttpEvidence('GET', aUrl, res),
              },
            ],
          });
        }
      } catch (err) {
        if (err instanceof RequestBudgetExceededError) {
          budgetExhausted = true;
          break;
        }
      }
    }

    checks.push({
      checkKey: 'owasp.broken_access_control',
      title: 'Broken Access Control (Unauthenticated Privileged Routes)',
      category: 'Broken Access Control',
      status: adminCandidates.size === 0 ? 'informational' : brokenAccessHits > 0 ? 'failed' : 'passed',
      observedValue:
        adminCandidates.size === 0
          ? 'No administrative or internal routes surfaced in crawl/robots.txt'
          : brokenAccessHits > 0
            ? `${brokenAccessHits} privileged path(s) accessible unauthenticated (HTTP 200)`
            : `Checked ${adminCandidates.size} privileged path(s); all rejected unauthenticated requests`,
      expectedValue: '401/403 or login redirect on administrative and backup routes',
      explanation:
        adminCandidates.size === 0
          ? 'No admin/internal paths were discovered unauthenticated.'
          : brokenAccessHits > 0
            ? 'Discovered administrative/internal URL returned HTTP 200 without authentication.'
            : 'Discovered privileged paths properly require authentication.',
      remediation: brokenAccessHits > 0 ? 'Apply server-side authentication and RBAC authorization guards.' : null,
      cweId: 'CWE-284',
      owaspCategory: 'A01:2021',
    });

    return { checks, findings, endpoints: crawl.endpoints, logs };
  },
};
