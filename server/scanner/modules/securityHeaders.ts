import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import type { CheckOutcome } from '../../db/types.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

interface HeaderAnalysis {
  header: string;
  observed: string | null;
  status: CheckOutcome;
  summary: string;
  recommended: string;
  severityIfWeak: 'high' | 'medium' | 'low' | 'informational';
  cweId: string;
  owasp: string;
}

export function analyzeSecurityHeaders(
  headers: Record<string, string>,
  isHttps: boolean
): HeaderAnalysis[] {
  const results: HeaderAnalysis[] = [];

  // 1. Content-Security-Policy
  const csp = headers['content-security-policy'] || null;
  if (!csp) {
    results.push({
      header: 'Content-Security-Policy',
      observed: null,
      status: 'failed',
      summary: 'Missing Content-Security-Policy header; browser lacks script and framing restrictions.',
      recommended: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
      severityIfWeak: 'medium',
      cweId: 'CWE-693',
      owasp: 'A05:2021',
    });
  } else {
    const issues: string[] = [];
    if (/'unsafe-inline'/i.test(csp)) issues.push("allows 'unsafe-inline'");
    if (/'unsafe-eval'/i.test(csp)) issues.push("allows 'unsafe-eval'");
    if (/\s\*(?:\s|;|$)/.test(csp)) issues.push('uses wildcard (*) source');
    if (!/default-src/i.test(csp)) issues.push('missing default-src fallback');
    if (!/frame-ancestors/i.test(csp)) issues.push('missing frame-ancestors directive');
    if (/http:\/\//i.test(csp)) issues.push('permits insecure http:// sources');

    results.push({
      header: 'Content-Security-Policy',
      observed: csp,
      status: issues.length > 0 ? 'failed' : 'passed',
      summary:
        issues.length > 0
          ? `CSP is present but weakened by insecure directives: ${issues.join(', ')}.`
          : 'CSP is configured without unsafe-inline, unsafe-eval, or wildcard sources.',
      recommended: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
      severityIfWeak: 'medium',
      cweId: 'CWE-693',
      owasp: 'A05:2021',
    });
  }

  // 2. Strict-Transport-Security
  const hsts = headers['strict-transport-security'] || null;
  if (!isHttps) {
    results.push({
      header: 'Strict-Transport-Security',
      observed: hsts,
      status: 'not_applicable',
      summary: 'HSTS applies only to HTTPS responses; primary response was not served over HTTPS.',
      recommended: 'max-age=31536000; includeSubDomains; preload',
      severityIfWeak: 'medium',
      cweId: 'CWE-319',
      owasp: 'A02:2021',
    });
  } else if (!hsts) {
    results.push({
      header: 'Strict-Transport-Security',
      observed: null,
      status: 'failed',
      summary: 'Missing Strict-Transport-Security header on HTTPS response.',
      recommended: 'max-age=31536000; includeSubDomains; preload',
      severityIfWeak: 'medium',
      cweId: 'CWE-319',
      owasp: 'A02:2021',
    });
  } else {
    const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
    const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
    const issues: string[] = [];
    if (maxAge < 15552000) issues.push(`max-age=${maxAge} is below 180 days (15552000s)`);
    if (!/includeSubDomains/i.test(hsts)) issues.push('missing includeSubDomains');
    results.push({
      header: 'Strict-Transport-Security',
      observed: hsts,
      status: issues.length > 0 ? 'failed' : 'passed',
      summary:
        issues.length > 0
          ? `HSTS header present but weak: ${issues.join('; ')}.`
          : `HSTS enforced with max-age=${maxAge} and includeSubDomains.`,
      recommended: 'max-age=31536000; includeSubDomains; preload',
      severityIfWeak: 'low',
      cweId: 'CWE-319',
      owasp: 'A02:2021',
    });
  }

  // 3. X-Frame-Options
  const xfo = headers['x-frame-options'] || null;
  const hasCspFrameAncestors = Boolean(csp && /frame-ancestors/i.test(csp));
  if (!xfo && !hasCspFrameAncestors) {
    results.push({
      header: 'X-Frame-Options',
      observed: null,
      status: 'failed',
      summary: 'Neither X-Frame-Options nor CSP frame-ancestors is configured (clickjacking exposure).',
      recommended: 'DENY (or SAMEORIGIN)',
      severityIfWeak: 'medium',
      cweId: 'CWE-1021',
      owasp: 'A05:2021',
    });
  } else if (xfo && !/^(DENY|SAMEORIGIN)$/i.test(xfo.trim())) {
    results.push({
      header: 'X-Frame-Options',
      observed: xfo,
      status: 'failed',
      summary: `X-Frame-Options value "${xfo}" is non-standard or deprecated.`,
      recommended: 'DENY',
      severityIfWeak: 'low',
      cweId: 'CWE-1021',
      owasp: 'A05:2021',
    });
  } else {
    results.push({
      header: 'X-Frame-Options',
      observed: xfo || '(covered by CSP frame-ancestors)',
      status: 'passed',
      summary: 'Framing protection is enforced.',
      recommended: 'DENY',
      severityIfWeak: 'low',
      cweId: 'CWE-1021',
      owasp: 'A05:2021',
    });
  }

  // 4. X-Content-Type-Options
  const xcto = headers['x-content-type-options'] || null;
  const xctoValid = xcto?.trim().toLowerCase() === 'nosniff';
  results.push({
    header: 'X-Content-Type-Options',
    observed: xcto,
    status: xctoValid ? 'passed' : 'failed',
    summary: xctoValid
      ? 'X-Content-Type-Options: nosniff prevents MIME-type sniffing.'
      : 'Missing or invalid X-Content-Type-Options header (expected "nosniff").',
    recommended: 'nosniff',
    severityIfWeak: 'low',
    cweId: 'CWE-16',
    owasp: 'A05:2021',
  });

  // 5. Referrer-Policy
  const refPol = headers['referrer-policy'] || null;
  const unsafeRef = refPol && /(unsafe-url|no-referrer-when-downgrade)/i.test(refPol);
  results.push({
    header: 'Referrer-Policy',
    observed: refPol,
    status: !refPol || unsafeRef ? 'failed' : 'passed',
    summary: !refPol
      ? 'Missing Referrer-Policy header; full URLs or query tokens may leak in Referer headers.'
      : unsafeRef
        ? `Referrer-Policy "${refPol}" allows full referrer leakage.`
        : `Referrer-Policy configured as "${refPol}".`,
    recommended: 'strict-origin-when-cross-origin',
    severityIfWeak: 'low',
    cweId: 'CWE-200',
    owasp: 'A05:2021',
  });

  // 6. Permissions-Policy
  const permPol = headers['permissions-policy'] || headers['feature-policy'] || null;
  results.push({
    header: 'Permissions-Policy',
    observed: permPol,
    status: permPol ? 'passed' : 'failed',
    summary: permPol
      ? 'Permissions-Policy restricts powerful browser APIs.'
      : 'Missing Permissions-Policy header to restrict camera, microphone, and geolocation APIs.',
    recommended: 'camera=(), microphone=(), geolocation=()',
    severityIfWeak: 'low',
    cweId: 'CWE-16',
    owasp: 'A05:2021',
  });

  // 7, 8, 9. Cross-Origin Isolation headers (CORP, COOP, COEP)
  const corp = headers['cross-origin-resource-policy'] || null;
  results.push({
    header: 'Cross-Origin-Resource-Policy',
    observed: corp,
    status: corp ? 'passed' : 'informational',
    summary: corp
      ? `Cross-Origin-Resource-Policy set to "${corp}".`
      : 'Cross-Origin-Resource-Policy not set; recommended for isolating cross-origin resource embedding.',
    recommended: 'same-origin',
    severityIfWeak: 'informational',
    cweId: 'CWE-346',
    owasp: 'A05:2021',
  });

  const coop = headers['cross-origin-opener-policy'] || null;
  results.push({
    header: 'Cross-Origin-Opener-Policy',
    observed: coop,
    status: coop ? 'passed' : 'informational',
    summary: coop
      ? `Cross-Origin-Opener-Policy set to "${coop}".`
      : 'Cross-Origin-Opener-Policy not configured; recommended to isolate browsing context groups.',
    recommended: 'same-origin',
    severityIfWeak: 'informational',
    cweId: 'CWE-346',
    owasp: 'A05:2021',
  });

  const coep = headers['cross-origin-embedder-policy'] || null;
  results.push({
    header: 'Cross-Origin-Embedder-Policy',
    observed: coep,
    status: coep ? 'passed' : 'informational',
    summary: coep
      ? `Cross-Origin-Embedder-Policy set to "${coep}".`
      : 'Cross-Origin-Embedder-Policy not configured.',
    recommended: 'require-corp',
    severityIfWeak: 'informational',
    cweId: 'CWE-346',
    owasp: 'A05:2021',
  });

  // 10. Cache-Control
  const cacheControl = headers['cache-control'] || null;
  const overlyCacheable = cacheControl && /public/i.test(cacheControl) && !/no-store/i.test(cacheControl);
  results.push({
    header: 'Cache-Control',
    observed: cacheControl,
    status: !cacheControl ? 'informational' : overlyCacheable ? 'potential' : 'passed',
    summary: !cacheControl
      ? 'Cache-Control header absent on primary HTML response.'
      : overlyCacheable
        ? `Cache-Control "${cacheControl}" marks HTML response as public; verify no user-specific data is cached.`
        : `Cache-Control configured as "${cacheControl}".`,
    recommended: 'no-store, max-age=0 (for authenticated/dynamic pages)',
    severityIfWeak: 'low',
    cweId: 'CWE-525',
    owasp: 'A05:2021',
  });

  return results;
}

export const securityHeadersModule: ScannerModule = {
  id: 'http-security-headers',
  name: 'HTTP Security Headers & CORS Analyzer',
  version: '1.4.0',
  category: 'HTTP Security Headers',
  description: 'Parses directives of 10 security headers plus active CORS reflection checks.',
  supportedProfiles: ['quick', 'standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 8000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const res = ctx.sharedState.homepageResponse || (await ctx.httpFetch(ctx.targetUrl));
    const isHttps = new URL(res.finalUrl).protocol === 'https:';
    const analyzed = analyzeSecurityHeaders(res.headers, isHttps);

    for (const item of analyzed) {
      checks.push({
        checkKey: `headers.${item.header.toLowerCase()}`,
        title: `Header: ${item.header}`,
        category: 'HTTP Security Headers',
        status: item.status,
        observedValue: item.observed ?? '(missing)',
        expectedValue: item.recommended,
        explanation: item.summary,
        remediation: item.status === 'passed' ? null : `Configure ${item.header}: ${item.recommended}`,
        cweId: item.cweId,
        owaspCategory: item.owasp,
      });

      if (item.status === 'failed') {
        const cvss =
          item.header === 'Content-Security-Policy' || item.header === 'X-Frame-Options'
            ? evaluateCvss4(
                { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'P', VC: 'L', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
                item.severityIfWeak,
                `Missing or misconfigured ${item.header} verified in live HTTP response headers.`
              )
            : evaluateCvss4(null, item.severityIfWeak, 'Hardening header omission; no direct standalone CVSS 4.0 score assigned without exploit chain.');

        findings.push({
          ruleId: `HDR_${item.header.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
          title: `Missing or Weak ${item.header} Header`,
          category: 'HTTP Security Headers',
          description: item.summary,
          technicalExplanation: `Observed value on ${res.finalUrl}: ${item.observed ?? 'Header absent'}. Recommended baseline: ${item.recommended}.`,
          affectedUrl: res.finalUrl,
          httpMethod: 'GET',
          parameterName: item.header,
          confidence: 'high',
          severity: item.severityIfWeak,
          cvssVersion: cvss.version,
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
          cvssRationale: cvss.rationale,
          cweId: item.cweId,
          cveId: null,
          owaspCategory: item.owasp,
          owaspApiCategory: null,
          businessImpact: `Increases exposure to client-side attacks or transport downgrade depending on ${item.header} enforcement.`,
          exploitationPrerequisites: 'Requires secondary vulnerability (e.g., reflected input) or framing context.',
          remediationInstructions: `Set "${item.header}: ${item.recommended}" on all application responses at the web server or reverse proxy.`,
          references: ['https://owasp.org/www-project-secure-headers/'],
          evidence: [
            {
              evidenceType: 'http_header',
              summary: `Observed ${item.header} header value`,
              rawExcerpt: `${item.header}: ${item.observed ?? '(not present)'}`,
            },
          ],
        });
      }
    }

    // Active safe CORS origin reflection probe
    try {
      const testOrigin = 'https://untrusted-origin-check.example';
      const corsRes = await ctx.httpFetch(res.finalUrl, {
        method: 'GET',
        headers: { Origin: testOrigin },
      });
      const acao = corsRes.headers['access-control-allow-origin'] || null;
      const acac = corsRes.headers['access-control-allow-credentials'] || null;
      const reflectsOrigin = acao === testOrigin;
      const wildcardWithCreds = acao === '*' && acac?.toLowerCase() === 'true';
      const permissiveWildcard = acao === '*';

      if (reflectsOrigin && acac?.toLowerCase() === 'true') {
        checks.push({
          checkKey: 'headers.cors',
          title: 'CORS Origin & Credentials Policy',
          category: 'HTTP Security Headers',
          status: 'failed',
          observedValue: `ACAO=${acao}, ACAC=${acac}`,
          expectedValue: 'Strict allowlist of trusted origins',
          explanation: 'Server dynamically reflects arbitrary Origin values with Access-Control-Allow-Credentials: true.',
          remediation: 'Validate Origin against an explicit server-side allowlist and never reflect arbitrary origins with credentials.',
          cweId: 'CWE-942',
          owaspCategory: 'A01:2021',
        });

        const cvss = evaluateCvss4(
          { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'P', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
          'high',
          'Arbitrary Origin reflection combined with Access-Control-Allow-Credentials: true verified.'
        );
        findings.push({
          ruleId: 'CORS_ARBITRARY_ORIGIN_CREDENTIALED',
          title: 'Permissive CORS Origin Reflection with Credentials Enabled',
          category: 'Security Misconfiguration',
          description: 'The application echoes untrusted Origin headers into Access-Control-Allow-Origin while permitting credentials.',
          technicalExplanation: `Sending Origin: ${testOrigin} returned Access-Control-Allow-Origin: ${acao} and Access-Control-Allow-Credentials: ${acac}.`,
          affectedUrl: res.finalUrl,
          httpMethod: 'GET',
          parameterName: 'Origin',
          confidence: 'high',
          severity: cvss.severity,
          cvssVersion: cvss.version,
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
          cvssRationale: cvss.rationale,
          cweId: 'CWE-942',
          cveId: null,
          owaspCategory: 'A01:2021',
          owaspApiCategory: 'API8:2023',
          businessImpact: 'Malicious third-party websites can make authenticated cross-origin requests and read sensitive user responses.',
          exploitationPrerequisites: 'Authenticated victim visits an attacker-controlled page.',
          remediationInstructions: 'Replace dynamic Origin reflection with a strict static allowlist of trusted origins.',
          references: ['https://portswigger.net/web-security/cors'],
          evidence: [
            {
              evidenceType: 'http_header',
              summary: 'Observed CORS reflection headers',
              rawExcerpt: `Request Origin: ${testOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
            },
          ],
        });
      } else if (reflectsOrigin || wildcardWithCreds) {
        checks.push({
          checkKey: 'headers.cors',
          title: 'CORS Origin & Credentials Policy',
          category: 'HTTP Security Headers',
          status: 'failed',
          observedValue: `ACAO=${acao}, ACAC=${acac ?? 'unset'}`,
          expectedValue: 'Strict allowlist of trusted origins',
          explanation: 'Permissive CORS policy observed.',
          remediation: 'Restrict Access-Control-Allow-Origin to explicitly trusted domains.',
          cweId: 'CWE-942',
          owaspCategory: 'A05:2021',
        });
      } else if (permissiveWildcard) {
        checks.push({
          checkKey: 'headers.cors',
          title: 'CORS Origin & Credentials Policy',
          category: 'HTTP Security Headers',
          status: 'informational',
          observedValue: 'Access-Control-Allow-Origin: * (credentials not enabled)',
          expectedValue: 'Wildcard only for intentional public unauthenticated resources',
          explanation: 'Wildcard CORS is enabled without credentials; acceptable for public assets, review if endpoint serves private data.',
          remediation: null,
          cweId: 'CWE-942',
          owaspCategory: 'A05:2021',
        });
      } else {
        checks.push({
          checkKey: 'headers.cors',
          title: 'CORS Origin & Credentials Policy',
          category: 'HTTP Security Headers',
          status: 'passed',
          observedValue: acao || '(no Access-Control-Allow-Origin reflected)',
          expectedValue: 'Arbitrary Origin not reflected',
          explanation: 'Server did not reflect untrusted test Origin header.',
          remediation: null,
          cweId: 'CWE-942',
          owaspCategory: 'A05:2021',
        });
      }
    } catch (err) {
      logs.push({
        level: 'warn',
        message: `CORS probe failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      });
    }

    return { checks, findings, endpoints: [], logs };
  },
};
