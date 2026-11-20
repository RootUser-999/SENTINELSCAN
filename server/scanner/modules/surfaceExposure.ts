import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import { crawlTargetSurface } from '../crawler.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

const SENSITIVE_PROBE_PATHS = [
  { path: '/robots.txt', label: 'robots.txt', sensitive: false },
  { path: '/.well-known/security.txt', label: 'security.txt', sensitive: false },
  { path: '/.env', label: 'Environment file (.env)', sensitive: true, sig: /(APP_KEY|DB_HOST|DB_PASSWORD|AWS_SECRET|API_KEY|APP_ENV)=/i },
  { path: '/.git/HEAD', label: 'Git repository metadata (.git/HEAD)', sensitive: true, sig: /^ref:\s+refs\//i },
  { path: '/.git/config', label: 'Git repository configuration (.git/config)', sensitive: true, sig: /\[core\]|\[remote\s+"/i },
  { path: '/config.json', label: 'Application config.json', sensitive: true, sig: /"(?:db|database|secret|apiKey|jwtSecret|password)"/i },
  { path: '/actuator/health', label: 'Spring Boot Actuator Health Endpoint', sensitive: true, sig: /"status"\s*:\s*"(?:UP|DOWN)"/i },
  { path: '/phpinfo.php', label: 'PHPInfo diagnostic page', sensitive: true, sig: /phpinfo\(\)|PHP Version/i },
  { path: '/server-status', label: 'Apache server-status', sensitive: true, sig: /Apache Server Status/i },
  { path: '/admin/', label: 'Exposed Admin Directory', sensitive: true, sig: /Index of \//i },
  { path: '/uploads/', label: 'Exposed Uploads Directory Listing', sensitive: true, sig: /Index of \/uploads/i },
];

const VERBOSE_ERROR_PATTERNS = [
  /SQLSTATE\[[0-9A-Z]+\]/i,
  /Uncaught TypeError:|ReferenceError:|SyntaxError:/,
  /Traceback \(most recent call last\):/,
  /Fatal error:.*on line \d+/i,
  /System\.NullReferenceException/,
  /at [A-Za-z0-9_$.]+\([^)]+:\d+:\d+\)/,
];

export const surfaceExposureModule: ScannerModule = {
  id: 'surface-discovery-exposure',
  name: 'Surface Discovery & Misconfiguration Scanner',
  version: '2.0.0',
  category: 'Security Misconfiguration & Surface Discovery',
  description:
    'Performs controlled recursive crawling (links, forms, parameters, JS bundles), checks exposed sensitive files, directory listings, HTTP OPTIONS methods, mixed content, and DOM XSS/verbose error indicators.',
  supportedProfiles: ['quick', 'standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 45000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const endpoints: ModuleExecutionResult['endpoints'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const baseRes = ctx.sharedState.homepageResponse || (await ctx.httpFetch(ctx.targetUrl));
    ctx.sharedState.homepageResponse = baseRes;
    const origin = new URL(baseRes.finalUrl).origin;

    // 1. HTML DOM passive inspection (mixed content, DOM sink patterns)
    const html = baseRes.bodyText || '';
    const isHttps = origin.startsWith('https://');
    const mixedContentMatches = isHttps ? html.match(/(?:src|href|action)=["']http:\/\/[^"']+["']/gi) || [] : [];

    checks.push({
      checkKey: 'surface.mixed_content',
      title: 'HTTPS Mixed Content Check',
      category: 'Data Protection & Encryption',
      status: !isHttps ? 'not_applicable' : mixedContentMatches.length > 0 ? 'failed' : 'passed',
      observedValue:
        mixedContentMatches.length > 0
          ? `${mixedContentMatches.length} insecure http:// asset reference(s): ${mixedContentMatches[0]}`
          : 'No insecure http:// subresources found in homepage HTML',
      expectedValue: 'All subresources loaded over https://',
      explanation:
        mixedContentMatches.length > 0
          ? 'HTTPS page references active/passive resources over plain HTTP.'
          : 'No mixed-content links detected in HTML entry response.',
      remediation: mixedContentMatches.length > 0 ? 'Migrate all script, stylesheet, and media URLs to HTTPS.' : null,
      cweId: 'CWE-311',
      owaspCategory: 'A02:2021',
    });

    if (mixedContentMatches.length > 0) {
      const cvss = evaluateCvss4(
        { AV: 'N', AC: 'H', AT: 'P', PR: 'N', UI: 'P', VC: 'L', VI: 'H', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
        'medium',
        'Insecure http:// script/resource loaded inside HTTPS origin.'
      );
      findings.push({
        ruleId: 'MIXED_CONTENT_ACTIVE',
        title: 'Mixed Content: Insecure HTTP Resource Referenced on HTTPS Page',
        category: 'Data Protection & Encryption',
        description: 'An HTTPS page loads or links to resources over unencrypted HTTP.',
        technicalExplanation: `Detected HTML reference(s): ${mixedContentMatches.slice(0, 3).join(', ')}`,
        detectionTechnique: 'HTML subresource protocol inspection (http:// references on https:// origin)',
        affectedUrl: baseRes.finalUrl,
        httpMethod: 'GET',
        parameterName: null,
        confidence: 'high',
        severity: cvss.severity,
        cvssVersion: cvss.version,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        cvssRationale: cvss.rationale,
        cweId: 'CWE-311',
        cveId: null,
        owaspCategory: 'A02:2021',
        owaspApiCategory: null,
        businessImpact: 'Active mixed content (scripts) allows an on-path attacker to tamper with client-side execution inside an HTTPS session.',
        exploitationPrerequisites: 'Network MitM position on the insecure subresource request.',
        remediationInstructions: 'Update all subresource URLs to https:// and add "upgrade-insecure-requests" to Content-Security-Policy.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content'],
        evidence: [
          {
            evidenceType: 'http_response',
            summary: 'Observed insecure http:// resource tag in HTML',
            rawExcerpt: mixedContentMatches.slice(0, 5).join('\n'),
          },
        ],
      });
    }

    // 2. DOM-based XSS sink pattern indicator (passive inline script inspection)
    const domSinkMatch = html.match(/(?:location\.search|location\.hash|document\.URL)[\s\S]{0,180}(?:\.innerHTML|document\.write)/i);
    if (domSinkMatch) {
      checks.push({
        checkKey: 'surface.dom_xss_indicator',
        title: 'DOM-Based XSS Sink Indicator',
        category: 'Cross-Site Scripting (XSS)',
        status: 'potential',
        observedValue: domSinkMatch[0].slice(0, 140),
        expectedValue: 'Safe DOM textContent / sanitized rendering',
        explanation: 'Inline script reads URL location state and writes to innerHTML/document.write.',
        remediation: 'Replace innerHTML with textContent or sanitize using DOMPurify before DOM insertion.',
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021',
      });

      const cvss = evaluateCvss4(
        { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'P', VC: 'L', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
        'high',
        'Observable source-to-sink URL parameter flow into innerHTML in delivered HTML.'
      );
      findings.push({
        ruleId: 'XSS_DOM_SOURCE_SINK_INDICATOR',
        title: 'DOM-Based XSS Source-to-Sink Pattern Detected',
        category: 'Cross-Site Scripting (XSS)',
        description: 'Client-side script passes URL query/fragment data directly into an unsafe HTML sink (innerHTML).',
        technicalExplanation: `Matched inline script pattern on ${baseRes.finalUrl}: ${domSinkMatch[0].slice(0, 180)}`,
        detectionTechnique: 'Passive inline script DOM source-to-sink inspection',
        affectedUrl: baseRes.finalUrl,
        httpMethod: 'GET',
        parameterName: 'URL query/fragment',
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
        businessImpact: 'Attackers may execute arbitrary JavaScript in victims’ browsers via crafted links.',
        exploitationPrerequisites: 'Victim follows a crafted URL containing untrusted query/hash parameters.',
        remediationInstructions: 'Use textContent instead of innerHTML or apply strict HTML sanitization (e.g., DOMPurify).',
        references: ['https://owasp.org/www-community/attacks/DOM_Based_XSS'],
        evidence: [
          {
            evidenceType: 'http_response',
            summary: 'Inline script source-to-sink excerpt',
            rawExcerpt: domSinkMatch[0].slice(0, 200),
          },
        ],
      });
    } else {
      checks.push({
        checkKey: 'surface.dom_xss_indicator',
        title: 'DOM-Based XSS Sink Indicator (Inline HTML)',
        category: 'Cross-Site Scripting (XSS)',
        status: 'passed',
        observedValue: 'No obvious URL-source-to-innerHTML pattern in inline HTML',
        expectedValue: 'No unguarded DOM XSS sinks',
        explanation: 'Passive inspection of homepage inline scripts did not detect direct location-to-innerHTML flows.',
        remediation: null,
        cweId: 'CWE-79',
        owaspCategory: 'A03:2021',
      });
    }

    // 3. HTTP OPTIONS / Unnecessary Methods
    try {
      const optRes = await ctx.httpFetch(baseRes.finalUrl, { method: 'OPTIONS' });
      const allow = optRes.headers['allow'] || optRes.headers['access-control-allow-methods'] || '';
      const riskyMethods = ['TRACE', 'PUT', 'DELETE'].filter((m) => new RegExp(`\\b${m}\\b`, 'i').test(allow));

      checks.push({
        checkKey: 'surface.http_methods',
        title: 'HTTP Methods & TRACE Exposure',
        category: 'Security Misconfiguration',
        status: riskyMethods.length > 0 ? 'failed' : 'passed',
        observedValue: allow || '(Allow header omitted)',
        expectedValue: 'Only required safe methods (GET, HEAD, POST)',
        explanation:
          riskyMethods.length > 0
            ? `OPTIONS response advertises potentially unnecessary HTTP methods: ${riskyMethods.join(', ')}.`
            : 'No dangerous HTTP methods (TRACE/PUT/DELETE) advertised on entry endpoint.',
        remediation: riskyMethods.length > 0 ? 'Disable TRACE and restrict PUT/DELETE to authorized API endpoints.' : null,
        cweId: 'CWE-749',
        owaspCategory: 'A05:2021',
      });

      if (riskyMethods.includes('TRACE')) {
        findings.push({
          ruleId: 'HTTP_TRACE_ENABLED',
          title: 'HTTP TRACE Method Advertised on Web Server',
          category: 'Security Misconfiguration',
          description: 'The server advertises support for the HTTP TRACE diagnostic method.',
          technicalExplanation: `OPTIONS ${baseRes.finalUrl} returned Allow: ${allow}`,
          detectionTechnique: 'HTTP OPTIONS Allow header inspection',
          affectedUrl: baseRes.finalUrl,
          httpMethod: 'OPTIONS',
          parameterName: null,
          confidence: 'medium',
          severity: 'low',
          cvssVersion: null,
          cvssScore: null,
          cvssVector: null,
          cvssRationale: 'HTTP TRACE advertisement alone does not justify a high CVSS score without Cross-Site Tracing evidence.',
          cweId: 'CWE-693',
          cveId: null,
          owaspCategory: 'A05:2021',
          owaspApiCategory: null,
          businessImpact: 'Unnecessary diagnostic HTTP methods increase attack surface.',
          exploitationPrerequisites: 'Legacy client or proxy misconfiguration.',
          remediationInstructions: 'Disable TRACE/TRACK methods in Apache (TraceEnable Off) or reverse proxy configuration.',
          references: ['https://owasp.org/www-community/attacks/Cross_Site_Tracing'],
          evidence: [
            {
              evidenceType: 'http_header',
              summary: 'Observed Allow header from OPTIONS request',
              rawExcerpt: `Allow: ${allow}`,
            },
          ],
        });
      }
    } catch {
      logs.push({ level: 'info', message: 'OPTIONS probe did not return method listing.' });
    }

    // 4. Sensitive exposure & standard file probes
    const exposedFiles: string[] = [];
    let securityTxtFound = false;

    for (const probe of SENSITIVE_PROBE_PATHS) {
      if (ctx.isCancelled()) break;
      const target = `${origin}${probe.path}`;
      try {
        const probeRes = await ctx.httpFetch(target, { followRedirects: false });
        endpoints.push({
          url: target,
          path: probe.path,
          method: 'GET',
          source: 'probe',
          authRequired: probeRes.status === 401 || probeRes.status === 403 ? 'required' : 'none_detected',
          statusCode: probeRes.status,
          contentType: probeRes.headers['content-type'] || null,
          parameters: [],
          notes: probe.label,
        });

        if (probe.path === '/.well-known/security.txt' && probeRes.status === 200) {
          securityTxtFound = true;
        }

        if (probe.sensitive && probeRes.status === 200 && probe.sig && probe.sig.test(probeRes.bodyText)) {
          exposedFiles.push(`${probe.path} (HTTP 200)`);
          const isHighSensitivity = probe.path === '/.env' || probe.path.startsWith('/.git');
          const cvss = evaluateCvss4(
            isHighSensitivity
              ? { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'H', VI: 'N', VA: 'N', SC: 'H', SI: 'N', SA: 'N' }
              : { AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N', VC: 'L', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
            isHighSensitivity ? 'critical' : 'medium',
            `Verified public HTTP 200 exposure matching ${probe.label} signature.`
          );

          findings.push({
            ruleId: `EXPOSED_${probe.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `Publicly Exposed ${probe.label}`,
            category: 'Security Misconfiguration',
            description: `Sensitive resource ${probe.path} is publicly accessible without authentication.`,
            technicalExplanation: `GET ${target} returned HTTP 200 and matched expected signature for ${probe.label}.`,
            detectionTechnique: 'Signature-verified sensitive path probe (no blind HTTP 200 false positives)',
            affectedUrl: target,
            httpMethod: 'GET',
            parameterName: null,
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: probe.path.endsWith('/') ? 'CWE-548' : 'CWE-538',
            cveId: null,
            owaspCategory: 'A05:2021',
            owaspApiCategory: null,
            businessImpact: isHighSensitivity
              ? 'Exposure of environment files or git metadata frequently leaks database credentials, API tokens, and proprietary source code.'
              : 'Directory listing or diagnostic exposure reveals internal file paths and backup artifacts.',
            exploitationPrerequisites: 'Unauthenticated HTTP GET access.',
            remediationInstructions: `Immediately remove ${probe.path} from web root, block dotfile/directory access at the reverse proxy, and rotate any exposed secrets.`,
            references: ['https://cwe.mitre.org/data/definitions/538.html'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: `Matched ${probe.label} signature in HTTP 200 body`,
                rawExcerpt: probeRes.bodyText.slice(0, 240).replace(/=.+/g, '=[REDACTED_VALUE]'),
              },
            ],
          });
        }
      } catch {
        // Ignore transient probe error for single path
      }
    }

    checks.push({
      checkKey: 'surface.sensitive_files',
      title: 'Publicly Exposed Sensitive Files & Directory Listing',
      category: 'Security Misconfiguration',
      status: exposedFiles.length > 0 ? 'failed' : 'passed',
      observedValue: exposedFiles.length > 0 ? exposedFiles.join(', ') : 'No sensitive files (.env, .git, config, directory indexes) exposed',
      expectedValue: '403/404 on internal config, backup, and VCS paths',
      explanation:
        exposedFiles.length > 0
          ? `Confirmed public exposure of: ${exposedFiles.join(', ')}.`
          : 'Common sensitive files and directory listings returned non-200 or non-matching responses.',
      remediation: exposedFiles.length > 0 ? 'Block access to dotfiles, backups, and disable autoindex.' : null,
      cweId: 'CWE-538',
      owaspCategory: 'A05:2021',
    });

    checks.push({
      checkKey: 'surface.security_txt',
      title: 'Vulnerability Disclosure Contact (security.txt)',
      category: 'Security Governance',
      status: securityTxtFound ? 'passed' : 'informational',
      observedValue: securityTxtFound ? 'Present at /.well-known/security.txt' : 'Not found at /.well-known/security.txt',
      expectedValue: 'RFC 9116 security.txt',
      explanation: securityTxtFound
        ? 'Organization publishes a security vulnerability reporting policy at /.well-known/security.txt.'
        : 'Optional RFC 9116 security.txt was not found.',
      remediation: securityTxtFound ? null : 'Publish /.well-known/security.txt per RFC 9116.',
      cweId: null,
      owaspCategory: null,
    });

    // 5. Controlled recursive in-scope crawl across links, forms, params, JS bundles
    const crawl = await crawlTargetSurface(ctx);
    for (const ep of crawl.endpoints) {
      endpoints.push(ep);
    }

    logs.push({
      level: 'info',
      message: `Discovered ${crawl.stats.pagesCrawled} page(s), ${crawl.stats.formsFound} form(s), ${crawl.stats.paramsFound} parameter(s), ${crawl.stats.jsFilesFetched} JS bundle(s), ${crawl.stats.apiRoutesFromJs} JS API route(s).`,
    });

    let verboseErrorsFound = 0;
    for (const page of crawl.pages) {
      for (const pat of VERBOSE_ERROR_PATTERNS) {
        const errMatch = page.bodyText.match(pat);
        if (errMatch) {
          verboseErrorsFound += 1;
          findings.push({
            ruleId: `INFO_VERBOSE_ERROR_STACK_${page.path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `Verbose Application Error / Stack Trace Disclosure (${page.path})`,
            category: 'Security Misconfiguration',
            description: 'Application response contains database or runtime error diagnostics.',
            technicalExplanation: `Crawling ${page.finalUrl} revealed error signature "${errMatch[0]}".`,
            detectionTechnique: 'Recursive crawl response error signature matching',
            affectedUrl: page.finalUrl,
            httpMethod: 'GET',
            parameterName: null,
            confidence: 'high',
            severity: 'medium',
            cvssVersion: null,
            cvssScore: null,
            cvssVector: null,
            cvssRationale: 'Error disclosure reveals internal architecture; CVSS depends on whether sensitive secrets or SQL queries appear.',
            cweId: 'CWE-209',
            cveId: null,
            owaspCategory: 'A05:2021',
            owaspApiCategory: null,
            businessImpact: 'Exposes internal SQL dialects, file paths, and framework stack traces.',
            exploitationPrerequisites: 'Standard GET navigation.',
            remediationInstructions: 'Disable debug mode in production and return generic error pages while logging details server-side.',
            references: ['https://cwe.mitre.org/data/definitions/209.html'],
            evidence: [
              {
                evidenceType: 'http_response',
                summary: 'Matched verbose error pattern',
                rawExcerpt: errMatch[0],
              },
            ],
          });
          break;
        }
      }
    }

    checks.push({
      checkKey: 'surface.crawl_coverage',
      title: 'Recursive Attack Surface Crawl Coverage',
      category: 'Surface Discovery',
      status: 'informational',
      observedValue: `${crawl.stats.pagesCrawled} page(s) (depth ${crawl.stats.maxDepthReached}), ${crawl.stats.formsFound} form(s), ${crawl.stats.paramsFound} param(s), ${crawl.stats.jsFilesFetched} JS file(s)`,
      expectedValue: 'In-scope pages, forms, parameters, and scripts inventoried within safety budget',
      explanation: `Crawler discovered ${crawl.endpoints.length} endpoint record(s) and ${crawl.loginPages.length} authentication workflow(s) (${crawl.stats.stoppedReason}).`,
      remediation: null,
      cweId: null,
      owaspCategory: null,
    });

    checks.push({
      checkKey: 'surface.verbose_errors',
      title: 'Verbose Error & Debug Trace Disclosure',
      category: 'Security Misconfiguration',
      status: verboseErrorsFound > 0 ? 'failed' : 'passed',
      observedValue: `${verboseErrorsFound} verbose error pattern(s) across ${crawl.pages.length} crawled page(s)`,
      expectedValue: 'Generic error messages without stack traces or SQL errors',
      explanation:
        verboseErrorsFound > 0
          ? `Detected ${verboseErrorsFound} response(s) containing debug/SQL error text.`
          : 'No verbose stack traces or SQL error disclosures observed across crawled pages.',
      remediation: verboseErrorsFound > 0 ? 'Set APP_DEBUG=false / NODE_ENV=production and use sanitized error handlers.' : null,
      cweId: 'CWE-209',
      owaspCategory: 'A05:2021',
    });

    return { checks, findings, endpoints, logs };
  },
};
