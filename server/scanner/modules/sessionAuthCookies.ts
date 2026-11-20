import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import { crawlTargetSurface } from '../crawler.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

export const sessionAuthCookiesModule: ScannerModule = {
  id: 'session-auth-cookies',
  name: 'Authentication & Session Cookie Auditor',
  version: '1.4.0',
  category: 'Authentication & Session Security',
  description:
    'Inspects Set-Cookie attributes (HttpOnly, Secure, SameSite) across all crawled and login pages, evaluates HTML form CSRF protection, and identifies server-side auth controls requiring verification.',
  supportedProfiles: ['standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 25000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const crawl = await crawlTargetSurface(ctx);
    const allCookies: Array<{ url: string; raw: string }> = [];
    for (const p of crawl.pages) {
      for (const c of p.setCookies) {
        allCookies.push({ url: p.finalUrl, raw: c });
      }
    }

    // Probe discovered login pages (or fallback /login) if not already crawled
    const origin = new URL(crawl.pages[0]?.finalUrl || ctx.targetUrl).origin;
    const loginUrlsToCheck = crawl.loginPages.length > 0 ? crawl.loginPages : [`${origin}/login`];
    let loginHtml = crawl.pages[0]?.bodyText || '';
    let loginUrl = loginUrlsToCheck[0];

    for (const lUrl of loginUrlsToCheck.slice(0, 3)) {
      const existing = crawl.pages.find((p) => p.finalUrl === lUrl || p.url === lUrl);
      if (existing) {
        loginHtml = existing.bodyText;
        loginUrl = existing.finalUrl;
      } else {
        try {
          const loginProbe = await ctx.httpFetch(lUrl);
          if (loginProbe.status === 200) {
            for (const c of loginProbe.setCookies) {
              allCookies.push({ url: loginProbe.finalUrl, raw: c });
            }
            loginHtml = loginProbe.bodyText;
            loginUrl = loginProbe.finalUrl;
          }
        } catch {
          // Optional login path
        }
      }
    }

    // 1. Cookie Attribute Inspection across all crawled pages + login workflows
    if (allCookies.length === 0) {
      checks.push({
        checkKey: 'auth.cookie_attributes',
        title: 'Session Cookie Security Attributes (HttpOnly / Secure / SameSite)',
        category: 'Session Security',
        status: 'informational',
        observedValue: `No Set-Cookie headers observed across ${crawl.pages.length} crawled page(s)`,
        expectedValue: 'HttpOnly; Secure; SameSite=Lax|Strict on all session cookies',
        explanation: 'No cookies were issued during unauthenticated browsing. Provide authenticated credentials or login-form config to inspect post-login session cookies.',
        remediation: null,
        cweId: 'CWE-614',
        owaspCategory: 'A07:2021',
      });
    } else {
      const weakCookies: string[] = [];
      const seenCookieKey = new Set<string>();
      for (const item of allCookies) {
        const namePart = item.raw.split(';')[0] || 'cookie';
        const cookieName = namePart.split('=')[0]?.trim() || 'cookie';
        const lower = item.raw.toLowerCase();
        const missing: string[] = [];
        if (!lower.includes('httponly')) missing.push('HttpOnly');
        if (!lower.includes('secure')) missing.push('Secure');
        if (!lower.includes('samesite=')) missing.push('SameSite');
        const dedup = `${cookieName}|${missing.join(',')}`;
        if (missing.length > 0 && !seenCookieKey.has(dedup)) {
          seenCookieKey.add(dedup);
          weakCookies.push(`${cookieName} (missing ${missing.join(', ')})`);
        }
      }

      const firstCookieUrl = allCookies[0]?.url || loginUrl;

      checks.push({
        checkKey: 'auth.cookie_attributes',
        title: 'Session Cookie Security Attributes (HttpOnly / Secure / SameSite)',
        category: 'Session Security',
        status: weakCookies.length > 0 ? 'failed' : 'passed',
        observedValue: weakCookies.length > 0 ? weakCookies.join('; ') : `${allCookies.length} cookie(s) enforce HttpOnly, Secure, and SameSite`,
        expectedValue: 'HttpOnly; Secure; SameSite=Lax or Strict',
        explanation:
          weakCookies.length > 0
            ? `Cookies lack protective flags: ${weakCookies.join('; ')}.`
            : 'All observed cookies enforce HttpOnly, Secure, and SameSite attributes.',
        remediation:
          weakCookies.length > 0 ? 'Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all session cookies.' : null,
        cweId: 'CWE-614',
        owaspCategory: 'A07:2021',
      });

      if (weakCookies.length > 0) {
        const cvss = evaluateCvss4(
          { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'P', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
          'medium',
          'Observed Set-Cookie header missing HttpOnly/Secure/SameSite flags.'
        );
        findings.push({
          ruleId: 'COOKIE_MISSING_SECURITY_FLAGS',
          title: 'Cookie Missing HttpOnly, Secure, or SameSite Attributes',
          category: 'Authentication & Session Security',
          description: 'One or more cookies returned by the application lack recommended security flags.',
          technicalExplanation: `Observed weak cookie attributes on ${firstCookieUrl}: ${weakCookies.join('; ')}`,
          detectionTechnique: 'Multi-page Set-Cookie header attribute inspection',
          affectedUrl: firstCookieUrl,
          httpMethod: 'GET',
          parameterName: 'Set-Cookie',
          confidence: 'high',
          severity: cvss.severity,
          cvssVersion: cvss.version,
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
          cvssRationale: cvss.rationale,
          cweId: 'CWE-614',
          cveId: null,
          owaspCategory: 'A07:2021',
          owaspApiCategory: null,
          businessImpact: 'Session identifiers without HttpOnly are readable via XSS; missing Secure risks cleartext interception; missing SameSite weakens CSRF defense.',
          exploitationPrerequisites: 'XSS vector, network interception, or cross-site form submission.',
          remediationInstructions: 'Configure session middleware to emit HttpOnly; Secure; SameSite=Lax (or SameSite=None; Secure for cross-site contexts).',
          references: ['https://owasp.org/www-community/controls/SecureCookieAttribute'],
          evidence: [
            {
              evidenceType: 'http_header',
              summary: 'Observed Set-Cookie header(s)',
              rawExcerpt: allCookies.slice(0, 5).map((c) => `${c.url}: ${c.raw.replace(/=[^;]+/, '=[VALUE_REDACTED]')}`).join('\n'),
            },
          ],
        });
      }
    }

    // 2. HTML Form CSRF token indicator across crawled POST forms
    const postForms = crawl.forms.filter((f) => f.method !== 'GET');
    const missingCsrfForms = postForms.filter((f) => !f.hasCsrfField);
    if (postForms.length > 0) {
      const sampleTarget = missingCsrfForms[0]?.pageUrl || loginUrl;
      checks.push({
        checkKey: 'auth.form_csrf_indicator',
        title: 'HTML Form Anti-CSRF Token Indicator',
        category: 'Cross-Site Request Forgery (CSRF)',
        status: missingCsrfForms.length === 0 ? 'passed' : 'potential',
        observedValue:
          missingCsrfForms.length === 0
            ? `All ${postForms.length} state-changing POST form(s) contain CSRF token field patterns`
            : `${missingCsrfForms.length} of ${postForms.length} POST form(s) detected without visible hidden CSRF token input`,
        expectedValue: 'Synchronizer token or double-submit / custom-header CSRF defense',
        explanation:
          missingCsrfForms.length === 0
            ? 'POST forms include anti-CSRF field indicators (server-side validation must still be verified).'
            : 'HTML POST form lacks a conventional hidden CSRF input field; verify if custom JSON headers or SameSite=Strict protects the endpoint.',
        remediation:
          missingCsrfForms.length === 0 ? null : 'Implement per-session anti-CSRF tokens validated on all state-changing POST/PUT/DELETE routes.',
        cweId: 'CWE-352',
        owaspCategory: 'A01:2021',
      });

      if (missingCsrfForms.length > 0) {
        findings.push({
          ruleId: 'CSRF_FORM_TOKEN_MISSING_INDICATOR',
          title: 'POST Form Lacks Visible Anti-CSRF Token Field',
          category: 'Cross-Site Request Forgery (CSRF)',
          description: `${missingCsrfForms.length} HTML POST form(s) were observed without a conventional CSRF token field.`,
          technicalExplanation: `POST form(s) inspected at ${missingCsrfForms.map((f) => f.actionUrl).join(', ')} did not match common CSRF token field names.`,
          detectionTechnique: 'HTML <form method="POST"> input & anti-CSRF field inspection',
          affectedUrl: sampleTarget,
          httpMethod: 'POST',
          parameterName: 'form',
          confidence: 'medium',
          severity: 'medium',
          cvssVersion: null,
          cvssScore: null,
          cvssVector: null,
          cvssRationale: 'Passive HTML form inspection cannot confirm whether server validates Origin/Referer or custom headers.',
          cweId: 'CWE-352',
          cveId: null,
          owaspCategory: 'A01:2021',
          owaspApiCategory: null,
          businessImpact: 'If state-changing forms rely solely on ambient cookies without SameSite=Strict or CSRF tokens, attackers may forge user actions.',
          exploitationPrerequisites: 'Victim has active session and submits cross-site form.',
          remediationInstructions: 'Add cryptographic per-session CSRF tokens to all state-changing forms and verify Origin/Referer headers server-side.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
          evidence: [
            {
              evidenceType: 'http_response',
              summary: 'Observed POST form markup without CSRF field',
              rawExcerpt: (loginHtml.match(/<form[\s\S]{0,300}<\/form>/i) || [`POST -> ${sampleTarget}`])[0],
            },
          ],
        });
      }
    }

    // 3. Explicit manual-required server-side auth controls
    checks.push({
      checkKey: 'auth.password_storage_hashing',
      title: 'Password Storage Architecture (Argon2id / bcrypt / scrypt)',
      category: 'Authentication Security',
      status: 'manual_required',
      observedValue: 'External HTTP probes cannot inspect server-side password hashing',
      expectedValue: 'Argon2id, scrypt, or bcrypt (cost >= 12)',
      explanation: 'Verify password hashing algorithm via source code review or SAST module.',
      remediation: 'Use Argon2id or bcrypt/scrypt with per-user cryptographic salts.',
      cweId: 'CWE-916',
      owaspCategory: 'A07:2021',
    });

    checks.push({
      checkKey: 'auth.mfa_rate_limit_lockout',
      title: 'MFA Enforcement, Login Rate Limiting & Session Invalidation',
      category: 'Authentication Security',
      status: 'manual_required',
      observedValue: 'Brute-force / lockout attacks are intentionally prohibited in safe mode',
      expectedValue: 'MFA for privileged accounts, progressive login rate limits, server-side session revocation on logout',
      explanation: 'SentinelScan does not execute automated brute-force or credential stuffing attacks against targets. Verify rate limiting, lockout, and logout session revocation via authorized test accounts or code review.',
      remediation: null,
      cweId: 'CWE-307',
      owaspCategory: 'A07:2021',
    });

    return { checks, findings, endpoints: [], logs };
  },
};
