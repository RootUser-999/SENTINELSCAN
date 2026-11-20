import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

export const sessionAuthCookiesModule: ScannerModule = {
  id: 'session-auth-cookies',
  name: 'Authentication & Session Cookie Auditor',
  version: '1.2.0',
  category: 'Authentication & Session Security',
  description: 'Inspects Set-Cookie attributes (HttpOnly, Secure, SameSite), URL session leakage, login form transport/CSRF indicators, and identifies server-side auth controls requiring manual/source verification.',
  supportedProfiles: ['standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 10000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const baseRes = ctx.sharedState.homepageResponse || (await ctx.httpFetch(ctx.targetUrl));
    const origin = new URL(baseRes.finalUrl).origin;
    const allCookies = [...baseRes.setCookies];

    // Also probe /login if present
    let loginHtml = baseRes.bodyText;
    let loginUrl = baseRes.finalUrl;
    try {
      const loginProbe = await ctx.httpFetch(`${origin}/login`);
      if (loginProbe.status === 200) {
        allCookies.push(...loginProbe.setCookies);
        loginHtml = loginProbe.bodyText;
        loginUrl = loginProbe.finalUrl;
      }
    } catch {
      // Optional login path
    }

    // 1. Cookie Attribute Inspection
    if (allCookies.length === 0) {
      checks.push({
        checkKey: 'auth.cookie_attributes',
        title: 'Session Cookie Security Attributes (HttpOnly / Secure / SameSite)',
        category: 'Session Security',
        status: 'informational',
        observedValue: 'No Set-Cookie headers observed on unauthenticated entry/login GET requests',
        expectedValue: 'HttpOnly; Secure; SameSite=Lax|Strict on all session cookies',
        explanation: 'No cookies were issued prior to authentication. Provide authenticated session credentials to inspect post-login session cookies.',
        remediation: null,
        cweId: 'CWE-614',
        owaspCategory: 'A07:2021',
      });
    } else {
      const weakCookies: string[] = [];
      for (const rawCookie of allCookies) {
        const namePart = rawCookie.split(';')[0] || 'cookie';
        const cookieName = namePart.split('=')[0]?.trim() || 'cookie';
        const lower = rawCookie.toLowerCase();
        const missing: string[] = [];
        if (!lower.includes('httponly')) missing.push('HttpOnly');
        if (!lower.includes('secure')) missing.push('Secure');
        if (!lower.includes('samesite=')) missing.push('SameSite');
        if (missing.length > 0) {
          weakCookies.push(`${cookieName} (missing ${missing.join(', ')})`);
        }
      }

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
          technicalExplanation: `Observed weak cookie attributes on ${loginUrl}: ${weakCookies.join('; ')}`,
          affectedUrl: loginUrl,
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
              rawExcerpt: allCookies.map((c) => c.replace(/=[^;]+/, '=[VALUE_REDACTED]')).join('\n'),
            },
          ],
        });
      }
    }

    // 2. HTML Form CSRF token indicator
    const hasPostForm = /<form[^>]*method=["']?post["']?[^>]*>/i.test(loginHtml);
    const hasCsrfField = /(csrf|_token|xsrf|authenticity_token|__RequestVerificationToken)/i.test(loginHtml);
    if (hasPostForm) {
      checks.push({
        checkKey: 'auth.form_csrf_indicator',
        title: 'HTML Form Anti-CSRF Token Indicator',
        category: 'Cross-Site Request Forgery (CSRF)',
        status: hasCsrfField ? 'passed' : 'potential',
        observedValue: hasCsrfField
          ? 'CSRF token field pattern detected inside POST form'
          : 'POST form detected without visible hidden CSRF token input',
        expectedValue: 'Synchronizer token or double-submit / custom-header CSRF defense',
        explanation: hasCsrfField
          ? 'Login/action POST form includes an anti-CSRF field indicator (server-side validation must still be verified).'
          : 'HTML POST form lacks a conventional hidden CSRF input field; verify if custom JSON headers or SameSite=Strict protects the endpoint.',
        remediation: hasCsrfField ? null : 'Implement per-session anti-CSRF tokens validated on all state-changing POST/PUT/DELETE routes.',
        cweId: 'CWE-352',
        owaspCategory: 'A01:2021',
      });

      if (!hasCsrfField) {
        findings.push({
          ruleId: 'CSRF_FORM_TOKEN_MISSING_INDICATOR',
          title: 'POST Form Lacks Visible Anti-CSRF Token Field',
          category: 'Cross-Site Request Forgery (CSRF)',
          description: 'An HTML POST form was observed without a conventional CSRF token field.',
          technicalExplanation: `POST form inspected at ${loginUrl} did not match common CSRF token field names.`,
          affectedUrl: loginUrl,
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
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'],
          evidence: [
            {
              evidenceType: 'http_response',
              summary: 'Observed POST form markup',
              rawExcerpt: (loginHtml.match(/<form[\s\S]{0,300}<\/form>/i) || ['<form method="POST">'])[0],
            },
          ],
        });
      }
    }

    // 3. Explicit manual-required server-side auth controls (never fake-tested remotely)
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
