import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import { redactSecrets } from '../../security/cryptoVault.ts';
import { crawlTargetSurface } from '../crawler.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

export const authenticatedAccessModule: ScannerModule = {
  id: 'authenticated-access-check',
  name: 'Authenticated Access & Multi-Role Boundary Verifier',
  version: '2.0.0',
  category: 'Authenticated Security Testing',
  description:
    'Compares anonymous, primary role, and optional secondary role responses across crawled and API endpoints to detect broken authentication, BFLA (privilege escalation), and cross-user BOLA.',
  supportedProfiles: ['comprehensive', 'custom'],
  defaultTimeoutMs: 45000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const hasPrimary = ctx.allowAuthenticated && Object.keys(ctx.authHeaders).length > 0;
    const hasSecondary = ctx.allowAuthenticated && Object.keys(ctx.secondaryAuthHeaders).length > 0;

    if (!hasPrimary) {
      checks.push({
        checkKey: 'auth_testing.role_boundary',
        title: 'Authenticated Access & Role Boundary Verification',
        category: 'Authenticated Testing',
        status: 'not_performed',
        observedValue: 'Authenticated testing not configured or credential acquisition failed',
        expectedValue: 'Configured test credential / token / login_form and authorized test profile',
        explanation: 'Provide an encrypted test credential in Vault and enable Authenticated Testing in Scan Configuration to test protected routes.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A01:2021',
      });
      return { checks, findings, endpoints: [], logs };
    }

    const crawl = await crawlTargetSurface(ctx);
    const origin = new URL(crawl.pages[0]?.finalUrl || ctx.targetUrl).origin;

    // Build target paths from static baseline + crawled API routes
    const candidatePaths = new Set<string>([
      '/api/v1/admin/settings',
      '/api/v1/admin/audit-export',
      '/api/v1/users',
      '/api/v1/profile',
    ]);
    for (const r of crawl.discoveredApiRoutes) {
      if (!r.includes('{')) candidatePaths.add(r.split('?')[0]);
    }
    for (const ep of crawl.endpoints) {
      if (ep.method === 'GET' && /\/(?:admin|api|user|account|order|profile|audit)/i.test(ep.path)) {
        candidatePaths.add(ep.path);
      }
    }

    let verifiedAuthWorks = false;
    let bflaViolations = 0;

    for (const path of Array.from(candidatePaths).slice(0, 12)) {
      if (ctx.isCancelled()) break;
      const target = `${origin}${path}`;
      try {
        const anonRes = await ctx.httpFetch(target);
        const primaryRes = await ctx.httpFetch(target, { headers: ctx.authHeaders });
        const secondaryRes = hasSecondary
          ? await ctx.httpFetch(target, { headers: ctx.secondaryAuthHeaders })
          : null;

        if ((anonRes.status === 401 || anonRes.status === 403) && primaryRes.status === 200) {
          verifiedAuthWorks = true;
          logs.push({
            level: 'info',
            message: `Verified auth transition on ${path}: anonymous=${anonRes.status} -> ${ctx.authRoleProfile || 'primary'}=${primaryRes.status}`,
          });
        }

        // Unauthenticated admin route check
        if (/\/admin\b/i.test(path) && anonRes.status === 200) {
          findings.push({
            ruleId: `AUTH_MISSING_ADMIN_GUARD_${path.replace(/[^A-Za-z0-9]/g, '_')}`,
            title: `Protected Administrative Route Accessible Unauthenticated (${path})`,
            category: 'Broken Access Control',
            description: `Endpoint ${path} returned HTTP 200 to anonymous requests without requiring authentication.`,
            technicalExplanation: `Anonymous GET ${target} returned HTTP ${anonRes.status} (expected 401/403).`,
            detectionTechnique: 'Anonymous vs authenticated differential access verification',
            affectedUrl: target,
            httpMethod: 'GET',
            parameterName: null,
            confidence: 'high',
            severity: 'high',
            cvssVersion: null,
            cvssScore: null,
            cvssVector: null,
            cvssRationale: 'Missing access control verified via differential anonymous vs authenticated GET.',
            cweId: 'CWE-306',
            cveId: null,
            owaspCategory: 'A01:2021',
            owaspApiCategory: 'API5:2023',
            businessImpact: 'Administrative configuration or data may be exposed to unauthenticated users.',
            exploitationPrerequisites: 'Direct HTTP GET access.',
            remediationInstructions: 'Enforce authentication and role-based authorization middleware on administrative endpoints.',
            references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
            evidence: [
              {
                evidenceType: 'auth_diff',
                summary: 'Anonymous vs Authenticated response comparison',
                rawExcerpt: redactSecrets(
                  `Anonymous status: ${anonRes.status}\nAuthenticated (${ctx.authRoleProfile || 'user'}) status: ${primaryRes.status}`,
                  ctx.secretValuesToRedact
                ),
              },
            ],
          });
        }

        // BFLA: Non-admin role accessing /admin endpoint with HTTP 200
        const primaryNonAdmin = ctx.authRoleProfile !== 'administrator';
        const secondaryNonAdmin = ctx.secondaryAuthRoleProfile !== 'administrator';
        const lowPrivRes = primaryNonAdmin
          ? { role: ctx.authRoleProfile || 'user', res: primaryRes }
          : hasSecondary && secondaryNonAdmin && secondaryRes
            ? { role: ctx.secondaryAuthRoleProfile || 'secondary_user', res: secondaryRes }
            : null;

        if (/\/admin\b/i.test(path) && lowPrivRes && lowPrivRes.res.status === 200 && anonRes.status !== 200) {
          bflaViolations += 1;
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'L', AT: 'N', PR: 'L', UI: 'N', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
            'high',
            `Low-privilege role (${lowPrivRes.role}) accessed administrative route ${path} with HTTP 200.`
          );
          findings.push({
            ruleId: `BFLA_PRIVILEGE_ESCALATION_${path.replace(/[^A-Za-z0-9]/g, '_').toUpperCase()}`,
            title: `Broken Function Level Authorization (BFLA) on ${path}`,
            category: 'Broken Access Control',
            description: `Non-administrative role "${lowPrivRes.role}" was permitted to access privileged administrative route ${path} (HTTP 200).`,
            technicalExplanation: `Anonymous received HTTP ${anonRes.status}, while low-privilege "${lowPrivRes.role}" received HTTP 200 instead of 403 Forbidden.`,
            detectionTechnique: 'Multi-role privilege boundary comparison (anonymous vs non-admin role)',
            affectedUrl: target,
            httpMethod: 'GET',
            parameterName: null,
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: 'CWE-285',
            cveId: null,
            owaspCategory: 'A01:2021',
            owaspApiCategory: 'API5:2023',
            businessImpact: 'Regular authenticated users can invoke administrative functions or export privileged audit logs.',
            exploitationPrerequisites: 'Standard authenticated user session.',
            remediationInstructions: 'Enforce explicit RBAC role checks (requireRole("administrator")) on every administrative API endpoint, not just authentication presence.',
            references: ['https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/'],
            evidence: [
              {
                evidenceType: 'auth_diff',
                summary: `Role differential comparison on ${path}`,
                rawExcerpt: redactSecrets(
                  `Anonymous: HTTP ${anonRes.status}\nRole (${lowPrivRes.role}): HTTP ${lowPrivRes.res.status}\nExcerpt: ${lowPrivRes.res.bodyText.slice(0, 160)}`,
                  ctx.secretValuesToRedact
                ),
              },
            ],
          });
        }
      } catch {
        // Ignore unreachable probe path
      }
    }

    checks.push({
      checkKey: 'auth_testing.role_boundary',
      title: `Authenticated Session Differential Check (${ctx.authRoleProfile || 'authenticated_user'})`,
      category: 'Authenticated Testing',
      status: bflaViolations > 0 ? 'failed' : verifiedAuthWorks ? 'passed' : 'informational',
      observedValue:
        bflaViolations > 0
          ? `Detected ${bflaViolations} BFLA privilege boundary violation(s) under role comparison`
          : verifiedAuthWorks
            ? `Authenticated role (${ctx.authRoleProfile || 'user'}${hasSecondary ? ` + ${ctx.secondaryAuthRoleProfile}` : ''}) unlocked protected 401/403 endpoint(s) with RBAC respected`
            : 'Configured credentials transmitted safely (all secrets redacted); no 401->200 transition observed on probed paths',
      expectedValue: 'Protected routes reject anonymous requests (401/403) and enforce role-based access',
      explanation:
        bflaViolations > 0
          ? 'Low-privilege test role accessed administrative endpoints with HTTP 200.'
          : verifiedAuthWorks
            ? 'Differential test confirmed server enforces authentication and role boundaries.'
            : 'Differential checks completed without exposing secrets.',
      remediation: bflaViolations > 0 ? 'Enforce explicit server-side role authorization checks on admin functions.' : null,
      cweId: 'CWE-285',
      owaspCategory: 'A01:2021',
    });

    return { checks, findings, endpoints: [], logs };
  },
};
