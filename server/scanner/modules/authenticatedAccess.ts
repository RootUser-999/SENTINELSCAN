import { redactSecrets } from '../../security/cryptoVault.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

export const authenticatedAccessModule: ScannerModule = {
  id: 'authenticated-access-check',
  name: 'Authenticated Access & Role Boundary Verifier',
  version: '1.0.0',
  category: 'Authenticated Security Testing',
  description: 'Verifies configured authentication credentials against protected endpoints and compares anonymous vs authenticated responses safely.',
  supportedProfiles: ['comprehensive', 'custom'],
  defaultTimeoutMs: 12000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    if (!ctx.allowAuthenticated || Object.keys(ctx.authHeaders).length === 0) {
      checks.push({
        checkKey: 'auth_testing.role_boundary',
        title: 'Authenticated Access & Role Boundary Verification',
        category: 'Authenticated Testing',
        status: 'not_performed',
        observedValue: 'Authenticated testing not configured for this scan',
        expectedValue: 'Configured test credential / token and authorized test profile',
        explanation: 'Provide an encrypted test credential in Vault and enable Authenticated Testing in Scan Configuration to test protected routes.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A01:2021',
      });
      return { checks, findings, endpoints: [], logs };
    }

    const origin = new URL(ctx.targetUrl).origin;
    const probePaths = ['/api/v1/admin/settings', '/api/v1/users', '/'];
    let verifiedAuthWorks = false;

    for (const path of probePaths) {
      if (ctx.isCancelled()) break;
      const target = `${origin}${path}`;
      try {
        const anonRes = await ctx.httpFetch(target);
        const authRes = await ctx.httpFetch(target, { headers: ctx.authHeaders });

        if ((anonRes.status === 401 || anonRes.status === 403) && authRes.status === 200) {
          verifiedAuthWorks = true;
          logs.push({
            level: 'info',
            message: `Verified authentication state transition on ${path}: anonymous=${anonRes.status} -> ${ctx.authRoleProfile || 'authenticated'}=${authRes.status}`,
          });
        }

        if (path.includes('admin') && anonRes.status === 200) {
          findings.push({
            ruleId: `AUTH_MISSING_ADMIN_GUARD_${path.replace(/[^A-Za-z0-9]/g, '_')}`,
            title: `Protected Administrative Route Accessible Unauthenticated (${path})`,
            category: 'Broken Access Control',
            description: `Endpoint ${path} returned HTTP 200 to anonymous requests without requiring authentication.`,
            technicalExplanation: `Anonymous GET ${target} returned HTTP ${anonRes.status} (expected 401/403).`,
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
                  `Anonymous status: ${anonRes.status}\nAuthenticated (${ctx.authRoleProfile || 'user'}) status: ${authRes.status}`,
                  ctx.secretValuesToRedact
                ),
              },
            ],
          });
        }
      } catch {
        // Ignore non-existent test path
      }
    }

    checks.push({
      checkKey: 'auth_testing.role_boundary',
      title: `Authenticated Session Differential Check (${ctx.authRoleProfile || 'authenticated_user'})`,
      category: 'Authenticated Testing',
      status: verifiedAuthWorks ? 'passed' : 'informational',
      observedValue: verifiedAuthWorks
        ? `Authenticated role (${ctx.authRoleProfile || 'user'}) unlocked protected 401/403 endpoint(s)`
        : 'Configured credentials transmitted safely (all secrets redacted); no 401->200 protected endpoint transition observed on probed paths',
      expectedValue: 'Protected routes reject anonymous requests (401/403) and enforce role-based access',
      explanation: verifiedAuthWorks
        ? 'Differential test confirmed server enforces authentication on protected routes.'
        : 'Differential checks completed without exposing secrets.',
      remediation: null,
      cweId: 'CWE-287',
      owaspCategory: 'A01:2021',
    });

    return { checks, findings, endpoints: [], logs };
  },
};
