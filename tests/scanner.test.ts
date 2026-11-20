import test from 'node:test';
import assert from 'node:assert/strict';
import { SsrfSafeHttpClient } from '../server/scanner/httpClient.ts';
import {
  PRACTICE_OPENAPI_SAMPLE,
  PRACTICE_SAST_SAMPLE,
} from '../server/scanner/practiceTarget.ts';
import { securityHeadersModule } from '../server/scanner/modules/securityHeaders.ts';
import { surfaceExposureModule } from '../server/scanner/modules/surfaceExposure.ts';
import { sessionAuthCookiesModule } from '../server/scanner/modules/sessionAuthCookies.ts';
import { apiSecurityModule } from '../server/scanner/modules/apiSecurity.ts';
import { staticCodeSastModule } from '../server/scanner/modules/staticCodeSast.ts';
import { parseDependencyManifest } from '../server/scanner/modules/dependencySca.ts';
import { PRACTICE_LAB_HOSTNAME } from '../server/security/ssrfGuard.ts';
import type { ScanContext } from '../server/scanner/types.ts';

function buildPracticeContext(): ScanContext {
  const client = new SsrfSafeHttpClient({
    allowedHostname: PRACTICE_LAB_HOSTNAME,
    allowPracticeTarget: true,
    rateLimitRps: 20,
    timeoutMs: 5000,
    maxRequests: 250,
  });

  return {
    scanId: 'test-scan-1',
    organizationId: 'test-org-1',
    assetId: 'test-asset-1',
    targetUrl: `https://${PRACTICE_LAB_HOSTNAME}`,
    hostname: PRACTICE_LAB_HOSTNAME,
    isPracticeTarget: true,
    profile: 'comprehensive',
    maxDepth: 3,
    maxUrls: 60,
    maxRequests: 250,
    concurrencyLimit: 3,
    requestTimeoutMs: 5000,
    rateLimitRps: 20,
    scopeIncludePaths: ['/'],
    scopeExcludePaths: [],
    allowAuthenticated: false,
    authHeaders: {},
    authRoleProfile: null,
    secondaryAuthHeaders: {},
    secondaryAuthRoleProfile: null,
    customHeaders: {},
    secretValuesToRedact: [],
    openapiSpecRaw: PRACTICE_OPENAPI_SAMPLE,
    scaManifestName: null,
    scaManifestRaw: null,
    sastFilename: 'checkout.ts',
    sastCodeRaw: PRACTICE_SAST_SAMPLE,
    sastFiles: [],
    isCancelled: () => false,
    httpFetch: (url, init) => client.request(url, init),
    getHttpStats: () => client.getStats(),
    log: () => {},
    sharedState: { discoveredUrls: new Set() },
  };
}

test('Dependency manifest parser extracts pinned packages across ecosystems', () => {
  const npmPkgs = parseDependencyManifest('package.json', '{"dependencies":{"lodash":"^4.17.20","express":"4.18.2"}}');
  assert.equal(npmPkgs.length, 2);
  assert.equal(npmPkgs[0].name, 'lodash');
  assert.equal(npmPkgs[0].version, '4.17.20');

  const pyPkgs = parseDependencyManifest('requirements.txt', 'django==4.1.0\nrequests==2.28.1\n');
  assert.equal(pyPkgs.length, 2);
  assert.equal(pyPkgs[0].ecosystem, 'PyPI');

  const goPkgs = parseDependencyManifest('go.mod', 'require github.com/gin-gonic/gin v1.9.1\n');
  assert.equal(goPkgs.length, 1);
  assert.equal(goPkgs[0].ecosystem, 'Go');
});

test('Scanner modules detect real intentional weaknesses on isolated Practice Lab target', async () => {
  const ctx = buildPracticeContext();

  const hdrRes = await securityHeadersModule.execute(ctx);
  assert.ok(hdrRes.findings.some((f) => f.ruleId === 'CORS_ARBITRARY_ORIGIN_CREDENTIALED'));
  assert.ok(hdrRes.checks.some((c) => c.checkKey === 'headers.content-security-policy' && c.status === 'failed'));

  const surfRes = await surfaceExposureModule.execute(ctx);
  assert.ok(surfRes.findings.some((f) => f.ruleId === 'EXPOSED___ENV'));
  assert.ok(surfRes.findings.some((f) => f.ruleId === 'MIXED_CONTENT_ACTIVE'));
  assert.ok(surfRes.findings.some((f) => f.ruleId === 'XSS_DOM_SOURCE_SINK_INDICATOR'));

  const sessRes = await sessionAuthCookiesModule.execute(ctx);
  assert.ok(sessRes.findings.some((f) => f.ruleId === 'COOKIE_MISSING_SECURITY_FLAGS'));
  assert.ok(sessRes.checks.some((c) => c.checkKey === 'auth.password_storage_hashing' && c.status === 'manual_required'));

  const apiRes = await apiSecurityModule.execute(ctx);
  assert.ok(apiRes.endpoints.length >= 3);
  assert.ok(apiRes.findings.some((f) => f.ruleId === 'API_GRAPHQL_INTROSPECTION'));
  assert.ok(apiRes.findings.some((f) => f.ruleId === 'API_BOLA_INDICATOR'));

  const sastRes = await staticCodeSastModule.execute(ctx);
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-798'));
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-89'));
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-328'));
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-79'));
});
