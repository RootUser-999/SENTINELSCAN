import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { getDb } from '../server/db/database.ts';
import { normalizeCheckOutcome } from '../server/db/types.ts';
import { computeReconciledScanStats, reconcileScanCountersInDb } from '../server/intelligence/reconcile.ts';
import { upsertScanFindings } from '../server/intelligence/findingManager.ts';
import { generateCsvReport } from '../server/reports/csvExporter.ts';
import { buildStructuredReportData } from '../server/reports/jsonExporter.ts';
import { generatePdfReportBuffer } from '../server/reports/pdfGenerator.ts';
import { crawlTargetSurface } from '../server/scanner/crawler.ts';
import { SsrfSafeHttpClient } from '../server/scanner/httpClient.ts';
import { apiSecurityModule } from '../server/scanner/modules/apiSecurity.ts';
import { authenticatedAccessModule } from '../server/scanner/modules/authenticatedAccess.ts';
import { dependencyScaModule } from '../server/scanner/modules/dependencySca.ts';
import { owaspActiveProbesModule } from '../server/scanner/modules/owaspActiveProbes.ts';
import { staticCodeSastModule } from '../server/scanner/modules/staticCodeSast.ts';
import { PRACTICE_OPENAPI_SAMPLE, simulatePracticeHttp } from '../server/scanner/practiceTarget.ts';
import type { ScanContext } from '../server/scanner/types.ts';
import { PRACTICE_LAB_HOSTNAME } from '../server/security/ssrfGuard.ts';

function buildContext(overrides: Partial<ScanContext> = {}): {
  ctx: ScanContext;
  recordedRequests: Array<{ url: string; method: string; body?: string }>;
} {
  const recordedRequests: Array<{ url: string; method: string; body?: string }> = [];
  const client = new SsrfSafeHttpClient({
    allowedHostname: PRACTICE_LAB_HOSTNAME,
    allowPracticeTarget: true,
    rateLimitRps: 20,
    timeoutMs: 5000,
    maxRequests: overrides.maxRequests ?? 300,
    mockTransport: (rawUrl, method, headers, body) => {
      recordedRequests.push({ url: rawUrl, method, body });
      return simulatePracticeHttp(rawUrl, method, headers, body || '');
    },
  });

  const ctx: ScanContext = {
    scanId: 'owasp-test-scan',
    organizationId: 'owasp-test-org',
    assetId: 'owasp-test-asset',
    targetUrl: `https://${PRACTICE_LAB_HOSTNAME}`,
    hostname: PRACTICE_LAB_HOSTNAME,
    isPracticeTarget: true,
    profile: 'comprehensive',
    maxDepth: 3,
    maxUrls: 60,
    maxRequests: 300,
    concurrencyLimit: 3,
    requestTimeoutMs: 5000,
    rateLimitRps: 20,
    scopeIncludePaths: ['/'],
    scopeExcludePaths: ['/excluded-area'],
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
    sastFilename: null,
    sastCodeRaw: null,
    sastFiles: [],
    isCancelled: () => false,
    httpFetch: (url, init) => client.request(url, init),
    getHttpStats: () => client.getStats(),
    log: () => {},
    sharedState: { discoveredUrls: new Set() },
    ...overrides,
  };

  return { ctx, recordedRequests };
}

test('Recursive crawler discovers multi-depth links, HTML forms, query params, and JS API routes while honoring limits', async () => {
  const { ctx } = buildContext({ maxDepth: 2, maxUrls: 25 });
  const crawl = await crawlTargetSurface(ctx);

  assert.ok(crawl.pages.length >= 6, `Expected >= 6 pages crawled, got ${crawl.pages.length}`);
  assert.ok(crawl.forms.some((f) => f.hasPasswordField));
  assert.ok(crawl.forms.some((f) => f.hasFileInput));
  assert.ok(crawl.parameterizedUrls.some((p) => p.params.includes('q')));
  assert.ok(crawl.jsResources.some((j) => j.url.endsWith('/app.js')));
  assert.ok(crawl.discoveredApiRoutes.includes('/api/v1/profile'));
  assert.ok(crawl.loginPages.some((u) => u.endsWith('/login')));
  assert.ok(crawl.uploadEndpoints.some((u) => u.actionUrl.endsWith('/upload')));

  // Scope exclusion enforcement
  const { ctx: limitedCtx } = buildContext({
    scopeExcludePaths: ['/catalog', '/upload'],
    maxUrls: 5,
  });
  const limited = await crawlTargetSurface(limitedCtx);
  assert.ok(limited.pages.length <= 5);
  assert.ok(!limited.pages.some((p) => p.path.startsWith('/catalog') || p.path.startsWith('/upload')));
});

test('OWASP active probes detect genuine true positives without false positives on hardened routes and without unsafe payloads', async () => {
  const { ctx, recordedRequests } = buildContext();
  const res = await owaspActiveProbesModule.execute(ctx);

  // Required true positives on Practice Lab vulnerable endpoints
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-89' && f.affectedUrl.includes('/catalog')), 'Should detect SQLi');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-943' && f.affectedUrl.includes('/search')), 'Should detect NoSQLi');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-79' && f.affectedUrl.includes('/catalog')), 'Should detect Reflected XSS');
  assert.ok(res.findings.some((f) => f.ruleId.startsWith('OWASP_DOM_XSS_')), 'Should detect DOM XSS in HTML/JS');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-639' && f.affectedUrl.includes('/api/v1/orders/')), 'Should detect IDOR/BOLA');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-22' && f.affectedUrl.includes('/download')), 'Should detect Path Traversal');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-601' && f.affectedUrl.includes('/redirect')), 'Should detect Open Redirect');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-918' && f.affectedUrl.includes('/preview')), 'Should detect SSRF indicator');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-611' && f.affectedUrl.includes('/api/v1/xml/parse')), 'Should detect XXE parser surface');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-434' && f.affectedUrl.includes('/upload')), 'Should detect File Upload weakness');
  assert.ok(res.findings.some((f) => f.cweId === 'CWE-284' && f.affectedUrl.includes('/admin')), 'Should detect Broken Access Control');

  // Verify every finding carries complete assessment evidence metadata
  for (const f of res.findings) {
    assert.ok(f.affectedUrl);
    assert.ok(f.detectionTechnique && f.detectionTechnique.length > 5);
    assert.ok(f.cweId);
    assert.ok(f.owaspCategory);
    assert.ok(f.remediationInstructions);
    assert.ok(f.evidence.length > 0);
  }

  // Zero false positives on hardened routes (/safe-search and /safe-redirect)
  assert.ok(!res.findings.some((f) => f.affectedUrl.includes('/safe-search')), 'Hardened /safe-search must NOT trigger XSS/SQLi');
  assert.ok(!res.findings.some((f) => f.affectedUrl.includes('/safe-redirect')), 'Hardened /safe-redirect must NOT trigger Open Redirect');

  // Safety guarantee: NEVER probe private/metadata IPs or send <!ENTITY DTD payloads
  for (const req of recordedRequests) {
    assert.ok(!req.url.includes('169.254.169.254'), 'Must never probe cloud metadata IP');
    assert.ok(!req.url.includes('127.0.0.1'), 'Must never probe loopback IP');
    assert.ok(!(req.body || '').includes('<!ENTITY'), 'Must never send external DTD entity payloads');
  }
});

test('API security and multi-role authenticated differential testing detect JWT flaws, excessive exposure, and BFLA', async () => {
  const { ctx } = buildContext({
    allowAuthenticated: true,
    authHeaders: { Authorization: 'Bearer user-demo-token' },
    authRoleProfile: 'authenticated_user',
    secondaryAuthHeaders: { Authorization: 'Bearer admin-demo-token' },
    secondaryAuthRoleProfile: 'administrator',
    secretValuesToRedact: ['user-demo-token', 'admin-demo-token'],
  });

  const apiRes = await apiSecurityModule.execute(ctx);
  assert.ok(apiRes.findings.some((f) => f.cweId === 'CWE-347'), 'Should detect alg=none JWT');
  assert.ok(apiRes.findings.some((f) => f.cweId === 'CWE-213'), 'Should detect passwordHash property exposure');
  assert.ok(apiRes.checks.some((c) => c.checkKey === 'api.graphql_hardening'));
  assert.ok(apiRes.checks.some((c) => c.checkKey === 'api.rate_limiting'));

  const authRes = await authenticatedAccessModule.execute(ctx);
  assert.ok(
    authRes.findings.some((f) => f.cweId === 'CWE-285' && f.affectedUrl.includes('/api/v1/admin/audit-export')),
    'Should detect BFLA when low-privilege user accesses /api/v1/admin/audit-export'
  );
  // Secrets must be redacted in evidence
  for (const f of authRes.findings) {
    for (const ev of f.evidence) {
      assert.ok(!ev.rawExcerpt.includes('user-demo-token'));
      assert.ok(!ev.rawExcerpt.includes('admin-demo-token'));
    }
  }
});

test('SCA & SAST truthfully report NOT_PERFORMED when inputs or external CLI binaries are missing', async () => {
  const { ctx } = buildContext();
  const emptySca = await dependencyScaModule.execute(ctx);
  assert.equal(emptySca.checks[0].status, 'not_performed');
  assert.equal(normalizeCheckOutcome(emptySca.checks[0].status), 'NOT_PERFORMED');

  const emptySast = await staticCodeSastModule.execute(ctx);
  assert.equal(emptySast.checks[0].status, 'not_performed');
  assert.equal(normalizeCheckOutcome(emptySast.checks[0].status), 'NOT_PERFORMED');

  // Multi-file SAST runs built-in rules and does not fabricate semgrep/gitleaks passes when absent
  const { ctx: multiSastCtx } = buildContext({
    sastFiles: [
      { filename: 'app.ts', content: 'const k = "sk_live_test_secret_123456";\nfetch(req.query.url);\n' },
      { filename: 'views.py', content: 'import pickle\npickle.loads(raw)\n' },
    ],
  });
  const sastRes = await staticCodeSastModule.execute(multiSastCtx);
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-798'));
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-918'));
  assert.ok(sastRes.findings.some((f) => f.cweId === 'CWE-502'));
  assert.equal(sastRes.checks.find((c) => c.checkKey === 'sast.source_review')?.status, 'failed');
});

test('Reconciler guarantees exact parity across DB counters, JSON, CSV, and PDF reports', async () => {
  const db = getDb();
  const orgId = `test-org-${crypto.randomUUID()}`;
  const userId = `test-user-${crypto.randomUUID()}`;
  const assetId = `test-asset-${crypto.randomUUID()}`;
  const cfgId = `test-cfg-${crypto.randomUUID()}`;
  const scanId = `test-scan-${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  db.prepare('INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)').run(
    orgId,
    'Parity QA Org',
    orgId,
    now
  );
  db.prepare(
    'INSERT INTO users (id, email, full_name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, `${userId}@example.test`, 'Parity Tester', 'hash', now);
  db.prepare(
    'INSERT INTO organization_memberships (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), orgId, userId, 'admin', now);
  db.prepare(
    `INSERT INTO assets (id, organization_id, name, target_url, hostname, environment, criticality, ownership_status, authorization_signed_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'practice_lab', 'high', 'verified', 'QA Signoff', ?, ?)`
  ).run(assetId, orgId, 'Parity App', `https://${PRACTICE_LAB_HOSTNAME}`, PRACTICE_LAB_HOSTNAME, now, now);
  db.prepare(
    `INSERT INTO scan_configurations (id, organization_id, name, profile, selected_modules_json, created_at)
     VALUES (?, ?, 'cfg', 'standard', '["owasp-active-probes"]', ?)`
  ).run(cfgId, orgId, now);
  db.prepare(
    `INSERT INTO scans (id, organization_id, asset_id, configuration_id, initiated_by_user_id, profile, status, progress_pct, created_at)
     VALUES (?, ?, ?, ?, ?, 'standard', 'completed', 100, ?)`
  ).run(scanId, orgId, assetId, cfgId, userId, now);
  db.prepare(
    `INSERT INTO scan_executions (id, scan_id, module_id, module_name, module_version, status, checks_executed, findings_created)
     VALUES (?, ?, 'owasp-active-probes', 'OWASP Probes', '2.0.0', 'completed', 0, 1)`
  ).run(crypto.randomUUID(), scanId);

  const statuses: Array<'passed' | 'failed' | 'potential' | 'informational' | 'manual_required' | 'not_performed' | 'not_applicable'> = [
    'passed',
    'failed',
    'potential',
    'informational',
    'manual_required',
    'not_performed',
    'not_applicable',
  ];
  const insertChk = db.prepare(
    `INSERT INTO security_checks (id, scan_id, asset_id, module_id, check_key, title, category, status, explanation, created_at)
     VALUES (?, ?, ?, 'owasp-active-probes', ?, ?, 'OWASP', ?, 'exp', ?)`
  );
  statuses.forEach((st, idx) => {
    insertChk.run(crypto.randomUUID(), scanId, assetId, `key.${idx}`, `Check ${idx}`, st, now);
  });

  const findingIds = upsertScanFindings(db, {
    organizationId: orgId,
    assetId,
    scanId,
    scannerModuleId: 'owasp-active-probes',
    userId,
    findings: [
      {
        ruleId: 'PARITY_TEST_FINDING',
        title: 'Parity Finding',
        category: 'Injection',
        description: 'Test',
        technicalExplanation: 'Test',
        detectionTechnique: 'Unit test probe',
        affectedUrl: `https://${PRACTICE_LAB_HOSTNAME}/catalog`,
        httpMethod: 'GET',
        parameterName: 'q',
        confidence: 'high',
        severity: 'high',
        cvssVersion: null,
        cvssScore: null,
        cvssVector: null,
        cvssRationale: 'Test',
        cweId: 'CWE-89',
        cveId: null,
        owaspCategory: 'A03:2021',
        owaspApiCategory: null,
        businessImpact: 'Test',
        exploitationPrerequisites: 'Test',
        remediationInstructions: 'Fix SQL query',
        references: [],
        evidence: [{ evidenceType: 'http_response', summary: 'test', rawExcerpt: 'test' }],
      },
    ],
  });

  const stats = reconcileScanCountersInDb(db, scanId);
  assert.equal(stats.totalChecks, 7);
  assert.equal(
    stats.passedChecks +
      stats.failedChecks +
      stats.potentialChecks +
      stats.informationalChecks +
      stats.manualRequiredChecks +
      stats.notPerformedChecks +
      stats.notApplicableChecks,
    7
  );

  const jsonReport = buildStructuredReportData(db, scanId, orgId)!;
  assert.equal(jsonReport.executiveSummary.totalChecks, 7);
  assert.equal(jsonReport.securityChecks.length, 7);
  assert.equal(jsonReport.executiveSummary.severityDistribution.high, 1);
  assert.equal(jsonReport.moduleExecutions[0].checks_executed, 7);

  const csvPassed = generateCsvReport(db, scanId, orgId, 'passed-checks');
  assert.ok(csvPassed.content.includes(',PASS,'));
  const csvFindings = generateCsvReport(db, scanId, orgId, 'all-findings');
  assert.ok(csvFindings.content.includes('Detection Technique'));

  const pdf = await generatePdfReportBuffer(db, scanId, orgId);
  assert.ok(pdf && pdf.buffer.byteLength > 1000);

  // Marking finding remediated updates active severity counts cleanly
  db.prepare("UPDATE vulnerabilities SET verification_status = 'remediated' WHERE id = ?").run(findingIds[0]);
  const afterRemediation = computeReconciledScanStats(db, scanId);
  assert.equal(afterRemediation.severityCountsActive.high, 0);
  assert.equal(afterRemediation.severityCountsAll.high, 1);

  // Cleanup test rows
  db.prepare('DELETE FROM organizations WHERE id = ?').run(orgId);
});
