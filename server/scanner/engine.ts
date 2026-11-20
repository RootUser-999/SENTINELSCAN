import crypto from 'node:crypto';
import { getDb } from '../db/database.ts';
import type { ScanProfile } from '../db/types.ts';
import { generateComplianceMappingsForScan } from '../compliance/mapper.ts';
import { upsertScanFindings } from '../intelligence/findingManager.ts';
import { calculatePostureScore } from '../intelligence/posture.ts';
import { createNotification, writeAuditLog } from '../security/audit.ts';
import { decryptSecret } from '../security/cryptoVault.ts';
import { SsrfSafeHttpClient } from './httpClient.ts';
import { apiSecurityModule } from './modules/apiSecurity.ts';
import { authenticatedAccessModule } from './modules/authenticatedAccess.ts';
import { dependencyScaModule } from './modules/dependencySca.ts';
import { dnsInfrastructureModule } from './modules/dnsInfrastructure.ts';
import { httpTlsTransportModule } from './modules/httpTlsTransport.ts';
import { securityHeadersModule } from './modules/securityHeaders.ts';
import { sessionAuthCookiesModule } from './modules/sessionAuthCookies.ts';
import { staticCodeSastModule } from './modules/staticCodeSast.ts';
import { surfaceExposureModule } from './modules/surfaceExposure.ts';
import type { ScanContext, ScannerModule } from './types.ts';

export const SCANNER_MODULES: ScannerModule[] = [
  httpTlsTransportModule,
  securityHeadersModule,
  dnsInfrastructureModule,
  surfaceExposureModule,
  sessionAuthCookiesModule,
  apiSecurityModule,
  dependencyScaModule,
  staticCodeSastModule,
  authenticatedAccessModule,
];

const cancelledScans = new Set<string>();
const activeQueue: string[] = [];
let runningWorkers = 0;
const MAX_CONCURRENT_SCANS = 2;

export function syncScannerModuleRegistry(): void {
  const db = getDb();
  const upsert = db.prepare(
    `INSERT INTO scan_modules (id, name, version, category, description, default_timeout_ms)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET name = excluded.name, version = excluded.version, category = excluded.category, description = excluded.description, default_timeout_ms = excluded.default_timeout_ms`
  );
  for (const mod of SCANNER_MODULES) {
    upsert.run(mod.id, mod.name, mod.version, mod.category, mod.description, mod.defaultTimeoutMs);
  }
}

export function selectModulesForProfile(profile: ScanProfile, customModuleIds?: string[]): ScannerModule[] {
  if (profile === 'custom' && customModuleIds && customModuleIds.length > 0) {
    const allowed = new Set(customModuleIds);
    return SCANNER_MODULES.filter((m) => allowed.has(m.id));
  }
  return SCANNER_MODULES.filter((m) => m.supportedProfiles.includes(profile));
}

export function enqueueScan(scanId: string): void {
  activeQueue.push(scanId);
  processQueue();
}

export function requestScanCancellation(scanId: string): void {
  cancelledScans.add(scanId);
  const db = getDb();
  const row = db.prepare('SELECT status FROM scans WHERE id = ?').get(scanId) as { status: string } | undefined;
  if (row && row.status === 'queued') {
    db.prepare('UPDATE scans SET status = ?, completed_at = ?, current_module = NULL WHERE id = ?').run(
      'cancelled',
      new Date().toISOString(),
      scanId
    );
  }
}

function processQueue(): void {
  while (runningWorkers < MAX_CONCURRENT_SCANS && activeQueue.length > 0) {
    const nextId = activeQueue.shift();
    if (!nextId) continue;
    if (cancelledScans.has(nextId)) continue;
    runningWorkers += 1;
    executeScanAsync(nextId)
      .catch((err) => {
        console.error(`Unhandled scan worker error for ${nextId}:`, err);
      })
      .finally(() => {
        runningWorkers -= 1;
        cancelledScans.delete(nextId);
        processQueue();
      });
  }
}

function appendScanLog(
  scanId: string,
  level: 'info' | 'warn' | 'error',
  moduleId: string | null,
  message: string
): void {
  const db = getDb();
  db.prepare(
    `INSERT INTO scan_progress (id, scan_id, timestamp, level, module_id, message)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(crypto.randomUUID(), scanId, new Date().toISOString(), level, moduleId, message);
}

async function executeScanAsync(scanId: string): Promise<void> {
  const db = getDb();
  const scanRow = db
    .prepare(
      `SELECT s.*, a.target_url, a.hostname, a.is_practice_target, a.ownership_status,
              a.scope_include_paths, a.scope_exclude_paths,
              c.selected_modules_json, c.max_depth, c.request_timeout_ms, c.rate_limit_rps,
              c.allow_authenticated, c.credential_id, c.openapi_spec_raw,
              c.sca_manifest_name, c.sca_manifest_raw, c.sast_filename, c.sast_code_raw
       FROM scans s
       JOIN assets a ON a.id = s.asset_id
       JOIN scan_configurations c ON c.id = s.configuration_id
       WHERE s.id = ?`
    )
    .get(scanId) as Record<string, unknown> | undefined;

  if (!scanRow) return;
  if (scanRow.status === 'cancelled' || cancelledScans.has(scanId)) return;

  const startedAtMs = Date.now();
  const startedAtIso = new Date(startedAtMs).toISOString();

  db.prepare('UPDATE scans SET status = ?, started_at = ?, progress_pct = 2 WHERE id = ?').run(
    'running',
    startedAtIso,
    scanId
  );

  // Enforce ownership verification right before running active scan
  if (scanRow.ownership_status !== 'verified') {
    db.prepare(
      'UPDATE scans SET status = ?, completed_at = ?, error_message = ? WHERE id = ?'
    ).run('failed', new Date().toISOString(), 'Asset ownership is not verified.', scanId);
    appendScanLog(scanId, 'error', null, 'Aborted scan: target asset ownership verification is required.');
    return;
  }

  const selectedIds = JSON.parse(String(scanRow.selected_modules_json || '[]')) as string[];
  const modules = selectModulesForProfile(scanRow.profile as ScanProfile, selectedIds);

  // Pre-create module execution rows
  const insertExec = db.prepare(
    `INSERT INTO scan_executions (id, scan_id, module_id, module_name, module_version, status)
     VALUES (?, ?, ?, ?, ?, 'pending')`
  );
  const execIds = new Map<string, string>();
  for (const mod of modules) {
    const eid = crypto.randomUUID();
    execIds.set(mod.id, eid);
    insertExec.run(eid, scanId, mod.id, mod.name, mod.version);
  }

  // Decrypt optional test credential if authorized
  const authHeaders: Record<string, string> = {};
  const secretValuesToRedact: string[] = [];
  let authRoleProfile: string | null = null;

  if (scanRow.allow_authenticated && scanRow.credential_id) {
    const credRow = db
      .prepare('SELECT * FROM scan_credentials WHERE id = ? AND organization_id = ?')
      .get(String(scanRow.credential_id), String(scanRow.organization_id)) as Record<string, unknown> | undefined;

    if (credRow) {
      if (new Date(String(credRow.expires_at)).getTime() < Date.now()) {
        appendScanLog(scanId, 'warn', null, 'Configured scan credential has expired; authenticated checks skipped.');
      } else {
        const plain = decryptSecret({
          ciphertextHex: String(credRow.encrypted_secret_blob),
          ivHex: String(credRow.iv_hex),
          authTagHex: String(credRow.auth_tag_hex),
        });
        if (plain) {
          secretValuesToRedact.push(plain);
          authRoleProfile = String(credRow.role_profile);
          if (credRow.auth_type === 'bearer_token') {
            authHeaders['Authorization'] = `Bearer ${plain}`;
          } else if (credRow.auth_type === 'cookie') {
            authHeaders['Cookie'] = plain;
          } else if (credRow.auth_type === 'basic_header') {
            authHeaders['Authorization'] = plain;
          }
        } else {
          appendScanLog(scanId, 'warn', null, 'Configured credential could not be decrypted; re-save credential.');
        }
      }
    }
  }

  const httpClient = new SsrfSafeHttpClient({
    allowedHostname: String(scanRow.hostname),
    allowPracticeTarget: Boolean(scanRow.is_practice_target),
    rateLimitRps: Number(scanRow.rate_limit_rps || 5),
    timeoutMs: Number(scanRow.request_timeout_ms || 8000),
  });

  const sharedState: ScanContext['sharedState'] = {
    discoveredUrls: new Set<string>(),
  };

  const ctx: ScanContext = {
    scanId,
    organizationId: String(scanRow.organization_id),
    assetId: String(scanRow.asset_id),
    targetUrl: String(scanRow.target_url),
    hostname: String(scanRow.hostname),
    isPracticeTarget: Boolean(scanRow.is_practice_target),
    profile: scanRow.profile as ScanProfile,
    maxDepth: Number(scanRow.max_depth || 2),
    requestTimeoutMs: Number(scanRow.request_timeout_ms || 8000),
    rateLimitRps: Number(scanRow.rate_limit_rps || 5),
    scopeIncludePaths: String(scanRow.scope_include_paths || '/').split(',').map((s) => s.trim()).filter(Boolean),
    scopeExcludePaths: String(scanRow.scope_exclude_paths || '').split(',').map((s) => s.trim()).filter(Boolean),
    allowAuthenticated: Boolean(scanRow.allow_authenticated),
    authHeaders,
    authRoleProfile,
    secretValuesToRedact,
    openapiSpecRaw: scanRow.openapi_spec_raw ? String(scanRow.openapi_spec_raw) : null,
    scaManifestName: scanRow.sca_manifest_name ? String(scanRow.sca_manifest_name) : null,
    scaManifestRaw: scanRow.sca_manifest_raw ? String(scanRow.sca_manifest_raw) : null,
    sastFilename: scanRow.sast_filename ? String(scanRow.sast_filename) : null,
    sastCodeRaw: scanRow.sast_code_raw ? String(scanRow.sast_code_raw) : null,
    isCancelled: () => cancelledScans.has(scanId),
    httpFetch: (url, init) => httpClient.request(url, init),
    log: (level, msg) => appendScanLog(scanId, level, null, msg),
    sharedState,
  };

  appendScanLog(
    scanId,
    'info',
    null,
    `Starting ${scanRow.profile} assessment on ${scanRow.target_url} with ${modules.length} module(s).`
  );

  for (let idx = 0; idx < modules.length; idx++) {
    const mod = modules[idx];
    const execId = execIds.get(mod.id)!;

    if (cancelledScans.has(scanId)) {
      db.prepare('UPDATE scan_executions SET status = ? WHERE id = ?').run('cancelled', execId);
      continue;
    }

    const modStart = Date.now();
    db.prepare('UPDATE scans SET current_module = ?, progress_pct = ? WHERE id = ?').run(
      mod.name,
      Math.round((idx / Math.max(1, modules.length)) * 90) + 5,
      scanId
    );
    db.prepare('UPDATE scan_executions SET status = ?, started_at = ? WHERE id = ?').run(
      'running',
      new Date(modStart).toISOString(),
      execId
    );
    appendScanLog(scanId, 'info', mod.id, `Executing ${mod.name} (v${mod.version})...`);

    try {
      const result = await Promise.race([
        mod.execute(ctx),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Module timed out after ${mod.defaultTimeoutMs}ms`)), mod.defaultTimeoutMs)
        ),
      ]);

      for (const l of result.logs) {
        appendScanLog(scanId, l.level, mod.id, l.message);
      }

      const nowIso = new Date().toISOString();
      const insertCheck = db.prepare(
        `INSERT INTO security_checks (id, scan_id, asset_id, module_id, check_key, title, category, status, observed_value, expected_value, explanation, remediation, cwe_id, owasp_category, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const chk of result.checks) {
        insertCheck.run(
          crypto.randomUUID(),
          scanId,
          ctx.assetId,
          mod.id,
          chk.checkKey,
          chk.title,
          chk.category,
          chk.status,
          chk.observedValue,
          chk.expectedValue,
          chk.explanation,
          chk.remediation,
          chk.cweId,
          chk.owaspCategory,
          nowIso
        );
      }

      const insertEndpoint = db.prepare(
        `INSERT INTO endpoints (id, scan_id, asset_id, url, path, method, source, auth_required, status_code, content_type, parameters_json, notes, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );
      for (const ep of result.endpoints) {
        insertEndpoint.run(
          crypto.randomUUID(),
          scanId,
          ctx.assetId,
          ep.url,
          ep.path,
          ep.method,
          ep.source,
          ep.authRequired,
          ep.statusCode,
          ep.contentType,
          JSON.stringify(ep.parameters),
          ep.notes,
          nowIso
        );
      }

      const findingIds = upsertScanFindings(db, {
        organizationId: ctx.organizationId,
        assetId: ctx.assetId,
        scanId,
        scannerModuleId: mod.id,
        userId: String(scanRow.initiated_by_user_id),
        findings: result.findings,
      });

      const modDuration = Date.now() - modStart;
      db.prepare(
        `UPDATE scan_executions
         SET status = 'completed', completed_at = ?, duration_ms = ?, checks_executed = ?, findings_created = ?
         WHERE id = ?`
      ).run(new Date().toISOString(), modDuration, result.checks.length, findingIds.length, execId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown module error';
      appendScanLog(scanId, 'error', mod.id, `Module failed safely without terminating scan: ${msg}`);
      db.prepare(
        `UPDATE scan_executions SET status = 'failed', completed_at = ?, duration_ms = ?, error_message = ? WHERE id = ?`
      ).run(new Date().toISOString(), Date.now() - modStart, msg, execId);
    }
  }

  // Finalize scan counts & posture score
  const checksRows = db
    .prepare('SELECT status FROM security_checks WHERE scan_id = ?')
    .all(scanId) as Array<{ status: string }>;

  const counts = {
    total: checksRows.length,
    passed: 0,
    failed: 0,
    potential: 0,
    informational: 0,
    not_applicable: 0,
    not_performed: 0,
    manual_required: 0,
  };

  for (const r of checksRows) {
    if (r.status === 'passed') counts.passed += 1;
    else if (r.status === 'failed') counts.failed += 1;
    else if (r.status === 'potential') counts.potential += 1;
    else if (r.status === 'informational') counts.informational += 1;
    else if (r.status === 'not_applicable') counts.not_applicable += 1;
    else if (r.status === 'not_performed') counts.not_performed += 1;
    else if (r.status === 'manual_required') counts.manual_required += 1;
  }

  const scanVulns = db
    .prepare('SELECT severity, verification_status FROM vulnerabilities WHERE latest_scan_id = ?')
    .all(scanId) as Array<{ severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'; verification_status: 'open' | 'confirmed' | 'false_positive' | 'risk_accepted' | 'remediated' | 'reopened' }>;

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of scanVulns) {
    if (v.verification_status === 'false_positive' || v.verification_status === 'remediated') continue;
    if (v.severity === 'critical') sevCounts.critical += 1;
    else if (v.severity === 'high') sevCounts.high += 1;
    else if (v.severity === 'medium') sevCounts.medium += 1;
    else if (v.severity === 'low') sevCounts.low += 1;
    else sevCounts.info += 1;
  }

  const posture = calculatePostureScore({
    passedChecks: counts.passed,
    failedChecks: counts.failed,
    findings: scanVulns.map((v) => ({ severity: v.severity, verificationStatus: v.verification_status })),
  });

  generateComplianceMappingsForScan(db, scanId);

  const finalStatus = cancelledScans.has(scanId) ? 'cancelled' : 'completed';
  const durationMs = Date.now() - startedAtMs;

  db.prepare(
    `UPDATE scans
     SET status = ?, progress_pct = 100, current_module = NULL, completed_at = ?, duration_ms = ?,
         posture_score = ?, total_checks = ?, passed_checks = ?, failed_checks = ?, potential_checks = ?,
         informational_checks = ?, not_applicable_checks = ?, not_performed_checks = ?, manual_required_checks = ?,
         critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, info_count = ?
     WHERE id = ?`
  ).run(
    finalStatus,
    new Date().toISOString(),
    durationMs,
    posture.score,
    counts.total,
    counts.passed,
    counts.failed,
    counts.potential,
    counts.informational,
    counts.not_applicable,
    counts.not_performed,
    counts.manual_required,
    sevCounts.critical,
    sevCounts.high,
    sevCounts.medium,
    sevCounts.low,
    sevCounts.info,
    scanId
  );

  appendScanLog(
    scanId,
    'info',
    null,
    `Assessment ${finalStatus} in ${durationMs}ms. Checks: ${counts.total} (${counts.passed} passed, ${counts.failed} failed, ${counts.manual_required} manual required).`
  );

  writeAuditLog(db, {
    organizationId: ctx.organizationId,
    userId: String(scanRow.initiated_by_user_id),
    action: `scan.${finalStatus}`,
    entityType: 'scan',
    entityId: scanId,
    details: { assetId: ctx.assetId, durationMs, postureScore: posture.score, totalChecks: counts.total },
  });

  if (sevCounts.critical > 0 || sevCounts.high > 0) {
    createNotification(db, {
      organizationId: ctx.organizationId,
      severity: sevCounts.critical > 0 ? 'critical' : 'high',
      title: `Assessment Completed: ${sevCounts.critical} Critical, ${sevCounts.high} High Findings`,
      message: `Scan on ${scanRow.target_url} completed with posture score ${posture.score ?? 'N/A'}.`,
    });
  }
}
