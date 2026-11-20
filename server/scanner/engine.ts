import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { getDb } from '../db/database.ts';
import type { ScanProfile } from '../db/types.ts';
import { generateComplianceMappingsForScan } from '../compliance/mapper.ts';
import { upsertScanFindings } from '../intelligence/findingManager.ts';
import { reconcileScanCountersInDb } from '../intelligence/reconcile.ts';
import { createNotification, writeAuditLog } from '../security/audit.ts';
import { decryptSecret } from '../security/cryptoVault.ts';
import { SsrfSafeHttpClient } from './httpClient.ts';
import { apiSecurityModule } from './modules/apiSecurity.ts';
import { authenticatedAccessModule } from './modules/authenticatedAccess.ts';
import { dependencyScaModule } from './modules/dependencySca.ts';
import { dnsInfrastructureModule } from './modules/dnsInfrastructure.ts';
import { httpTlsTransportModule } from './modules/httpTlsTransport.ts';
import { owaspActiveProbesModule } from './modules/owaspActiveProbes.ts';
import { securityHeadersModule } from './modules/securityHeaders.ts';
import { sessionAuthCookiesModule } from './modules/sessionAuthCookies.ts';
import { staticCodeSastModule } from './modules/staticCodeSast.ts';
import { surfaceExposureModule } from './modules/surfaceExposure.ts';
import type { SastSourceFile, ScanContext, ScannerModule } from './types.ts';

export const SCANNER_MODULES: ScannerModule[] = [
  httpTlsTransportModule,
  securityHeadersModule,
  dnsInfrastructureModule,
  surfaceExposureModule,
  owaspActiveProbesModule,
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

async function resolveCredentialAuthHeaders(
  db: DatabaseSync,
  scanId: string,
  credentialId: string | null | undefined,
  organizationId: string,
  httpClient: SsrfSafeHttpClient,
  targetOrigin: string,
  secretValuesToRedact: string[]
): Promise<{ headers: Record<string, string>; roleProfile: string | null }> {
  const headers: Record<string, string> = {};
  if (!credentialId) return { headers, roleProfile: null };

  const credRow = db
    .prepare('SELECT * FROM scan_credentials WHERE id = ? AND organization_id = ?')
    .get(String(credentialId), organizationId) as Record<string, unknown> | undefined;

  if (!credRow) return { headers, roleProfile: null };

  if (new Date(String(credRow.expires_at)).getTime() < Date.now()) {
    appendScanLog(scanId, 'warn', null, `Credential "${credRow.label}" has expired; skipping.`);
    return { headers, roleProfile: null };
  }

  const plain = decryptSecret({
    ciphertextHex: String(credRow.encrypted_secret_blob),
    ivHex: String(credRow.iv_hex),
    authTagHex: String(credRow.auth_tag_hex),
  });

  if (!plain) {
    appendScanLog(scanId, 'warn', null, `Credential "${credRow.label}" could not be decrypted; re-save credential.`);
    return { headers, roleProfile: null };
  }

  secretValuesToRedact.push(plain);
  const roleProfile = String(credRow.role_profile);

  if (credRow.auth_type === 'bearer_token') {
    headers['Authorization'] = `Bearer ${plain}`;
  } else if (credRow.auth_type === 'cookie') {
    headers['Cookie'] = plain;
  } else if (credRow.auth_type === 'basic_header') {
    headers['Authorization'] = plain;
  } else if (credRow.auth_type === 'login_form') {
    const loginUrlRaw = credRow.login_url ? String(credRow.login_url) : `${targetOrigin}/login`;
    const loginUrl = loginUrlRaw.startsWith('http') ? loginUrlRaw : `${targetOrigin}${loginUrlRaw.startsWith('/') ? '' : '/'}${loginUrlRaw}`;
    const username = credRow.username_hint ? String(credRow.username_hint) : 'testuser@example.test';
    try {
      const loginRes = await httpClient.request(loginUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: username, username, password: plain }),
        followRedirects: false,
      });
      if (loginRes.setCookies.length > 0) {
        const cookiePairs = loginRes.setCookies.map((c) => c.split(';')[0]).filter(Boolean);
        if (cookiePairs.length > 0) {
          headers['Cookie'] = cookiePairs.join('; ');
          for (const cp of cookiePairs) secretValuesToRedact.push(cp);
        }
      }
      try {
        const bodyJson = JSON.parse(loginRes.bodyText) as { token?: string; accessToken?: string; access_token?: string };
        const tok = bodyJson.token || bodyJson.accessToken || bodyJson.access_token;
        if (tok && typeof tok === 'string') {
          headers['Authorization'] = `Bearer ${tok}`;
          secretValuesToRedact.push(tok);
        }
      } catch {
        // Non-JSON login response; cookie-only auth is fine
      }
      if (Object.keys(headers).length === 0) {
        appendScanLog(scanId, 'warn', null, `Form login credential "${credRow.label}" did not yield session cookie or token.`);
      } else {
        appendScanLog(scanId, 'info', null, `Acquired authenticated session via login form for role "${roleProfile}".`);
      }
    } catch (err) {
      appendScanLog(
        scanId,
        'warn',
        null,
        `Form login failed for "${credRow.label}": ${err instanceof Error ? err.message : 'unknown error'}`
      );
    }
  }

  return { headers, roleProfile };
}

async function executeScanAsync(scanId: string): Promise<void> {
  const db = getDb();
  const scanRow = db
    .prepare(
      `SELECT s.*, a.target_url, a.hostname, a.is_practice_target, a.ownership_status,
              a.scope_include_paths, a.scope_exclude_paths,
              c.selected_modules_json, c.max_depth, c.max_urls, c.max_requests,
              c.concurrency_limit, c.request_timeout_ms, c.rate_limit_rps,
              c.allow_authenticated, c.credential_id, c.secondary_credential_id,
              c.custom_headers_json, c.openapi_spec_raw,
              c.sca_manifest_name, c.sca_manifest_raw, c.sast_filename, c.sast_code_raw, c.sast_files_json
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

  if (scanRow.ownership_status !== 'verified') {
    db.prepare(
      'UPDATE scans SET status = ?, completed_at = ?, error_message = ? WHERE id = ?'
    ).run('failed', new Date().toISOString(), 'Asset ownership is not verified.', scanId);
    appendScanLog(scanId, 'error', null, 'Aborted scan: target asset ownership verification is required.');
    return;
  }

  const selectedIds = JSON.parse(String(scanRow.selected_modules_json || '[]')) as string[];
  const modules = selectModulesForProfile(scanRow.profile as ScanProfile, selectedIds);

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

  let customHeaders: Record<string, string> = {};
  try {
    const parsedHdrs = JSON.parse(String(scanRow.custom_headers_json || '{}'));
    if (parsedHdrs && typeof parsedHdrs === 'object' && !Array.isArray(parsedHdrs)) {
      for (const [k, v] of Object.entries(parsedHdrs)) {
        if (typeof k === 'string' && typeof v === 'string' && k.trim()) {
          customHeaders[k.trim()] = v;
        }
      }
    }
  } catch {
    customHeaders = {};
  }

  let sastFiles: SastSourceFile[] = [];
  try {
    const parsedFiles = JSON.parse(String(scanRow.sast_files_json || '[]'));
    if (Array.isArray(parsedFiles)) {
      sastFiles = parsedFiles.filter(
        (f): f is SastSourceFile => Boolean(f && typeof f.filename === 'string' && typeof f.content === 'string')
      );
    }
  } catch {
    sastFiles = [];
  }

  const maxRequests = Number(scanRow.max_requests || (scanRow.profile === 'quick' ? 60 : scanRow.profile === 'comprehensive' ? 400 : 200));
  const httpClient = new SsrfSafeHttpClient({
    allowedHostname: String(scanRow.hostname),
    allowPracticeTarget: Boolean(scanRow.is_practice_target),
    rateLimitRps: Number(scanRow.rate_limit_rps || 5),
    timeoutMs: Number(scanRow.request_timeout_ms || 10000),
    maxRequests,
    defaultHeaders: customHeaders,
  });

  const targetOrigin = new URL(String(scanRow.target_url)).origin;
  const secretValuesToRedact: string[] = Object.values(customHeaders).filter((v) => v.length >= 6);
  let authHeaders: Record<string, string> = {};
  let authRoleProfile: string | null = null;
  let secondaryAuthHeaders: Record<string, string> = {};
  let secondaryAuthRoleProfile: string | null = null;

  if (scanRow.allow_authenticated) {
    const primary = await resolveCredentialAuthHeaders(
      db,
      scanId,
      scanRow.credential_id ? String(scanRow.credential_id) : null,
      String(scanRow.organization_id),
      httpClient,
      targetOrigin,
      secretValuesToRedact
    );
    authHeaders = primary.headers;
    authRoleProfile = primary.roleProfile;

    const secondary = await resolveCredentialAuthHeaders(
      db,
      scanId,
      scanRow.secondary_credential_id ? String(scanRow.secondary_credential_id) : null,
      String(scanRow.organization_id),
      httpClient,
      targetOrigin,
      secretValuesToRedact
    );
    secondaryAuthHeaders = secondary.headers;
    secondaryAuthRoleProfile = secondary.roleProfile;
  }

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
    maxUrls: Number(scanRow.max_urls || (scanRow.profile === 'quick' ? 12 : 60)),
    maxRequests,
    concurrencyLimit: Number(scanRow.concurrency_limit || 3),
    requestTimeoutMs: Number(scanRow.request_timeout_ms || 10000),
    rateLimitRps: Number(scanRow.rate_limit_rps || 5),
    scopeIncludePaths: String(scanRow.scope_include_paths || '/').split(',').map((s) => s.trim()).filter(Boolean),
    scopeExcludePaths: String(scanRow.scope_exclude_paths || '').split(',').map((s) => s.trim()).filter(Boolean),
    allowAuthenticated: Boolean(scanRow.allow_authenticated),
    authHeaders,
    authRoleProfile,
    secondaryAuthHeaders,
    secondaryAuthRoleProfile,
    customHeaders,
    secretValuesToRedact,
    openapiSpecRaw: scanRow.openapi_spec_raw ? String(scanRow.openapi_spec_raw) : null,
    scaManifestName: scanRow.sca_manifest_name ? String(scanRow.sca_manifest_name) : null,
    scaManifestRaw: scanRow.sca_manifest_raw ? String(scanRow.sca_manifest_raw) : null,
    sastFilename: scanRow.sast_filename ? String(scanRow.sast_filename) : null,
    sastCodeRaw: scanRow.sast_code_raw ? String(scanRow.sast_code_raw) : null,
    sastFiles,
    isCancelled: () => cancelledScans.has(scanId),
    httpFetch: (url, init) => httpClient.request(url, init),
    getHttpStats: () => httpClient.getStats(),
    log: (level, msg) => appendScanLog(scanId, level, null, msg),
    sharedState,
  };

  appendScanLog(
    scanId,
    'info',
    null,
    `Starting ${scanRow.profile} assessment on ${scanRow.target_url} with ${modules.length} module(s) (maxDepth=${ctx.maxDepth}, maxUrls=${ctx.maxUrls}, budget=${ctx.maxRequests}, concurrency=${ctx.concurrencyLimit}).`
  );

  const seenCheckKeys = new Set<string>();

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

    const moduleBudgetMs = Math.max(
      mod.defaultTimeoutMs,
      ctx.profile === 'comprehensive' ? 120_000 : ctx.profile === 'standard' ? 60_000 : 20_000
    );

    let timerHandle: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([
        mod.execute(ctx),
        new Promise<never>((_, reject) => {
          timerHandle = setTimeout(
            () => reject(new Error(`Module timed out after ${moduleBudgetMs}ms`)),
            moduleBudgetMs
          );
        }),
      ]);
      if (timerHandle) clearTimeout(timerHandle);

      for (const l of result.logs) {
        appendScanLog(scanId, l.level, mod.id, l.message);
      }

      const nowIso = new Date().toISOString();
      const insertCheck = db.prepare(
        `INSERT INTO security_checks (id, scan_id, asset_id, module_id, check_key, title, category, status, observed_value, expected_value, explanation, remediation, cwe_id, owasp_category, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );

      let insertedChecksForMod = 0;
      for (const chk of result.checks) {
        if (seenCheckKeys.has(chk.checkKey)) continue;
        seenCheckKeys.add(chk.checkKey);
        insertedChecksForMod += 1;
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

      const uniqueFindingCount = new Set(findingIds).size;
      const modDuration = Date.now() - modStart;
      db.prepare(
        `UPDATE scan_executions
         SET status = 'completed', completed_at = ?, duration_ms = ?, checks_executed = ?, findings_created = ?
         WHERE id = ?`
      ).run(new Date().toISOString(), modDuration, insertedChecksForMod, uniqueFindingCount, execId);
    } catch (err) {
      if (timerHandle) clearTimeout(timerHandle);
      const msg = err instanceof Error ? err.message : 'Unknown module error';
      appendScanLog(scanId, 'error', mod.id, `Module failed safely without terminating scan: ${msg}`);
      db.prepare(
        `UPDATE scan_executions SET status = 'failed', completed_at = ?, duration_ms = ?, error_message = ? WHERE id = ?`
      ).run(new Date().toISOString(), Date.now() - modStart, msg, execId);
    }
  }

  generateComplianceMappingsForScan(db, scanId);
  const stats = reconcileScanCountersInDb(db, scanId);

  const finalStatus = cancelledScans.has(scanId) ? 'cancelled' : 'completed';
  const durationMs = Date.now() - startedAtMs;

  db.prepare(
    `UPDATE scans
     SET status = ?, progress_pct = 100, current_module = NULL, completed_at = ?, duration_ms = ?
     WHERE id = ?`
  ).run(finalStatus, new Date().toISOString(), durationMs, scanId);

  const httpStats = httpClient.getStats();
  appendScanLog(
    scanId,
    'info',
    null,
    `Assessment ${finalStatus} in ${durationMs}ms (${httpStats.requestsSent} HTTP request(s), ${httpStats.retries} retries). Checks: ${stats.totalChecks} (PASS=${stats.passedChecks}, FAIL=${stats.failedChecks}, POTENTIAL=${stats.potentialChecks}, INFO=${stats.informationalChecks}, MANUAL_REQUIRED=${stats.manualRequiredChecks}, NOT_PERFORMED=${stats.notPerformedChecks}, NOT_APPLICABLE=${stats.notApplicableChecks}).`
  );

  writeAuditLog(db, {
    organizationId: ctx.organizationId,
    userId: String(scanRow.initiated_by_user_id),
    action: `scan.${finalStatus}`,
    entityType: 'scan',
    entityId: scanId,
    details: {
      assetId: ctx.assetId,
      durationMs,
      postureScore: stats.postureScore,
      totalChecks: stats.totalChecks,
      httpRequests: httpStats.requestsSent,
    },
  });

  if (stats.severityCountsActive.critical > 0 || stats.severityCountsActive.high > 0) {
    createNotification(db, {
      organizationId: ctx.organizationId,
      severity: stats.severityCountsActive.critical > 0 ? 'critical' : 'high',
      title: `Assessment Completed: ${stats.severityCountsActive.critical} Critical, ${stats.severityCountsActive.high} High Findings`,
      message: `Scan on ${scanRow.target_url} completed with posture score ${stats.postureScore ?? 'N/A'}.`,
    });
  }
}
