import crypto from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { getDb } from '../db/database.ts';
import { enqueueScan, requestScanCancellation, selectModulesForProfile } from '../scanner/engine.ts';
import { writeAuditLog } from '../security/audit.ts';
import { type AuthenticatedRequest, rateLimit, requireAuth, requireRole } from '../security/auth.ts';

const router = Router();

router.get('/modules', requireAuth, (_req, res) => {
  const db = getDb();
  const modules = db.prepare('SELECT * FROM scan_modules ORDER BY name ASC').all();
  res.json({ modules });
});

router.get('/', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scans = db
    .prepare(
      `SELECT s.*, a.name as asset_name, a.target_url, a.environment, u.full_name as initiated_by_name
       FROM scans s
       JOIN assets a ON a.id = s.asset_id
       JOIN users u ON u.id = s.initiated_by_user_id
       WHERE s.organization_id = ?
       ORDER BY s.created_at DESC`
    )
    .all(req.authUser!.organizationId);

  res.json({ scans });
});

const launchScanSchema = z.object({
  assetId: z.string().min(1),
  profile: z.enum(['quick', 'standard', 'comprehensive', 'custom']),
  selectedModules: z.array(z.string()).optional(),
  maxDepth: z.number().int().min(1).max(5).optional().default(2),
  requestTimeoutMs: z.number().int().min(2000).max(15000).optional().default(8000),
  rateLimitRps: z.number().int().min(1).max(20).optional().default(5),
  allowAuthenticated: z.boolean().optional().default(false),
  credentialId: z.string().nullable().optional().default(null),
  openapiSpecRaw: z.string().max(300_000).nullable().optional().default(null),
  scaManifestName: z.string().max(120).nullable().optional().default(null),
  scaManifestRaw: z.string().max(500_000).nullable().optional().default(null),
  sastFilename: z.string().max(120).nullable().optional().default(null),
  sastCodeRaw: z.string().max(500_000).nullable().optional().default(null),
});

router.post('/', requireAuth, requireRole(['admin', 'analyst']), rateLimit(15, 60_000), (req: AuthenticatedRequest, res) => {
  const parsed = launchScanSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid scan launch payload' });
    return;
  }

  const db = getDb();
  const asset = db
    .prepare('SELECT * FROM assets WHERE id = ? AND organization_id = ?')
    .get(parsed.data.assetId, req.authUser!.organizationId) as Record<string, unknown> | undefined;

  if (!asset) {
    res.status(404).json({ error: 'Target asset not found' });
    return;
  }

  if (asset.ownership_status !== 'verified') {
    res.status(403).json({
      error: 'Ownership verification and explicit written authorization are required before launching an assessment.',
    });
    return;
  }

  const modules = selectModulesForProfile(parsed.data.profile, parsed.data.selectedModules);
  if (modules.length === 0) {
    res.status(400).json({ error: 'Select at least one scanner module to launch an assessment.' });
    return;
  }

  const now = new Date().toISOString();
  const configId = crypto.randomUUID();
  const scanId = crypto.randomUUID();

  db.prepare(
    `INSERT INTO scan_configurations (
      id, organization_id, name, profile, selected_modules_json, max_depth, request_timeout_ms,
      concurrency_limit, rate_limit_rps, allow_authenticated, credential_id, openapi_spec_raw,
      sca_manifest_name, sca_manifest_raw, sast_filename, sast_code_raw, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    configId,
    req.authUser!.organizationId,
    `${asset.name} (${parsed.data.profile})`,
    parsed.data.profile,
    JSON.stringify(modules.map((m) => m.id)),
    parsed.data.maxDepth,
    parsed.data.requestTimeoutMs,
    Math.min(Number(asset.max_requests_per_sec || 5), parsed.data.rateLimitRps),
    parsed.data.allowAuthenticated ? 1 : 0,
    parsed.data.credentialId,
    parsed.data.openapiSpecRaw,
    parsed.data.scaManifestName,
    parsed.data.scaManifestRaw,
    parsed.data.sastFilename,
    parsed.data.sastCodeRaw,
    now
  );

  db.prepare(
    `INSERT INTO scans (
      id, organization_id, asset_id, configuration_id, initiated_by_user_id, profile, status, progress_pct, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'queued', 0, ?)`
  ).run(scanId, req.authUser!.organizationId, String(asset.id), configId, req.authUser!.id, parsed.data.profile, now);

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'scan.launched',
    entityType: 'scan',
    entityId: scanId,
    details: { assetId: asset.id, profile: parsed.data.profile, moduleCount: modules.length },
    ipAddress: req.ip || null,
  });

  enqueueScan(scanId);

  res.status(202).json({ id: scanId, status: 'queued' });
});

router.get('/compare', requireAuth, (req: AuthenticatedRequest, res) => {
  const baselineId = String(req.query.baselineId || '');
  const targetId = String(req.query.targetId || '');
  if (!baselineId || !targetId) {
    res.status(400).json({ error: 'baselineId and targetId query parameters are required' });
    return;
  }

  const db = getDb();
  const orgId = req.authUser!.organizationId;
  const baseline = db
    .prepare('SELECT s.*, a.name as asset_name, a.target_url FROM scans s JOIN assets a ON a.id = s.asset_id WHERE s.id = ? AND s.organization_id = ?')
    .get(baselineId, orgId) as Record<string, unknown> | undefined;
  const target = db
    .prepare('SELECT s.*, a.name as asset_name, a.target_url FROM scans s JOIN assets a ON a.id = s.asset_id WHERE s.id = ? AND s.organization_id = ?')
    .get(targetId, orgId) as Record<string, unknown> | undefined;

  if (!baseline || !target) {
    res.status(404).json({ error: 'One or both scans were not found' });
    return;
  }

  const baseChecks = db
    .prepare('SELECT check_key, title, status FROM security_checks WHERE scan_id = ?')
    .all(baselineId) as Array<{ check_key: string; title: string; status: string }>;
  const targetChecks = db
    .prepare('SELECT check_key, title, status FROM security_checks WHERE scan_id = ?')
    .all(targetId) as Array<{ check_key: string; title: string; status: string }>;

  const baseMap = new Map(baseChecks.map((c) => [c.check_key, c]));
  const checkDiffs: Array<{ checkKey: string; title: string; baselineStatus: string; targetStatus: string }> = [];
  for (const tc of targetChecks) {
    const bc = baseMap.get(tc.check_key);
    if (!bc || bc.status !== tc.status) {
      checkDiffs.push({
        checkKey: tc.check_key,
        title: tc.title,
        baselineStatus: bc ? bc.status : 'absent',
        targetStatus: tc.status,
      });
    }
  }

  res.json({
    baseline,
    target,
    postureDelta:
      baseline.posture_score !== null && target.posture_score !== null
        ? Math.round((Number(target.posture_score) - Number(baseline.posture_score)) * 10) / 10
        : null,
    passedDelta: Number(target.passed_checks) - Number(baseline.passed_checks),
    failedDelta: Number(target.failed_checks) - Number(baseline.failed_checks),
    checkDiffs,
  });
});

router.get('/:id', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scan = db
    .prepare(
      `SELECT s.*, a.name as asset_name, a.target_url, a.environment, a.ownership_status,
              u.full_name as initiated_by_name
       FROM scans s
       JOIN assets a ON a.id = s.asset_id
       JOIN users u ON u.id = s.initiated_by_user_id
       WHERE s.id = ? AND s.organization_id = ?`
    )
    .get(req.params.id, req.authUser!.organizationId);

  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  const executions = db
    .prepare('SELECT * FROM scan_executions WHERE scan_id = ? ORDER BY rowid ASC')
    .all(req.params.id);
  const logs = db
    .prepare('SELECT * FROM scan_progress WHERE scan_id = ? ORDER BY timestamp ASC')
    .all(req.params.id);
  const checks = db
    .prepare('SELECT * FROM security_checks WHERE scan_id = ? ORDER BY category ASC, title ASC')
    .all(req.params.id);
  const endpoints = db
    .prepare('SELECT * FROM endpoints WHERE scan_id = ? ORDER BY path ASC, method ASC')
    .all(req.params.id);
  const findings = db
    .prepare(
      `SELECT * FROM vulnerabilities WHERE organization_id = ? AND latest_scan_id = ?
       ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`
    )
    .all(req.authUser!.organizationId, req.params.id);

  res.json({ scan, executions, logs, checks, endpoints, findings });
});

router.post('/:id/cancel', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scan = db
    .prepare('SELECT id, status FROM scans WHERE id = ? AND organization_id = ?')
    .get(req.params.id, req.authUser!.organizationId) as { id: string; status: string } | undefined;

  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  requestScanCancellation(scan.id);
  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'scan.cancel_requested',
    entityType: 'scan',
    entityId: scan.id,
  });

  res.json({ cancelled: true });
});

export default router;
