import crypto from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { getDb } from '../db/database.ts';
import {
  PRACTICE_OPENAPI_SAMPLE,
  PRACTICE_PACKAGE_JSON_SAMPLE,
  PRACTICE_SAST_SAMPLE,
} from '../scanner/practiceTarget.ts';
import { writeAuditLog } from '../security/audit.ts';
import { type AuthenticatedRequest, hashApiKey, requireAuth, requireRole } from '../security/auth.ts';
import { encryptSecret } from '../security/cryptoVault.ts';
import { PRACTICE_LAB_HOSTNAME } from '../security/ssrfGuard.ts';

const router = Router();

router.get('/dashboard/summary', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const orgId = req.authUser!.organizationId;

  const assetCount = (db.prepare('SELECT COUNT(*) as cnt FROM assets WHERE organization_id = ?').get(orgId) as { cnt: number }).cnt;
  const verifiedAssetCount = (db.prepare("SELECT COUNT(*) as cnt FROM assets WHERE organization_id = ? AND ownership_status = 'verified'").get(orgId) as { cnt: number }).cnt;
  const totalScans = (db.prepare('SELECT COUNT(*) as cnt FROM scans WHERE organization_id = ?').get(orgId) as { cnt: number }).cnt;
  const activeScans = (db.prepare("SELECT COUNT(*) as cnt FROM scans WHERE organization_id = ? AND status IN ('queued', 'running')").get(orgId) as { cnt: number }).cnt;

  const sevRows = db
    .prepare(
      `SELECT severity, COUNT(*) as cnt
       FROM vulnerabilities
       WHERE organization_id = ? AND verification_status IN ('open', 'confirmed', 'reopened')
       GROUP BY severity`
    )
    .all(orgId) as Array<{ severity: string; cnt: number }>;

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const r of sevRows) {
    if (r.severity in severityCounts) {
      severityCounts[r.severity as keyof typeof severityCounts] = r.cnt;
    }
  }

  const postureTrend = db
    .prepare(
      `SELECT s.id, s.completed_at, s.posture_score, s.passed_checks, s.failed_checks, a.name as asset_name
       FROM scans s
       JOIN assets a ON a.id = s.asset_id
       WHERE s.organization_id = ? AND s.status = 'completed' AND s.posture_score IS NOT NULL
       ORDER BY s.completed_at ASC
       LIMIT 20`
    )
    .all(orgId);

  const recentScans = db
    .prepare(
      `SELECT s.*, a.name as asset_name, a.target_url
       FROM scans s
       JOIN assets a ON a.id = s.asset_id
       WHERE s.organization_id = ?
       ORDER BY s.created_at DESC
       LIMIT 8`
    )
    .all(orgId);

  const mostVulnerableAssets = db
    .prepare(
      `SELECT a.id, a.name, a.target_url, a.environment, a.criticality,
              SUM(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
              SUM(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as high_count,
              COUNT(v.id) as total_open_findings
       FROM assets a
       LEFT JOIN vulnerabilities v ON v.asset_id = a.id AND v.verification_status IN ('open', 'confirmed', 'reopened')
       WHERE a.organization_id = ?
       GROUP BY a.id
       ORDER BY critical_count DESC, high_count DESC, total_open_findings DESC
       LIMIT 6`
    )
    .all(orgId);

  const recentFindings = db
    .prepare(
      `SELECT v.id, v.finding_code, v.title, v.severity, v.verification_status, v.category,
              v.cvss_score, v.cwe_id, v.cve_id, v.detected_at, a.name as asset_name
       FROM vulnerabilities v
       JOIN assets a ON a.id = v.asset_id
       WHERE v.organization_id = ?
       ORDER BY v.updated_at DESC
       LIMIT 8`
    )
    .all(orgId);

  res.json({
    metrics: {
      totalAssets: assetCount,
      verifiedAssets: verifiedAssetCount,
      totalScans,
      activeScans,
      ...severityCounts,
    },
    postureTrend,
    recentScans,
    mostVulnerableAssets,
    recentFindings,
  });
});

// Encrypted Scan Credentials Vault
router.get('/credentials', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const credentials = db
    .prepare(
      `SELECT c.id, c.asset_id, c.label, c.auth_type, c.role_profile, c.login_url, c.username_hint,
              c.expires_at, c.created_at, a.name as asset_name
       FROM scan_credentials c
       LEFT JOIN assets a ON a.id = c.asset_id
       WHERE c.organization_id = ?
       ORDER BY c.created_at DESC`
    )
    .all(req.authUser!.organizationId);
  res.json({ credentials });
});

const createCredentialSchema = z.object({
  assetId: z.string().nullable().optional().default(null),
  label: z.string().min(2).max(120),
  authType: z.enum(['bearer_token', 'cookie', 'basic_header', 'login_form']),
  roleProfile: z.enum(['authenticated_user', 'administrator', 'custom']),
  loginUrl: z.string().max(300).nullable().optional().default(null),
  usernameHint: z.string().max(120).nullable().optional().default(null),
  secretValue: z.string().min(4).max(2000),
  ttlDays: z.number().int().min(1).max(30).optional().default(7),
});

router.post('/credentials', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const parsed = createCredentialSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid credential payload' });
    return;
  }

  const db = getDb();
  const enc = encryptSecret(parsed.data.secretValue);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + parsed.data.ttlDays * 86_400_000).toISOString();
  const id = crypto.randomUUID();

  db.prepare(
    `INSERT INTO scan_credentials (
      id, organization_id, asset_id, label, auth_type, role_profile, login_url, username_hint,
      encrypted_secret_blob, iv_hex, auth_tag_hex, expires_at, created_by_user_id, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    req.authUser!.organizationId,
    parsed.data.assetId,
    parsed.data.label.trim(),
    parsed.data.authType,
    parsed.data.roleProfile,
    parsed.data.loginUrl,
    parsed.data.usernameHint,
    enc.ciphertextHex,
    enc.ivHex,
    enc.authTagHex,
    expiresAt,
    req.authUser!.id,
    now.toISOString()
  );

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'credential.created',
    entityType: 'scan_credential',
    entityId: id,
    details: { label: parsed.data.label, authType: parsed.data.authType, roleProfile: parsed.data.roleProfile, expiresAt },
  });

  res.status(201).json({ id, label: parsed.data.label, expiresAt });
});

router.delete('/credentials/:id', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const db = getDb();
  db.prepare('DELETE FROM scan_credentials WHERE id = ? AND organization_id = ?').run(
    req.params.id,
    req.authUser!.organizationId
  );
  res.json({ deleted: true });
});

// API Keys
router.get('/api-keys', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const keys = db
    .prepare(
      `SELECT id, name, key_prefix, role, last_used_at, expires_at, revoked_at, created_at
       FROM api_keys WHERE organization_id = ? ORDER BY created_at DESC`
    )
    .all(req.authUser!.organizationId);
  res.json({ keys });
});

router.post('/api-keys', requireAuth, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const role = req.body?.role === 'viewer' || req.body?.role === 'analyst' ? req.body.role : 'analyst';
  if (name.length < 2) {
    res.status(400).json({ error: 'API key name is required' });
    return;
  }

  const rawKey = `ssk_${crypto.randomBytes(24).toString('hex')}`;
  const prefix = rawKey.slice(0, 12);
  const keyHash = hashApiKey(rawKey);
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const db = getDb();
  db.prepare(
    `INSERT INTO api_keys (id, organization_id, created_by_user_id, name, key_prefix, key_hash, role, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, req.authUser!.organizationId, req.authUser!.id, name, prefix, keyHash, role, now);

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'api_key.created',
    entityType: 'api_key',
    entityId: id,
    details: { name, role, prefix },
  });

  // Return rawKey exactly once on creation
  res.status(201).json({ id, name, keyPrefix: prefix, rawKey, role });
});

router.delete('/api-keys/:id', requireAuth, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const db = getDb();
  db.prepare('UPDATE api_keys SET revoked_at = ? WHERE id = ? AND organization_id = ?').run(
    new Date().toISOString(),
    req.params.id,
    req.authUser!.organizationId
  );
  res.json({ revoked: true });
});

router.get('/audit-logs', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const logs = db
    .prepare(
      `SELECT l.*, u.full_name as user_name, u.email as user_email
       FROM audit_logs l
       LEFT JOIN users u ON u.id = l.user_id
       WHERE l.organization_id = ?
       ORDER BY l.created_at DESC
       LIMIT 100`
    )
    .all(req.authUser!.organizationId);
  res.json({ logs });
});

router.get('/notifications', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const notifications = db
    .prepare('SELECT * FROM notifications WHERE organization_id = ? ORDER BY created_at DESC LIMIT 30')
    .all(req.authUser!.organizationId);
  res.json({ notifications });
});

router.post('/notifications/read-all', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  db.prepare('UPDATE notifications SET read_at = ? WHERE organization_id = ? AND read_at IS NULL').run(
    new Date().toISOString(),
    req.authUser!.organizationId
  );
  res.json({ ok: true });
});

router.get('/practice-samples', requireAuth, (_req, res) => {
  res.json({
    practiceTargetUrl: `https://${PRACTICE_LAB_HOSTNAME}`,
    openapiSpec: PRACTICE_OPENAPI_SAMPLE,
    packageJson: PRACTICE_PACKAGE_JSON_SAMPLE,
    sastSnippet: PRACTICE_SAST_SAMPLE,
  });
});

export default router;
