import crypto from 'node:crypto';
import dns from 'node:dns';
import { Router } from 'express';
import { z } from 'zod';
import { getDb } from '../db/database.ts';
import { writeAuditLog } from '../security/audit.ts';
import { type AuthenticatedRequest, requireAuth, requireRole } from '../security/auth.ts';
import { PRACTICE_LAB_HOSTNAME, validateTargetUrl } from '../security/ssrfGuard.ts';

const router = Router();

// Controlled testing bypass: set REQUIRE_DNS_OWNERSHIP_VERIFICATION=true before public release
const REQUIRE_DNS_OWNERSHIP_VERIFICATION = process.env.REQUIRE_DNS_OWNERSHIP_VERIFICATION === 'true';

const createAssetSchema = z.object({
  name: z.string().min(2).max(120),
  targetUrl: z.string().url().max(500),
  environment: z.enum(['production', 'staging', 'development', 'practice_lab']),
  criticality: z.enum(['critical', 'high', 'medium', 'low']),
  scopeIncludePaths: z.string().max(500).optional().default('/'),
  scopeExcludePaths: z.string().max(500).optional().default(''),
  maxRequestsPerSec: z.number().int().min(1).max(20).optional().default(5),
});

router.get('/', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const orgId = req.authUser!.organizationId;

  const assets = db
    .prepare(
      `SELECT a.*,
              (SELECT posture_score FROM scans s WHERE s.asset_id = a.id AND s.status = 'completed' ORDER BY s.completed_at DESC LIMIT 1) as latest_posture_score,
              (SELECT completed_at FROM scans s WHERE s.asset_id = a.id AND s.status = 'completed' ORDER BY s.completed_at DESC LIMIT 1) as last_scanned_at,
              (SELECT COUNT(*) FROM scans s WHERE s.asset_id = a.id) as total_scans,
              (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = a.id AND v.verification_status IN ('open', 'confirmed', 'reopened')) as open_findings
       FROM assets a
       WHERE a.organization_id = ?
       ORDER BY a.created_at DESC`
    )
    .all(orgId);

  const verifications = db
    .prepare(
      `SELECT v.* FROM asset_ownership_verifications v
       JOIN assets a ON a.id = v.asset_id
       WHERE a.organization_id = ?
       ORDER BY v.created_at DESC`
    )
    .all(orgId);

  res.json({ assets, verifications });
});

router.post('/', requireAuth, requireRole(['admin', 'analyst']), async (req: AuthenticatedRequest, res) => {
  const parsed = createAssetSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid asset payload' });
    return;
  }

  const isPractice = parsed.data.environment === 'practice_lab' || parsed.data.targetUrl.includes(PRACTICE_LAB_HOSTNAME);

  let validated;
  try {
    validated = await validateTargetUrl(parsed.data.targetUrl, {
      allowPracticeTarget: isPractice,
      skipDnsLookup: isPractice,
    });
  } catch (err) {
    res.status(400).json({ error: err instanceof Error ? err.message : 'Target URL rejected by SSRF policy' });
    return;
  }

  const db = getDb();
  const now = new Date().toISOString();
  const assetId = crypto.randomUUID();
  const verifyToken = `sentinel-verify-${crypto.randomBytes(12).toString('hex')}`;
  const method = validated.isPracticeTarget ? 'practice_lab_attestation' : 'dns_txt';
  const targetLocation = validated.isPracticeTarget
    ? `Isolated Lab Target (${PRACTICE_LAB_HOSTNAME})`
    : `_sentinelscan-verify.${validated.hostname}`;

  db.prepare(
    `INSERT INTO assets (
      id, organization_id, name, target_url, hostname, environment, criticality,
      scope_include_paths, scope_exclude_paths, max_requests_per_sec, is_practice_target,
      ownership_status, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
  ).run(
    assetId,
    req.authUser!.organizationId,
    parsed.data.name.trim(),
    validated.url.origin,
    validated.hostname,
    validated.isPracticeTarget ? 'practice_lab' : parsed.data.environment,
    parsed.data.criticality,
    parsed.data.scopeIncludePaths,
    parsed.data.scopeExcludePaths,
    parsed.data.maxRequestsPerSec,
    validated.isPracticeTarget ? 1 : 0,
    now,
    now
  );

  db.prepare(
    `INSERT INTO asset_ownership_verifications (id, asset_id, method, token, target_location, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?)`
  ).run(crypto.randomUUID(), assetId, method, verifyToken, targetLocation, now);

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'asset.created',
    entityType: 'asset',
    entityId: assetId,
    details: { targetUrl: validated.url.origin, hostname: validated.hostname, isPracticeTarget: validated.isPracticeTarget },
    ipAddress: req.ip || null,
  });

  res.status(201).json({
    id: assetId,
    targetUrl: validated.url.origin,
    hostname: validated.hostname,
    ownershipStatus: 'pending',
    verificationToken: verifyToken,
  });
});

const verifyOwnershipSchema = z.object({
  method: z.enum(['dns_txt', 'http_file', 'html_meta', 'practice_lab_attestation']).optional().default('dns_txt'),
  authorizedBy: z.string().min(2).max(120),
  authorizationNotes: z.string().min(5).max(500),
  confirmExplicitAuthorization: z.literal(true),
});

router.post('/:id/verify-ownership', requireAuth, requireRole(['admin', 'analyst']), async (req: AuthenticatedRequest, res) => {
  const parsed = verifyOwnershipSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Written authorization confirmation and authorized signatory name are required.' });
    return;
  }

  const db = getDb();
  const asset = db
    .prepare('SELECT * FROM assets WHERE id = ? AND organization_id = ?')
    .get(req.params.id, req.authUser!.organizationId) as Record<string, unknown> | undefined;

  if (!asset) {
    res.status(404).json({ error: 'Asset not found' });
    return;
  }

  const verRow = db
    .prepare('SELECT * FROM asset_ownership_verifications WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1')
    .get(String(asset.id)) as Record<string, unknown> | undefined;

  const token = verRow ? String(verRow.token) : `sentinel-verify-${crypto.randomBytes(12).toString('hex')}`;
  const now = new Date().toISOString();

  let verified = false;
  let failureReason: string | null = null;
  let targetLocation = '';

  try {
    if (parsed.data.method === 'practice_lab_attestation') {
      if (!asset.is_practice_target) {
        res.status(400).json({ error: 'Practice lab attestation is only valid for the isolated practice target.' });
        return;
      }
      verified = true;
      targetLocation = `Isolated Lab (${PRACTICE_LAB_HOSTNAME})`;
    } else if (parsed.data.method === 'dns_txt') {
      if (REQUIRE_DNS_OWNERSHIP_VERIFICATION) {
        targetLocation = `_sentinelscan-verify.${asset.hostname}`;
        const records = await dns.promises.resolveTxt(targetLocation).catch(() => [] as string[][]);
        const flat = records.map((r) => r.join(''));
        if (flat.some((t) => t.includes(token))) {
          verified = true;
        } else {
          failureReason = `DNS TXT record at ${targetLocation} did not contain token "${token}".`;
        }
      } else {
        targetLocation = `Controlled testing bypass (${asset.hostname})`;
        verified = true;
      }
    } else if (parsed.data.method === 'http_file') {
      const checkUrl = `${asset.target_url}/.well-known/sentinelscan-verification.txt`;
      targetLocation = checkUrl;
      await validateTargetUrl(checkUrl, { allowPracticeTarget: false });
      const resp = await fetch(checkUrl, { redirect: 'manual', signal: AbortSignal.timeout(6000) });
      const body = await resp.text();
      if (resp.ok && body.includes(token)) {
        verified = true;
      } else {
        failureReason = `HTTP ${resp.status} from ${checkUrl} did not contain token "${token}".`;
      }
    } else if (parsed.data.method === 'html_meta') {
      const checkUrl = String(asset.target_url);
      targetLocation = checkUrl;
      await validateTargetUrl(checkUrl, { allowPracticeTarget: false });
      const resp = await fetch(checkUrl, { redirect: 'manual', signal: AbortSignal.timeout(6000) });
      const body = await resp.text();
      if (resp.ok && body.includes(`name="sentinelscan-verification"`) && body.includes(token)) {
        verified = true;
      } else {
        failureReason = `Meta tag <meta name="sentinelscan-verification" content="${token}"> not found at ${checkUrl}.`;
      }
    }
  } catch (err) {
    failureReason = err instanceof Error ? err.message : 'Verification probe failed';
  }

  db.prepare(
    `INSERT INTO asset_ownership_verifications (id, asset_id, method, token, target_location, status, checked_at, failure_reason, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    crypto.randomUUID(),
    String(asset.id),
    parsed.data.method,
    token,
    targetLocation,
    verified ? 'verified' : 'failed',
    now,
    failureReason,
    now
  );

  if (verified) {
    db.prepare(
      `UPDATE assets
       SET ownership_status = 'verified', authorization_signed_by = ?, authorization_signed_at = ?, authorization_notes = ?, updated_at = ?
       WHERE id = ?`
    ).run(parsed.data.authorizedBy.trim(), now, parsed.data.authorizationNotes.trim(), now, String(asset.id));
  }

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: verified ? 'asset.ownership_verified' : 'asset.ownership_verification_failed',
    entityType: 'asset',
    entityId: String(asset.id),
    details: { method: parsed.data.method, authorizedBy: parsed.data.authorizedBy, failureReason },
    ipAddress: req.ip || null,
  });

  if (!verified) {
    res.status(422).json({
      verified: false,
      token,
      targetLocation,
      error: failureReason || 'Ownership verification token not matched.',
    });
    return;
  }

  res.json({ verified: true, ownershipStatus: 'verified', authorizedBy: parsed.data.authorizedBy, verifiedAt: now });
});

const patchAssetSchema = z.object({
  name: z.string().min(2).max(120).optional(),
  criticality: z.enum(['critical', 'high', 'medium', 'low']).optional(),
  scopeIncludePaths: z.string().max(500).optional(),
  scopeExcludePaths: z.string().max(500).optional(),
  maxRequestsPerSec: z.number().int().min(1).max(20).optional(),
});

router.patch('/:id', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const parsed = patchAssetSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid asset update payload' });
    return;
  }

  const db = getDb();
  const asset = db
    .prepare('SELECT id FROM assets WHERE id = ? AND organization_id = ?')
    .get(req.params.id, req.authUser!.organizationId);
  if (!asset) {
    res.status(404).json({ error: 'Asset not found' });
    return;
  }

  const d = parsed.data;
  const now = new Date().toISOString();
  db.prepare(
    `UPDATE assets
     SET name = COALESCE(?, name),
         criticality = COALESCE(?, criticality),
         scope_include_paths = COALESCE(?, scope_include_paths),
         scope_exclude_paths = COALESCE(?, scope_exclude_paths),
         max_requests_per_sec = COALESCE(?, max_requests_per_sec),
         updated_at = ?
     WHERE id = ?`
  ).run(
    d.name ?? null,
    d.criticality ?? null,
    d.scopeIncludePaths ?? null,
    d.scopeExcludePaths ?? null,
    d.maxRequestsPerSec ?? null,
    now,
    req.params.id
  );

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'asset.updated',
    entityType: 'asset',
    entityId: String(req.params.id),
    details: d as Record<string, unknown>,
  });

  res.json({ ok: true });
});

router.delete('/:id', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const existing = db
    .prepare('SELECT id, name FROM assets WHERE id = ? AND organization_id = ?')
    .get(req.params.id, req.authUser!.organizationId) as { id: string; name: string } | undefined;

  if (!existing) {
    res.status(404).json({ error: 'Asset not found' });
    return;
  }

  db.prepare('DELETE FROM assets WHERE id = ? AND organization_id = ?').run(
    req.params.id,
    req.authUser!.organizationId
  );

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'asset.deleted',
    entityType: 'asset',
    entityId: String(req.params.id),
    details: { name: existing.name },
  });

  res.json({ deleted: true });
});

export default router;
