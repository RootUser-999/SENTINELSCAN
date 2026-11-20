import crypto from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { getDb } from '../db/database.ts';
import { reconcileScanCountersInDb } from '../intelligence/reconcile.ts';
import { writeAuditLog } from '../security/audit.ts';
import { type AuthenticatedRequest, requireAuth, requireRole } from '../security/auth.ts';

const router = Router();

router.get('/', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const orgId = req.authUser!.organizationId;
  const severity = typeof req.query.severity === 'string' ? req.query.severity : '';
  const status = typeof req.query.status === 'string' ? req.query.status : '';
  const assetId = typeof req.query.assetId === 'string' ? req.query.assetId : '';
  const category = typeof req.query.category === 'string' ? req.query.category : '';
  const search = typeof req.query.search === 'string' ? req.query.search.trim().toLowerCase() : '';

  const conditions: string[] = ['v.organization_id = ?'];
  const params: Array<string | number | null> = [orgId];

  if (severity) {
    conditions.push('v.severity = ?');
    params.push(severity);
  }
  if (status) {
    conditions.push('v.verification_status = ?');
    params.push(status);
  }
  if (assetId) {
    conditions.push('v.asset_id = ?');
    params.push(assetId);
  }
  if (category) {
    conditions.push('v.category = ?');
    params.push(category);
  }
  if (search) {
    conditions.push('(LOWER(v.title) LIKE ? OR LOWER(v.finding_code) LIKE ? OR LOWER(v.affected_url) LIKE ? OR LOWER(COALESCE(v.cwe_id, \'\')) LIKE ? OR LOWER(COALESCE(v.cve_id, \'\')) LIKE ?)');
    const like = `%${search}%`;
    params.push(like, like, like, like, like);
  }

  const sql = `
    SELECT v.*, a.name as asset_name, a.target_url
    FROM vulnerabilities v
    JOIN assets a ON a.id = v.asset_id
    WHERE ${conditions.join(' AND ')}
    ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
             COALESCE(v.cvss_score, 0) DESC,
             v.updated_at DESC
  `;

  const findings = db.prepare(sql).all(...params);
  res.json({ findings });
});

router.get('/:id', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const finding = db
    .prepare(
      `SELECT v.*, a.name as asset_name, a.target_url
       FROM vulnerabilities v
       JOIN assets a ON a.id = v.asset_id
       WHERE v.id = ? AND v.organization_id = ?`
    )
    .get(req.params.id, req.authUser!.organizationId) as Record<string, unknown> | undefined;

  if (!finding) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }

  const evidence = db
    .prepare('SELECT * FROM finding_evidence WHERE vulnerability_id = ? ORDER BY observed_at DESC')
    .all(String(finding.id));

  const history = db
    .prepare(
      `SELECT h.*, u.full_name as changed_by_name, u.email as changed_by_email
       FROM finding_status_history h
       JOIN users u ON u.id = h.changed_by_user_id
       WHERE h.vulnerability_id = ?
       ORDER BY h.changed_at DESC`
    )
    .all(String(finding.id));

  res.json({
    finding: {
      ...finding,
      references: JSON.parse(String(finding.references_json || '[]')),
    },
    evidence,
    history,
  });
});

const statusUpdateSchema = z.object({
  status: z.enum(['open', 'confirmed', 'false_positive', 'risk_accepted', 'remediated', 'reopened']),
  rationale: z.string().min(3).max(500),
});

router.patch('/:id/status', requireAuth, requireRole(['admin', 'analyst']), (req: AuthenticatedRequest, res) => {
  const parsed = statusUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Valid verification status and rationale are required' });
    return;
  }

  const db = getDb();
  const finding = db
    .prepare('SELECT id, verification_status, latest_scan_id, finding_code FROM vulnerabilities WHERE id = ? AND organization_id = ?')
    .get(req.params.id, req.authUser!.organizationId) as
    | { id: string; verification_status: string; latest_scan_id: string; finding_code: string }
    | undefined;

  if (!finding) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE vulnerabilities SET verification_status = ?, updated_at = ? WHERE id = ?').run(
    parsed.data.status,
    now,
    finding.id
  );

  db.prepare(
    `INSERT INTO finding_status_history (id, vulnerability_id, changed_by_user_id, previous_status, new_status, rationale, changed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    crypto.randomUUID(),
    finding.id,
    req.authUser!.id,
    finding.verification_status,
    parsed.data.status,
    parsed.data.rationale.trim(),
    now
  );

  if (finding.latest_scan_id) {
    reconcileScanCountersInDb(db, finding.latest_scan_id);
  }

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'finding.status_updated',
    entityType: 'vulnerability',
    entityId: finding.id,
    details: {
      findingCode: finding.finding_code,
      from: finding.verification_status,
      to: parsed.data.status,
      rationale: parsed.data.rationale,
    },
  });

  res.json({ ok: true, status: parsed.data.status });
});

export default router;
