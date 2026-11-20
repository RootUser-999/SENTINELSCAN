import crypto from 'node:crypto';
import { Router } from 'express';
import { getDb } from '../db/database.ts';
import { generateCsvReport, type CsvExportScope } from '../reports/csvExporter.ts';
import { buildStructuredReportData } from '../reports/jsonExporter.ts';
import { generatePdfReportBuffer } from '../reports/pdfGenerator.ts';
import { writeAuditLog } from '../security/audit.ts';
import { type AuthenticatedRequest, requireAuth } from '../security/auth.ts';

const router = Router();

const VALID_CSV_SCOPES = new Set<CsvExportScope>([
  'all-findings',
  'passed-checks',
  'failed-checks',
  'vulnerability-inventory',
  'endpoint-inventory',
  'security-headers',
  'compliance-mapping',
]);

router.get('/compliance', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const orgId = req.authUser!.organizationId;
  let scanId = typeof req.query.scanId === 'string' ? req.query.scanId : '';

  if (!scanId) {
    const latest = db
      .prepare("SELECT id FROM scans WHERE organization_id = ? AND status = 'completed' ORDER BY completed_at DESC LIMIT 1")
      .get(orgId) as { id: string } | undefined;
    scanId = latest?.id || '';
  } else {
    const owned = db
      .prepare('SELECT id FROM scans WHERE id = ? AND organization_id = ?')
      .get(scanId, orgId);
    if (!owned) {
      res.status(404).json({ error: 'Scan not found' });
      return;
    }
  }

  const frameworks = db.prepare('SELECT * FROM compliance_frameworks ORDER BY name ASC').all();
  const controls = db.prepare('SELECT * FROM compliance_controls ORDER BY control_code ASC').all();
  const mappings = scanId
    ? db.prepare('SELECT * FROM compliance_mappings WHERE scan_id = ?').all(scanId)
    : [];

  res.json({
    scanId: scanId || null,
    nonCertificationNotice:
      'Framework mappings represent technical observations from automated checks and submitted artifacts only. They do not constitute formal regulatory certification (PCI DSS, GDPR, ISO 27001, or NIST compliance).',
    frameworks,
    controls,
    mappings,
  });
});

router.get('/reports', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const reports = db
    .prepare(
      `SELECT r.*, a.name as asset_name, s.profile, u.full_name as generated_by_name
       FROM reports r
       JOIN scans s ON s.id = r.scan_id
       JOIN assets a ON a.id = s.asset_id
       JOIN users u ON u.id = r.generated_by_user_id
       WHERE r.organization_id = ?
       ORDER BY r.created_at DESC
       LIMIT 50`
    )
    .all(req.authUser!.organizationId);

  res.json({ reports });
});

router.get('/reports/:scanId/pdf', requireAuth, async (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scanId = String(req.params.scanId);
  const result = await generatePdfReportBuffer(db, scanId, req.authUser!.organizationId);
  if (!result) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  db.prepare(
    `INSERT INTO reports (id, organization_id, scan_id, generated_by_user_id, format, export_scope, filename, file_size_bytes, created_at)
     VALUES (?, ?, ?, ?, 'pdf', 'full_assessment', ?, ?, ?)`
  ).run(
    crypto.randomUUID(),
    req.authUser!.organizationId,
    scanId,
    req.authUser!.id,
    result.filename,
    result.buffer.length,
    new Date().toISOString()
  );

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'report.generated_pdf',
    entityType: 'scan',
    entityId: scanId,
    details: { filename: result.filename, bytes: result.buffer.length },
  });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
  res.send(result.buffer);
});

router.get('/reports/:scanId/csv', requireAuth, (req: AuthenticatedRequest, res) => {
  const scopeRaw = String(req.query.scope || 'all-findings') as CsvExportScope;
  if (!VALID_CSV_SCOPES.has(scopeRaw)) {
    res.status(400).json({ error: 'Invalid CSV export scope' });
    return;
  }

  const db = getDb();
  const scanId = String(req.params.scanId);
  const scan = db
    .prepare('SELECT id FROM scans WHERE id = ? AND organization_id = ?')
    .get(scanId, req.authUser!.organizationId);
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  const { filename, content } = generateCsvReport(db, scanId, req.authUser!.organizationId, scopeRaw);
  const buf = Buffer.from(content, 'utf8');

  db.prepare(
    `INSERT INTO reports (id, organization_id, scan_id, generated_by_user_id, format, export_scope, filename, file_size_bytes, created_at)
     VALUES (?, ?, ?, ?, 'csv', ?, ?, ?, ?)`
  ).run(
    crypto.randomUUID(),
    req.authUser!.organizationId,
    scanId,
    req.authUser!.id,
    scopeRaw,
    filename,
    buf.length,
    new Date().toISOString()
  );

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'report.generated_csv',
    entityType: 'scan',
    entityId: scanId,
    details: { scope: scopeRaw, filename },
  });

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(buf);
});

router.get('/reports/:scanId/json', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const scanId = String(req.params.scanId);
  const data = buildStructuredReportData(db, scanId, req.authUser!.organizationId);
  if (!data) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  const filename = `sentinelscan-report-${scanId.slice(0, 8)}.json`;
  const jsonStr = JSON.stringify(data, null, 2);

  db.prepare(
    `INSERT INTO reports (id, organization_id, scan_id, generated_by_user_id, format, export_scope, filename, file_size_bytes, created_at)
     VALUES (?, ?, ?, ?, 'json', 'full_assessment', ?, ?, ?)`
  ).run(
    crypto.randomUUID(),
    req.authUser!.organizationId,
    scanId,
    req.authUser!.id,
    filename,
    Buffer.byteLength(jsonStr, 'utf8'),
    new Date().toISOString()
  );

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'report.generated_json',
    entityType: 'scan',
    entityId: scanId,
    details: { filename },
  });

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(jsonStr);
});

export default router;
