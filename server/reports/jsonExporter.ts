import type { DatabaseSync } from 'node:sqlite';
import { normalizeCheckOutcome } from '../db/types.ts';
import { computeReconciledScanStats } from '../intelligence/reconcile.ts';

export function buildStructuredReportData(
  db: DatabaseSync,
  scanId: string,
  organizationId: string
) {
  const scan = db
    .prepare(
      `SELECT s.*, a.name as asset_name, a.target_url, a.hostname, a.environment, a.criticality,
              a.ownership_status, a.authorization_signed_by, a.authorization_signed_at, a.scope_include_paths,
              a.scope_exclude_paths, o.name as organization_name, u.full_name as initiated_by_name, u.email as initiated_by_email
       FROM scans s
       JOIN assets a ON a.id = s.asset_id
       JOIN organizations o ON o.id = s.organization_id
       JOIN users u ON u.id = s.initiated_by_user_id
       WHERE s.id = ? AND s.organization_id = ?`
    )
    .get(scanId, organizationId) as Record<string, unknown> | undefined;

  if (!scan) return null;

  const reconciled = computeReconciledScanStats(db, scanId);

  const executions = db
    .prepare('SELECT * FROM scan_executions WHERE scan_id = ? ORDER BY rowid ASC')
    .all(scanId) as Array<Record<string, unknown>>;

  const rawChecks = db
    .prepare('SELECT * FROM security_checks WHERE scan_id = ? ORDER BY category, title')
    .all(scanId) as Array<Record<string, unknown>>;
  const checks: Array<Record<string, unknown>> = rawChecks.map((c) => ({
    ...c,
    normalized_status: normalizeCheckOutcome(String(c.status)),
  }));

  const findings = db
    .prepare(
      `SELECT * FROM vulnerabilities
       WHERE organization_id = ? AND latest_scan_id = ?
       ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, detected_at DESC`
    )
    .all(organizationId, scanId) as Array<Record<string, unknown>>;

  const evidenceRows = db
    .prepare('SELECT * FROM finding_evidence WHERE scan_id = ?')
    .all(scanId) as Array<Record<string, unknown>>;

  const evidenceByVuln = new Map<string, Array<Record<string, unknown>>>();
  for (const ev of evidenceRows) {
    const vid = String(ev.vulnerability_id);
    if (!evidenceByVuln.has(vid)) evidenceByVuln.set(vid, []);
    evidenceByVuln.get(vid)!.push(ev);
  }

  const enrichedFindings: Array<Record<string, unknown>> = findings.map((f) => ({
    ...f,
    references: JSON.parse(String(f.references_json || '[]')) as string[],
    evidence: evidenceByVuln.get(String(f.id)) || [],
  }));

  const endpoints = db
    .prepare('SELECT * FROM endpoints WHERE scan_id = ? ORDER BY path, method')
    .all(scanId) as Array<Record<string, unknown>>;

  const compliance = db
    .prepare(
      `SELECT f.code as framework_code, f.name as framework_name, f.version as framework_version,
              c.control_code, c.title as control_title, c.category, c.evidence_required,
              m.status, m.notes
       FROM compliance_mappings m
       JOIN compliance_frameworks f ON f.id = m.framework_id
       JOIN compliance_controls c ON c.id = m.control_id
       WHERE m.scan_id = ?
       ORDER BY f.name, c.control_code`
    )
    .all(scanId) as Array<Record<string, unknown>>;

  return {
    metadata: {
      platform: 'SentinelScan Enterprise Security Assessment Platform',
      reportGeneratedAt: new Date().toISOString(),
      assessmentId: scan.id,
      organization: scan.organization_name,
      targetName: scan.asset_name,
      targetUrl: scan.target_url,
      environment: scan.environment,
      criticality: scan.criticality,
      ownershipStatus: scan.ownership_status,
      authorizationSignedBy: scan.authorization_signed_by,
      authorizationSignedAt: scan.authorization_signed_at,
      profile: scan.profile,
      status: scan.status,
      startedAt: scan.started_at,
      completedAt: scan.completed_at,
      durationMs: scan.duration_ms,
      scopeIncludePaths: scan.scope_include_paths,
      scopeExcludePaths: scan.scope_exclude_paths,
      initiatedBy: `${scan.initiated_by_name} (${scan.initiated_by_email})`,
    },
    limitationsAndDisclaimers: [
      'Automated web security assessments observe externally accessible HTTP responses, TLS parameters, DNS records, and user-supplied artifacts.',
      'Security posture scores reflect only executed automated checks and do not guarantee absence of vulnerabilities or regulatory compliance (GDPR, PCI DSS, ISO 27001).',
      'Checks marked MANUAL_REQUIRED or NOT_PERFORMED were not verified remotely and must never be interpreted as PASS.',
    ],
    executiveSummary: {
      postureScore: reconciled.postureScore,
      totalChecks: reconciled.totalChecks,
      passedChecks: reconciled.passedChecks,
      failedChecks: reconciled.failedChecks,
      potentialChecks: reconciled.potentialChecks,
      informationalChecks: reconciled.informationalChecks,
      notApplicableChecks: reconciled.notApplicableChecks,
      notPerformedChecks: reconciled.notPerformedChecks,
      manualRequiredChecks: reconciled.manualRequiredChecks,
      byNormalizedStatus: reconciled.byNormalizedStatus,
      activeFindingsTotal: reconciled.activeFindingsTotal,
      allScanFindingsTotal: reconciled.allScanFindingsTotal,
      severityDistribution: {
        critical: reconciled.severityCountsActive.critical,
        high: reconciled.severityCountsActive.high,
        medium: reconciled.severityCountsActive.medium,
        low: reconciled.severityCountsActive.low,
        informational: reconciled.severityCountsActive.info,
      },
      allDetectedSeverityDistribution: {
        critical: reconciled.severityCountsAll.critical,
        high: reconciled.severityCountsAll.high,
        medium: reconciled.severityCountsAll.medium,
        low: reconciled.severityCountsAll.low,
        informational: reconciled.severityCountsAll.info,
      },
    },
    moduleExecutions: executions,
    findings: enrichedFindings,
    securityChecks: checks,
    endpoints,
    complianceMapping: compliance,
  };
}
