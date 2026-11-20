import type { DatabaseSync } from 'node:sqlite';
import { normalizeCheckOutcome, type NormalizedCheckOutcome } from '../db/types.ts';
import { calculatePostureScore } from './posture.ts';

export interface ReconciledScanCounts {
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  potentialChecks: number;
  informationalChecks: number;
  manualRequiredChecks: number;
  notPerformedChecks: number;
  notApplicableChecks: number;
  byNormalizedStatus: Record<NormalizedCheckOutcome, number>;
  activeFindingsTotal: number;
  allScanFindingsTotal: number;
  severityCountsActive: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  severityCountsAll: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  postureScore: number | null;
}

export function computeReconciledScanStats(db: DatabaseSync, scanId: string): ReconciledScanCounts {
  const checksRows = db
    .prepare('SELECT status FROM security_checks WHERE scan_id = ?')
    .all(scanId) as Array<{ status: string }>;

  const byNormalizedStatus: Record<NormalizedCheckOutcome, number> = {
    PASS: 0,
    FAIL: 0,
    POTENTIAL: 0,
    INFORMATIONAL: 0,
    MANUAL_REQUIRED: 0,
    NOT_PERFORMED: 0,
    NOT_APPLICABLE: 0,
  };

  for (const r of checksRows) {
    const norm = normalizeCheckOutcome(r.status);
    byNormalizedStatus[norm] += 1;
  }

  const scanVulns = db
    .prepare('SELECT severity, verification_status FROM vulnerabilities WHERE latest_scan_id = ?')
    .all(scanId) as Array<{
    severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
    verification_status: 'open' | 'confirmed' | 'false_positive' | 'risk_accepted' | 'remediated' | 'reopened';
  }>;

  const severityCountsActive = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const severityCountsAll = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let activeFindingsTotal = 0;

  for (const v of scanVulns) {
    if (v.severity === 'critical') severityCountsAll.critical += 1;
    else if (v.severity === 'high') severityCountsAll.high += 1;
    else if (v.severity === 'medium') severityCountsAll.medium += 1;
    else if (v.severity === 'low') severityCountsAll.low += 1;
    else severityCountsAll.info += 1;

    if (v.verification_status === 'false_positive' || v.verification_status === 'remediated') continue;
    activeFindingsTotal += 1;
    if (v.severity === 'critical') severityCountsActive.critical += 1;
    else if (v.severity === 'high') severityCountsActive.high += 1;
    else if (v.severity === 'medium') severityCountsActive.medium += 1;
    else if (v.severity === 'low') severityCountsActive.low += 1;
    else severityCountsActive.info += 1;
  }

  const posture = calculatePostureScore({
    passedChecks: byNormalizedStatus.PASS,
    failedChecks: byNormalizedStatus.FAIL,
    findings: scanVulns.map((v) => ({ severity: v.severity, verificationStatus: v.verification_status })),
  });

  return {
    totalChecks: checksRows.length,
    passedChecks: byNormalizedStatus.PASS,
    failedChecks: byNormalizedStatus.FAIL,
    potentialChecks: byNormalizedStatus.POTENTIAL,
    informationalChecks: byNormalizedStatus.INFORMATIONAL,
    manualRequiredChecks: byNormalizedStatus.MANUAL_REQUIRED,
    notPerformedChecks: byNormalizedStatus.NOT_PERFORMED,
    notApplicableChecks: byNormalizedStatus.NOT_APPLICABLE,
    byNormalizedStatus,
    activeFindingsTotal,
    allScanFindingsTotal: scanVulns.length,
    severityCountsActive,
    severityCountsAll,
    postureScore: posture.score,
  };
}

export function reconcileScanCountersInDb(db: DatabaseSync, scanId: string): ReconciledScanCounts {
  const stats = computeReconciledScanStats(db, scanId);

  // Reconcile per-module check counts directly from persisted security_checks rows
  const moduleCheckCounts = db
    .prepare('SELECT module_id, COUNT(*) as cnt FROM security_checks WHERE scan_id = ? GROUP BY module_id')
    .all(scanId) as Array<{ module_id: string; cnt: number }>;
  const countMap = new Map(moduleCheckCounts.map((m) => [m.module_id, m.cnt]));

  const execRows = db
    .prepare('SELECT id, module_id FROM scan_executions WHERE scan_id = ?')
    .all(scanId) as Array<{ id: string; module_id: string }>;

  const updateExec = db.prepare('UPDATE scan_executions SET checks_executed = ? WHERE id = ?');
  for (const ex of execRows) {
    updateExec.run(countMap.get(ex.module_id) || 0, ex.id);
  }

  db.prepare(
    `UPDATE scans
     SET posture_score = ?,
         total_checks = ?,
         passed_checks = ?,
         failed_checks = ?,
         potential_checks = ?,
         informational_checks = ?,
         not_applicable_checks = ?,
         not_performed_checks = ?,
         manual_required_checks = ?,
         critical_count = ?,
         high_count = ?,
         medium_count = ?,
         low_count = ?,
         info_count = ?
     WHERE id = ?`
  ).run(
    stats.postureScore,
    stats.totalChecks,
    stats.passedChecks,
    stats.failedChecks,
    stats.potentialChecks,
    stats.informationalChecks,
    stats.notApplicableChecks,
    stats.notPerformedChecks,
    stats.manualRequiredChecks,
    stats.severityCountsActive.critical,
    stats.severityCountsActive.high,
    stats.severityCountsActive.medium,
    stats.severityCountsActive.low,
    stats.severityCountsActive.info,
    scanId
  );

  return stats;
}
