import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { FindingCandidate } from '../scanner/types.ts';

function computeFingerprint(assetId: string, f: FindingCandidate): string {
  const raw = `${assetId}|${f.ruleId}|${f.affectedUrl}|${f.parameterName || ''}`;
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24);
}

function generateFindingCode(ruleId: string, fingerprint: string): string {
  const shortPrefix = ruleId
    .split('_')
    .slice(0, 2)
    .map((s) => s.slice(0, 4))
    .join('-')
    .toUpperCase();
  return `SEN-${shortPrefix}-${fingerprint.slice(0, 5).toUpperCase()}`;
}

export function upsertScanFindings(
  db: DatabaseSync,
  params: {
    organizationId: string;
    assetId: string;
    scanId: string;
    scannerModuleId: string;
    userId: string;
    findings: FindingCandidate[];
  }
): string[] {
  const now = new Date().toISOString();
  const createdOrUpdatedIds: string[] = [];

  for (const f of params.findings) {
    const fingerprint = computeFingerprint(params.assetId, f);
    const existing = db
      .prepare('SELECT id, verification_status FROM vulnerabilities WHERE organization_id = ? AND fingerprint = ?')
      .get(params.organizationId, fingerprint) as
      | { id: string; verification_status: string }
      | undefined;

    let vulnId: string;
    if (existing) {
      vulnId = existing.id;
      const nextStatus = existing.verification_status === 'remediated' ? 'reopened' : existing.verification_status;
      db.prepare(
        `UPDATE vulnerabilities
         SET latest_scan_id = ?, title = ?, description = ?, technical_explanation = ?,
             severity = ?, cvss_version = ?, cvss_score = ?, cvss_vector = ?, cvss_rationale = ?,
             verification_status = ?, updated_at = ?
         WHERE id = ?`
      ).run(
        params.scanId,
        f.title,
        f.description,
        f.technicalExplanation,
        f.severity,
        f.cvssVersion,
        f.cvssScore,
        f.cvssVector,
        f.cvssRationale,
        nextStatus,
        now,
        vulnId
      );

      if (existing.verification_status === 'remediated') {
        db.prepare(
          `INSERT INTO finding_status_history (id, vulnerability_id, changed_by_user_id, previous_status, new_status, rationale, changed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(
          crypto.randomUUID(),
          vulnId,
          params.userId,
          'remediated',
          'reopened',
          `Re-detected during reassessment scan ${params.scanId}`,
          now
        );
      }
    } else {
      vulnId = crypto.randomUUID();
      const findingCode = generateFindingCode(f.ruleId, fingerprint);
      db.prepare(
        `INSERT INTO vulnerabilities (
          id, organization_id, asset_id, first_scan_id, latest_scan_id, fingerprint, finding_code,
          title, category, description, technical_explanation, affected_url, http_method, parameter_name,
          scanner_module, confidence, severity, cvss_version, cvss_score, cvss_vector, cvss_rationale,
          cwe_id, cve_id, owasp_category, owasp_api_category, business_impact, exploitation_prerequisites,
          remediation_instructions, references_json, verification_status, assigned_to, detected_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', NULL, ?, ?)`
      ).run(
        vulnId,
        params.organizationId,
        params.assetId,
        params.scanId,
        params.scanId,
        fingerprint,
        findingCode,
        f.title,
        f.category,
        f.description,
        f.technicalExplanation,
        f.affectedUrl,
        f.httpMethod,
        f.parameterName,
        params.scannerModuleId,
        f.confidence,
        f.severity,
        f.cvssVersion,
        f.cvssScore,
        f.cvssVector,
        f.cvssRationale,
        f.cweId,
        f.cveId,
        f.owaspCategory,
        f.owaspApiCategory,
        f.businessImpact,
        f.exploitationPrerequisites,
        f.remediationInstructions,
        JSON.stringify(f.references),
        now,
        now
      );

      db.prepare(
        `INSERT INTO finding_status_history (id, vulnerability_id, changed_by_user_id, previous_status, new_status, rationale, changed_at)
         VALUES (?, ?, ?, 'new', 'open', 'Initial detection by automated scanner module', ?)`
      ).run(crypto.randomUUID(), vulnId, params.userId, now);
    }

    for (const ev of f.evidence) {
      db.prepare(
        `INSERT INTO finding_evidence (id, vulnerability_id, scan_id, evidence_type, summary, raw_excerpt, observed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(crypto.randomUUID(), vulnId, params.scanId, ev.evidenceType, ev.summary, ev.rawExcerpt, now);
    }

    createdOrUpdatedIds.push(vulnId);
  }

  return createdOrUpdatedIds;
}
