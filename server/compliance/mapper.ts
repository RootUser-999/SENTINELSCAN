import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

interface CheckRow {
  id: string;
  check_key: string;
  status: string;
  owasp_category: string | null;
}

interface VulnRow {
  id: string;
  owasp_category: string | null;
  owasp_api_category: string | null;
  verification_status: string;
}

const CONTROL_TO_CHECK_KEYS: Record<string, string[]> = {
  // OWASP Top 10
  'ctrl-a01': ['headers.cors', 'auth.form_csrf_indicator', 'auth_testing.role_boundary'],
  'ctrl-a02': ['transport.https_primary', 'transport.http_to_https_redirect', 'transport.tls_protocol', 'transport.tls_certificate', 'headers.strict-transport-security', 'surface.mixed_content'],
  'ctrl-a03': ['surface.dom_xss_indicator', 'sast.source_review'],
  'ctrl-a04': ['auth.mfa_rate_limit_lockout'],
  'ctrl-a05': ['headers.content-security-policy', 'headers.x-frame-options', 'headers.x-content-type-options', 'headers.referrer-policy', 'headers.permissions-policy', 'surface.http_methods', 'surface.sensitive_files', 'surface.verbose_errors', 'infra.version_disclosure'],
  'ctrl-a06': ['sca.manifest_analysis', 'infra.version_disclosure'],
  'ctrl-a07': ['auth.cookie_attributes', 'auth.password_storage_hashing', 'auth.mfa_rate_limit_lockout'],
  'ctrl-a08': ['sast.source_review'],
  'ctrl-a09': [],
  'ctrl-a10': ['sast.source_review'],

  // OWASP API Top 10
  'ctrl-api1': ['api.openapi_security_schemes', 'auth_testing.role_boundary'],
  'ctrl-api2': ['api.openapi_security_schemes'],
  'ctrl-api3': ['api.openapi_security_schemes'],
  'ctrl-api8': ['api.openapi_exposure', 'api.graphql_introspection', 'headers.cors'],
  'ctrl-api9': ['api.openapi_exposure', 'api.openapi_security_schemes'],

  // OWASP ASVS
  'ctrl-asvs-v3': ['auth.cookie_attributes'],
  'ctrl-asvs-v9': ['transport.https_primary', 'transport.tls_protocol', 'transport.tls_certificate'],
  'ctrl-asvs-v14': ['headers.content-security-policy', 'headers.strict-transport-security', 'headers.x-frame-options', 'headers.x-content-type-options'],

  // NIST CSF
  'ctrl-nist-prds': ['transport.https_primary', 'transport.tls_protocol', 'headers.strict-transport-security'],
  'ctrl-nist-prps': ['headers.content-security-policy', 'surface.sensitive_files', 'surface.http_methods'],
  'ctrl-nist-idra': ['sca.manifest_analysis', 'sast.source_review'],

  // CIS v8
  'ctrl-cis-04': ['headers.content-security-policy', 'surface.sensitive_files', 'surface.verbose_errors'],
  'ctrl-cis-07': ['transport.https_primary', 'headers.x-content-type-options'],
  'ctrl-cis-16': ['sca.manifest_analysis', 'sast.source_review'],

  // PCI DSS indicators
  'ctrl-pci-42': ['transport.https_primary', 'transport.tls_protocol', 'transport.tls_certificate'],
  'ctrl-pci-62': ['sca.manifest_analysis', 'sast.source_review', 'surface.dom_xss_indicator'],
  'ctrl-pci-643': ['headers.content-security-policy'],

  // GDPR Art 32 indicators
  'ctrl-gdpr-32': ['transport.https_primary', 'auth.cookie_attributes', 'surface.sensitive_files'],
  'ctrl-gdpr-rest': ['data.encryption_at_rest'],
};

export function generateComplianceMappingsForScan(db: DatabaseSync, scanId: string): void {
  db.prepare('DELETE FROM compliance_mappings WHERE scan_id = ?').run(scanId);

  const checks = db
    .prepare('SELECT id, check_key, status, owasp_category FROM security_checks WHERE scan_id = ?')
    .all(scanId) as unknown as CheckRow[];

  const vulns = db
    .prepare('SELECT id, owasp_category, owasp_api_category, verification_status FROM vulnerabilities WHERE latest_scan_id = ?')
    .all(scanId) as unknown as VulnRow[];

  const controls = db
    .prepare('SELECT id, framework_id, control_code, evidence_required, automatable FROM compliance_controls')
    .all() as unknown as Array<{
      id: string;
      framework_id: string;
      control_code: string;
      evidence_required: string;
      automatable: number;
    }>;

  const insert = db.prepare(
    `INSERT INTO compliance_mappings (id, scan_id, framework_id, control_id, status, linked_check_ids_json, linked_finding_ids_json, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  for (const ctrl of controls) {
    const keys = CONTROL_TO_CHECK_KEYS[ctrl.id] || [];
    const matchedChecks = checks.filter((c) => keys.includes(c.check_key));
    const matchedFindings = vulns.filter(
      (v) =>
        v.verification_status !== 'false_positive' &&
        ((v.owasp_category && ctrl.control_code.startsWith(v.owasp_category.split(':')[0])) ||
          (v.owasp_api_category && ctrl.control_code.startsWith(v.owasp_api_category.split(':')[0])))
    );

    const evaluatedChecks = matchedChecks.filter((c) => c.status === 'passed' || c.status === 'failed' || c.status === 'potential');
    const failedChecks = matchedChecks.filter((c) => c.status === 'failed');
    const potentialOrManual = matchedChecks.filter((c) => c.status === 'potential' || c.status === 'manual_required');

    let status: 'passed' | 'failed' | 'not_assessed' | 'partial' = 'not_assessed';
    let notes = `Requires: ${ctrl.evidence_required}.`;

    if (ctrl.automatable === 0 || (evaluatedChecks.length === 0 && matchedFindings.length === 0)) {
      status = 'not_assessed';
      notes = `Not automatically verified. ${ctrl.evidence_required}.`;
    } else if (failedChecks.length > 0 || matchedFindings.length > 0) {
      status = 'failed';
      notes = `${failedChecks.length} failed technical check(s) and ${matchedFindings.length} open finding(s) observed.`;
    } else if (potentialOrManual.length > 0) {
      status = 'partial';
      notes = `Automated checks passed, but ${potentialOrManual.length} indicator(s) require manual/authenticated review.`;
    } else {
      status = 'passed';
      notes = `All ${evaluatedChecks.length} mapped technical indicator check(s) passed in this scan (observational only).`;
    }

    insert.run(
      crypto.randomUUID(),
      scanId,
      ctrl.framework_id,
      ctrl.id,
      status,
      JSON.stringify(matchedChecks.map((c) => c.id)),
      JSON.stringify(matchedFindings.map((v) => v.id)),
      notes
    );
  }
}
