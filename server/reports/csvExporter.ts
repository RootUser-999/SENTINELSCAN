import type { DatabaseSync } from 'node:sqlite';

export type CsvExportScope =
  | 'all-findings'
  | 'passed-checks'
  | 'failed-checks'
  | 'vulnerability-inventory'
  | 'endpoint-inventory'
  | 'security-headers'
  | 'compliance-mapping';

function escapeCsvCell(val: unknown): string {
  const raw = val === null || val === undefined ? '' : String(val);
  // Neutralize CSV spreadsheet formula injection
  const safe = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  if (/[",\r\n]/.test(safe)) {
    return `"${safe.replace(/"/g, '""')}"`;
  }
  return safe;
}

function toCsv(headers: string[], rows: Array<Array<unknown>>): string {
  const lines = [headers.map(escapeCsvCell).join(',')];
  for (const row of rows) {
    lines.push(row.map(escapeCsvCell).join(','));
  }
  return lines.join('\r\n');
}

export function generateCsvReport(
  db: DatabaseSync,
  scanId: string,
  organizationId: string,
  scope: CsvExportScope
): { filename: string; content: string } {
  const shortId = scanId.slice(0, 8);

  if (scope === 'passed-checks' || scope === 'failed-checks') {
    const targetStatus = scope === 'passed-checks' ? 'passed' : 'failed';
    const rows = db
      .prepare(
        `SELECT check_key, title, category, status, observed_value, expected_value, cwe_id, owasp_category, explanation, remediation
         FROM security_checks WHERE scan_id = ? AND status = ? ORDER BY category, title`
      )
      .all(scanId, targetStatus) as Array<Record<string, unknown>>;

    return {
      filename: `sentinelscan-${shortId}-${scope}.csv`,
      content: toCsv(
        ['Check Key', 'Title', 'Category', 'Status', 'Observed Value', 'Expected Value', 'CWE', 'OWASP', 'Explanation', 'Remediation'],
        rows.map((r) => [
          r.check_key,
          r.title,
          r.category,
          r.status,
          r.observed_value,
          r.expected_value,
          r.cwe_id,
          r.owasp_category,
          r.explanation,
          r.remediation,
        ])
      ),
    };
  }

  if (scope === 'security-headers') {
    const rows = db
      .prepare(
        `SELECT title, status, observed_value, expected_value, explanation, remediation
         FROM security_checks WHERE scan_id = ? AND check_key LIKE 'headers.%' ORDER BY title`
      )
      .all(scanId) as Array<Record<string, unknown>>;

    return {
      filename: `sentinelscan-${shortId}-security-headers.csv`,
      content: toCsv(
        ['Header', 'Status', 'Observed Value', 'Recommended Configuration', 'Impact & Analysis', 'Remediation'],
        rows.map((r) => [r.title, r.status, r.observed_value, r.expected_value, r.explanation, r.remediation])
      ),
    };
  }

  if (scope === 'endpoint-inventory') {
    const rows = db
      .prepare(
        `SELECT method, path, url, source, auth_required, status_code, content_type, parameters_json, notes
         FROM endpoints WHERE scan_id = ? ORDER BY path, method`
      )
      .all(scanId) as Array<Record<string, unknown>>;

    return {
      filename: `sentinelscan-${shortId}-endpoint-inventory.csv`,
      content: toCsv(
        ['Method', 'Path', 'URL', 'Discovery Source', 'Authentication', 'Status Code', 'Content-Type', 'Parameters', 'Notes'],
        rows.map((r) => [
          r.method,
          r.path,
          r.url,
          r.source,
          r.auth_required,
          r.status_code,
          r.content_type,
          r.parameters_json,
          r.notes,
        ])
      ),
    };
  }

  if (scope === 'compliance-mapping') {
    const rows = db
      .prepare(
        `SELECT f.name as framework, f.version, c.control_code, c.title, m.status, c.evidence_required, m.notes
         FROM compliance_mappings m
         JOIN compliance_frameworks f ON f.id = m.framework_id
         JOIN compliance_controls c ON c.id = m.control_id
         WHERE m.scan_id = ?
         ORDER BY f.name, c.control_code`
      )
      .all(scanId) as Array<Record<string, unknown>>;

    return {
      filename: `sentinelscan-${shortId}-compliance-mapping.csv`,
      content: toCsv(
        ['Framework', 'Version', 'Control Code', 'Control Title', 'Assessed Status', 'Evidence Required', 'Assessment Notes'],
        rows.map((r) => [r.framework, r.version, r.control_code, r.title, r.status, r.evidence_required, r.notes])
      ),
    };
  }

  // 'all-findings' or 'vulnerability-inventory'
  const rows = db
    .prepare(
      `SELECT v.finding_code, v.title, v.severity, v.verification_status, v.category, v.affected_url, v.http_method,
              v.parameter_name, v.cvss_version, v.cvss_score, v.cvss_vector, v.cwe_id, v.cve_id, v.owasp_category,
              v.owasp_api_category, v.confidence, v.scanner_module, v.detected_at, v.remediation_instructions
       FROM vulnerabilities v
       WHERE v.organization_id = ? AND v.latest_scan_id = ?
       ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, v.detected_at DESC`
    )
    .all(organizationId, scanId) as Array<Record<string, unknown>>;

  return {
    filename: `sentinelscan-${shortId}-${scope}.csv`,
    content: toCsv(
      [
        'Finding ID',
        'Title',
        'Severity',
        'Status',
        'Category',
        'Affected URL',
        'Method',
        'Parameter',
        'CVSS Version',
        'CVSS Score',
        'CVSS Vector',
        'CWE',
        'CVE',
        'OWASP Top 10',
        'OWASP API Top 10',
        'Confidence',
        'Scanner Module',
        'Detected At',
        'Remediation',
      ],
      rows.map((r) => [
        r.finding_code,
        r.title,
        r.severity,
        r.verification_status,
        r.category,
        r.affected_url,
        r.http_method,
        r.parameter_name,
        r.cvss_version,
        r.cvss_score,
        r.cvss_vector,
        r.cwe_id,
        r.cve_id,
        r.owasp_category,
        r.owasp_api_category,
        r.confidence,
        r.scanner_module,
        r.detected_at,
        r.remediation_instructions,
      ])
    ),
  };
}
