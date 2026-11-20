import PDFDocument from 'pdfkit';
import type { DatabaseSync } from 'node:sqlite';
import { normalizeCheckOutcome } from '../db/types.ts';
import { buildStructuredReportData } from './jsonExporter.ts';

const COLORS = {
  navy: '#0F172A',
  slate: '#1E293B',
  muted: '#475569',
  lightBg: '#F8FAFC',
  border: '#CBD5E1',
  blue: '#2563EB',
  critical: '#DC2626',
  high: '#EA580C',
  medium: '#D97706',
  low: '#0284C7',
  info: '#64748B',
  passed: '#16A34A',
};

function severityColor(sev: string): string {
  switch (sev) {
    case 'critical':
      return COLORS.critical;
    case 'high':
      return COLORS.high;
    case 'medium':
      return COLORS.medium;
    case 'low':
      return COLORS.low;
    default:
      return COLORS.info;
  }
}

export async function generatePdfReportBuffer(
  db: DatabaseSync,
  scanId: string,
  organizationId: string
): Promise<{ filename: string; buffer: Buffer } | null> {
  const data = buildStructuredReportData(db, scanId, organizationId);
  if (!data) return null;

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 50,
      bufferPages: true,
      info: {
        Title: `SentinelScan Security Assessment - ${data.metadata.targetName}`,
        Author: 'SentinelScan Platform',
        Subject: `Assessment ID ${data.metadata.assessmentId}`,
      },
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => {
      resolve({
        filename: `sentinelscan-report-${String(scanId).slice(0, 8)}.pdf`,
        buffer: Buffer.concat(chunks),
      });
    });
    doc.on('error', reject);

    const pageWidth = doc.page.width - 100;

    // === PAGE 1: PROFESSIONAL COVER PAGE ===
    doc.rect(0, 0, doc.page.width, 210).fill(COLORS.navy);
    doc.fillColor('#93C5FD').fontSize(10).font('Helvetica-Bold').text('SENTINELSCAN ENTERPRISE SECURITY ASSESSMENT', 50, 56);
    doc.fillColor('#FFFFFF').fontSize(26).font('Helvetica-Bold').text('Web Application Security\nAssessment Report', 50, 82);
    doc.fillColor('#CBD5E1').fontSize(11).font('Helvetica').text(`Prepared for ${data.metadata.organization}`, 50, 158);

    let y = 245;
    doc.fillColor(COLORS.navy).fontSize(13).font('Helvetica-Bold').text('Assessment Metadata & Authorization Scope', 50, y);
    y += 22;

    const metaPairs: Array<[string, string]> = [
      ['Target Application', String(data.metadata.targetName)],
      ['Target URL', String(data.metadata.targetUrl)],
      ['Environment / Criticality', `${data.metadata.environment} / ${data.metadata.criticality}`],
      ['Assessment ID', String(data.metadata.assessmentId)],
      ['Scan Profile & Status', `${String(data.metadata.profile).toUpperCase()} (${data.metadata.status})`],
      ['Started / Completed', `${data.metadata.startedAt || 'N/A'} — ${data.metadata.completedAt || 'N/A'}`],
      ['Execution Duration', data.metadata.durationMs ? `${(Number(data.metadata.durationMs) / 1000).toFixed(2)} seconds` : 'N/A'],
      ['Ownership & Auth Sign-off', `${data.metadata.ownershipStatus} (Authorized by ${data.metadata.authorizationSignedBy || 'N/A'})`],
      ['Included Scope Paths', String(data.metadata.scopeIncludePaths || '/')],
      ['Initiated By', String(data.metadata.initiatedBy)],
    ];

    doc.rect(50, y, pageWidth, metaPairs.length * 24 + 12).fill(COLORS.lightBg).stroke(COLORS.border);
    let my = y + 10;
    for (const [k, v] of metaPairs) {
      doc.fillColor(COLORS.muted).fontSize(9).font('Helvetica-Bold').text(k, 62, my, { width: 155 });
      doc.fillColor(COLORS.navy).fontSize(9).font('Helvetica').text(v, 222, my, { width: pageWidth - 180 });
      my += 24;
    }

    y = my + 24;
    doc.fillColor(COLORS.navy).fontSize(11).font('Helvetica-Bold').text('Methodology & Non-Certification Notice', 50, y);
    y += 16;
    doc.fillColor(COLORS.muted).fontSize(9).font('Helvetica').text(
      data.limitationsAndDisclaimers.join(' '),
      50,
      y,
      { width: pageWidth, lineGap: 3 }
    );

    // === PAGE 2: EXECUTIVE SUMMARY & CHARTS ===
    doc.addPage();
    y = 65;
    doc.fillColor(COLORS.navy).fontSize(16).font('Helvetica-Bold').text('1. Executive Summary & Security Posture', 50, y);
    y += 26;

    const es = data.executiveSummary;
    const scoreDisplay = es.postureScore !== null ? `${es.postureScore} / 100` : 'N/A';

    const kpis: Array<[string, string, string]> = [
      ['Posture Score', scoreDisplay, COLORS.blue],
      ['Total Checks', String(es.totalChecks), COLORS.navy],
      ['PASS', String(es.passedChecks), COLORS.passed],
      ['FAIL', String(es.failedChecks), COLORS.critical],
      ['MANUAL_REQUIRED', String(es.manualRequiredChecks), COLORS.medium],
    ];
    const boxW = (pageWidth - 24) / 5;
    kpis.forEach(([label, val, col], idx) => {
      const bx = 50 + idx * (boxW + 6);
      doc.rect(bx, y, boxW, 52).fill(COLORS.lightBg).stroke(COLORS.border);
      doc.fillColor(COLORS.muted).fontSize(7.5).font('Helvetica-Bold').text(label, bx + 8, y + 10, { width: boxW - 16 });
      doc.fillColor(col).fontSize(14).font('Helvetica-Bold').text(val, bx + 8, y + 26, { width: boxW - 16 });
    });

    y += 72;
    doc.fillColor(COLORS.navy).fontSize(12).font('Helvetica-Bold').text(
      `Active Vulnerability Severity Distribution (${es.activeFindingsTotal} Active / ${es.allScanFindingsTotal} Total Detected)`,
      50,
      y
    );
    y += 18;

    const sevBars: Array<[string, number, string]> = [
      ['Critical', Number(es.severityDistribution.critical), COLORS.critical],
      ['High', Number(es.severityDistribution.high), COLORS.high],
      ['Medium', Number(es.severityDistribution.medium), COLORS.medium],
      ['Low', Number(es.severityDistribution.low), COLORS.low],
      ['Informational', Number(es.severityDistribution.informational), COLORS.info],
    ];
    const maxSev = Math.max(1, ...sevBars.map((s) => s[1]));

    for (const [label, count, color] of sevBars) {
      doc.fillColor(COLORS.slate).fontSize(9).font('Helvetica-Bold').text(label, 50, y + 3, { width: 80 });
      doc.rect(135, y + 2, 290, 12).fill('#E2E8F0');
      const barW = count > 0 ? Math.max(6, (count / maxSev) * 290) : 0;
      if (barW > 0) doc.rect(135, y + 2, barW, 12).fill(color);
      doc.fillColor(COLORS.navy).fontSize(9).font('Helvetica-Bold').text(String(count), 435, y + 3);
      y += 20;
    }

    y += 14;
    doc.fillColor(COLORS.navy).fontSize(12).font('Helvetica-Bold').text('Normalized Check Outcomes (Reconciled Total: ' + es.totalChecks + ')', 50, y);
    y += 18;
    const outcomeRows: Array<[string, number]> = [
      ['PASS (Verified Compliant)', Number(es.passedChecks)],
      ['FAIL (Confirmed Weakness)', Number(es.failedChecks)],
      ['POTENTIAL (Requires Verification)', Number(es.potentialChecks)],
      ['INFORMATIONAL (Observations)', Number(es.informationalChecks)],
      ['MANUAL_REQUIRED (Manual / Authenticated Verification)', Number(es.manualRequiredChecks)],
      ['NOT_APPLICABLE', Number(es.notApplicableChecks)],
      ['NOT_PERFORMED (Skipped / Missing Input or CLI)', Number(es.notPerformedChecks)],
    ];
    for (const [label, count] of outcomeRows) {
      doc.fillColor(COLORS.muted).fontSize(9).font('Helvetica').text(label, 55, y, { width: 300 });
      doc.fillColor(COLORS.navy).fontSize(9).font('Helvetica-Bold').text(String(count), 360, y);
      y += 16;
    }

    y += 14;
    doc.fillColor(COLORS.navy).fontSize(12).font('Helvetica-Bold').text('Scanner Module Executions', 50, y);
    y += 16;
    for (const mod of data.moduleExecutions) {
      if (y > 740) { doc.addPage(); y = 65; }
      doc.fillColor(COLORS.slate).fontSize(8.5).font('Helvetica-Bold').text(`${mod.module_name} (v${mod.module_version})`, 50, y, { width: 250 });
      doc.fillColor(COLORS.muted).fontSize(8.5).font('Helvetica').text(
        `Status: ${mod.status} · Checks: ${mod.checks_executed} · Findings: ${mod.findings_created} · ${mod.duration_ms ?? 0}ms`,
        305,
        y,
        { width: pageWidth - 255 }
      );
      y += 15;
    }

    // === PAGE 3+: DETAILED TECHNICAL FINDINGS ===
    doc.addPage();
    y = 65;
    doc.fillColor(COLORS.navy).fontSize(16).font('Helvetica-Bold').text('2. Detailed Technical Findings', 50, y);
    y += 24;

    if (data.findings.length === 0) {
      doc.fillColor(COLORS.muted).fontSize(10).font('Helvetica').text('No vulnerabilities were recorded for this assessment.', 50, y);
    } else {
      for (const f of data.findings) {
        if (y > 650) { doc.addPage(); y = 65; }
        const sev = String(f.severity || 'informational');
        doc.rect(50, y, pageWidth, 22).fill(COLORS.lightBg).stroke(COLORS.border);
        doc.fillColor(severityColor(sev)).fontSize(9).font('Helvetica-Bold').text(sev.toUpperCase(), 58, y + 6, { width: 70 });
        doc.fillColor(COLORS.navy).fontSize(9.5).font('Helvetica-Bold').text(`${f.finding_code} — ${f.title}`, 132, y + 6, { width: pageWidth - 140 });
        y += 28;

        const metaLine = [
          `Status: ${f.verification_status}`,
          `Confidence: ${f.confidence}`,
          f.cvss_score ? `CVSS ${f.cvss_version}: ${f.cvss_score}` : 'CVSS: Not assigned',
          f.cwe_id || null,
          f.cve_id || null,
          f.owasp_category || null,
          f.owasp_api_category || null,
        ].filter(Boolean).join('  |  ');

        doc.fillColor(COLORS.muted).fontSize(8).font('Helvetica-Bold').text(metaLine, 50, y, { width: pageWidth });
        y += 14;
        doc.fillColor(COLORS.slate).fontSize(8.5).font('Helvetica').text(
          `Affected Endpoint: ${f.http_method ? `${f.http_method} ` : ''}${f.affected_url}${f.parameter_name ? ` (param: ${f.parameter_name})` : ''}`,
          50,
          y,
          { width: pageWidth }
        );
        y += 14;
        if (f.detection_technique) {
          doc.fillColor(COLORS.muted).fontSize(8).font('Helvetica').text(`Detection Technique: ${f.detection_technique}`, 50, y, { width: pageWidth });
          y = doc.y + 4;
        }
        doc.fillColor(COLORS.navy).fontSize(8.5).font('Helvetica').text(`Description: ${f.description}`, 50, y, { width: pageWidth });
        y = doc.y + 4;
        doc.fillColor(COLORS.muted).fontSize(8.5).font('Helvetica').text(`Technical Detail: ${f.technical_explanation}`, 50, y, { width: pageWidth });
        y = doc.y + 4;

        const evList = (f.evidence as Array<{ summary: string; raw_excerpt: string }>) || [];
        if (evList.length > 0) {
          const excerpt = `${evList[0].summary}: ${evList[0].raw_excerpt.slice(0, 260)}`;
          doc.fillColor(COLORS.slate).fontSize(8).font('Courier').text(excerpt, 56, y, { width: pageWidth - 12 });
          y = doc.y + 6;
        }

        doc.fillColor(COLORS.blue).fontSize(8.5).font('Helvetica-Bold').text(`Remediation: ${f.remediation_instructions}`, 50, y, { width: pageWidth });
        y = doc.y + 14;
      }
    }

    // === SECTION 3: SECURITY HEADERS & CHECKS ===
    doc.addPage();
    y = 65;
    doc.fillColor(COLORS.navy).fontSize(16).font('Helvetica-Bold').text('3. Security Checks & Configuration Ledger', 50, y);
    y += 24;

    for (const chk of data.securityChecks) {
      if (y > 725) { doc.addPage(); y = 65; }
      const stNorm = normalizeCheckOutcome(String(chk.status));
      const stColor =
        stNorm === 'PASS'
          ? COLORS.passed
          : stNorm === 'FAIL'
            ? COLORS.critical
            : stNorm === 'POTENTIAL' || stNorm === 'MANUAL_REQUIRED'
              ? COLORS.medium
              : COLORS.muted;
      doc.fillColor(stColor).fontSize(7.5).font('Helvetica-Bold').text(stNorm, 50, y, { width: 95 });
      doc.fillColor(COLORS.navy).fontSize(8.5).font('Helvetica-Bold').text(String(chk.title), 150, y, { width: pageWidth - 100 });
      y = doc.y + 2;
      doc.fillColor(COLORS.muted).fontSize(8).font('Helvetica').text(
        `Observed: ${String(chk.observed_value || 'N/A').slice(0, 140)}`,
        150,
        y,
        { width: pageWidth - 100 }
      );
      y = doc.y + 8;
    }

    // === SECTION 4: COMPLIANCE COVERAGE & ROADMAP ===
    doc.addPage();
    y = 65;
    doc.fillColor(COLORS.navy).fontSize(16).font('Helvetica-Bold').text('4. Compliance Framework Observations & Roadmap', 50, y);
    y += 20;
    doc.fillColor(COLORS.muted).fontSize(8.5).font('Helvetica').text(
      'Observational mapping only. Automated scanning cannot establish legal or regulatory certification (GDPR, PCI DSS, ISO 27001).',
      50,
      y,
      { width: pageWidth }
    );
    y += 22;

    for (const m of data.complianceMapping) {
      if (y > 730) { doc.addPage(); y = 65; }
      const normM = normalizeCheckOutcome(String(m.status));
      doc.fillColor(COLORS.navy).fontSize(8.5).font('Helvetica-Bold').text(
        `${m.framework_name} ${m.control_code} — ${m.control_title}`,
        50,
        y,
        { width: 320 }
      );
      doc.fillColor(normM === 'PASS' ? COLORS.passed : normM === 'FAIL' ? COLORS.critical : COLORS.muted)
        .fontSize(8)
        .font('Helvetica-Bold')
        .text(normM, 380, y, { width: 110 });
      y = doc.y + 2;
      doc.fillColor(COLORS.muted).fontSize(7.5).font('Helvetica').text(String(m.notes), 50, y, { width: pageWidth });
      y = doc.y + 8;
    }

    y += 14;
    if (y > 680) { doc.addPage(); y = 65; }
    doc.fillColor(COLORS.navy).fontSize(13).font('Helvetica-Bold').text('Prioritized Remediation Roadmap', 50, y);
    y += 18;
    doc.fillColor(COLORS.slate).fontSize(9).font('Helvetica').text(
      '1. Immediate (0–7 days): Remediate Critical/High exposures (SQL/NoSQL injection, XSS, path traversal, exposed .env/VCS files, hardcoded secrets, unauthenticated sensitive API endpoints).\n' +
      '2. Short-Term (7–30 days): Enforce strict CSP, HSTS, X-Frame-Options, CORS allowlisting, HttpOnly/Secure session cookies, and upgrade vulnerable dependencies.\n' +
      '3. Medium-Term (30–90 days): Complete all MANUAL_REQUIRED assessments (Argon2/bcrypt verification, encryption at rest, MFA/lockout policies, and role-based penetration testing).',
      50,
      y,
      { width: pageWidth, lineGap: 4 }
    );

    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
      doc.switchToPage(i);
      if (i > 0) {
        doc.fillColor(COLORS.muted).fontSize(8).font('Helvetica').text(
          `SentinelScan Security Assessment  |  ${data.metadata.targetName}  |  ID: ${String(scanId).slice(0, 8)}`,
          50,
          28,
          { width: pageWidth }
        );
        doc.moveTo(50, 42).lineTo(50 + pageWidth, 42).strokeColor(COLORS.border).lineWidth(0.5).stroke();
      }
      doc.fillColor(COLORS.muted).fontSize(8).font('Helvetica').text(
        `Confidential — ${data.metadata.organization}`,
        50,
        doc.page.height - 36,
        { width: pageWidth / 2 }
      );
      doc.text(
        `Page ${i + 1} of ${range.count}`,
        50 + pageWidth / 2,
        doc.page.height - 36,
        { width: pageWidth / 2, align: 'right' }
      );
    }

    doc.end();
  });
}
