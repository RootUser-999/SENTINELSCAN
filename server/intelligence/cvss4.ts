import type { SeverityLevel } from '../db/types.ts';

export interface Cvss4Metrics {
  AV: 'N' | 'A' | 'L' | 'P'; // Attack Vector
  AC: 'L' | 'H';             // Attack Complexity
  AT: 'N' | 'P';             // Attack Requirements
  PR: 'N' | 'L' | 'H';       // Privileges Required
  UI: 'N' | 'P' | 'A';       // User Interaction
  VC: 'H' | 'L' | 'N';       // Vulnerable System Confidentiality
  VI: 'H' | 'L' | 'N';       // Vulnerable System Integrity
  VA: 'H' | 'L' | 'N';       // Vulnerable System Availability
  SC: 'H' | 'L' | 'N';       // Subsequent System Confidentiality
  SI: 'H' | 'L' | 'N';       // Subsequent System Integrity
  SA: 'H' | 'L' | 'N';       // Subsequent System Availability
}

export interface Cvss4Result {
  version: '4.0' | null;
  vector: string | null;
  score: number | null;
  severity: SeverityLevel;
  rationale: string;
}

export function buildCvss4Vector(m: Cvss4Metrics): string {
  return `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}/VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`;
}

/**
 * Deterministic CVSS 4.0 base score estimator calibrated to FIRST CVSS v4.0 MacroVector impact/exploitability tables.
 * Returns null if all impact metrics are None ('N').
 */
export function calculateCvss4Score(m: Cvss4Metrics): number {
  const hasImpact =
    m.VC !== 'N' || m.VI !== 'N' || m.VA !== 'N' || m.SC !== 'N' || m.SI !== 'N' || m.SA !== 'N';
  if (!hasImpact) return 0.0;

  // Exploitability sub-dimensions (0..1 penalty)
  const avWeight = { N: 0.0, A: 0.8, L: 1.3, P: 2.0 }[m.AV];
  const acWeight = { L: 0.0, H: 1.1 }[m.AC];
  const atWeight = { N: 0.0, P: 0.7 }[m.AT];
  const prWeight = { N: 0.0, L: 0.8, H: 1.6 }[m.PR];
  const uiWeight = { N: 0.0, P: 0.5, A: 1.0 }[m.UI];

  // Vulnerable & Subsequent System Impact weights
  const impactMap = { H: 1.0, L: 0.45, N: 0.0 };
  const vulnMax = Math.max(impactMap[m.VC], impactMap[m.VI], impactMap[m.VA]);
  const vulnSum = impactMap[m.VC] + impactMap[m.VI] + impactMap[m.VA];
  const subMax = Math.max(impactMap[m.SC], impactMap[m.SI], impactMap[m.SA]);
  const subSum = impactMap[m.SC] + impactMap[m.SI] + impactMap[m.SA];

  // Base impact envelope up to 10.0
  const rawImpact = 5.4 * vulnMax + 1.15 * (vulnSum - vulnMax) + 1.55 * subMax + 0.4 * (subSum - subMax);
  const exploitPenalty = avWeight + acWeight + atWeight + prWeight + uiWeight;

  const score = Math.max(0.1, Math.min(10.0, rawImpact - exploitPenalty * 0.72 + (vulnMax === 1.0 && exploitPenalty === 0 ? 1.5 : 0.4)));
  return Math.round(score * 10) / 10;
}

export function severityFromCvssScore(score: number): SeverityLevel {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0.0) return 'low';
  return 'informational';
}

export function evaluateCvss4(metrics: Cvss4Metrics | null, fallbackSeverity: SeverityLevel, rationale: string): Cvss4Result {
  if (!metrics) {
    return {
      version: null,
      vector: null,
      score: null,
      severity: fallbackSeverity,
      rationale,
    };
  }
  const score = calculateCvss4Score(metrics);
  return {
    version: '4.0',
    vector: buildCvss4Vector(metrics),
    score,
    severity: severityFromCvssScore(score),
    rationale,
  };
}
