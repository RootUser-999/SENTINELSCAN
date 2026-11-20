import type { SeverityLevel, VerificationStatus } from '../db/types.ts';

export interface PostureInput {
  passedChecks: number;
  failedChecks: number;
  findings: Array<{
    severity: SeverityLevel;
    verificationStatus: VerificationStatus;
  }>;
}

export interface PostureResult {
  score: number | null;
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | 'N/A';
  checkPassRatePct: number | null;
  severityPenalty: number;
  activeFindingsCount: number;
  formulaDescription: string;
  disclaimer: string;
}

const ACTIVE_STATUSES = new Set<VerificationStatus>(['open', 'confirmed', 'reopened']);

export function calculatePostureScore(input: PostureInput): PostureResult {
  const totalEvaluatedChecks = input.passedChecks + input.failedChecks;
  const disclaimer =
    'Posture score reflects only the automated checks executed within configured scan scope. It does not guarantee total security or regulatory compliance.';
  const formulaDescription =
    'Score = (Check Pass Ratio × 40) + max(0, 60 − Severity Penalty), where Critical=18, High=10, Medium=4, Low=1.5 for active open/confirmed/reopened findings.';

  if (totalEvaluatedChecks === 0 && input.findings.length === 0) {
    return {
      score: null,
      grade: 'N/A',
      checkPassRatePct: null,
      severityPenalty: 0,
      activeFindingsCount: 0,
      formulaDescription,
      disclaimer,
    };
  }

  const checkPassRate = totalEvaluatedChecks > 0 ? input.passedChecks / totalEvaluatedChecks : 1;
  const checkComponent = checkPassRate * 40;

  let penalty = 0;
  let activeCount = 0;

  for (const f of input.findings) {
    if (!ACTIVE_STATUSES.has(f.verificationStatus)) continue;
    activeCount += 1;
    if (f.severity === 'critical') penalty += 18;
    else if (f.severity === 'high') penalty += 10;
    else if (f.severity === 'medium') penalty += 4;
    else if (f.severity === 'low') penalty += 1.5;
  }

  const cappedPenalty = Math.min(60, penalty);
  const rawScore = checkComponent + Math.max(0, 60 - cappedPenalty);
  const score = Math.round(rawScore * 10) / 10;

  let grade: PostureResult['grade'] = 'F';
  if (score >= 90) grade = 'A';
  else if (score >= 78) grade = 'B';
  else if (score >= 62) grade = 'C';
  else if (score >= 45) grade = 'D';

  return {
    score,
    grade,
    checkPassRatePct: totalEvaluatedChecks > 0 ? Math.round(checkPassRate * 1000) / 10 : null,
    severityPenalty: Math.round(cappedPenalty * 10) / 10,
    activeFindingsCount: activeCount,
    formulaDescription,
    disclaimer,
  };
}
