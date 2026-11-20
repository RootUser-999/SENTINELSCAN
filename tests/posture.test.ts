import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateCvss4Score, evaluateCvss4 } from '../server/intelligence/cvss4.ts';
import { calculatePostureScore } from '../server/intelligence/posture.ts';
import { isPrivateOrReservedIp, validateTargetUrl, PRACTICE_LAB_HOSTNAME } from '../server/security/ssrfGuard.ts';
import { analyzeSecurityHeaders } from '../server/scanner/modules/securityHeaders.ts';
import { encryptSecret, decryptSecret, redactSecrets } from '../server/security/cryptoVault.ts';

test('CVSS 4.0 calculates deterministic high score and omits score when metrics are null', () => {
  const highScore = calculateCvss4Score({
    AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
    VC: 'H', VI: 'H', VA: 'N', SC: 'H', SI: 'N', SA: 'N',
  });
  assert.ok(highScore >= 9.0 && highScore <= 10.0);

  const omitted = evaluateCvss4(null, 'informational', 'Insufficient evidence');
  assert.equal(omitted.score, null);
  assert.equal(omitted.vector, null);
  assert.equal(omitted.severity, 'informational');
});

test('Posture scoring returns null when 0 checks executed and deducts active findings only', () => {
  const empty = calculatePostureScore({ passedChecks: 0, failedChecks: 0, findings: [] });
  assert.equal(empty.score, null);
  assert.equal(empty.grade, 'N/A');

  const healthy = calculatePostureScore({
    passedChecks: 10,
    failedChecks: 0,
    findings: [
      { severity: 'critical', verificationStatus: 'remediated' },
      { severity: 'high', verificationStatus: 'false_positive' },
    ],
  });
  assert.equal(healthy.score, 100);
  assert.equal(healthy.grade, 'A');

  const degraded = calculatePostureScore({
    passedChecks: 5,
    failedChecks: 5,
    findings: [{ severity: 'critical', verificationStatus: 'open' }],
  });
  // 50% of 40 = 20, plus (60 - 18) = 42 => 62
  assert.equal(degraded.score, 62);
  assert.equal(degraded.grade, 'C');
});

test('SSRF Guard blocks private, loopback, metadata, and IPv4-mapped IPv6 addresses', async () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('10.24.1.5'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.10'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);

  await assert.rejects(() => validateTargetUrl('http://127.0.0.1:3000'));
  await assert.rejects(() => validateTargetUrl('http://169.254.169.254/latest/meta-data/'));
  await assert.rejects(() => validateTargetUrl(`https://${PRACTICE_LAB_HOSTNAME}`, { allowPracticeTarget: false }));

  const lab = await validateTargetUrl(`https://${PRACTICE_LAB_HOSTNAME}`, { allowPracticeTarget: true });
  assert.equal(lab.isPracticeTarget, true);
});

test('Security header analyzer inspects directives rather than mere existence', () => {
  const weak = analyzeSecurityHeaders(
    {
      'content-security-policy': "default-src 'self' 'unsafe-inline'",
      'x-content-type-options': 'nosniff',
    },
    true
  );
  const cspCheck = weak.find((h) => h.header === 'Content-Security-Policy');
  const hstsCheck = weak.find((h) => h.header === 'Strict-Transport-Security');
  const xctoCheck = weak.find((h) => h.header === 'X-Content-Type-Options');
  assert.equal(cspCheck?.status, 'failed');
  assert.equal(hstsCheck?.status, 'failed');
  assert.equal(xctoCheck?.status, 'passed');
});

test('Credential vault encrypts, decrypts, and redacts secrets', () => {
  const secret = 'super-secret-jwt-token-xyz';
  const enc = encryptSecret(secret);
  assert.notEqual(enc.ciphertextHex, secret);
  assert.equal(decryptSecret(enc), secret);
  assert.equal(redactSecrets(`Authorization: Bearer ${secret}`, [secret]), 'Authorization: Bearer [REDACTED]');
});
