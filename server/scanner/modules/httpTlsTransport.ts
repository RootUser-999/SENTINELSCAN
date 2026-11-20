import tls from 'node:tls';
import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

interface TlsInspection {
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipherName: string | null;
  subjectCN: string | null;
  issuerO: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
}

async function inspectRealTls(hostname: string, port: number, timeoutMs: number): Promise<TlsInspection> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        try {
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();
          const cert = socket.getPeerCertificate();
          const validToDate = cert?.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining = validToDate
            ? Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : null;
          const subjectCN = typeof cert?.subject?.CN === 'string' ? cert.subject.CN : null;
          const issuerO =
            typeof cert?.issuer?.O === 'string'
              ? cert.issuer.O
              : typeof cert?.issuer?.CN === 'string'
                ? cert.issuer.CN
                : null;

          socket.end();
          resolve({
            authorized: socket.authorized,
            authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
            protocol: protocol || null,
            cipherName: cipher?.name || null,
            subjectCN,
            issuerO,
            validFrom: cert?.valid_from || null,
            validTo: cert?.valid_to || null,
            daysRemaining,
          });
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error('TLS handshake timed out'));
    });

    socket.on('error', (err) => {
      reject(err);
    });
  });
}

export const httpTlsTransportModule: ScannerModule = {
  id: 'http-tls-transport',
  name: 'HTTP & TLS Transport Inspector',
  version: '1.2.0',
  category: 'Data Protection & Transport Security',
  description: 'Evaluates HTTPS enforcement, HTTP-to-HTTPS redirection, TLS protocol/ciphers, certificate validity, and HSTS.',
  supportedProfiles: ['quick', 'standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 10000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const endpoints: ModuleExecutionResult['endpoints'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const parsedTarget = new URL(ctx.targetUrl);
    const httpsUrl = `https://${parsedTarget.host}${parsedTarget.pathname}${parsedTarget.search}`;
    const httpUrl = `http://${parsedTarget.host}${parsedTarget.pathname}`;

    // 1. Fetch primary target URL
    const primaryRes = await ctx.httpFetch(ctx.targetUrl);
    ctx.sharedState.homepageResponse = primaryRes;
    ctx.sharedState.discoveredUrls.add(primaryRes.finalUrl);

    endpoints.push({
      url: primaryRes.finalUrl,
      path: new URL(primaryRes.finalUrl).pathname,
      method: 'GET',
      source: 'probe',
      authRequired: 'unknown',
      statusCode: primaryRes.status,
      contentType: primaryRes.headers['content-type'] || null,
      parameters: [],
      notes: 'Primary target entry response',
    });

    const isHttps = new URL(primaryRes.finalUrl).protocol === 'https:';
    checks.push({
      checkKey: 'transport.https_primary',
      title: 'HTTPS Transport Enforcement',
      category: 'Transport Encryption',
      status: isHttps ? 'passed' : 'failed',
      observedValue: primaryRes.finalUrl,
      expectedValue: 'https:// scheme',
      explanation: isHttps
        ? 'Primary target endpoint serves traffic over HTTPS.'
        : 'Primary target endpoint resolved over unencrypted HTTP.',
      remediation: isHttps ? null : 'Serve all application traffic over HTTPS with TLS 1.2+.',
      cweId: 'CWE-319',
      owaspCategory: 'A02:2021',
    });

    if (!isHttps) {
      const cvss = evaluateCvss4(
        { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'N', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
        'high',
        'Cleartext HTTP transport observed directly on primary endpoint.'
      );
      findings.push({
        ruleId: 'TLS_NO_HTTPS',
        title: 'Application Accessible Over Unencrypted HTTP',
        category: 'Data Protection & Encryption',
        description: 'The primary target endpoint is served over unencrypted HTTP without enforcing HTTPS.',
        technicalExplanation: `Direct HTTP request to ${primaryRes.finalUrl} returned HTTP ${primaryRes.status} without redirecting to HTTPS.`,
        affectedUrl: primaryRes.finalUrl,
        httpMethod: 'GET',
        parameterName: null,
        confidence: 'high',
        severity: cvss.severity,
        cvssVersion: cvss.version,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        cvssRationale: cvss.rationale,
        cweId: 'CWE-319',
        cveId: null,
        owaspCategory: 'A02:2021',
        owaspApiCategory: null,
        businessImpact: 'Session cookies, credentials, and application payloads can be intercepted or modified on untrusted networks.',
        exploitationPrerequisites: 'Attacker positioned on the network path (MitM).',
        remediationInstructions: 'Configure the web server or load balancer to redirect all HTTP (port 80) requests with 301/308 to HTTPS and enable HSTS.',
        references: ['https://cwe.mitre.org/data/definitions/319.html'],
        evidence: [
          {
            evidenceType: 'http_response',
            summary: `HTTP ${primaryRes.status} served on cleartext URL`,
            rawExcerpt: `GET ${primaryRes.finalUrl} -> HTTP ${primaryRes.status}`,
          },
        ],
      });
    }

    // 2. HTTP -> HTTPS redirect verification
    try {
      const httpProbe = await ctx.httpFetch(httpUrl, { followRedirects: false });
      const location = httpProbe.headers['location'] || '';
      const redirectsToHttps =
        httpProbe.status >= 300 && httpProbe.status < 400 && location.toLowerCase().startsWith('https://');

      checks.push({
        checkKey: 'transport.http_to_https_redirect',
        title: 'HTTP-to-HTTPS Automatic Redirect',
        category: 'Transport Encryption',
        status: redirectsToHttps ? 'passed' : 'failed',
        observedValue: `HTTP ${httpProbe.status}${location ? ` -> ${location}` : ' (no redirect)'}`,
        expectedValue: '301/308 redirect to https://',
        explanation: redirectsToHttps
          ? `Plain HTTP requests are redirected to ${location} (${httpProbe.status}).`
          : `Plain HTTP request returned status ${httpProbe.status} without redirecting to HTTPS.`,
        remediation: redirectsToHttps
          ? null
          : 'Configure port 80 virtual host to return HTTP 301 or 308 redirecting to the canonical https:// origin.',
        cweId: 'CWE-319',
        owaspCategory: 'A02:2021',
      });

      if (!redirectsToHttps) {
        const cvss = evaluateCvss4(
          { AV: 'N', AC: 'H', AT: 'P', PR: 'N', UI: 'P', VC: 'L', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
          'medium',
          'HTTP listener serves content directly without redirecting to HTTPS.'
        );
        findings.push({
          ruleId: 'HTTP_REDIRECT_MISSING',
          title: 'Missing HTTP-to-HTTPS Redirect on Port 80',
          category: 'Data Protection & Encryption',
          description: 'Requests made over plain HTTP are not automatically redirected to HTTPS.',
          technicalExplanation: `Probing ${httpUrl} without following redirects returned HTTP ${httpProbe.status}.`,
          affectedUrl: httpUrl,
          httpMethod: 'GET',
          parameterName: null,
          confidence: 'high',
          severity: cvss.severity,
          cvssVersion: cvss.version,
          cvssScore: cvss.score,
          cvssVector: cvss.vector,
          cvssRationale: cvss.rationale,
          cweId: 'CWE-319',
          cveId: null,
          owaspCategory: 'A02:2021',
          owaspApiCategory: null,
          businessImpact: 'Users navigating without an explicit https:// scheme may transmit sensitive data in cleartext.',
          exploitationPrerequisites: 'User accesses http:// URL before HSTS is cached.',
          remediationInstructions: 'Add a permanent redirect (301/308) from HTTP to HTTPS and deploy Strict-Transport-Security.',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
          evidence: [
            {
              evidenceType: 'http_response',
              summary: 'Cleartext HTTP probe did not redirect to HTTPS',
              rawExcerpt: `GET ${httpUrl}\nStatus: ${httpProbe.status}\nLocation: ${location || '(none)'}`,
            },
          ],
        });
      }
    } catch (err) {
      checks.push({
        checkKey: 'transport.http_to_https_redirect',
        title: 'HTTP-to-HTTPS Automatic Redirect',
        category: 'Transport Encryption',
        status: 'informational',
        observedValue: err instanceof Error ? err.message : 'Port 80 closed/unreachable',
        expectedValue: '301/308 redirect or port 80 closed',
        explanation: 'Plain HTTP port 80 did not respond (which may indicate port 80 is intentionally closed).',
        remediation: null,
        cweId: null,
        owaspCategory: 'A02:2021',
      });
    }

    // 3. TLS certificate & protocol inspection
    if (ctx.isPracticeTarget) {
      checks.push({
        checkKey: 'transport.tls_certificate',
        title: 'TLS Certificate & Protocol Inspection',
        category: 'Transport Encryption',
        status: 'not_applicable',
        observedValue: 'In-process isolated practice target (no external TLS socket)',
        expectedValue: 'TLS 1.2/1.3 with valid CA-signed certificate',
        explanation: 'Practice lab adapter runs isolated in memory without opening network sockets; external TLS handshake is marked Not Applicable.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A02:2021',
      });
    } else if (isHttps || parsedTarget.protocol === 'https:') {
      try {
        const port = parsedTarget.port ? Number(parsedTarget.port) : 443;
        const tlsInfo = await inspectRealTls(ctx.hostname, port, ctx.requestTimeoutMs);
        const weakProtocol = tlsInfo.protocol === 'TLSv1' || tlsInfo.protocol === 'TLSv1.1' || tlsInfo.protocol === 'SSLv3';
        const weakCipher = Boolean(tlsInfo.cipherName && /(RC4|DES|3DES|NULL|EXPORT|MD5)/i.test(tlsInfo.cipherName));
        const expired = tlsInfo.daysRemaining !== null && tlsInfo.daysRemaining <= 0;
        const expiringSoon = tlsInfo.daysRemaining !== null && tlsInfo.daysRemaining > 0 && tlsInfo.daysRemaining <= 21;

        checks.push({
          checkKey: 'transport.tls_protocol',
          title: 'TLS Protocol & Cipher Strength',
          category: 'Transport Encryption',
          status: weakProtocol || weakCipher ? 'failed' : 'passed',
          observedValue: `${tlsInfo.protocol || 'unknown'} / ${tlsInfo.cipherName || 'unknown'}`,
          expectedValue: 'TLSv1.2 or TLSv1.3 with AEAD cipher',
          explanation: weakProtocol || weakCipher
            ? `Negotiated weak TLS configuration (${tlsInfo.protocol} / ${tlsInfo.cipherName}).`
            : `Negotiated ${tlsInfo.protocol} using ${tlsInfo.cipherName}.`,
          remediation: weakProtocol || weakCipher
            ? 'Disable TLS 1.0/1.1 and weak ciphers; enforce TLS 1.2 and TLS 1.3 with ECDHE AEAD suites.'
            : null,
          cweId: 'CWE-326',
          owaspCategory: 'A02:2021',
        });

        checks.push({
          checkKey: 'transport.tls_certificate',
          title: 'TLS Certificate Chain & Expiration',
          category: 'Transport Encryption',
          status: !tlsInfo.authorized || expired ? 'failed' : expiringSoon ? 'potential' : 'passed',
          observedValue: `Subject: ${tlsInfo.subjectCN || 'N/A'}, Issuer: ${tlsInfo.issuerO || 'N/A'}, Days left: ${tlsInfo.daysRemaining ?? 'N/A'}, Chain valid: ${tlsInfo.authorized}`,
          expectedValue: 'Valid trusted certificate chain with >21 days remaining',
          explanation: !tlsInfo.authorized
            ? `Certificate chain validation failed: ${tlsInfo.authorizationError}`
            : expired
              ? `Certificate expired (${tlsInfo.validTo}).`
              : expiringSoon
                ? `Certificate expires in ${tlsInfo.daysRemaining} days (${tlsInfo.validTo}).`
                : `Certificate is trusted and valid for ${tlsInfo.daysRemaining} days.`,
          remediation: !tlsInfo.authorized || expired || expiringSoon
            ? 'Renew and install a valid CA-signed certificate with full intermediate chain.'
            : null,
          cweId: 'CWE-295',
          owaspCategory: 'A02:2021',
        });

        if (!tlsInfo.authorized || expired || weakProtocol || weakCipher) {
          const cvss = evaluateCvss4(
            { AV: 'N', AC: 'H', AT: 'P', PR: 'N', UI: 'N', VC: 'H', VI: 'L', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
            'high',
            'Confirmed TLS certificate or weak protocol/cipher weakness via direct TLS handshake.'
          );
          findings.push({
            ruleId: 'TLS_WEAK_OR_UNTRUSTED',
            title: 'TLS Certificate or Protocol Weakness Detected',
            category: 'Data Protection & Encryption',
            description: 'The target TLS endpoint exhibited certificate validation failure, expiration, or deprecated protocol/cipher negotiation.',
            technicalExplanation: `Protocol=${tlsInfo.protocol}, Cipher=${tlsInfo.cipherName}, Authorized=${tlsInfo.authorized}, Error=${tlsInfo.authorizationError || 'none'}, DaysRemaining=${tlsInfo.daysRemaining}.`,
            affectedUrl: httpsUrl,
            httpMethod: 'TLS',
            parameterName: null,
            confidence: 'high',
            severity: cvss.severity,
            cvssVersion: cvss.version,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            cvssRationale: cvss.rationale,
            cweId: !tlsInfo.authorized ? 'CWE-295' : 'CWE-326',
            cveId: null,
            owaspCategory: 'A02:2021',
            owaspApiCategory: null,
            businessImpact: 'Browsers display security warnings or attackers may downgrade/intercept encrypted sessions.',
            exploitationPrerequisites: 'Network interception or deprecated client negotiation.',
            remediationInstructions: 'Enforce TLS 1.2/1.3 only, use modern AEAD ciphers, and deploy a valid non-expired CA certificate chain.',
            references: ['https://ssl-config.mozilla.org/'],
            evidence: [
              {
                evidenceType: 'tls_cert',
                summary: 'Observed TLS socket parameters',
                rawExcerpt: JSON.stringify(tlsInfo, null, 2),
              },
            ],
          });
        }
      } catch (err) {
        logs.push({
          level: 'warn',
          message: `TLS handshake could not complete: ${err instanceof Error ? err.message : 'unknown error'}`,
        });
        checks.push({
          checkKey: 'transport.tls_certificate',
          title: 'TLS Certificate Chain & Expiration',
          category: 'Transport Encryption',
          status: 'not_performed',
          observedValue: err instanceof Error ? err.message : 'TLS handshake error',
          expectedValue: 'TLS 1.2+ handshake',
          explanation: 'TLS socket could not complete handshake; check was not performed and not marked passed.',
          remediation: null,
          cweId: null,
          owaspCategory: 'A02:2021',
        });
      }
    }

    // 4. Encryption at rest & backup security (explicitly manual_required remotely)
    checks.push({
      checkKey: 'data.encryption_at_rest',
      title: 'Database & Storage Encryption at Rest',
      category: 'Data Protection & Encryption',
      status: 'manual_required',
      observedValue: 'Cannot be verified via public HTTP/TLS requests',
      expectedValue: 'AES-256 / KMS-managed encryption at rest for DBs, volumes, and backups',
      explanation: 'Encryption at rest and backup encryption cannot be determined externally over HTTP. Administrative cloud/infrastructure configuration or source-code evidence is required.',
      remediation: 'Verify KMS-backed storage encryption in cloud provider console and backup policies.',
      cweId: 'CWE-311',
      owaspCategory: 'A02:2021',
    });

    return { checks, findings, endpoints, logs };
  },
};
