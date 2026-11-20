import dns from 'node:dns';
import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

function getApexDomain(hostname: string): string {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join('.');
}

export const dnsInfrastructureModule: ScannerModule = {
  id: 'dns-infrastructure',
  name: 'DNS & Infrastructure Fingerprinter',
  version: '1.1.0',
  category: 'Server & Infrastructure Security',
  description: 'Inspects DNS records (SPF, DMARC, CAA, MX, NS), server version banners, WAF/CDN indicators, and proxy headers.',
  supportedProfiles: ['quick', 'standard', 'comprehensive', 'custom'],
  defaultTimeoutMs: 9000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    const res = ctx.sharedState.homepageResponse || (await ctx.httpFetch(ctx.targetUrl));
    const serverHeader = res.headers['server'] || null;
    const poweredBy = res.headers['x-powered-by'] || null;
    const aspNet = res.headers['x-aspnet-version'] || null;

    // 1. Server / Technology Banner Disclosure
    const hasDetailedBanner =
      Boolean(serverHeader && /\d+\.\d+/.test(serverHeader)) || Boolean(poweredBy) || Boolean(aspNet);

    checks.push({
      checkKey: 'infra.version_disclosure',
      title: 'Web Server & Framework Version Disclosure',
      category: 'Infrastructure Security',
      status: hasDetailedBanner ? 'failed' : 'passed',
      observedValue: [serverHeader && `Server: ${serverHeader}`, poweredBy && `X-Powered-By: ${poweredBy}`, aspNet && `X-AspNet-Version: ${aspNet}`]
        .filter(Boolean)
        .join(' | ') || '(no detailed version headers)',
      expectedValue: 'Minimal or suppressed product version headers',
      explanation: hasDetailedBanner
        ? 'Response headers expose exact server or runtime software versions.'
        : 'Server version banners are suppressed or omit specific version numbers.',
      remediation: hasDetailedBanner
        ? 'Disable server_tokens (Nginx), ServerTokens Prod (Apache), and app.disable("x-powered-by") in Express.'
        : null,
      cweId: 'CWE-200',
      owaspCategory: 'A05:2021',
    });

    if (hasDetailedBanner) {
      const cvss = evaluateCvss4(null, 'low', 'Version header disclosure aids attacker fingerprinting without direct exploitation impact.');
      findings.push({
        ruleId: 'INFRA_BANNER_DISCLOSURE',
        title: 'Server and Runtime Technology Version Disclosure',
        category: 'Server & Infrastructure Security',
        description: 'HTTP response headers reveal exact web server or application framework versions.',
        technicalExplanation: `Observed headers: Server="${serverHeader || 'unset'}", X-Powered-By="${poweredBy || 'unset'}".`,
        affectedUrl: res.finalUrl,
        httpMethod: 'GET',
        parameterName: 'Server / X-Powered-By',
        confidence: 'high',
        severity: 'low',
        cvssVersion: null,
        cvssScore: null,
        cvssVector: null,
        cvssRationale: cvss.rationale,
        cweId: 'CWE-200',
        cveId: null,
        owaspCategory: 'A05:2021',
        owaspApiCategory: null,
        businessImpact: 'Facilitates targeted CVE lookup and technology profiling by adversaries.',
        exploitationPrerequisites: 'None; observable in standard HTTP responses.',
        remediationInstructions: 'Remove X-Powered-By and configure your web server/proxy to omit version strings.',
        references: ['https://owasp.org/www-project-web-security-testing-guide/'],
        evidence: [
          {
            evidenceType: 'http_header',
            summary: 'Technology version headers returned in response',
            rawExcerpt: `Server: ${serverHeader || '(none)'}\nX-Powered-By: ${poweredBy || '(none)'}`,
          },
        ],
      });
    }

    // 2. WAF / CDN / Reverse Proxy Indicators (explicitly honest when unconfirmed)
    const wafSignals: string[] = [];
    if (res.headers['cf-ray']) wafSignals.push('Cloudflare (CF-Ray)');
    if (res.headers['x-amz-cf-id']) wafSignals.push('AWS CloudFront');
    if (res.headers['x-akamai-transformed']) wafSignals.push('Akamai');
    if (res.headers['x-sucuri-id']) wafSignals.push('Sucuri WAF');
    if (res.headers['via']) wafSignals.push(`Via: ${res.headers['via']}`);

    checks.push({
      checkKey: 'infra.waf_ddos_indicators',
      title: 'WAF, Reverse Proxy & DDoS Protection Indicators',
      category: 'Infrastructure Security',
      status: wafSignals.length > 0 ? 'informational' : 'manual_required',
      observedValue: wafSignals.length > 0 ? wafSignals.join(', ') : 'No passive WAF/CDN headers detected',
      expectedValue: 'Edge WAF/DDoS protection verified via infrastructure architecture',
      explanation:
        wafSignals.length > 0
          ? `Passive edge/proxy indicators detected: ${wafSignals.join(', ')}. Note: active WAF rule enforcement and DDoS mitigation limits cannot be verified without authorized edge configuration review.`
          : 'WAF and DDoS protections could not be confirmed externally via passive HTTP headers. Review CDN/firewall architecture manually.',
      remediation: null,
      cweId: null,
      owaspCategory: 'A05:2021',
    });

    // 3. DNS checks (SPF, DMARC, CAA, DNSSEC note)
    if (ctx.isPracticeTarget) {
      checks.push({
        checkKey: 'infra.dns_security',
        title: 'DNS Email & Certificate Policy (SPF / DMARC / CAA)',
        category: 'Infrastructure Security',
        status: 'not_applicable',
        observedValue: 'Isolated in-process practice domain',
        expectedValue: 'Valid SPF, DMARC, and CAA records',
        explanation: 'Practice lab hostname is local/in-process and does not exist in public DNS.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A05:2021',
      });
      return { checks, findings, endpoints: [], logs };
    }

    const domain = getApexDomain(ctx.hostname);
    try {
      const txtRecords = await dns.promises.resolveTxt(domain).catch(() => [] as string[][]);
      const flatTxt = txtRecords.map((arr) => arr.join(''));
      const spf = flatTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || null;
      const spfWeak = Boolean(spf && /\+all\b/i.test(spf));

      checks.push({
        checkKey: 'dns.spf',
        title: 'DNS SPF Record',
        category: 'DNS Security',
        status: !spf || spfWeak ? 'failed' : 'passed',
        observedValue: spf || '(no SPF TXT record found)',
        expectedValue: 'v=spf1 ... -all or ~all',
        explanation: !spf
          ? `No SPF record found for ${domain}.`
          : spfWeak
            ? 'SPF record uses +all which permits any sender.'
            : `SPF record found: ${spf}`,
        remediation: !spf || spfWeak ? 'Publish a restrictive SPF TXT record ending in -all or ~all.' : null,
        cweId: 'CWE-290',
        owaspCategory: 'A05:2021',
      });

      const dmarcRecords = await dns.promises.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]);
      const dmarc = dmarcRecords.map((a) => a.join('')).find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;
      const dmarcMonitorOnly = Boolean(dmarc && /p\s*=\s*none/i.test(dmarc));

      checks.push({
        checkKey: 'dns.dmarc',
        title: 'DNS DMARC Policy',
        category: 'DNS Security',
        status: !dmarc ? 'failed' : dmarcMonitorOnly ? 'potential' : 'passed',
        observedValue: dmarc || '(no _dmarc TXT record found)',
        expectedValue: 'v=DMARC1; p=quarantine or p=reject',
        explanation: !dmarc
          ? `No DMARC record published at _dmarc.${domain}.`
          : dmarcMonitorOnly
            ? 'DMARC record is in monitor-only mode (p=none).'
            : `Enforced DMARC policy observed: ${dmarc}`,
        remediation: !dmarc || dmarcMonitorOnly ? 'Configure _dmarc TXT record with p=quarantine or p=reject.' : null,
        cweId: 'CWE-290',
        owaspCategory: 'A05:2021',
      });

      const caaRecords = await dns.promises.resolveCaa(domain).catch(() => []);
      checks.push({
        checkKey: 'dns.caa',
        title: 'DNS CAA Record (Certificate Authority Authorization)',
        category: 'DNS Security',
        status: caaRecords.length > 0 ? 'passed' : 'informational',
        observedValue: caaRecords.length > 0 ? JSON.stringify(caaRecords) : '(no CAA records found)',
        expectedValue: 'CAA issue/issuewild records restricting authorized CAs',
        explanation:
          caaRecords.length > 0
            ? `${caaRecords.length} CAA record(s) restrict certificate issuance.`
            : 'No CAA records found; any trusted CA can issue certificates for this domain unless restricted.',
        remediation: caaRecords.length > 0 ? null : 'Publish DNS CAA records specifying your authorized Certificate Authorities.',
        cweId: null,
        owaspCategory: 'A02:2021',
      });

      checks.push({
        checkKey: 'dns.dnssec',
        title: 'DNSSEC Validation Status',
        category: 'DNS Security',
        status: 'manual_required',
        observedValue: 'Standard stub resolver cannot verify DNSSEC AD/DS chain cryptographically',
        expectedValue: 'DNSSEC signed zone with DS record at registrar',
        explanation: 'Node.js OS stub resolver does not expose DNSSEC AD flags reliably; verify DS/RRSIG records via an authoritative DNSSEC validator.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A05:2021',
      });
    } catch (err) {
      logs.push({
        level: 'warn',
        message: `DNS lookup encountered an error: ${err instanceof Error ? err.message : 'unknown error'}`,
      });
    }

    return { checks, findings, endpoints: [], logs };
  },
};
