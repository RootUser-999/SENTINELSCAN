import { evaluateCvss4 } from '../../intelligence/cvss4.ts';
import type { ModuleExecutionResult, ScannerModule, ScanContext } from '../types.ts';

interface ParsedPackage {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | 'Packagist' | 'RubyGems';
}

export function parseDependencyManifest(filename: string, raw: string): ParsedPackage[] {
  const lower = filename.toLowerCase();
  const pkgs: ParsedPackage[] = [];

  if (lower.endsWith('package.json')) {
    const json = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const combined = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
    for (const [name, ver] of Object.entries(combined)) {
      const cleanVer = String(ver).replace(/^[~^>=<\s]+/, '');
      if (cleanVer && /^\d+\.\d+/.test(cleanVer)) {
        pkgs.push({ name, version: cleanVer, ecosystem: 'npm' });
      }
    }
  } else if (lower.endsWith('package-lock.json')) {
    const json = JSON.parse(raw) as {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    };
    if (json.packages) {
      for (const [pkgPath, meta] of Object.entries(json.packages)) {
        if (!pkgPath.startsWith('node_modules/') || !meta.version) continue;
        const name = pkgPath.replace(/^node_modules\//, '').replace(/.*node_modules\//, '');
        pkgs.push({ name, version: meta.version, ecosystem: 'npm' });
      }
    } else if (json.dependencies) {
      for (const [name, meta] of Object.entries(json.dependencies)) {
        if (meta.version) pkgs.push({ name, version: meta.version, ecosystem: 'npm' });
      }
    }
  } else if (lower.endsWith('requirements.txt')) {
    for (const line of raw.split(/\r?\n/)) {
      const clean = line.split('#')[0].trim();
      const match = clean.match(/^([A-Za-z0-9._-]+)\s*==\s*([0-9A-Za-z._-]+)/);
      if (match) pkgs.push({ name: match[1], version: match[2], ecosystem: 'PyPI' });
    }
  } else if (lower.endsWith('pyproject.toml')) {
    const depMatches = raw.matchAll(/["']([A-Za-z0-9._-]+)\s*==\s*([0-9A-Za-z._-]+)["']/g);
    for (const m of depMatches) {
      pkgs.push({ name: m[1], version: m[2], ecosystem: 'PyPI' });
    }
  } else if (lower.endsWith('composer.lock')) {
    const json = JSON.parse(raw) as { packages?: Array<{ name?: string; version?: string }> };
    for (const p of json.packages || []) {
      if (p.name && p.version) {
        pkgs.push({ name: p.name, version: p.version.replace(/^v/, ''), ecosystem: 'Packagist' });
      }
    }
  } else if (lower.endsWith('gemfile.lock')) {
    const lines = raw.split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^\s{4}([A-Za-z0-9_-]+)\s+\(([^)]+)\)/);
      if (m) pkgs.push({ name: m[1], version: m[2], ecosystem: 'RubyGems' });
    }
  } else if (lower.endsWith('yarn.lock') || lower.endsWith('pnpm-lock.yaml')) {
    const matches = raw.matchAll(/(?:^|\n)\s*["']?(@?[A-Za-z0-9._/-]+)@[^:\n]+:\s*\n\s+version[:\s]+["']?([0-9]+\.[0-9]+\.[0-9]+[^"'\s]*)/g);
    for (const m of matches) {
      pkgs.push({ name: m[1], version: m[2], ecosystem: 'npm' });
    }
  }

  return pkgs.slice(0, 60);
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
  references?: Array<{ url?: string }>;
}

// Minimal deterministic offline fallback ONLY used if live api.osv.dev network request fails
const FALLBACK_ADVISORIES: Array<{
  ecosystem: string;
  name: string;
  affectedBelow: string;
  id: string;
  cve: string;
  summary: string;
  severity: 'critical' | 'high' | 'medium';
}> = [
  { ecosystem: 'npm', name: 'lodash', affectedBelow: '4.17.21', id: 'GHSA-35jh-r3h4-6jhm', cve: 'CVE-2021-23337', summary: 'Command Injection in lodash template function', severity: 'high' },
  { ecosystem: 'npm', name: 'minimist', affectedBelow: '1.2.6', id: 'GHSA-xvch-5gv4-984h', cve: 'CVE-2021-44906', summary: 'Prototype Pollution in minimist', severity: 'critical' },
  { ecosystem: 'npm', name: 'jsonwebtoken', affectedBelow: '9.0.0', id: 'GHSA-qwph-4952-7xr6', cve: 'CVE-2022-23529', summary: 'Insecure key retrieval / algorithm handling in jsonwebtoken < 9.0.0', severity: 'high' },
  { ecosystem: 'npm', name: 'express', affectedBelow: '4.19.2', id: 'GHSA-rv95-896h-c2vc', cve: 'CVE-2024-29041', summary: 'Open redirect vulnerability in Express < 4.19.2', severity: 'medium' },
];

function compareSemver(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) < (pb[i] || 0)) return -1;
    if ((pa[i] || 0) > (pb[i] || 0)) return 1;
  }
  return 0;
}

export const dependencyScaModule: ScannerModule = {
  id: 'dependency-sca',
  name: 'Software Composition Analysis (OSV.dev)',
  version: '1.2.0',
  category: 'Dependency & Supply Chain Security',
  description: 'Parses dependency manifests/lockfiles and queries OSV vulnerability database for known CVEs.',
  supportedProfiles: ['comprehensive', 'custom', 'standard'],
  defaultTimeoutMs: 15000,

  async execute(ctx: ScanContext): Promise<ModuleExecutionResult> {
    const checks: ModuleExecutionResult['checks'] = [];
    const findings: ModuleExecutionResult['findings'] = [];
    const logs: ModuleExecutionResult['logs'] = [];

    if (!ctx.scaManifestRaw || !ctx.scaManifestName) {
      checks.push({
        checkKey: 'sca.manifest_analysis',
        title: 'Dependency Vulnerability Analysis (SCA)',
        category: 'Dependency Security',
        status: 'not_performed',
        observedValue: 'No dependency manifest or lockfile supplied',
        expectedValue: 'package.json, package-lock.json, requirements.txt, pyproject.toml, composer.lock, or Gemfile.lock',
        explanation: 'Supply a package manifest in Scan Configuration to execute live OSV CVE matching.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A06:2021',
      });
      return { checks, findings, endpoints: [], logs };
    }

    let packages: ParsedPackage[] = [];
    try {
      packages = parseDependencyManifest(ctx.scaManifestName, ctx.scaManifestRaw);
    } catch (err) {
      checks.push({
        checkKey: 'sca.manifest_analysis',
        title: 'Dependency Vulnerability Analysis (SCA)',
        category: 'Dependency Security',
        status: 'not_performed',
        observedValue: `Failed to parse ${ctx.scaManifestName}: ${err instanceof Error ? err.message : 'invalid format'}`,
        expectedValue: 'Valid manifest syntax',
        explanation: 'Manifest parsing failed; check was not marked passed.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A06:2021',
      });
      return { checks, findings, endpoints: [], logs };
    }

    if (packages.length === 0) {
      checks.push({
        checkKey: 'sca.manifest_analysis',
        title: 'Dependency Vulnerability Analysis (SCA)',
        category: 'Dependency Security',
        status: 'informational',
        observedValue: `0 pinned package versions found in ${ctx.scaManifestName}`,
        expectedValue: 'Pinned package versions',
        explanation: 'No pinned dependency versions could be extracted.',
        remediation: null,
        cweId: null,
        owaspCategory: 'A06:2021',
      });
      return { checks, findings, endpoints: [], logs };
    }

    let usedLiveOsv = false;
    let vulnHits = 0;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const osvRes = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: packages.map((p) => ({
            package: { name: p.name, ecosystem: p.ecosystem },
            version: p.version,
          })),
        }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (osvRes.ok) {
        usedLiveOsv = true;
        const data = (await osvRes.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
        const results = data.results || [];

        // Fetch detail for up to 12 discovered vulns
        for (let i = 0; i < results.length && vulnHits < 12; i++) {
          const pkg = packages[i];
          const vulns = results[i]?.vulns || [];
          for (const v of vulns.slice(0, 3)) {
            if (vulnHits >= 12) break;
            vulnHits += 1;
            let detail: OsvVuln = { id: v.id };
            try {
              const dRes = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(v.id)}`);
              if (dRes.ok) detail = (await dRes.json()) as OsvVuln;
            } catch {
              // Use minimal id if detail fails
            }
            const cve = (detail.aliases || []).find((a) => a.startsWith('CVE-')) || null;
            const fixed = detail.affected?.[0]?.ranges?.[0]?.events?.find((e) => e.fixed)?.fixed || 'latest patched release';
            const sev: 'critical' | 'high' | 'medium' =
              /critical|rce|remote code/i.test(`${detail.summary || ''} ${detail.details || ''}`)
                ? 'critical'
                : 'high';

            findings.push({
              ruleId: `SCA_${pkg.name.toUpperCase()}_${v.id}`,
              title: `Vulnerable Dependency: ${pkg.name}@${pkg.version} (${cve || v.id})`,
              category: 'Dependency & Supply Chain Security',
              description: detail.summary || `Known OSV vulnerability ${v.id} affects ${pkg.name} ${pkg.version}.`,
              technicalExplanation: `Matched via live OSV.dev API for ${pkg.ecosystem} package ${pkg.name}==${pkg.version}. Advisory: ${v.id}${cve ? ` (${cve})` : ''}.`,
              affectedUrl: `manifest://${ctx.scaManifestName}#${pkg.name}@${pkg.version}`,
              httpMethod: null,
              parameterName: pkg.name,
              confidence: 'high',
              severity: sev,
              cvssVersion: null,
              cvssScore: null,
              cvssVector: null,
              cvssRationale: 'Reported via OSV advisory metadata; review exact application reachability for contextual CVSS.',
              cweId: 'CWE-1395',
              cveId: cve || v.id,
              owaspCategory: 'A06:2021',
              owaspApiCategory: null,
              businessImpact: 'Known flaws in third-party dependencies can enable prototype pollution, injection, or unauthorized access.',
              exploitationPrerequisites: 'Vulnerable code path reachable in dependency.',
              remediationInstructions: `Upgrade ${pkg.name} in ${ctx.scaManifestName} to >= ${fixed}.`,
              references: [
                `https://osv.dev/vulnerability/${v.id}`,
                ...((detail.references || []).map((r) => r.url).filter(Boolean).slice(0, 2) as string[]),
              ],
              evidence: [
                {
                  evidenceType: 'dependency_advisory',
                  summary: `OSV.dev live match for ${pkg.name}@${pkg.version}`,
                  rawExcerpt: `Package: ${pkg.name}@${pkg.version} (${pkg.ecosystem})\nAdvisory: ${v.id} / ${cve || 'no CVE alias'}\nFixed in: ${fixed}`,
                },
              ],
            });
          }
        }
      }
    } catch {
      logs.push({ level: 'warn', message: 'Live OSV.dev API unreachable; running deterministic offline CVE baseline check.' });
    }

    if (!usedLiveOsv) {
      for (const pkg of packages) {
        for (const adv of FALLBACK_ADVISORIES) {
          if (adv.ecosystem === pkg.ecosystem && adv.name === pkg.name && compareSemver(pkg.version, adv.affectedBelow) < 0) {
            vulnHits += 1;
            const cvss = evaluateCvss4(
              { AV: 'N', AC: 'L', AT: 'P', PR: 'N', UI: 'N', VC: 'H', VI: 'H', VA: 'N', SC: 'N', SI: 'N', SA: 'N' },
              adv.severity,
              `Matched curated offline advisory ${adv.cve} because live OSV.dev was unreachable.`
            );
            findings.push({
              ruleId: `SCA_${pkg.name.toUpperCase()}_${adv.cve}`,
              title: `Vulnerable Dependency: ${pkg.name}@${pkg.version} (${adv.cve})`,
              category: 'Dependency & Supply Chain Security',
              description: adv.summary,
              technicalExplanation: `${pkg.name}@${pkg.version} is below patched version ${adv.affectedBelow}.`,
              affectedUrl: `manifest://${ctx.scaManifestName}#${pkg.name}@${pkg.version}`,
              httpMethod: null,
              parameterName: pkg.name,
              confidence: 'high',
              severity: adv.severity,
              cvssVersion: cvss.version,
              cvssScore: cvss.score,
              cvssVector: cvss.vector,
              cvssRationale: cvss.rationale,
              cweId: 'CWE-1395',
              cveId: adv.cve,
              owaspCategory: 'A06:2021',
              owaspApiCategory: null,
              businessImpact: 'Known vulnerable dependency in software supply chain.',
              exploitationPrerequisites: 'Vulnerable function invoked in runtime.',
              remediationInstructions: `Upgrade ${pkg.name} to >= ${adv.affectedBelow}.`,
              references: [`https://osv.dev/vulnerability/${adv.id}`],
              evidence: [
                {
                  evidenceType: 'dependency_advisory',
                  summary: `Offline advisory match (${adv.cve})`,
                  rawExcerpt: `Package: ${pkg.name}@${pkg.version}\nCVE: ${adv.cve}\nPatched: >= ${adv.affectedBelow}`,
                },
              ],
            });
          }
        }
      }
    }

    checks.push({
      checkKey: 'sca.manifest_analysis',
      title: `Dependency Vulnerability Scan (${ctx.scaManifestName})`,
      category: 'Dependency Security',
      status: vulnHits > 0 ? 'failed' : 'passed',
      observedValue: `Scanned ${packages.length} package(s) via ${usedLiveOsv ? 'OSV.dev Live API' : 'Offline CVE Baseline'} — ${vulnHits} vulnerable package match(es)`,
      expectedValue: '0 dependencies with known CVEs',
      explanation:
        vulnHits > 0
          ? `Detected ${vulnHits} vulnerable dependency record(s) across ${packages.length} parsed dependencies.`
          : `Zero known vulnerabilities matched across ${packages.length} parsed dependencies.`,
      remediation: vulnHits > 0 ? 'Upgrade flagged dependencies to patched versions and regenerate lockfiles.' : null,
      cweId: 'CWE-1395',
      owaspCategory: 'A06:2021',
    });

    return { checks, findings, endpoints: [], logs };
  },
};
