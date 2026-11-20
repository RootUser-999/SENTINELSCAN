import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_PATH = path.join(DATA_DIR, 'sentinelscan.db');

let dbInstance: DatabaseSync | null = null;

export function getDb(): DatabaseSync {
  if (dbInstance) return dbInstance;

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const db = new DatabaseSync(DB_PATH, { enableForeignKeyConstraints: true });
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA busy_timeout = 5000;');

  initializeSchema(db);
  seedComplianceFrameworks(db);

  dbInstance = db;
  return db;
}

function initializeSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      mfa_secret_enc TEXT,
      created_at TEXT NOT NULL,
      last_login_at TEXT
    );

    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS organization_memberships (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
      created_at TEXT NOT NULL,
      UNIQUE(organization_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      target_url TEXT NOT NULL,
      hostname TEXT NOT NULL,
      environment TEXT NOT NULL CHECK (environment IN ('production', 'staging', 'development', 'practice_lab')),
      criticality TEXT NOT NULL CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
      scope_include_paths TEXT NOT NULL DEFAULT '/',
      scope_exclude_paths TEXT NOT NULL DEFAULT '',
      max_requests_per_sec INTEGER NOT NULL DEFAULT 5,
      is_practice_target INTEGER NOT NULL DEFAULT 0,
      ownership_status TEXT NOT NULL DEFAULT 'unverified' CHECK (ownership_status IN ('unverified', 'pending', 'verified')),
      authorization_signed_by TEXT,
      authorization_signed_at TEXT,
      authorization_notes TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS asset_ownership_verifications (
      id TEXT PRIMARY KEY,
      asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      method TEXT NOT NULL CHECK (method IN ('dns_txt', 'http_file', 'html_meta', 'practice_lab_attestation')),
      token TEXT NOT NULL,
      target_location TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'failed')),
      checked_at TEXT,
      failure_reason TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_credentials (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      asset_id TEXT REFERENCES assets(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      auth_type TEXT NOT NULL CHECK (auth_type IN ('bearer_token', 'cookie', 'basic_header', 'login_form')),
      role_profile TEXT NOT NULL CHECK (role_profile IN ('authenticated_user', 'administrator', 'custom')),
      login_url TEXT,
      username_hint TEXT,
      encrypted_secret_blob TEXT NOT NULL,
      iv_hex TEXT NOT NULL,
      auth_tag_hex TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_by_user_id TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_configurations (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      profile TEXT NOT NULL CHECK (profile IN ('quick', 'standard', 'comprehensive', 'custom')),
      selected_modules_json TEXT NOT NULL,
      max_depth INTEGER NOT NULL DEFAULT 2,
      request_timeout_ms INTEGER NOT NULL DEFAULT 8000,
      concurrency_limit INTEGER NOT NULL DEFAULT 3,
      rate_limit_rps INTEGER NOT NULL DEFAULT 5,
      allow_authenticated INTEGER NOT NULL DEFAULT 0,
      credential_id TEXT REFERENCES scan_credentials(id) ON DELETE SET NULL,
      openapi_spec_raw TEXT,
      sca_manifest_name TEXT,
      sca_manifest_raw TEXT,
      sast_filename TEXT,
      sast_code_raw TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      configuration_id TEXT NOT NULL REFERENCES scan_configurations(id),
      initiated_by_user_id TEXT NOT NULL REFERENCES users(id),
      profile TEXT NOT NULL CHECK (profile IN ('quick', 'standard', 'comprehensive', 'custom')),
      status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
      progress_pct INTEGER NOT NULL DEFAULT 0,
      current_module TEXT,
      started_at TEXT,
      completed_at TEXT,
      duration_ms INTEGER,
      posture_score REAL,
      total_checks INTEGER NOT NULL DEFAULT 0,
      passed_checks INTEGER NOT NULL DEFAULT 0,
      failed_checks INTEGER NOT NULL DEFAULT 0,
      potential_checks INTEGER NOT NULL DEFAULT 0,
      informational_checks INTEGER NOT NULL DEFAULT 0,
      not_applicable_checks INTEGER NOT NULL DEFAULT 0,
      not_performed_checks INTEGER NOT NULL DEFAULT 0,
      manual_required_checks INTEGER NOT NULL DEFAULT 0,
      critical_count INTEGER NOT NULL DEFAULT 0,
      high_count INTEGER NOT NULL DEFAULT 0,
      medium_count INTEGER NOT NULL DEFAULT 0,
      low_count INTEGER NOT NULL DEFAULT 0,
      info_count INTEGER NOT NULL DEFAULT 0,
      error_message TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_modules (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      default_timeout_ms INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scan_executions (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL,
      module_name TEXT NOT NULL,
      module_version TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped', 'cancelled')),
      started_at TEXT,
      completed_at TEXT,
      duration_ms INTEGER,
      checks_executed INTEGER NOT NULL DEFAULT 0,
      findings_created INTEGER NOT NULL DEFAULT 0,
      error_message TEXT
    );

    CREATE TABLE IF NOT EXISTS scan_progress (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      timestamp TEXT NOT NULL,
      level TEXT NOT NULL CHECK (level IN ('info', 'warn', 'error')),
      module_id TEXT,
      message TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS endpoints (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      path TEXT NOT NULL,
      method TEXT NOT NULL,
      source TEXT NOT NULL CHECK (source IN ('crawl', 'openapi', 'probe')),
      auth_required TEXT NOT NULL CHECK (auth_required IN ('required', 'optional', 'none_detected', 'unknown')),
      status_code INTEGER,
      content_type TEXT,
      parameters_json TEXT NOT NULL DEFAULT '[]',
      notes TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_checks (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      module_id TEXT NOT NULL,
      check_key TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'potential', 'informational', 'not_applicable', 'not_performed', 'manual_required')),
      observed_value TEXT,
      expected_value TEXT,
      explanation TEXT NOT NULL,
      remediation TEXT,
      cwe_id TEXT,
      owasp_category TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      first_scan_id TEXT NOT NULL REFERENCES scans(id),
      latest_scan_id TEXT NOT NULL REFERENCES scans(id),
      fingerprint TEXT NOT NULL,
      finding_code TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      technical_explanation TEXT NOT NULL,
      affected_url TEXT NOT NULL,
      http_method TEXT,
      parameter_name TEXT,
      scanner_module TEXT NOT NULL,
      confidence TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
      severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
      cvss_version TEXT,
      cvss_score REAL,
      cvss_vector TEXT,
      cvss_rationale TEXT NOT NULL,
      cwe_id TEXT,
      cve_id TEXT,
      owasp_category TEXT,
      owasp_api_category TEXT,
      business_impact TEXT NOT NULL,
      exploitation_prerequisites TEXT NOT NULL,
      remediation_instructions TEXT NOT NULL,
      references_json TEXT NOT NULL DEFAULT '[]',
      verification_status TEXT NOT NULL DEFAULT 'open' CHECK (verification_status IN ('open', 'confirmed', 'false_positive', 'risk_accepted', 'remediated', 'reopened')),
      assigned_to TEXT,
      detected_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(organization_id, fingerprint)
    );

    CREATE TABLE IF NOT EXISTS finding_evidence (
      id TEXT PRIMARY KEY,
      vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      evidence_type TEXT NOT NULL,
      summary TEXT NOT NULL,
      raw_excerpt TEXT NOT NULL,
      observed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS finding_status_history (
      id TEXT PRIMARY KEY,
      vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
      changed_by_user_id TEXT NOT NULL REFERENCES users(id),
      previous_status TEXT NOT NULL,
      new_status TEXT NOT NULL,
      rationale TEXT NOT NULL,
      changed_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS compliance_frameworks (
      id TEXT PRIMARY KEY,
      code TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      description TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS compliance_controls (
      id TEXT PRIMARY KEY,
      framework_id TEXT NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
      control_code TEXT NOT NULL,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      description TEXT NOT NULL,
      evidence_required TEXT NOT NULL,
      automatable INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS compliance_mappings (
      id TEXT PRIMARY KEY,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      framework_id TEXT NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
      control_id TEXT NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('passed', 'failed', 'not_assessed', 'partial')),
      linked_check_ids_json TEXT NOT NULL DEFAULT '[]',
      linked_finding_ids_json TEXT NOT NULL DEFAULT '[]',
      notes TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      generated_by_user_id TEXT NOT NULL REFERENCES users(id),
      format TEXT NOT NULL CHECK (format IN ('pdf', 'csv', 'json')),
      export_scope TEXT NOT NULL,
      filename TEXT NOT NULL,
      file_size_bytes INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id),
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      details_json TEXT NOT NULL DEFAULT '{}',
      ip_address TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id),
      severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      read_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      id TEXT PRIMARY KEY,
      organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      created_by_user_id TEXT NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
      last_used_at TEXT,
      expires_at TEXT,
      revoked_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(organization_id);
    CREATE INDEX IF NOT EXISTS idx_scans_org_created ON scans(organization_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id);
    CREATE INDEX IF NOT EXISTS idx_checks_scan ON security_checks(scan_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_org_sev ON vulnerabilities(organization_id, severity);
    CREATE INDEX IF NOT EXISTS idx_vulns_asset ON vulnerabilities(asset_id);
    CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id, created_at DESC);
  `);
}

function seedComplianceFrameworks(db: DatabaseSync): void {
  const existing = db.prepare('SELECT COUNT(*) as cnt FROM compliance_frameworks').get() as { cnt: number };
  if (existing.cnt > 0) return;

  const frameworks = [
    {
      id: 'fw-owasp-top10',
      code: 'OWASP_TOP_10',
      name: 'OWASP Top 10',
      version: '2021 / 2025-Aligned',
      description: 'Web application security risk categories covering access control, cryptography, injection, misconfiguration, and authentication.',
    },
    {
      id: 'fw-owasp-api',
      code: 'OWASP_API_TOP_10',
      name: 'OWASP API Security Top 10',
      version: '2023',
      description: 'API-specific security controls covering BOLA, broken authentication, property authorization, inventory, and misconfiguration.',
    },
    {
      id: 'fw-owasp-asvs',
      code: 'OWASP_ASVS',
      name: 'OWASP ASVS',
      version: '4.0.3 (Level 1/2 Indicators)',
      description: 'Application Security Verification Standard technical verification requirements.',
    },
    {
      id: 'fw-nist-csf',
      code: 'NIST_CSF',
      name: 'NIST Cybersecurity Framework',
      version: '2.0',
      description: 'Technical Protect and Detect control observations mapped to external and code-level assessment evidence.',
    },
    {
      id: 'fw-cis-v8',
      code: 'CIS_CONTROLS',
      name: 'CIS Critical Security Controls',
      version: 'v8',
      description: 'Technical safeguard observations for continuous vulnerability management, secure configuration, and data protection.',
    },
    {
      id: 'fw-pci-dss',
      code: 'PCI_DSS',
      name: 'PCI DSS Technical Indicators',
      version: '4.0 (Non-Certifying)',
      description: 'Externally observable web/TLS and dependency hygiene indicators relevant to PCI DSS requirements 4, 6, and 11.',
    },
    {
      id: 'fw-gdpr-art32',
      code: 'GDPR_TECH',
      name: 'GDPR Art. 32 Technical Indicators',
      version: 'Technical Baseline',
      description: 'Transport encryption, header protection, and exposure minimization indicators (does not constitute legal GDPR compliance).',
    },
  ];

  const insertFw = db.prepare(
    'INSERT INTO compliance_frameworks (id, code, name, version, description) VALUES (?, ?, ?, ?, ?)'
  );
  for (const fw of frameworks) {
    insertFw.run(fw.id, fw.code, fw.name, fw.version, fw.description);
  }

  const controls = [
    // OWASP Top 10
    ['ctrl-a01', 'fw-owasp-top10', 'A01:2021', 'Broken Access Control', 'Access Control', 'CORS policy, directory listing, sensitive file exposure, and authorization boundary checks.', 'HTTP probe & authenticated differential testing', 1],
    ['ctrl-a02', 'fw-owasp-top10', 'A02:2021', 'Cryptographic Failures', 'Cryptography', 'HTTPS enforcement, TLS protocol/cipher strength, HSTS, and cookie Secure attributes.', 'TLS handshake, HTTP headers & source crypto audit', 1],
    ['ctrl-a03', 'fw-owasp-top10', 'A03:2021', 'Injection', 'Injection', 'Static sink indicators, reflected input handling, and unsafe query construction indicators.', 'SAST source analysis & passive/safe input reflection indicators', 1],
    ['ctrl-a04', 'fw-owasp-top10', 'A04:2021', 'Insecure Design', 'Architecture', 'Rate limiting, anti-automation, and security architecture controls.', 'Authenticated verification & architecture review', 0],
    ['ctrl-a05', 'fw-owasp-top10', 'A05:2021', 'Security Misconfiguration', 'Configuration', 'Security headers (CSP, XFO, XCTO, Referrer-Policy), verbose errors, unnecessary HTTP methods.', 'HTTP header & response inspection', 1],
    ['ctrl-a06', 'fw-owasp-top10', 'A06:2021', 'Vulnerable and Outdated Components', 'Dependencies', 'Known CVEs in third-party packages and exposed server version banners.', 'SCA manifest analysis (OSV) & technology fingerprinting', 1],
    ['ctrl-a07', 'fw-owasp-top10', 'A07:2021', 'Identification & Authentication Failures', 'Authentication', 'Session cookie attributes (HttpOnly, SameSite), URL token leakage, password hashing & MFA.', 'Cookie inspection & manual/authenticated auth review', 1],
    ['ctrl-a08', 'fw-owasp-top10', 'A08:2021', 'Software & Data Integrity Failures', 'Integrity', 'Subresource Integrity (SRI) on external scripts and unsafe deserialization sinks.', 'HTML DOM audit & SAST rules', 1],
    ['ctrl-a09', 'fw-owasp-top10', 'A09:2021', 'Security Logging & Monitoring Failures', 'Observability', 'Centralized alerting, tamper-evident audit trails, and intrusion monitoring.', 'Administrative configuration & SIEM evidence required', 0],
    ['ctrl-a10', 'fw-owasp-top10', 'A10:2021', 'Server-Side Request Forgery (SSRF)', 'SSRF', 'Unsafe outbound URL fetch patterns and redirect validation indicators.', 'SAST & parameter indicator inspection', 1],

    // OWASP API Top 10
    ['ctrl-api1', 'fw-owasp-api', 'API1:2023', 'Broken Object Level Authorization', 'API AuthZ', 'Object-parameterized API endpoints lacking documented security schemes or auth enforcement.', 'OpenAPI inventory & authenticated role differential check', 1],
    ['ctrl-api2', 'fw-owasp-api', 'API2:2023', 'Broken Authentication', 'API AuthN', 'Missing global or operation security schemes in OpenAPI specs and unauthenticated API responses.', 'OpenAPI securitySchemes & endpoint probe', 1],
    ['ctrl-api3', 'fw-owasp-api', 'API3:2023', 'Broken Object Property Level Authorization', 'API Data', 'Excessive data exposure and mass-assignment risk indicators in API schemas.', 'OpenAPI schema inspection', 1],
    ['ctrl-api8', 'fw-owasp-api', 'API8:2023', 'Security Misconfiguration', 'API Config', 'Exposed Swagger/OpenAPI docs in production, GraphQL introspection, and permissive API CORS.', 'API probe & header inspection', 1],
    ['ctrl-api9', 'fw-owasp-api', 'API9:2023', 'Improper Inventory Management', 'API Inventory', 'Undocumented or deprecated versioned API endpoints.', 'OpenAPI & endpoint discovery inventory', 1],

    // OWASP ASVS
    ['ctrl-asvs-v3', 'fw-owasp-asvs', 'V3.4', 'Cookie-based Session Management', 'Session', 'Session cookies enforce Secure, HttpOnly, and SameSite attributes.', 'Set-Cookie header inspection', 1],
    ['ctrl-asvs-v9', 'fw-owasp-asvs', 'V9.1', 'Client Communications Security', 'Transport', 'TLS 1.2+ only with strong ciphers and valid trusted certificate chain.', 'TLS socket inspection', 1],
    ['ctrl-asvs-v14', 'fw-owasp-asvs', 'V14.4', 'HTTP Security Headers', 'Headers', 'Strict Content-Security-Policy, HSTS, X-Content-Type-Options, and framing protections.', 'HTTP security header analyzer', 1],

    // NIST CSF
    ['ctrl-nist-prds', 'fw-nist-csf', 'PR.DS-02', 'Data-in-Transit Protection', 'Protect', 'Confidentiality and integrity of data in transit using modern TLS and HSTS.', 'TLS & HSTS verification', 1],
    ['ctrl-nist-prps', 'fw-nist-csf', 'PR.PS-01', 'Configuration Management', 'Protect', 'Hardened HTTP security configuration and minimal surface exposure.', 'Headers, methods & exposure checks', 1],
    ['ctrl-nist-idra', 'fw-nist-csf', 'ID.RA-01', 'Vulnerability Identification', 'Identify', 'Continuous detection of known CVEs in dependencies and web application weaknesses.', 'SCA OSV lookup & SAST analysis', 1],

    // CIS Controls v8
    ['ctrl-cis-04', 'fw-cis-v8', 'CIS 4.1', 'Secure Configuration of Enterprise Assets', 'Configuration', 'Eliminate default/debug exposures and enforce secure HTTP response policies.', 'Surface & header inspection', 1],
    ['ctrl-cis-07', 'fw-cis-v8', 'CIS 7.1', 'Continuous Vulnerability Management', 'Vulnerability Mgmt', 'Automated repeatable vulnerability assessment and remediation tracking.', 'Scan execution & finding lifecycle', 1],
    ['ctrl-cis-16', 'fw-cis-v8', 'CIS 16.11', 'Application Security & SAST/SCA', 'AppSec', 'Inspect third-party libraries and source patterns for known security defects.', 'SCA & SAST modules', 1],

    // PCI DSS 4.0 Technical Indicators
    ['ctrl-pci-42', 'fw-pci-dss', 'Req 4.2.1', 'Strong Cryptography During Transmission', 'Transport', 'Strong TLS protocols (>=1.2) and valid certificates on public web interfaces.', 'TLS handshake check (non-certifying)', 1],
    ['ctrl-pci-62', 'fw-pci-dss', 'Req 6.2 / 6.3', 'Bespoke Software & Known Vulnerabilities', 'AppSec', 'Identify known vulnerable software components and common web weaknesses.', 'SCA & passive web checks (non-certifying)', 1],
    ['ctrl-pci-643', 'fw-pci-dss', 'Req 6.4.3', 'Payment Page Script Integrity Indicators', 'Integrity', 'CSP script-src and SRI protections against unauthorized client-side script execution.', 'CSP & HTML SRI inspection (non-certifying)', 1],

    // GDPR Art 32 Technical Indicators
    ['ctrl-gdpr-32', 'fw-gdpr-art32', 'Art. 32(1)(a)', 'Encryption in Transit & Exposure Control', 'Data Security', 'HTTPS/TLS transport encryption, cookie protection, and absence of exposed backup/env files.', 'TLS, Cookie & Public Exposure checks (non-certifying)', 1],
    ['ctrl-gdpr-rest', 'fw-gdpr-art32', 'Art. 32(1)(b)', 'Encryption at Rest & Backup Resilience', 'Data Security', 'Database encryption at rest, key rotation, and verified backup recovery.', 'Manual administrative & infrastructure evidence required', 0],
  ];

  const insertCtrl = db.prepare(
    'INSERT INTO compliance_controls (id, framework_id, control_code, title, category, description, evidence_required, automatable) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  );
  for (const c of controls) {
    insertCtrl.run(...c);
  }
}
