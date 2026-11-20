# SentinelScan Architecture Specification

## 1. High-Level System Architecture

```
+-------------------------------------------------------------------+
|                   React 19 + TypeScript SPA                       |
|  Overview | Assets & Verification | Scan Console | Vulnerabilities|
|  API/SCA/SAST | Compliance & Reports | Vault, RBAC & Audit Logs   |
+---------------------------------+---------------------------------+
                                  | Authorization: Bearer (In-Memory)
                                  | /api/v1/* (JSON + PDF/CSV Streams)
+---------------------------------v---------------------------------+
|                Express API Gateway & Security Layer               |
|  - scrypt Auth + HMAC Tokens + API Keys + RBAC (admin/analyst)    |
|  - SSRF Guard (CIDR IP blocking, DNS lookup, hop-by-hop redirect) |
|  - AES-256-GCM Credential Vault + Secret Redaction                |
|  - Immutable Audit Log Middleware + Rate Limiting                 |
+-----------------+----------------------------------+--------------+
                  |                                  |
+-----------------v----------------+  +--------------v--------------+
|   Modular Scan Orchestrator      |  |  Intelligence & Reporting   |
|  - Async Queue (Concurrency=2)   |  |  - CVSS 4.0 Calculator      |
|  - Timeout Isolation & Cancel    |  |  - Posture Score Engine     |
|  - 9 Pluggable Scanner Modules   |  |  - Fingerprint Deduplication|
|  - Isolated Practice Target Lab  |  |  - PDFKit / 7 CSVs / JSON   |
+-----------------+----------------+  |  - 7 Compliance Frameworks  |
                  |                   +--------------+--------------+
                  v                                  v
+-------------------------------------------------------------------+
|             Normalized SQLite Database (WAL Mode, 23 Tables)      |
+-------------------------------------------------------------------+
```

## 2. Database Entity Relationship Summary
Normalized 23-table schema in `server/db/database.ts`:
- **Identity & Multi-Tenancy**: `users`, `organizations`, `organization_memberships`, `api_keys`
- **Targets & Authorization**: `assets`, `asset_ownership_verifications`, `scan_credentials`
- **Scanning Engine**: `scan_configurations`, `scans`, `scan_modules`, `scan_executions`, `scan_progress`, `endpoints`, `security_checks`
- **Vulnerability Intelligence**: `vulnerabilities`, `finding_evidence`, `finding_status_history`
- **Compliance & Reporting**: `compliance_frameworks`, `compliance_controls`, `compliance_mappings`, `reports`
- **Governance**: `audit_logs`, `notifications`

## 3. Scanner Module Plugin Interface
All 9 modules implement `ScannerModule` (`server/scanner/types.ts`):
1. `http-tls-transport` (v1.2.0) — HTTPS redirect, live `tls.connect` protocol/cipher/cert validation, manual encryption-at-rest disclosure
2. `http-security-headers` (v1.4.0) — Directive-level evaluation of CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy, CORP/COOP/COEP, Cache-Control, CORS reflection
3. `dns-infrastructure` (v1.1.0) — SPF, DMARC, CAA, server banner disclosure, WAF/CDN passive indicators
4. `surface-discovery-exposure` (v1.3.0) — Sensitive files (`.env`, `.git/HEAD`, directory indexes), HTTP `OPTIONS`, mixed content, DOM XSS source-to-sink, verbose errors, in-scope crawling
5. `session-auth-cookies` (v1.2.0) — `Set-Cookie` (`HttpOnly`, `Secure`, `SameSite`), form CSRF indicator, explicit `manual_required` flags for server-side Argon2/bcrypt & lockout checks
6. `api-security-openapi` (v1.3.0) — OpenAPI 3.x / Swagger JSON+YAML parsing, GraphQL introspection probe, endpoint inventory, OWASP API Top 10 (API1/API2/API8)
7. `dependency-sca` (v1.2.0) — Multi-manifest parsing (`package.json`, lockfiles, `requirements.txt`, `pyproject.toml`, `composer.lock`, `Gemfile.lock`) + live `api.osv.dev` CVE lookup
8. `static-code-sast` (v1.1.0) — Authorized source-code audit for hardcoded secrets, SQL/command sinks, weak hashing, XSS sinks, unsafe deserialization
9. `authenticated-access-check` (v1.0.0) — Encrypted credential differential GET check comparing anonymous vs authenticated access with secret redaction

## 4. Security & Authorization Boundaries
- **Zero Untrusted Network Proxy**: `server/security/ssrfGuard.ts` validates URL schemes (`http`/`https`), blocks private/loopback/link-local/metadata CIDRs (`127.0.0.0/8`, `10.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`, `fe80::/10`, `fc00::/7`), validates DNS resolution results, and enforces hop-by-hop redirect checks.
- **Mandatory Ownership Verification**: Active scans require `ownership_status === 'verified'` via DNS TXT (`_sentinelscan-verify.<domain>`), HTTP well-known file, HTML `<meta>` tag, or explicit Practice Lab attestation with signed authorization metadata.
- **No Fabricated Results**: Untested checks are explicitly recorded as `not_performed`, `not_applicable`, or `manual_required`, never `passed`.
