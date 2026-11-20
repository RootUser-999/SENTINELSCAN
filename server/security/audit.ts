import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

export interface AuditEntryInput {
  organizationId: string;
  userId: string | null;
  action: string;
  entityType: string;
  entityId?: string | null;
  details?: Record<string, unknown>;
  ipAddress?: string | null;
}

export function writeAuditLog(db: DatabaseSync, entry: AuditEntryInput): void {
  const id = crypto.randomUUID();
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO audit_logs (id, organization_id, user_id, action, entity_type, entity_id, details_json, ip_address, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    entry.organizationId,
    entry.userId,
    entry.action,
    entry.entityType,
    entry.entityId ?? null,
    JSON.stringify(entry.details ?? {}),
    entry.ipAddress ?? null,
    now
  );
}

export function createNotification(
  db: DatabaseSync,
  params: {
    organizationId: string;
    userId?: string | null;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    message: string;
  }
): void {
  db.prepare(
    `INSERT INTO notifications (id, organization_id, user_id, severity, title, message, read_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`
  ).run(
    crypto.randomUUID(),
    params.organizationId,
    params.userId ?? null,
    params.severity,
    params.title,
    params.message,
    new Date().toISOString()
  );
}
