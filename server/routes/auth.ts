import crypto from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { getDb } from '../db/database.ts';
import { writeAuditLog } from '../security/audit.ts';
import {
  type AuthenticatedRequest,
  hashPassword,
  rateLimit,
  requireAuth,
  requireRole,
  signSessionToken,
  verifyPassword,
} from '../security/auth.ts';

const router = Router();

const registerSchema = z.object({
  email: z.string().email().max(160),
  fullName: z.string().min(2).max(100),
  organizationName: z.string().min(2).max(120),
  password: z.string().min(8).max(128),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

router.get('/status', (_req, res) => {
  const db = getDb();
  const row = db.prepare('SELECT COUNT(*) as cnt FROM users').get() as { cnt: number };
  res.json({
    initialized: row.cnt > 0,
    userCount: row.cnt,
  });
});

router.post('/register', rateLimit(15, 60_000), (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid registration payload' });
    return;
  }

  const db = getDb();
  const email = parsed.data.email.trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    res.status(409).json({ error: 'An account with this email already exists' });
    return;
  }

  const now = new Date().toISOString();
  const userId = crypto.randomUUID();
  const orgId = crypto.randomUUID();
  const slugBase = parsed.data.organizationName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 40);
  const orgSlug = `${slugBase || 'org'}-${orgId.slice(0, 6)}`;

  const pwHash = hashPassword(parsed.data.password);

  db.prepare(
    'INSERT INTO users (id, email, full_name, password_hash, mfa_enabled, created_at, last_login_at) VALUES (?, ?, ?, ?, 0, ?, ?)'
  ).run(userId, email, parsed.data.fullName.trim(), pwHash, now, now);

  db.prepare('INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)').run(
    orgId,
    parsed.data.organizationName.trim(),
    orgSlug,
    now
  );

  db.prepare(
    'INSERT INTO organization_memberships (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), orgId, userId, 'admin', now);

  writeAuditLog(db, {
    organizationId: orgId,
    userId,
    action: 'auth.register_organization',
    entityType: 'organization',
    entityId: orgId,
    details: { email },
    ipAddress: req.ip || null,
  });

  const token = signSessionToken({ userId, organizationId: orgId, role: 'admin' });
  res.status(201).json({
    token,
    user: {
      id: userId,
      email,
      fullName: parsed.data.fullName.trim(),
      organizationId: orgId,
      organizationName: parsed.data.organizationName.trim(),
      role: 'admin',
      mfaEnabled: false,
    },
  });
});

router.post('/login', rateLimit(20, 60_000), (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Valid email and password are required' });
    return;
  }

  const db = getDb();
  const email = parsed.data.email.trim().toLowerCase();
  const userRow = db
    .prepare(
      `SELECT u.id, u.email, u.full_name, u.password_hash, u.mfa_enabled,
              m.organization_id, m.role, o.name as org_name
       FROM users u
       JOIN organization_memberships m ON m.user_id = u.id
       JOIN organizations o ON o.id = m.organization_id
       WHERE u.email = ?`
    )
    .get(email) as
    | {
        id: string;
        email: string;
        full_name: string;
        password_hash: string;
        mfa_enabled: number;
        organization_id: string;
        role: 'admin' | 'analyst' | 'viewer';
        org_name: string;
      }
    | undefined;

  if (!userRow || !verifyPassword(parsed.data.password, userRow.password_hash)) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE users SET last_login_at = ? WHERE id = ?').run(now, userRow.id);

  writeAuditLog(db, {
    organizationId: userRow.organization_id,
    userId: userRow.id,
    action: 'auth.login',
    entityType: 'user',
    entityId: userRow.id,
    ipAddress: req.ip || null,
  });

  const token = signSessionToken({
    userId: userRow.id,
    organizationId: userRow.organization_id,
    role: userRow.role,
  });

  res.json({
    token,
    user: {
      id: userRow.id,
      email: userRow.email,
      fullName: userRow.full_name,
      organizationId: userRow.organization_id,
      organizationName: userRow.org_name,
      role: userRow.role,
      mfaEnabled: Boolean(userRow.mfa_enabled),
    },
  });
});

router.get('/me', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const members = db
    .prepare(
      `SELECT u.id, u.email, u.full_name, u.mfa_enabled, u.last_login_at, m.role, m.created_at
       FROM organization_memberships m
       JOIN users u ON u.id = m.user_id
       WHERE m.organization_id = ?
       ORDER BY m.created_at ASC`
    )
    .all(req.authUser!.organizationId);

  res.json({
    user: req.authUser,
    members,
  });
});

const addMemberSchema = z.object({
  email: z.string().email().max(160),
  fullName: z.string().min(2).max(100),
  password: z.string().min(8).max(128),
  role: z.enum(['admin', 'analyst', 'viewer']),
});

router.post('/members', requireAuth, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const parsed = addMemberSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid member details' });
    return;
  }

  const db = getDb();
  const email = parsed.data.email.trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    res.status(409).json({ error: 'A user with this email already exists' });
    return;
  }

  const now = new Date().toISOString();
  const userId = crypto.randomUUID();
  db.prepare(
    'INSERT INTO users (id, email, full_name, password_hash, mfa_enabled, created_at) VALUES (?, ?, ?, ?, 0, ?)'
  ).run(userId, email, parsed.data.fullName.trim(), hashPassword(parsed.data.password), now);

  db.prepare(
    'INSERT INTO organization_memberships (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(crypto.randomUUID(), req.authUser!.organizationId, userId, parsed.data.role, now);

  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: 'org.member_added',
    entityType: 'user',
    entityId: userId,
    details: { email, role: parsed.data.role },
    ipAddress: req.ip || null,
  });

  res.status(201).json({ id: userId, email, fullName: parsed.data.fullName.trim(), role: parsed.data.role });
});

router.post('/mfa/toggle', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = getDb();
  const nextVal = req.authUser!.mfaEnabled ? 0 : 1;
  db.prepare('UPDATE users SET mfa_enabled = ? WHERE id = ?').run(nextVal, req.authUser!.id);
  writeAuditLog(db, {
    organizationId: req.authUser!.organizationId,
    userId: req.authUser!.id,
    action: nextVal ? 'auth.mfa_enabled' : 'auth.mfa_disabled',
    entityType: 'user',
    entityId: req.authUser!.id,
  });
  res.json({ mfaEnabled: Boolean(nextVal) });
});

export default router;
