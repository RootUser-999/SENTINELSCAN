import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { getDb } from '../db/database.ts';
import type { AuthUser, UserRole } from '../db/types.ts';

const EPHEMERAL_AUTH_SECRET = crypto.randomBytes(32).toString('hex');

function getAuthSecret(): string {
  const configured = process.env.SENTINEL_AUTH_SECRET;
  if (configured && configured.trim().length >= 16) {
    return configured.trim();
  }
  return EPHEMERAL_AUTH_SECRET;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export interface SessionTokenPayload {
  userId: string;
  organizationId: string;
  role: UserRole;
  exp: number;
}

export function signSessionToken(payload: Omit<SessionTokenPayload, 'exp'>, ttlHours = 12): string {
  const fullPayload: SessionTokenPayload = {
    ...payload,
    exp: Date.now() + ttlHours * 60 * 60 * 1000,
  };
  const body = Buffer.from(JSON.stringify(fullPayload), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getAuthSecret())
    .update(body)
    .digest('base64url');
  return `${body}.${sig}`;
}

export function verifySessionToken(token: string): SessionTokenPayload | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  if (!body || !sig) return null;
  const expectedSig = crypto
    .createHmac('sha256', getAuthSecret())
    .update(body)
    .digest('base64url');
  const sigBuf = Buffer.from(sig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as SessionTokenPayload;
    if (!parsed.userId || !parsed.organizationId || !parsed.exp || parsed.exp < Date.now()) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function hashApiKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

export interface AuthenticatedRequest extends Request {
  authUser?: AuthUser;
}

export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const db = getDb();
  const authHeader = req.headers.authorization;
  const apiKeyHeader = req.headers['x-api-key'];

  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7).trim();
    const payload = verifySessionToken(token);
    if (!payload) {
      res.status(401).json({ error: 'Invalid or expired authentication token' });
      return;
    }
    const row = db
      .prepare(
        `SELECT u.id, u.email, u.full_name, u.mfa_enabled, m.organization_id, m.role, o.name as org_name
         FROM users u
         JOIN organization_memberships m ON m.user_id = u.id
         JOIN organizations o ON o.id = m.organization_id
         WHERE u.id = ? AND m.organization_id = ?`
      )
      .get(payload.userId, payload.organizationId) as
      | {
          id: string;
          email: string;
          full_name: string;
          mfa_enabled: number;
          organization_id: string;
          role: UserRole;
          org_name: string;
        }
      | undefined;

    if (!row) {
      res.status(401).json({ error: 'Workspace membership not found' });
      return;
    }

    req.authUser = {
      id: row.id,
      email: row.email,
      fullName: row.full_name,
      organizationId: row.organization_id,
      organizationName: row.org_name,
      role: row.role,
      mfaEnabled: Boolean(row.mfa_enabled),
    };
    next();
    return;
  }

  if (typeof apiKeyHeader === 'string' && apiKeyHeader.trim().length > 0) {
    const hashed = hashApiKey(apiKeyHeader.trim());
    const keyRow = db
      .prepare(
        `SELECT k.id, k.organization_id, k.role, k.expires_at, k.revoked_at, k.created_by_user_id,
                o.name as org_name, u.email, u.full_name
         FROM api_keys k
         JOIN organizations o ON o.id = k.organization_id
         JOIN users u ON u.id = k.created_by_user_id
         WHERE k.key_hash = ?`
      )
      .get(hashed) as
      | {
          id: string;
          organization_id: string;
          role: UserRole;
          expires_at: string | null;
          revoked_at: string | null;
          created_by_user_id: string;
          org_name: string;
          email: string;
          full_name: string;
        }
      | undefined;

    if (!keyRow || keyRow.revoked_at) {
      res.status(401).json({ error: 'API key is invalid or revoked' });
      return;
    }
    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() < Date.now()) {
      res.status(401).json({ error: 'API key has expired' });
      return;
    }

    db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(
      new Date().toISOString(),
      keyRow.id
    );

    req.authUser = {
      id: keyRow.created_by_user_id,
      email: keyRow.email,
      fullName: keyRow.full_name,
      organizationId: keyRow.organization_id,
      organizationName: keyRow.org_name,
      role: keyRow.role,
      mfaEnabled: false,
    };
    next();
    return;
  }

  res.status(401).json({ error: 'Authentication required' });
}

export function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.authUser) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }
    if (!allowedRoles.includes(req.authUser.role)) {
      res.status(403).json({
        error: `Insufficient permissions. Required role: ${allowedRoles.join(' or ')}`,
      });
      return;
    }
    next();
  };
}

// Simple per-IP in-memory rate limiter for auth & scan creation
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(maxRequests: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = `${req.ip || 'unknown'}:${req.baseUrl}${req.path}`;
    const now = Date.now();
    const bucket = rateBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
      next();
      return;
    }
    if (bucket.count >= maxRequests) {
      res.status(429).json({
        error: 'Rate limit exceeded. Please wait before retrying.',
      });
      return;
    }
    bucket.count += 1;
    next();
  };
}
