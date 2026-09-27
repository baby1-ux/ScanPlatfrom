import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import type { NextFunction, Request, Response } from 'express';
import { ERROR_CODES, ROLE_PERMISSIONS, type Permission, type Role } from '@vuln/shared';
import { config } from '../config/index.js';
import { AppError } from '../core/errors.js';
import { getDb } from '../db/index.js';
import { apiKeyHash } from '../services/fingerprint.js';

// ------------------------------------------------------------------ 密码
const BCRYPT_ROUNDS = 10;

export function hashPassword(plain: string): string {
  return bcrypt.hashSync(plain, BCRYPT_ROUNDS);
}

export function verifyPassword(plain: string, hash: string): boolean {
  try {
    return bcrypt.compareSync(plain, hash);
  } catch {
    return false;
  }
}

/** 密码强度：≥ 8 位，且至少包含大写/小写/数字/特殊字符中的 3 类 */
export function passwordStrengthIssue(pwd: string): string | null {
  if (pwd.length < 8) return '新密码长度至少 8 位';
  const classes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pwd)).length;
  if (classes < 3) return '新密码需至少包含大写字母、小写字母、数字、特殊字符中的 3 类';
  return null;
}

// -------------------------------------------------------------------- JWT
export interface JwtPayload {
  sub: number;
  username: string;
  role: Role;
}

export function signToken(payload: JwtPayload): { accessToken: string; expiresIn: number } {
  const accessToken = jwt.sign(payload, config.jwt.secret, {
    expiresIn: config.jwt.expiresIn as jwt.SignOptions['expiresIn'],
  });
  const decoded = jwt.decode(accessToken) as { exp?: number; iat?: number } | null;
  const expiresIn = decoded?.exp && decoded?.iat ? decoded.exp - decoded.iat : 28800;
  return { accessToken, expiresIn };
}

export function verifyToken(token: string): JwtPayload {
  try {
    return jwt.verify(token, config.jwt.secret) as unknown as JwtPayload;
  } catch {
    throw AppError.unauthorized(ERROR_CODES.UNAUTHORIZED);
  }
}

// ------------------------------------------------------------- JWT 中间件
interface UserRow {
  id: number;
  username: string;
  display_name: string | null;
  role: Role;
  status: number;
}

/** 平台前端接口鉴权：Authorization: Bearer <accessToken> */
export function jwtAuth(req: Request, _res: Response, next: NextFunction): void {
  const header = req.header('Authorization') ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!m) throw AppError.unauthorized(ERROR_CODES.UNAUTHORIZED);

  const payload = verifyToken(m[1]!);
  const db = getDb();
  const row = db.get<UserRow>(
    `SELECT id, username, display_name, role, status FROM users WHERE id = ?`,
    [payload.sub],
  );
  if (!row) throw AppError.unauthorized(ERROR_CODES.UNAUTHORIZED);
  if (row.status !== 1) throw AppError.forbidden(ERROR_CODES.ACCOUNT_DISABLED);

  req.user = {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
    permissions: ROLE_PERMISSIONS[row.role] ?? [],
  };
  next();
}

/** 角色/权限校验：requirePermission('vuln:write') */
export function requirePermission(...needed: Permission[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const perms = req.user?.permissions ?? [];
    const missing = needed.filter((p) => !perms.includes(p));
    if (missing.length > 0) {
      throw AppError.forbidden(ERROR_CODES.FORBIDDEN);
    }
    next();
  };
}

export function requireRole(...roles: Role[]) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      throw AppError.forbidden(ERROR_CODES.FORBIDDEN);
    }
    next();
  };
}

// --------------------------------------------------------- API Key 中间件
interface ApiKeyRow {
  id: number;
  name: string;
  scopes: string;
  repo_scope: string | null;
  expires_at: string | null;
  status: number;
}

/** 扫描工具接口鉴权：X-API-Key: vuln_sk_xxx */
export function apiKeyAuth(req: Request, _res: Response, next: NextFunction): void {
  const raw = req.header('X-API-Key') ?? '';
  if (!raw.trim()) throw AppError.unauthorized(ERROR_CODES.API_KEY_INVALID);

  const db = getDb();
  const row = db.get<ApiKeyRow>(
    `SELECT id, name, scopes, repo_scope, expires_at, status FROM api_keys WHERE key_hash = ?`,
    [apiKeyHash(raw.trim())],
  );
  if (!row || row.status !== 1) throw AppError.unauthorized(ERROR_CODES.API_KEY_INVALID);

  if (row.expires_at) {
    const exp = Date.parse(row.expires_at);
    if (Number.isFinite(exp) && exp < Date.now()) {
      throw AppError.unauthorized(ERROR_CODES.API_KEY_EXPIRED);
    }
  }

  db.run(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, [new Date().toISOString(), row.id]);

  req.apiKey = {
    id: row.id,
    name: row.name,
    scopes: row.scopes.split(',').map((s) => s.trim()).filter(Boolean),
    repoScope: row.repo_scope
      ? row.repo_scope.split(',').map((s) => s.trim()).filter(Boolean)
      : null,
  };
  next();
}

/**
 * API Key 仓库白名单校验。
 * repoScope 为空 = 不限；否则上报的 repoUrl 必须在白名单内。
 */
export function assertRepoAllowed(repoUrl: string | undefined, key: Request['apiKey']): void {
  if (!key?.repoScope || key.repoScope.length === 0) return;
  if (!repoUrl) throw AppError.unauthorized(ERROR_CODES.API_KEY_REPO_DENIED);
  const normalized = repoUrl.trim().replace(/\.git$/, '').replace(/\/+$/, '');
  const allowed = key.repoScope.some(
    (r) => r.trim().replace(/\.git$/, '').replace(/\/+$/, '') === normalized,
  );
  if (!allowed) throw AppError.unauthorized(ERROR_CODES.API_KEY_REPO_DENIED);
}
