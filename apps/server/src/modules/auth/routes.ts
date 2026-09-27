import { Router } from 'express';
import { z } from 'zod';
import { ERROR_CODES, ROLE_PERMISSIONS, type Role } from '@vuln/shared';
import { AppError } from '../../core/errors.js';
import { getDb } from '../../db/index.js';
import {
  hashPassword,
  jwtAuth,
  passwordStrengthIssue,
  signToken,
  verifyPassword,
} from '../../core/auth.js';
import { asyncHandler, ok } from '../../core/http.js';
import { loginRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow } from '../../core/validate.js';

export const authRouter: Router = Router();

const loginSchema = z.object({
  username: z.string().min(1, 'username 不能为空').max(64),
  password: z.string().min(1, 'password 不能为空').max(128),
});

const changePasswordSchema = z.object({
  oldPassword: z.string().min(1, 'oldPassword 不能为空'),
  newPassword: z.string().min(1, 'newPassword 不能为空'),
});

interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  display_name: string | null;
  email: string | null;
  role: Role;
  status: number;
  last_login_at: string | null;
}

function toUserInfo(row: UserRow) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    email: row.email,
    role: row.role,
    status: row.status,
    lastLoginAt: row.last_login_at,
    permissions: ROLE_PERMISSIONS[row.role] ?? [],
  };
}

/** POST /auth/login —— 无需鉴权，按 IP 限流 10 次/分钟 */
authRouter.post(
  '/login',
  loginRateLimit,
  asyncHandler((req, res) => {
    const { username, password } = parseOrThrow(loginSchema, req.body);
    const db = getDb();
    const row = db.get<UserRow>(
      `SELECT id, username, password_hash, display_name, email, role, status, last_login_at
         FROM users WHERE username = ?`,
      [username],
    );

    // 不区分「用户不存在」与「密码错误」，防账号枚举
    if (!row || !verifyPassword(password, row.password_hash)) {
      throw AppError.unauthorized(ERROR_CODES.UNAUTHORIZED);
    }
    if (row.status !== 1) throw AppError.forbidden(ERROR_CODES.ACCOUNT_DISABLED);

    const nowIso = new Date().toISOString();
    db.run(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?`, [nowIso, nowIso, row.id]);

    const { accessToken, expiresIn } = signToken({
      sub: row.id,
      username: row.username,
      role: row.role,
    });

    ok(res, {
      accessToken,
      tokenType: 'Bearer' as const,
      expiresIn,
      user: toUserInfo({ ...row, last_login_at: nowIso }),
    });
  }),
);

/** GET /auth/me */
authRouter.get(
  '/me',
  jwtAuth,
  asyncHandler((req, res) => {
    const db = getDb();
    const row = db.get<UserRow>(
      `SELECT id, username, password_hash, display_name, email, role, status, last_login_at
         FROM users WHERE id = ?`,
      [req.user!.id],
    );
    if (!row) throw AppError.unauthorized();
    ok(res, toUserInfo(row));
  }),
);

/** POST /auth/logout —— 前端清理本地 token 即可 */
authRouter.post(
  '/logout',
  jwtAuth,
  asyncHandler((_req, res) => {
    ok(res, null);
  }),
);

/** POST /auth/change-password */
authRouter.post(
  '/change-password',
  jwtAuth,
  asyncHandler((req, res) => {
    const { oldPassword, newPassword } = parseOrThrow(changePasswordSchema, req.body);
    const db = getDb();
    const row = db.get<{ password_hash: string }>(`SELECT password_hash FROM users WHERE id = ?`, [
      req.user!.id,
    ]);
    if (!row || !verifyPassword(oldPassword, row.password_hash)) {
      throw new AppError(ERROR_CODES.OLD_PASSWORD_WRONG, undefined, 400);
    }
    const issue = passwordStrengthIssue(newPassword);
    if (issue) throw new AppError(ERROR_CODES.PASSWORD_TOO_WEAK, issue, 400);

    const nowIso = new Date().toISOString();
    db.run(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, [
      hashPassword(newPassword),
      nowIso,
      req.user!.id,
    ]);
    ok(res, { id: req.user!.id, updatedAt: nowIso });
  }),
);
