import { Router } from 'express';
import { z } from 'zod';
import { ROLES, ROLE_PERMISSIONS, type Role } from '@vuln/shared';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { hashPassword, jwtAuth, passwordStrengthIssue, requireRole } from '../../core/auth.js';
import { asyncHandler, created, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow, zPagination } from '../../core/validate.js';

export const userRouter: Router = Router();
userRouter.use(jwtAuth, requireRole('admin'), generalRateLimit);

const createSchema = z.object({
  username: z
    .string()
    .min(3, 'username 至少 3 位')
    .max(64)
    .regex(/^[A-Za-z0-9_.-]+$/, 'username 只允许字母、数字、下划线、点、连字符'),
  password: z.string().min(8, 'password 至少 8 位').max(128),
  displayName: z.string().max(64).optional().nullable(),
  email: z.string().email('email 格式不正确').max(128).optional().nullable(),
  role: z.enum(ROLES).default('auditor'),
  status: z.coerce.number().int().min(0).max(1).default(1),
});

const updateSchema = z.object({
  displayName: z.string().max(64).optional().nullable(),
  email: z.string().email('email 格式不正确').max(128).optional().nullable(),
  role: z.enum(ROLES).optional(),
  status: z.coerce.number().int().min(0).max(1).optional(),
  password: z.string().min(8).max(128).optional(),
});

const listSchema = z.object({
  ...zPagination,
  keyword: z.string().optional(),
  role: z.enum(ROLES).optional(),
  status: z.coerce.number().int().min(0).max(1).optional(),
});

interface UserRow {
  id: number;
  username: string;
  display_name: string | null;
  email: string | null;
  role: Role;
  status: number;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

function mapUser(r: UserRow) {
  return {
    id: r.id,
    username: r.username,
    displayName: r.display_name,
    email: r.email,
    role: r.role,
    status: r.status,
    permissions: ROLE_PERMISSIONS[r.role] ?? [],
    lastLoginAt: r.last_login_at,
    createdAt: r.created_at,
  };
}

/** GET /users */
userRouter.get(
  '/',
  asyncHandler((req, res) => {
    const q = parseOrThrow(listSchema, req.query, 'query');
    const db = getDb();
    const cond: string[] = ['1 = 1'];
    const params: (string | number)[] = [];
    if (q.keyword) {
      cond.push('(username LIKE ? OR display_name LIKE ? OR email LIKE ?)');
      const kw = `%${q.keyword}%`;
      params.push(kw, kw, kw);
    }
    if (q.role) {
      cond.push('role = ?');
      params.push(q.role);
    }
    if (q.status !== undefined) {
      cond.push('status = ?');
      params.push(q.status);
    }
    const where = cond.join(' AND ');

    const totalRow = db.get<{ c: number }>(`SELECT COUNT(*) AS c FROM users WHERE ${where}`, params);
    const total = Number(totalRow?.c ?? 0);
    const list = db.all<UserRow>(
      `SELECT id, username, display_name, email, role, status, last_login_at, created_at, updated_at
         FROM users WHERE ${where} ORDER BY id ASC LIMIT ? OFFSET ?`,
      [...params, q.pageSize, (q.page - 1) * q.pageSize],
    );

    ok(res, {
      list: list.map(mapUser),
      pagination: {
        page: q.page,
        pageSize: q.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / q.pageSize)),
      },
    });
  }),
);

/** GET /users/options —— 指派下拉用（管理员以外不可访问，故另开公开版见下方） */
userRouter.get(
  '/options',
  asyncHandler((_req, res) => {
    const db = getDb();
    const list = db.all<{ id: number; username: string; display_name: string | null; role: Role }>(
      `SELECT id, username, display_name, role FROM users WHERE status = 1 ORDER BY role ASC, id ASC`,
    );
    ok(res, { list: list.map((u) => ({ id: u.id, username: u.username, displayName: u.display_name, role: u.role })) });
  }),
);

/** POST /users */
userRouter.post(
  '/',
  asyncHandler((req, res) => {
    const body = parseOrThrow(createSchema, req.body);
    const issue = passwordStrengthIssue(body.password);
    if (issue) throw new AppError(40003, issue, 400);

    const db = getDb();
    const dup = db.get<{ id: number }>(`SELECT id FROM users WHERE username = ?`, [body.username]);
    if (dup) throw AppError.conflict(`用户名已存在：${body.username}`);

    const nowIso = new Date().toISOString();
    const r = db.run(
      `INSERT INTO users(username, password_hash, display_name, email, role, status, created_at, updated_at)
       VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        body.username,
        hashPassword(body.password),
        body.displayName ?? null,
        body.email ?? null,
        body.role,
        body.status,
        nowIso,
        nowIso,
      ],
    );
    const row = db.get<UserRow>(
      `SELECT id, username, display_name, email, role, status, last_login_at, created_at, updated_at
         FROM users WHERE id = ?`,
      [r.lastInsertRowid],
    );
    created(res, row ? mapUser(row) : { id: r.lastInsertRowid });
  }),
);

/** PATCH /users/:id */
userRouter.patch(
  '/:id',
  asyncHandler((req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw AppError.invalid('id 必须是正整数', 'id');
    const body = parseOrThrow(updateSchema, req.body);
    const db = getDb();
    const exists = db.get<{ id: number; role: Role }>(`SELECT id, role FROM users WHERE id = ?`, [id]);
    if (!exists) throw AppError.notFound(`用户不存在：${id}`);

    // 不允许把自己降级/禁用，避免把管理权限锁死
    if (id === req.user!.id) {
      if (body.role && body.role !== 'admin') throw AppError.invalid('不能修改自己的角色', 'role');
      if (body.status === 0) throw AppError.invalid('不能禁用当前登录账号', 'status');
    }
    if (body.password) {
      const issue = passwordStrengthIssue(body.password);
      if (issue) throw new AppError(40003, issue, 400);
    }

    const sets: string[] = [];
    const params: (string | number | null)[] = [];
    if (body.displayName !== undefined) {
      sets.push('display_name = ?');
      params.push(body.displayName);
    }
    if (body.email !== undefined) {
      sets.push('email = ?');
      params.push(body.email);
    }
    if (body.role !== undefined) {
      sets.push('role = ?');
      params.push(body.role);
    }
    if (body.status !== undefined) {
      sets.push('status = ?');
      params.push(body.status);
    }
    if (body.password) {
      sets.push('password_hash = ?');
      params.push(hashPassword(body.password));
    }
    if (sets.length === 0) throw AppError.invalid('没有需要更新的字段', 'body');

    sets.push('updated_at = ?');
    params.push(new Date().toISOString(), id);
    db.run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, params);

    const row = db.get<UserRow>(
      `SELECT id, username, display_name, email, role, status, last_login_at, created_at, updated_at
         FROM users WHERE id = ?`,
      [id],
    );
    ok(res, row ? mapUser(row) : null);
  }),
);
