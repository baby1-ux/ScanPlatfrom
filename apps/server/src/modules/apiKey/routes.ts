import { Router } from 'express';
import { z } from 'zod';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { jwtAuth, requireRole } from '../../core/auth.js';
import { asyncHandler, created, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow, zPagination } from '../../core/validate.js';
import { apiKeyHash, generateApiKey, maskApiKey } from '../../services/fingerprint.js';

export const apiKeyRouter: Router = Router();
// API Key 管理：JWT 且角色必须是 admin（docs/02 第 4 章）
apiKeyRouter.use(jwtAuth, requireRole('admin'), generalRateLimit);

const createSchema = z.object({
  name: z.string().min(1, 'name 不能为空').max(64),
  scopes: z.array(z.string().min(1)).optional().default(['ingest']),
  repoScope: z.array(z.string().min(1)).optional().nullable(),
  expiresAt: z
    .string()
    .refine((s) => Number.isFinite(Date.parse(s)), { message: 'expiresAt 必须是 ISO 8601 时间' })
    .optional()
    .nullable(),
});

const listSchema = z.object({
  ...zPagination,
  status: z.coerce.number().int().min(0).max(1).optional(),
  keyword: z.string().optional(),
});

interface KeyRow {
  id: number;
  name: string;
  key_prefix: string;
  key_hash: string;
  scopes: string;
  repo_scope: string | null;
  status: number;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

/**
 * 列表：只返回掩码。
 * 说明：契约示例里的 maskedKey 形如 `vuln_sk_9f3a****2e4c`，但平台只存 sha256，
 * 无法还原明文。因此这里基于 key_prefix 与 hash 尾 4 位生成稳定的展示掩码，
 * 既能区分不同 Key，又不泄露任何可用于鉴权的信息。
 */
function mapKey(r: KeyRow) {
  return {
    id: r.id,
    name: r.name,
    keyPrefix: r.key_prefix,
    maskedKey: `${r.key_prefix}****${r.key_hash.slice(-4)}`,
    scopes: r.scopes.split(',').map((s) => s.trim()).filter(Boolean),
    repoScope: r.repo_scope
      ? r.repo_scope.split(',').map((s) => s.trim()).filter(Boolean)
      : null,
    status: r.status,
    expiresAt: r.expires_at,
    lastUsedAt: r.last_used_at,
    createdAt: r.created_at,
  };
}

/** POST /api-keys —— 明文只在创建时返回一次 */
apiKeyRouter.post(
  '/',
  asyncHandler((req, res) => {
    const body = parseOrThrow(createSchema, req.body);
    const db = getDb();
    const plain = generateApiKey();
    const nowIso = new Date().toISOString();

    const r = db.run(
      `INSERT INTO api_keys(name, key_prefix, key_hash, scopes, repo_scope, expires_at, status, created_by, created_at, updated_at)
       VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`,
      [
        body.name,
        plain.slice(0, 12),
        apiKeyHash(plain),
        (body.scopes.length ? body.scopes : ['ingest']).join(','),
        body.repoScope && body.repoScope.length ? body.repoScope.join(',') : null,
        body.expiresAt ?? null,
        req.user!.id,
        nowIso,
        nowIso,
      ],
    );

    created(res, {
      id: r.lastInsertRowid,
      name: body.name,
      /** ⚠️ 仅本次返回，之后无法找回 */
      apiKey: plain,
      keyPrefix: plain.slice(0, 12),
      maskedKey: maskApiKey(plain),
      scopes: body.scopes.length ? body.scopes : ['ingest'],
      repoScope: body.repoScope ?? null,
      expiresAt: body.expiresAt ?? null,
      status: 1,
      createdAt: nowIso,
    });
  }),
);

/** GET /api-keys */
apiKeyRouter.get(
  '/',
  asyncHandler((req, res) => {
    const q = parseOrThrow(listSchema, req.query, 'query');
    const db = getDb();
    const cond: string[] = ['1 = 1'];
    const params: (string | number)[] = [];
    if (q.status !== undefined) {
      cond.push('status = ?');
      params.push(q.status);
    }
    if (q.keyword) {
      cond.push('(name LIKE ? OR key_prefix LIKE ?)');
      params.push(`%${q.keyword}%`, `%${q.keyword}%`);
    }
    const where = cond.join(' AND ');

    const totalRow = db.get<{ c: number }>(`SELECT COUNT(*) AS c FROM api_keys WHERE ${where}`, params);
    const total = Number(totalRow?.c ?? 0);
    const list = db.all<KeyRow>(
      `SELECT * FROM api_keys WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`,
      [...params, q.pageSize, (q.page - 1) * q.pageSize],
    );

    ok(res, {
      list: list.map(mapKey),
      pagination: {
        page: q.page,
        pageSize: q.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / q.pageSize)),
      },
    });
  }),
);

/** DELETE /api-keys/:id —— 吊销（立即生效） */
apiKeyRouter.delete(
  '/:id',
  asyncHandler((req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw AppError.invalid('id 必须是正整数', 'id');
    const db = getDb();
    const row = db.get<{ id: number }>(`SELECT id FROM api_keys WHERE id = ?`, [id]);
    if (!row) throw AppError.notFound(`API Key 不存在：${id}`);
    db.run(`UPDATE api_keys SET status = 0, updated_at = ? WHERE id = ?`, [
      new Date().toISOString(),
      id,
    ]);
    ok(res, { id, status: 0 });
  }),
);

/** POST /api-keys/:id/restore —— 恢复启用（契约未定义，管理便利性补充，只增不改语义） */
apiKeyRouter.post(
  '/:id/restore',
  asyncHandler((req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw AppError.invalid('id 必须是正整数', 'id');
    const db = getDb();
    const row = db.get<{ id: number }>(`SELECT id FROM api_keys WHERE id = ?`, [id]);
    if (!row) throw AppError.notFound(`API Key 不存在：${id}`);
    db.run(`UPDATE api_keys SET status = 1, updated_at = ? WHERE id = ?`, [
      new Date().toISOString(),
      id,
    ]);
    ok(res, { id, status: 1 });
  }),
);
