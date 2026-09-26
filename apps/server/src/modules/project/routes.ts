import { Router } from 'express';
import { z } from 'zod';
import { REPO_TYPES, type Severity } from '@vuln/shared';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { jwtAuth, requirePermission } from '../../core/auth.js';
import { asyncHandler, created, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow, zPagination } from '../../core/validate.js';

export const projectRouter: Router = Router();
projectRouter.use(jwtAuth, generalRateLimit);

const projectBodySchema = z.object({
  name: z.string().min(1, 'name 不能为空').max(128),
  repoType: z.enum(REPO_TYPES),
  repoUrl: z.string().min(1, 'repoUrl 不能为空').max(512),
  repoFullName: z.string().max(255).optional().nullable(),
  defaultBranch: z.string().max(128).optional().nullable(),
  owner: z.string().max(64).optional().nullable(),
  description: z.string().max(512).optional().nullable(),
  status: z.coerce.number().int().min(0).max(1).optional(),
});

const listQuerySchema = z.object({
  ...zPagination,
  keyword: z.string().optional(),
  repoType: z.enum(REPO_TYPES).optional(),
});

interface ProjectRow {
  id: number;
  name: string;
  repo_type: string;
  repo_url: string;
  repo_full_name: string | null;
  default_branch: string | null;
  owner: string | null;
  description: string | null;
  status: number;
  created_at: string;
  updated_at: string;
  scan_count: number;
  vuln_total: number;
  vuln_open: number;
  vuln_critical: number;
  vuln_high: number;
  last_scan_at: string | null;
}

const PROJECT_SELECT = `
  SELECT p.id, p.name, p.repo_type, p.repo_url, p.repo_full_name, p.default_branch,
         p.owner, p.description, p.status, p.created_at, p.updated_at,
         (SELECT COUNT(*) FROM scan_tasks s WHERE s.project_id = p.id) AS scan_count,
         (SELECT COUNT(*) FROM vulnerabilities v
           WHERE v.project_id = p.id AND v.status NOT IN ('false_positive','ignored')) AS vuln_total,
         (SELECT COUNT(*) FROM vulnerabilities v
           WHERE v.project_id = p.id AND v.status IN ('open','confirmed','fixing')) AS vuln_open,
         (SELECT COUNT(*) FROM vulnerabilities v
           WHERE v.project_id = p.id AND v.severity = 'critical'
             AND v.status NOT IN ('false_positive','ignored')) AS vuln_critical,
         (SELECT COUNT(*) FROM vulnerabilities v
           WHERE v.project_id = p.id AND v.severity = 'high'
             AND v.status NOT IN ('false_positive','ignored')) AS vuln_high,
         (SELECT MAX(COALESCE(s.finished_at, s.started_at, s.created_at)) FROM scan_tasks s
           WHERE s.project_id = p.id) AS last_scan_at
    FROM projects p`;

function mapProject(r: ProjectRow) {
  return {
    id: r.id,
    name: r.name,
    repoType: r.repo_type,
    repoUrl: r.repo_url,
    repoFullName: r.repo_full_name,
    defaultBranch: r.default_branch,
    owner: r.owner,
    description: r.description,
    status: r.status,
    stats: {
      scanCount: Number(r.scan_count ?? 0),
      vulnTotal: Number(r.vuln_total ?? 0),
      vulnOpen: Number(r.vuln_open ?? 0),
      vulnCritical: Number(r.vuln_critical ?? 0),
      vulnHigh: Number(r.vuln_high ?? 0),
    },
    lastScanAt: r.last_scan_at,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

/** GET /projects —— 项目列表（含扫描次数 / 漏洞数） */
projectRouter.get(
  '/',
  requirePermission('project:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(listQuerySchema, req.query, 'query');
    const db = getDb();
    const cond: string[] = ['1 = 1'];
    const params: (string | number)[] = [];
    if (q.keyword) {
      cond.push(`(p.name LIKE ? OR p.repo_url LIKE ? OR p.repo_full_name LIKE ? OR p.owner LIKE ?)`);
      const kw = `%${q.keyword}%`;
      params.push(kw, kw, kw, kw);
    }
    if (q.repoType) {
      cond.push(`p.repo_type = ?`);
      params.push(q.repoType);
    }
    const where = cond.join(' AND ');

    const totalRow = db.get<{ c: number }>(`SELECT COUNT(*) AS c FROM projects p WHERE ${where}`, params);
    const total = Number(totalRow?.c ?? 0);
    const offset = (q.page - 1) * q.pageSize;

    const list = db.all<ProjectRow>(
      `${PROJECT_SELECT} WHERE ${where}
        ORDER BY vuln_open DESC, p.id DESC LIMIT ? OFFSET ?`,
      [...params, q.pageSize, offset],
    );

    ok(res, {
      list: list.map(mapProject),
      pagination: {
        page: q.page,
        pageSize: q.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / q.pageSize)),
      },
    });
  }),
);

/** GET /projects/:id —— 详情，附等级分布 + 最近 5 次扫描 */
projectRouter.get(
  '/:id',
  requirePermission('project:read'),
  asyncHandler((req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw AppError.invalid('id 必须是正整数', 'id');
    const db = getDb();
    const row = db.get<ProjectRow>(`${PROJECT_SELECT} WHERE p.id = ?`, [id]);
    if (!row) throw AppError.notFound(`项目不存在：${id}`);

    const severityDistribution = db.all<{ severity: Severity; c: number }>(
      `SELECT severity, COUNT(*) AS c FROM vulnerabilities
        WHERE project_id = ? AND status NOT IN ('false_positive','ignored')
        GROUP BY severity`,
      [id],
    );

    const recentScans = db.all<Record<string, unknown>>(
      `SELECT id, scan_no, status, branch, commit_id, vuln_count, sample_count,
              started_at, finished_at, created_at
         FROM scan_tasks WHERE project_id = ?
        ORDER BY created_at DESC LIMIT 5`,
      [id],
    );

    ok(res, {
      ...mapProject(row),
      severityDistribution: severityDistribution.map((s) => ({
        severity: s.severity,
        count: Number(s.c),
      })),
      recentScans: recentScans.map((s) => ({
        id: s.id,
        scanNo: s.scan_no,
        status: s.status,
        branch: s.branch,
        commitId: s.commit_id,
        vulnCount: s.vuln_count,
        sampleCount: s.sample_count,
        startedAt: s.started_at,
        finishedAt: s.finished_at,
        createdAt: s.created_at,
      })),
    });
  }),
);

/** POST /projects —— 预先注册项目（扫描工具上报时也会自动创建） */
projectRouter.post(
  '/',
  requirePermission('project:write'),
  asyncHandler((req, res) => {
    const body = parseOrThrow(projectBodySchema, req.body);
    const db = getDb();
    const repoUrl = body.repoUrl.trim().replace(/\/+$/, '');
    const dup = db.get<{ id: number }>(
      `SELECT id FROM projects WHERE repo_type = ? AND repo_url = ?`,
      [body.repoType, repoUrl],
    );
    if (dup) throw AppError.conflict(`该仓库已存在项目（id=${dup.id}），请直接编辑`);

    const nowIso = new Date().toISOString();
    const r = db.run(
      `INSERT INTO projects(name, repo_type, repo_url, repo_full_name, default_branch, owner, description, status, created_at, updated_at)
       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        body.name,
        body.repoType,
        repoUrl,
        body.repoFullName ?? null,
        body.defaultBranch ?? null,
        body.owner ?? null,
        body.description ?? null,
        body.status ?? 1,
        nowIso,
        nowIso,
      ],
    );
    const row = db.get<ProjectRow>(`${PROJECT_SELECT} WHERE p.id = ?`, [r.lastInsertRowid]);
    created(res, row ? mapProject(row) : { id: r.lastInsertRowid });
  }),
);

/** PATCH /projects/:id —— 部分字段更新 */
projectRouter.patch(
  '/:id',
  requirePermission('project:write'),
  asyncHandler((req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw AppError.invalid('id 必须是正整数', 'id');
    const body = parseOrThrow(projectBodySchema.partial(), req.body);
    const db = getDb();
    const exists = db.get<{ id: number }>(`SELECT id FROM projects WHERE id = ?`, [id]);
    if (!exists) throw AppError.notFound(`项目不存在：${id}`);

    const map: Record<string, string | number | null> = {
      name: body.name ?? null,
      repo_type: body.repoType ?? null,
      repo_url: body.repoUrl ? body.repoUrl.trim().replace(/\/+$/, '') : null,
      repo_full_name: body.repoFullName ?? null,
      default_branch: body.defaultBranch ?? null,
      owner: body.owner ?? null,
      description: body.description ?? null,
      status: body.status ?? null,
    };
    const sets: string[] = [];
    const params: (string | number | null)[] = [];
    for (const [col, val] of Object.entries(map)) {
      if (val !== null) {
        sets.push(`${col} = ?`);
        params.push(val);
      }
    }
    if (sets.length === 0) throw AppError.invalid('没有需要更新的字段', 'body');

    sets.push('updated_at = ?');
    params.push(new Date().toISOString(), id);
    db.run(`UPDATE projects SET ${sets.join(', ')} WHERE id = ?`, params);

    const row = db.get<ProjectRow>(`${PROJECT_SELECT} WHERE p.id = ?`, [id]);
    ok(res, row ? mapProject(row) : null);
  }),
);

/** 项目下拉选项（看板筛选用，轻量） */
projectRouter.get(
  '/options/all',
  requirePermission('project:read'),
  asyncHandler((_req, res) => {
    const db = getDb();
    const list = db.all<{ id: number; name: string; repo_type: string }>(
      `SELECT id, name, repo_type FROM projects WHERE status = 1 ORDER BY name ASC`,
    );
    ok(res, { list: list.map((p) => ({ id: p.id, name: p.name, repoType: p.repo_type })) });
  }),
);
