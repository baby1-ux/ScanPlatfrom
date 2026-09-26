import { Router } from 'express';
import { z } from 'zod';
import { SEVERITIES, type Severity } from '@vuln/shared';
import { getDb } from '../../db/index.js';
import { jwtAuth, requirePermission } from '../../core/auth.js';
import { asyncHandler, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow, zIdList } from '../../core/validate.js';

/**
 * 统计接口 —— 看板数据源（docs/02 第 8 章）。
 * 口径约定：
 *  - vulnTotal 不含误报与已忽略
 *  - vulnOpen = open + confirmed + fixing
 *  - avgFixHours 由 fixed_at - first_found_at 计算
 */
export const statsRouter: Router = Router();
statsRouter.use(jwtAuth, generalRateLimit);

const OPEN_STATUSES = `('open','confirmed','fixing')`;
const EXCLUDED = `('false_positive','ignored')`;

const overviewQuery = z.object({
  projectId: zIdList,
  days: z.coerce.number().int().min(1).max(365).default(30),
});

/** GET /stats/overview */
statsRouter.get(
  '/overview',
  requirePermission('vuln:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(overviewQuery, req.query, 'query');
    const db = getDb();

    const projFilter = q.projectId?.length
      ? `AND project_id IN (${q.projectId.map(() => '?').join(',')})`
      : '';
    const projParams = (q.projectId ?? []) as number[];

    const since = new Date(Date.now() - q.days * 86_400_000).toISOString();

    const vuln = db.get<{
      total: number;
      open_count: number;
      critical: number;
      high: number;
      new_in_period: number;
      fixed_in_period: number;
    }>(
      `SELECT
         SUM(CASE WHEN status NOT IN ${EXCLUDED} THEN 1 ELSE 0 END) AS total,
         SUM(CASE WHEN status IN ${OPEN_STATUSES} THEN 1 ELSE 0 END) AS open_count,
         SUM(CASE WHEN severity = 'critical' AND status NOT IN ${EXCLUDED} THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN severity = 'high' AND status NOT IN ${EXCLUDED} THEN 1 ELSE 0 END) AS high,
         SUM(CASE WHEN first_found_at >= ? THEN 1 ELSE 0 END) AS new_in_period,
         SUM(CASE WHEN fixed_at IS NOT NULL AND fixed_at >= ? THEN 1 ELSE 0 END) AS fixed_in_period
       FROM vulnerabilities WHERE 1 = 1 ${projFilter}`,
      [since, since, ...projParams],
    );

    const scans = db.get<{ c: number }>(
      `SELECT COUNT(*) AS c FROM scan_tasks WHERE 1 = 1 ${projFilter}`,
      projParams,
    );
    const samples = db.get<{ c: number }>(
      `SELECT COUNT(*) AS c FROM samples WHERE 1 = 1 ${projFilter}`,
      projParams,
    );
    const projects = db.get<{ c: number }>(
      `SELECT COUNT(*) AS c FROM projects WHERE status = 1`,
    );

    const avg = db.get<{ v: number | null }>(
      `SELECT AVG((julianday(fixed_at) - julianday(first_found_at)) * 24.0) AS v
         FROM vulnerabilities
        WHERE fixed_at IS NOT NULL AND status = 'fixed' ${projFilter}`,
      projParams,
    );

    ok(res, {
      vulnTotal: Number(vuln?.total ?? 0),
      vulnOpen: Number(vuln?.open_count ?? 0),
      vulnCritical: Number(vuln?.critical ?? 0),
      vulnHigh: Number(vuln?.high ?? 0),
      newInPeriod: Number(vuln?.new_in_period ?? 0),
      fixedInPeriod: Number(vuln?.fixed_in_period ?? 0),
      projectCount: Number(projects?.c ?? 0),
      scanCount: Number(scans?.c ?? 0),
      sampleCount: Number(samples?.c ?? 0),
      avgFixHours: avg?.v === null || avg?.v === undefined ? null : Math.round(Number(avg.v) * 10) / 10,
    });
  }),
);

/** GET /stats/trend —— 按天的新增 / 修复 / 未处理存量 */
statsRouter.get(
  '/trend',
  requirePermission('vuln:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(overviewQuery, req.query, 'query');
    const db = getDb();
    const projFilter = q.projectId?.length
      ? `AND project_id IN (${q.projectId.map(() => '?').join(',')})`
      : '';
    const projParams = (q.projectId ?? []) as number[];

    const now = new Date();
    const days: string[] = [];
    for (let i = q.days - 1; i >= 0; i -= 1) {
      const d = new Date(now.getTime() - i * 86_400_000);
      days.push(d.toISOString().slice(0, 10));
    }
    const sinceIso = `${days[0]}T00:00:00.000Z`;

    const newRows = db.all<{ d: string; c: number }>(
      `SELECT substr(first_found_at, 1, 10) AS d, COUNT(*) AS c
         FROM vulnerabilities
        WHERE first_found_at >= ? ${projFilter}
        GROUP BY d`,
      [sinceIso, ...projParams],
    );
    const fixedRows = db.all<{ d: string; c: number }>(
      `SELECT substr(fixed_at, 1, 10) AS d, COUNT(*) AS c
         FROM vulnerabilities
        WHERE fixed_at IS NOT NULL AND fixed_at >= ? ${projFilter}
        GROUP BY d`,
      [sinceIso, ...projParams],
    );
    // 存量口径：截至当天仍未处理（open/confirmed/fixing）且首次发现时间 <= 当天
    const openRows = db.all<{ d: string; c: number }>(
      `SELECT substr(first_found_at, 1, 10) AS d, COUNT(*) AS c
         FROM vulnerabilities
        WHERE status IN ${OPEN_STATUSES} AND first_found_at <= ? ${projFilter}
        GROUP BY d`,
      [`${days[days.length - 1]}T23:59:59.999Z`, ...projParams],
    );

    const newMap = new Map(newRows.map((r) => [r.d, Number(r.c)]));
    const fixedMap = new Map(fixedRows.map((r) => [r.d, Number(r.c)]));

    // 累计存量：初始为「窗口起点之前就已存在且仍未处理」的数量
    const before = db.get<{ c: number }>(
      `SELECT COUNT(*) AS c FROM vulnerabilities
        WHERE status IN ${OPEN_STATUSES} AND first_found_at < ? ${projFilter}`,
      [sinceIso, ...projParams],
    );
    // 每天净增 = 当天新增 - 当天修复（近似），据此递推存量曲线
    let running = Number(before?.c ?? 0);
    const fixedByDay = new Map(fixedRows.map((r) => [r.d, Number(r.c)]));
    const newByDay = new Map(newRows.map((r) => [r.d, Number(r.c)]));
    const list = days.map((d) => {
      running += (newByDay.get(d) ?? 0) - (fixedByDay.get(d) ?? 0);
      return {
        date: d,
        newCount: newMap.get(d) ?? 0,
        fixedCount: fixedMap.get(d) ?? 0,
        openCount: Math.max(0, running),
      };
    });

    ok(res, { list });
  }),
);

/** GET /stats/severity —— 等级分布 */
statsRouter.get(
  '/severity',
  requirePermission('vuln:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(
      z.object({ projectId: zIdList, includeExcluded: z.coerce.boolean().default(false) }),
      req.query,
      'query',
    );
    const db = getDb();
    const projFilter = q.projectId?.length
      ? `AND project_id IN (${q.projectId.map(() => '?').join(',')})`
      : '';
    const params = (q.projectId ?? []) as number[];
    const excl = q.includeExcluded ? '' : `AND status NOT IN ${EXCLUDED}`;

    const rows = db.all<{ severity: Severity; count: number; open_count: number; fixed_count: number }>(
      `SELECT severity,
              COUNT(*) AS count,
              SUM(CASE WHEN status IN ${OPEN_STATUSES} THEN 1 ELSE 0 END) AS open_count,
              SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) AS fixed_count
         FROM vulnerabilities
        WHERE 1 = 1 ${excl} ${projFilter}
        GROUP BY severity`,
      params,
    );
    const map = new Map(rows.map((r) => [r.severity, r]));
    ok(res, {
      list: SEVERITIES.map((sev) => {
        const r = map.get(sev);
        return {
          severity: sev,
          count: Number(r?.count ?? 0),
          openCount: Number(r?.open_count ?? 0),
          fixedCount: Number(r?.fixed_count ?? 0),
        };
      }),
    });
  }),
);

/** GET /stats/top-rules */
statsRouter.get(
  '/top-rules',
  requirePermission('vuln:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(
      z.object({
        limit: z.coerce.number().int().min(1).max(50).default(10),
        projectId: zIdList,
        days: z.coerce.number().int().min(1).max(365).optional(),
      }),
      req.query,
      'query',
    );
    const db = getDb();
    const cond: string[] = ['rule_id IS NOT NULL'];
    const params: (string | number)[] = [];
    if (q.projectId?.length) {
      cond.push(`project_id IN (${q.projectId.map(() => '?').join(',')})`);
      params.push(...q.projectId);
    }
    if (q.days) {
      cond.push(`last_found_at >= ?`);
      params.push(new Date(Date.now() - q.days * 86_400_000).toISOString());
    }
    const where = cond.join(' AND ');

    const rows = db.all<{
      rule_id: string;
      rule_name: string | null;
      category: string | null;
      count: number;
      critical_count: number;
      open_count: number;
    }>(
      `SELECT rule_id, MAX(rule_name) AS rule_name, MAX(category) AS category,
              COUNT(*) AS count,
              SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
              SUM(CASE WHEN status IN ${OPEN_STATUSES} THEN 1 ELSE 0 END) AS open_count
         FROM vulnerabilities WHERE ${where}
        GROUP BY rule_id ORDER BY count DESC LIMIT ?`,
      [...params, q.limit],
    );

    ok(res, {
      list: rows.map((r) => ({
        ruleId: r.rule_id,
        ruleName: r.rule_name,
        category: r.category,
        count: Number(r.count),
        criticalCount: Number(r.critical_count ?? 0),
        openCount: Number(r.open_count ?? 0),
      })),
    });
  }),
);

/** GET /stats/top-projects */
statsRouter.get(
  '/top-projects',
  requirePermission('vuln:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(
      z.object({
        limit: z.coerce.number().int().min(1).max(50).default(10),
        sortBy: z.enum(['vulnOpen', 'vulnTotal', 'criticalCount']).default('vulnOpen'),
      }),
      req.query,
      'query',
    );
    const db = getDb();
    const orderCol =
      q.sortBy === 'vulnTotal' ? 'vuln_total' : q.sortBy === 'criticalCount' ? 'critical_count' : 'vuln_open';

    const rows = db.all<{
      project_id: number;
      name: string;
      repo_type: string;
      vuln_total: number;
      vuln_open: number;
      critical_count: number;
      high_count: number;
    }>(
      `SELECT p.id AS project_id, p.name, p.repo_type,
              (SELECT COUNT(*) FROM vulnerabilities v
                WHERE v.project_id = p.id AND v.status NOT IN ${EXCLUDED}) AS vuln_total,
              (SELECT COUNT(*) FROM vulnerabilities v
                WHERE v.project_id = p.id AND v.status IN ${OPEN_STATUSES}) AS vuln_open,
              (SELECT COUNT(*) FROM vulnerabilities v
                WHERE v.project_id = p.id AND v.severity = 'critical'
                  AND v.status NOT IN ${EXCLUDED}) AS critical_count,
              (SELECT COUNT(*) FROM vulnerabilities v
                WHERE v.project_id = p.id AND v.severity = 'high'
                  AND v.status NOT IN ${EXCLUDED}) AS high_count
         FROM projects p WHERE p.status = 1
        ORDER BY ${orderCol} DESC, p.id DESC LIMIT ?`,
      [q.limit],
    );

    ok(res, {
      list: rows.map((r) => ({
        projectId: r.project_id,
        name: r.name,
        repoType: r.repo_type,
        vulnTotal: Number(r.vuln_total ?? 0),
        vulnOpen: Number(r.vuln_open ?? 0),
        criticalCount: Number(r.critical_count ?? 0),
        highCount: Number(r.high_count ?? 0),
      })),
    });
  }),
);

/** GET /stats/status —— 状态分布（看板补充用） */
statsRouter.get(
  '/status',
  requirePermission('vuln:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(z.object({ projectId: zIdList }), req.query, 'query');
    const db = getDb();
    const projFilter = q.projectId?.length
      ? `AND project_id IN (${q.projectId.map(() => '?').join(',')})`
      : '';
    const rows = db.all<{ status: string; c: number }>(
      `SELECT status, COUNT(*) AS c FROM vulnerabilities WHERE 1 = 1 ${projFilter} GROUP BY status`,
      (q.projectId ?? []) as number[],
    );
    ok(res, { list: rows.map((r) => ({ status: r.status, count: Number(r.c) })) });
  }),
);

/** GET /stats/recent-scans —— 看板「最近扫描」小表 */
statsRouter.get(
  '/recent-scans',
  requirePermission('scan:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(
      z.object({ limit: z.coerce.number().int().min(1).max(20).default(8) }),
      req.query,
      'query',
    );
    const db = getDb();
    const list = db.all<Record<string, unknown>>(
      `SELECT s.id, s.scan_no, s.status, s.branch, s.commit_message, s.commit_author,
              s.vuln_count, s.sample_count, s.started_at, s.finished_at, s.created_at,
              p.name AS project_name, p.repo_type
         FROM scan_tasks s LEFT JOIN projects p ON p.id = s.project_id
        ORDER BY s.created_at DESC LIMIT ?`,
      [q.limit],
    );
    ok(res, {
      list: list.map((r) => ({
        id: r.id,
        scanNo: r.scan_no,
        project: { name: r.project_name, repoType: r.repo_type },
        status: r.status,
        branch: r.branch,
        commitMessage: r.commit_message,
        commitAuthor: r.commit_author,
        vulnCount: r.vuln_count,
        sampleCount: r.sample_count,
        startedAt: r.started_at,
        finishedAt: r.finished_at,
        createdAt: r.created_at,
        durationMs:
          r.started_at && r.finished_at
            ? Math.max(0, Date.parse(String(r.finished_at)) - Date.parse(String(r.started_at)))
            : null,
      })),
    });
  }),
);
