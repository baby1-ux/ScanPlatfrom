import { Router } from 'express';
import { z } from 'zod';
import { SCAN_STATUSES, TRIGGER_TYPES, type Severity } from '@vuln/shared';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { jwtAuth, requirePermission } from '../../core/auth.js';
import { asyncHandler, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow, zEnumList, zIdList, zPagination } from '../../core/validate.js';

export const scanRouter: Router = Router();
scanRouter.use(jwtAuth, generalRateLimit);

const listQuerySchema = z.object({
  ...zPagination,
  projectId: zIdList,
  status: zEnumList(SCAN_STATUSES),
  triggerType: zEnumList(TRIGGER_TYPES),
  branch: z.string().optional(),
  keyword: z.string().optional(),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  sortBy: z.enum(['createdAt', 'startedAt', 'vulnCount', 'durationMs']).default('createdAt'),
});

interface ScanRow {
  id: number;
  scan_no: string;
  project_id: number;
  project_name: string | null;
  repo_type: string | null;
  scanner_name: string | null;
  scanner_version: string | null;
  trigger_type: string;
  branch: string | null;
  commit_id: string | null;
  commit_message: string | null;
  commit_author: string | null;
  commit_time: string | null;
  status: string;
  total_files: number;
  scanned_files: number;
  vuln_count: number;
  sample_count: number;
  positive_count: number;
  negative_count: number;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

const SCAN_SELECT = `
  SELECT s.id, s.scan_no, s.project_id, p.name AS project_name, p.repo_type,
         s.scanner_name, s.scanner_version, s.trigger_type, s.branch, s.commit_id,
         s.commit_message, s.commit_author, s.commit_time, s.status, s.total_files,
         s.scanned_files, s.vuln_count, s.sample_count, s.positive_count, s.negative_count,
         s.error_message, s.started_at, s.finished_at, s.created_at
    FROM scan_tasks s
    LEFT JOIN projects p ON p.id = s.project_id`;

function mapScan(r: ScanRow) {
  const durationMs =
    r.started_at && r.finished_at
      ? Math.max(0, Date.parse(r.finished_at) - Date.parse(r.started_at))
      : null;
  return {
    id: r.id,
    scanNo: r.scan_no,
    project: r.project_id ? { id: r.project_id, name: r.project_name, repoType: r.repo_type } : null,
    scanner: { name: r.scanner_name, version: r.scanner_version },
    triggerType: r.trigger_type,
    branch: r.branch,
    commitId: r.commit_id,
    commitMessage: r.commit_message,
    commitAuthor: r.commit_author,
    commitTime: r.commit_time,
    status: r.status,
    totalFiles: r.total_files,
    scannedFiles: r.scanned_files,
    vulnCount: r.vuln_count,
    sampleCount: r.sample_count,
    positiveCount: r.positive_count,
    negativeCount: r.negative_count,
    durationMs,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    createdAt: r.created_at,
  };
}

/** GET /scans —— 扫描批次列表 */
scanRouter.get(
  '/',
  requirePermission('scan:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(listQuerySchema, req.query, 'query');
    const db = getDb();
    const cond: string[] = ['1 = 1'];
    const params: (string | number)[] = [];

    if (q.projectId?.length) {
      cond.push(`s.project_id IN (${q.projectId.map(() => '?').join(',')})`);
      params.push(...q.projectId);
    }
    if (q.status?.length) {
      cond.push(`s.status IN (${q.status.map(() => '?').join(',')})`);
      params.push(...q.status);
    }
    if (q.triggerType?.length) {
      cond.push(`s.trigger_type IN (${q.triggerType.map(() => '?').join(',')})`);
      params.push(...q.triggerType);
    }
    if (q.branch) {
      cond.push(`s.branch = ?`);
      params.push(q.branch);
    }
    if (q.keyword) {
      cond.push(`(s.scan_no LIKE ? OR s.commit_message LIKE ? OR s.commit_author LIKE ? OR p.name LIKE ?)`);
      const kw = `%${q.keyword}%`;
      params.push(kw, kw, kw, kw);
    }
    if (q.startTime) {
      cond.push(`s.created_at >= ?`);
      params.push(q.startTime);
    }
    if (q.endTime) {
      cond.push(`s.created_at <= ?`);
      params.push(q.endTime);
    }
    const where = cond.join(' AND ');

    const totalRow = db.get<{ c: number }>(
      `SELECT COUNT(*) AS c FROM scan_tasks s LEFT JOIN projects p ON p.id = s.project_id WHERE ${where}`,
      params,
    );
    const total = Number(totalRow?.c ?? 0);

    const orderMap: Record<string, string> = {
      createdAt: 's.created_at',
      startedAt: 's.started_at',
      vulnCount: 's.vuln_count',
      durationMs: '(julianday(s.finished_at) - julianday(s.started_at))',
    };
    const orderCol = orderMap[q.sortBy] ?? 's.created_at';
    const offset = (q.page - 1) * q.pageSize;

    const list = db.all<ScanRow>(
      `${SCAN_SELECT} WHERE ${where} ORDER BY ${orderCol} ${q.sortOrder === 'asc' ? 'ASC' : 'DESC'}, s.id DESC LIMIT ? OFFSET ?`,
      [...params, q.pageSize, offset],
    );

    // 顶部统计条
    const agg = db.get<{
      total_scans: number;
      success: number;
      failed: number;
      running: number;
      vuln_total: number;
    }>(
      `SELECT COUNT(*) AS total_scans,
              SUM(CASE WHEN s.status = 'success' THEN 1 ELSE 0 END) AS success,
              SUM(CASE WHEN s.status = 'failed' THEN 1 ELSE 0 END) AS failed,
              SUM(CASE WHEN s.status = 'running' THEN 1 ELSE 0 END) AS running,
              SUM(s.vuln_count) AS vuln_total
         FROM scan_tasks s LEFT JOIN projects p ON p.id = s.project_id WHERE ${where}`,
      params,
    );

    ok(res, {
      list: list.map(mapScan),
      pagination: {
        page: q.page,
        pageSize: q.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / q.pageSize)),
      },
      summary: {
        total: Number(agg?.total_scans ?? 0),
        success: Number(agg?.success ?? 0),
        failed: Number(agg?.failed ?? 0),
        running: Number(agg?.running ?? 0),
        vulnTotal: Number(agg?.vuln_total ?? 0),
      },
    });
  }),
);

/** GET /scans/:scanNo —— 批次详情，附等级分布与 Top 规则 */
scanRouter.get(
  '/:scanNo',
  requirePermission('scan:read'),
  asyncHandler((req, res) => {
    const scanNo = decodeURIComponent(req.params.scanNo!);
    const db = getDb();
    const row = db.get<ScanRow>(`${SCAN_SELECT} WHERE s.scan_no = ?`, [scanNo]);
    if (!row) throw AppError.notFound(`扫描批次不存在：${scanNo}`);

    const sevRows = db.all<{ severity: Severity; c: number }>(
      `SELECT severity, COUNT(*) AS c FROM vulnerabilities WHERE scan_id = ? GROUP BY severity`,
      [row.id],
    );
    const vulnSummary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const s of sevRows) vulnSummary[s.severity] = Number(s.c);

    const topRules = db.all<{ rule_id: string; rule_name: string | null; c: number }>(
      `SELECT rule_id, rule_name, COUNT(*) AS c FROM vulnerabilities
        WHERE scan_id = ? GROUP BY rule_id, rule_name ORDER BY c DESC LIMIT 10`,
      [row.id],
    );

    ok(res, {
      ...mapScan(row),
      errorMessage: row.error_message,
      vulnSummary,
      topRules: topRules.map((t) => ({ ruleId: t.rule_id, ruleName: t.rule_name, count: Number(t.c) })),
    });
  }),
);
