import { Router } from 'express';
import { z } from 'zod';
import { SAMPLE_LABELS } from '@vuln/shared';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { jwtAuth, requirePermission } from '../../core/auth.js';
import { asyncHandler, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow, zEnumList, zIdList, zPagination } from '../../core/validate.js';

export const sampleRouter: Router = Router();
sampleRouter.use(jwtAuth, generalRateLimit);

const listQuerySchema = z.object({
  ...zPagination,
  projectId: zIdList,
  label: zEnumList(SAMPLE_LABELS),
  ruleId: z.string().optional(),
  scanNo: z.string().optional(),
  language: z.string().optional(),
  keyword: z.string().optional(),
});

interface SampleRow {
  id: number;
  label: string;
  project_id: number;
  project_name: string | null;
  scan_no: string | null;
  file_path: string;
  language: string | null;
  line_start: number | null;
  line_end: number | null;
  snippet: string | null;
  snippet_size: number;
  vuln_id: number | null;
  rule_id: string | null;
  created_at: string;
}

/** GET /samples/stats —— 正负样本分布（必须注册在 /:id 之前） */
sampleRouter.get(
  '/stats',
  requirePermission('sample:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(
      z.object({
        projectId: z.coerce.number().int().positive().optional(),
        startTime: z.string().optional(),
        endTime: z.string().optional(),
      }),
      req.query,
      'query',
    );
    const db = getDb();
    // 两个查询共用同一套筛选条件，但列前缀分别是 samples / s，这里显式构造两份
    const condA: string[] = ['1 = 1'];
    const condB: string[] = ['1 = 1'];
    const params: (string | number)[] = [];
    if (q.projectId) {
      condA.push('project_id = ?');
      condB.push('s.project_id = ?');
      params.push(q.projectId);
    }
    if (q.startTime) {
      condA.push('created_at >= ?');
      condB.push('s.created_at >= ?');
      params.push(q.startTime);
    }
    if (q.endTime) {
      condA.push('created_at <= ?');
      condB.push('s.created_at <= ?');
      params.push(q.endTime);
    }
    const whereA = condA.join(' AND ');
    const whereB = condB.join(' AND ');

    const totals = db.get<{ total: number; pos: number; neg: number }>(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN label = 'positive' THEN 1 ELSE 0 END) AS pos,
              SUM(CASE WHEN label = 'negative' THEN 1 ELSE 0 END) AS neg
         FROM samples WHERE ${whereA}`,
      params,
    );
    const total = Number(totals?.total ?? 0);
    const positive = Number(totals?.pos ?? 0);
    const negative = Number(totals?.neg ?? 0);

    const byLanguage = db.all<{ language: string | null; pos: number; neg: number }>(
      `SELECT language,
              SUM(CASE WHEN label = 'positive' THEN 1 ELSE 0 END) AS pos,
              SUM(CASE WHEN label = 'negative' THEN 1 ELSE 0 END) AS neg
         FROM samples WHERE ${whereA}
        GROUP BY language ORDER BY (SUM(CASE WHEN label = 'positive' THEN 1 ELSE 0 END) + SUM(CASE WHEN label = 'negative' THEN 1 ELSE 0 END)) DESC LIMIT 12`,
      params,
    );

    const byRule = db.all<{ rule_id: string; rule_name: string | null; c: number }>(
      `SELECT s.rule_id, MAX(v.rule_name) AS rule_name, COUNT(*) AS c
         FROM samples s LEFT JOIN vulnerabilities v ON v.id = s.vuln_id
        WHERE s.rule_id IS NOT NULL AND ${whereB}
        GROUP BY s.rule_id ORDER BY c DESC LIMIT 12`,
      params,
    );

    ok(res, {
      total,
      positive,
      negative,
      positiveRatio: total > 0 ? Math.round((positive / total) * 10000) / 10000 : 0,
      byLanguage: byLanguage.map((l) => ({
        language: l.language,
        positive: Number(l.pos ?? 0),
        negative: Number(l.neg ?? 0),
      })),
      byRule: byRule.map((r) => ({ ruleId: r.rule_id, ruleName: r.rule_name, count: Number(r.c) })),
    });
  }),
);

/** GET /samples —— 样本列表，列表返回 snippetPreview（前 200 字符） */
sampleRouter.get(
  '/',
  requirePermission('sample:read'),
  asyncHandler((req, res) => {
    const q = parseOrThrow(listQuerySchema, req.query, 'query');
    const db = getDb();
    const cond: string[] = ['1 = 1'];
    const params: (string | number)[] = [];

    if (q.projectId?.length) {
      cond.push(`s.project_id IN (${q.projectId.map(() => '?').join(',')})`);
      params.push(...q.projectId);
    }
    if (q.label?.length) {
      cond.push(`s.label IN (${q.label.map(() => '?').join(',')})`);
      params.push(...q.label);
    }
    if (q.ruleId) {
      cond.push('s.rule_id = ?');
      params.push(q.ruleId);
    }
    if (q.language) {
      cond.push('LOWER(s.language) = LOWER(?)');
      params.push(q.language);
    }
    if (q.scanNo) {
      cond.push('t.scan_no = ?');
      params.push(q.scanNo);
    }
    if (q.keyword) {
      cond.push('(s.file_path LIKE ? OR s.snippet LIKE ?)');
      const kw = `%${q.keyword}%`;
      params.push(kw, kw);
    }
    const where = cond.join(' AND ');
    const from = `FROM samples s
                  LEFT JOIN projects p ON p.id = s.project_id
                  LEFT JOIN scan_tasks t ON t.id = s.scan_id`;

    const totalRow = db.get<{ c: number }>(`SELECT COUNT(*) AS c ${from} WHERE ${where}`, params);
    const total = Number(totalRow?.c ?? 0);

    const list = db.all<SampleRow>(
      `SELECT s.id, s.label, s.project_id, p.name AS project_name, t.scan_no, s.file_path,
              s.language, s.line_start, s.line_end, s.snippet,
              LENGTH(COALESCE(s.snippet, '')) AS snippet_size,
              s.vuln_id, s.rule_id, s.created_at
         ${from} WHERE ${where}
        ORDER BY s.created_at DESC, s.id DESC LIMIT ? OFFSET ?`,
      [...params, q.pageSize, (q.page - 1) * q.pageSize],
    );

    const sumRow = db.get<{ pos: number; neg: number }>(
      `SELECT SUM(CASE WHEN s.label = 'positive' THEN 1 ELSE 0 END) AS pos,
              SUM(CASE WHEN s.label = 'negative' THEN 1 ELSE 0 END) AS neg
         ${from} WHERE ${where}`,
      params,
    );

    ok(res, {
      list: list.map((r) => ({
        id: r.id,
        label: r.label,
        projectId: r.project_id,
        projectName: r.project_name,
        scanNo: r.scan_no,
        filePath: r.file_path,
        language: r.language,
        lineStart: r.line_start,
        lineEnd: r.line_end,
        snippetPreview: r.snippet ? r.snippet.slice(0, 200) : null,
        snippetSize: Number(r.snippet_size ?? 0),
        vulnId: r.vuln_id,
        ruleId: r.rule_id,
        createdAt: r.created_at,
      })),
      pagination: {
        page: q.page,
        pageSize: q.pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / q.pageSize)),
      },
      summary: { positive: Number(sumRow?.pos ?? 0), negative: Number(sumRow?.neg ?? 0) },
    });
  }),
);

/** GET /samples/:id —— 返回完整 snippet */
sampleRouter.get(
  '/:id',
  requirePermission('sample:read'),
  asyncHandler((req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) throw AppError.invalid('id 必须是正整数', 'id');
    const db = getDb();
    const r = db.get<SampleRow & { snippet_hash: string; file_hash: string | null; external_sample_id: string | null }>(
      `SELECT s.*, p.name AS project_name, t.scan_no
         FROM samples s
         LEFT JOIN projects p ON p.id = s.project_id
         LEFT JOIN scan_tasks t ON t.id = s.scan_id
        WHERE s.id = ?`,
      [id],
    );
    if (!r) throw AppError.notFound(`样本不存在：${id}`);

    const vuln = r.vuln_id
      ? db.get<{ id: number; vuln_no: string; title: string; severity: string; rule_id: string | null }>(
          `SELECT id, vuln_no, title, severity, rule_id FROM vulnerabilities WHERE id = ?`,
          [r.vuln_id],
        )
      : null;

    ok(res, {
      id: r.id,
      label: r.label,
      projectId: r.project_id,
      projectName: r.project_name,
      scanNo: r.scan_no,
      externalSampleId: r.external_sample_id,
      filePath: r.file_path,
      language: r.language,
      lineStart: r.line_start,
      lineEnd: r.line_end,
      snippet: r.snippet,
      snippetHash: r.snippet_hash,
      fileHash: r.file_hash,
      vuln: vuln
        ? {
            id: vuln.id,
            vulnNo: vuln.vuln_no,
            title: vuln.title,
            severity: vuln.severity,
            ruleId: vuln.rule_id,
          }
        : null,
      createdAt: r.created_at,
    });
  }),
);
