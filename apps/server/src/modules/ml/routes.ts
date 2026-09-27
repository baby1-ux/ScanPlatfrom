import { Router } from 'express';
import { z } from 'zod';
import type { Severity } from '@vuln/shared';
import { config } from '../../config/index.js';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { jwtAuth, requirePermission } from '../../core/auth.js';
import { asyncHandler, ok } from '../../core/http.js';
import { generalRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow } from '../../core/validate.js';
import { completeScan, createScan, ingestSamples, ingestVulnerabilities, resolveProject } from '../ingest/service.js';
import { degradedPredict, health, modelInfo, predict, type MlPredictResult } from './client.js';

/**
 * ScanMan 模型检测模块。
 *
 * 前端「模型检测」页调 POST /ml/detect 做单段代码判定；
 * 需要归档时调 POST /ml/analyze，把判定结果作为一次扫描批次写入平台
 * （漏洞 + 正样本），这样检测结果与扫描链路共用同一套数据模型与看板统计。
 */
export const mlRouter: Router = Router();
mlRouter.use(jwtAuth, generalRateLimit);

const CODE_MAX = 64 * 1024;

/** GET /ml/status —— 模型服务在线状态（前端顶部展示） */
mlRouter.get(
  '/status',
  requirePermission('ml:invoke'),
  asyncHandler(async (_req, res) => {
    const h = await health();
    ok(res, {
      online: h.ok,
      url: config.ml.url,
      fallbackMode: config.ml.fallback,
      modelName: h.ok ? (h.data?.modelName as string | null) ?? null : null,
      checkpoint: h.ok
        ? ((h.data?.detectionCheckpoint as string | null) ??
           (h.data?.classificationCheckpoint as string | null) ??
           null)
        : null,
      devices: h.ok ? [String(h.data?.device ?? '未知')] : null,
      detail: h.ok ? (h.data?.degradedReason as string | null) ?? null : h.error,
      checkedAt: new Date().toISOString(),
    });
  }),
);

/** GET /ml/info —— 模型与两套权重的详细信息 */
mlRouter.get(
  '/info',
  requirePermission('ml:invoke'),
  asyncHandler(async (_req, res) => {
    const info = await modelInfo();
    if (!info.ok || !info.data) {
      ok(res, { available: false, error: info.error, url: config.ml.url });
      return;
    }
    ok(res, { available: true, url: config.ml.url, ...info.data });
  }),
);

const detectSchema = z.object({
  code: z.string().min(1, 'code 不能为空').max(CODE_MAX),
  filePath: z.string().max(512).optional(),
  language: z.string().max(32).optional(),
  mode: z.enum(['auto', 'detection', 'classification']).default('auto'),
  threshold: z.coerce.number().min(0).max(1).optional(),
});

/** 调模型；失败时按 ML_FALLBACK 决定降级或报错 */
async function runPredict(input: {
  code: string;
  mode: 'auto' | 'detection' | 'classification';
  threshold?: number;
  filePath?: string;
  language?: string;
}, req: { header(name: string): string | undefined }, res: { setHeader(k: string, v: string): void }): Promise<MlPredictResult> {
  if (req.header('X-Skip-Model') === '1') {
    return degradedPredict(input.code, '请求头 X-Skip-Model:1，按要求使用降级启发式判定', input.threshold ?? 0.5);
  }

  const r = await predict({ ...input, threshold: input.threshold, topK: 5 });
  if (r.ok && r.data) return r.data;

  const reason = r.error ?? '模型服务不可用';
  if (config.ml.fallback === 'strict') {
    throw new AppError(50300, `模型服务不可用：${reason}`, 503, { mlUrl: config.ml.url });
  }
  res.setHeader('X-ML-Degraded', '1');
  return degradedPredict(input.code, reason, input.threshold ?? 0.5);
}

/** POST /ml/detect —— 单段代码检测（不落库） */
mlRouter.post(
  '/detect',
  requirePermission('ml:invoke'),
  asyncHandler(async (req, res) => {
    const input = parseOrThrow(detectSchema, req.body);
    const result = await runPredict(input, req, res);
    ok(res, result, result.degraded ? '模型不可用，已降级为启发式判定' : 'success');
  }),
);

/** 置信度 → 漏洞等级。模型只给概率，平台侧按统一口径映射，避免扫描侧各写一套 */
function severityFrom(result: MlPredictResult): Severity {
  const p = result.vulnerableProbability ?? 0;
  if (p >= 0.9) return 'high';
  if (p >= 0.75) return 'medium';
  if (p >= 0.6) return 'low';
  return 'info';
}

const analyzeSchema = detectSchema.extend({
  /** 写入哪个项目；不传则写入/复用内置的「ScanMan 模型检测」项目 */
  projectId: z.coerce.number().int().positive().optional(),
  repoUrl: z.string().max(512).optional(),
  repoType: z.enum(['github', 'gitlab', 'gitee', 'bitbucket', 'other']).optional(),
  branch: z.string().max(128).optional(),
  commitId: z.string().max(64).optional(),
  title: z.string().max(512).optional(),
});

const ML_PROJECT = {
  repoType: 'other' as const,
  repoUrl: 'https://scanman.local/model-detect',
  repoFullName: 'scanman/model-detect',
  projectName: 'ScanMan 模型检测',
  branch: 'ad-hoc',
};

/** POST /ml/analyze —— 检测 + 落库为一次扫描批次（漏洞 + 正/负样本） */
mlRouter.post(
  '/analyze',
  requirePermission('ml:invoke'),
  asyncHandler(async (req, res) => {
    const input = parseOrThrow(analyzeSchema, req.body);
    const result = await runPredict(input, req, res);

    const db = getDb();
    const filePath = (input.filePath ?? 'snippet.txt').replace(/^\/+/, '');
    const language = input.language ?? null;
    const usedDegraded = result.degraded;

    // 项目：显式指定则用它，否则复用/自动创建内置的「ScanMan 模型检测」项目
    let projectId: number;
    let projectName: string;
    if (input.projectId) {
      const p = db.get<{ id: number; name: string }>(`SELECT id, name FROM projects WHERE id = ?`, [
        input.projectId,
      ]);
      if (!p) throw AppError.notFound(`项目不存在：${input.projectId}`);
      projectId = p.id;
      projectName = p.name;
    } else {
      const project = resolveProject(db, {
        repoType: input.repoType ?? ML_PROJECT.repoType,
        repoUrl: input.repoUrl ?? ML_PROJECT.repoUrl,
        repoFullName: ML_PROJECT.repoFullName,
        projectName: ML_PROJECT.projectName,
        branch: input.branch ?? ML_PROJECT.branch,
      });
      projectId = project.id;
      projectName = project.name;
    }

    const vulnDetected = result.verdict === 'vulnerable';
    const scanNo = `ml-detect-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random()
      .toString(16)
      .slice(2, 9)}`;

    const scanRef = createScan(db, {
      scanNo,
      scanner: { name: 'ScanMan', version: 'model-detect' },
      triggerType: 'manual',
      scan: {
        repoType: input.repoType ?? ML_PROJECT.repoType,
        repoUrl: input.repoUrl ?? ML_PROJECT.repoUrl,
        repoFullName: ML_PROJECT.repoFullName,
        projectName: ML_PROJECT.projectName,
        branch: input.branch ?? ML_PROJECT.branch,
        commitId: input.commitId,
        commitMessage: `模型检测：${filePath}`,
        commitAuthor: req.user!.displayName ?? req.user!.username,
        commitTime: new Date().toISOString(),
      },
    });
    // createScan 按 (repoType, repoUrl) 解析项目；显式指定 projectId 时以指定值为准
    if (scanRef.projectId !== projectId) {
      db.run(`UPDATE scan_tasks SET project_id = ? WHERE id = ?`, [projectId, scanRef.scanId]);
    }

    let vulnCreated = 0;
    let vulnUpdated = 0;
    let vulnSkipped = 0;

    if (vulnDetected) {
      const severity = severityFrom(result);
      const vulnSummary = ingestVulnerabilities(
        db,
        { scanId: scanRef.scanId, projectId, scanNo: scanRef.scanNo },
        [
          {
            ruleId: result.predictedCwe ?? 'scanman-model-detection',
            ruleName: result.predictedCweName ?? 'ScanMan 模型判定为漏洞',
            title:
              input.title ??
              `[模型判定] ${result.predictedCweName ?? result.predictedCwe ?? '疑似漏洞'} @ ${filePath}`,
            severity,
            category: 'model_detection',
            cwe: result.predictedCwe ?? undefined,
            language: language ?? undefined,
            filePath,
            lineStart: 1,
            lineEnd: input.code.split('\n').length,
            codeSnippet: input.code,
            description: usedDegraded
              ? `ScanMan 模型服务不可用，本条由降级启发式判定产生（原因：${result.degradedReason}）。`
              : `由 ScanMan 检测模型判定为 vulnerable，漏洞概率 ${result.vulnerableProbability}；` +
                `分类模型预测 ${result.predictedCwe ?? '未知'}（置信度 ${result.cweConfidence ?? 'N/A'}）。`,
            suggestion: '请结合代码上下文人工确认；确认后按平台流程修复并置为已修复。',
            confidence: result.vulnerableProbability ?? undefined,
            externalVulnId: `ML-${scanRef.scanId}`,
          },
        ],
      );
      vulnCreated = vulnSummary.created;
      vulnUpdated = vulnSummary.updated + vulnSummary.resurfaced;
      vulnSkipped = vulnSummary.skipped;
    }

    // 把被检测的代码作为样本沉淀：判定为漏洞 → 正样本，否则 → 负样本
    const sampleSummary = ingestSamples(
      db,
      { scanId: scanRef.scanId, projectId, scanNo: scanRef.scanNo },
      [
        {
          label: vulnDetected ? 'positive' : 'negative',
          filePath,
          language: language ?? undefined,
          lineStart: 1,
          lineEnd: input.code.split('\n').length,
          snippet: input.code,
          externalVulnId: vulnDetected ? `ML-${scanRef.scanId}` : undefined,
        },
      ],
    );

    completeScan(db, scanRef.scanNo, { status: 'success', scannedFiles: 1, totalFiles: 1 });

    ok(res, {
      scan: {
        scanId: scanRef.scanId,
        scanNo: scanRef.scanNo,
        projectId,
        projectName,
        vulnCreated,
        vulnUpdated,
        vulnSkipped,
        positiveSamples: sampleSummary.positiveCount,
        negativeSamples: sampleSummary.negativeCount,
      },
      result,
    });
  }),
);
