import { Router } from 'express';
import { ERROR_CODES, LIMITS } from '@vuln/shared';
import { getDb } from '../../db/index.js';
import { AppError } from '../../core/errors.js';
import { apiKeyAuth, assertRepoAllowed } from '../../core/auth.js';
import { asyncHandler, created, ok } from '../../core/http.js';
import { assertBatchSize, ingestRateLimit } from '../../core/rateLimit.js';
import { parseOrThrow } from '../../core/validate.js';
import {
  completeScan,
  createScan,
  ingestSamples,
  ingestVulnerabilities,
  requireScanByNo,
  type SampleIngestSummary,
  type VulnIngestSummary,
} from './service.js';
import {
  completeScanSchema,
  createScanSchema,
  fullReportSchema,
  samplesBodySchema,
  vulnerabilitiesBodySchema,
} from './schema.js';

/**
 * 扫描结果上报接口 —— 全部使用 X-API-Key 鉴权（docs/02 第 5 章）。
 * 模式 A：scans → vulnerabilities → samples → complete（4 步）
 * 模式 B：report（1 步全量）
 */
export const ingestRouter: Router = Router();

ingestRouter.use(ingestRateLimit);
ingestRouter.use(apiKeyAuth);

/** API Key 自检，扫描侧正式上报前先调这个 */
ingestRouter.get(
  '/ping',
  asyncHandler((req, res) => {
    ok(res, {
      valid: true,
      keyName: req.apiKey?.name ?? null,
      scopes: req.apiKey?.scopes ?? [],
      repoScope: req.apiKey?.repoScope ?? null,
      serverTime: new Date().toISOString(),
      apiVersion: 'v1',
    });
  }),
);

/** Step 1 — 创建扫描批次（scanNo 幂等） */
ingestRouter.post(
  '/scans',
  asyncHandler((req, res) => {
    const input = parseOrThrow(createScanSchema, req.body);
    assertRepoAllowed(input.scan.repoUrl, req.apiKey);
    const db = getDb();
    const ref = createScan(db, input);
    const payload = {
      scanId: ref.scanId,
      scanNo: ref.scanNo,
      projectId: ref.projectId,
      projectCreated: ref.projectCreated,
      status: ref.status,
      duplicated: ref.duplicated,
      createdAt: ref.createdAt,
    };
    if (ref.duplicated) ok(res, payload, '扫描批次已存在，返回原记录');
    else created(res, payload);
  }),
);

/** Step 2 — 批量上报漏洞 */
ingestRouter.post(
  '/scans/:scanNo/vulnerabilities',
  asyncHandler((req, res) => {
    const { vulnerabilities } = parseOrThrow(vulnerabilitiesBodySchema, req.body);
    assertBatchSize(vulnerabilities.length, 'vulnerabilities');

    const db = getDb();
    const scan = requireScanByNo(db, req.params.scanNo!);
    if (scan.status !== 'running') {
      throw new AppError(
        ERROR_CODES.SCAN_STATE_NOT_ALLOWED,
        `批次 ${scan.scan_no} 状态为 ${scan.status}，不允许继续上报漏洞`,
        400,
      );
    }

    const result = ingestVulnerabilities(
      db,
      { scanId: scan.id, projectId: scan.project_id, scanNo: scan.scan_no },
      vulnerabilities,
    );

    if (result.created + result.updated + result.resurfaced === 0 && result.skipped > 0) {
      // 全部被跳过 → 400 / 40001（部分成功语义）
      throw AppError.badRequest(
        result.skippedItems.map((s) => ({ field: `vulnerabilities[${s.index}]`, message: s.reason })),
        '全部漏洞项校验失败',
      );
    }

    ok(
      res,
      {
        received: result.received,
        created: result.created,
        updated: result.updated + result.resurfaced,
        resurfaced: result.resurfaced,
        skipped: result.skipped,
        details: result.details,
        ...(result.skippedItems.length ? { skippedItems: result.skippedItems } : {}),
      },
      result.skipped > 0 ? '部分数据被跳过' : 'success',
    );
  }),
);

/** Step 3 — 批量上报正负样本 */
ingestRouter.post(
  '/scans/:scanNo/samples',
  asyncHandler((req, res) => {
    const { samples } = parseOrThrow(samplesBodySchema, req.body);
    assertBatchSize(samples.length, 'samples');

    const db = getDb();
    const scan = requireScanByNo(db, req.params.scanNo!);
    const result = ingestSamples(
      db,
      { scanId: scan.id, projectId: scan.project_id, scanNo: scan.scan_no },
      samples,
    );
    ok(res, result);
  }),
);

/** Step 4 — 结束扫描批次 */
ingestRouter.post(
  '/scans/:scanNo/complete',
  asyncHandler((req, res) => {
    const input = parseOrThrow(completeScanSchema, req.body);
    const db = getDb();
    const result = completeScan(db, req.params.scanNo!, input);
    ok(res, result);
  }),
);

/** 模式 B — 一次性全量上报（小仓库 / 本地调试） */
ingestRouter.post(
  '/report',
  asyncHandler((req, res) => {
    const input = parseOrThrow(fullReportSchema, req.body);
    assertRepoAllowed(input.scan.repoUrl, req.apiKey);
    assertBatchSize(input.vulnerabilities.length, 'vulnerabilities');
    assertBatchSize(input.samples.length, 'samples');

    const db = getDb();
    // 事务内全程同步（SQLite 适配层为同步驱动），因此可以整体包在一个事务里
    const body = db.tx(() => {
      const ref = createScan(db, input);
      const scanRef = { scanId: ref.scanId, projectId: ref.projectId, scanNo: ref.scanNo };

      const vulnSummary: VulnIngestSummary = input.vulnerabilities.length
        ? ingestVulnerabilities(db, scanRef, input.vulnerabilities)
        : { received: 0, created: 0, updated: 0, resurfaced: 0, skipped: 0, details: [], skippedItems: [] };
      const sampleSummary: SampleIngestSummary = input.samples.length
        ? ingestSamples(db, scanRef, input.samples)
        : { received: 0, created: 0, duplicated: 0, truncated: 0, positiveCount: 0, negativeCount: 0 };

      if (input.status && input.status !== 'running') {
        completeScan(db, ref.scanNo, {
          status: input.status as 'success' | 'failed' | 'partial',
          finishedAt: input.finishedAt ?? undefined,
          totalFiles: input.totalFiles,
          scannedFiles: input.scannedFiles,
        });
      }

      return {
        scanId: ref.scanId,
        scanNo: ref.scanNo,
        projectId: ref.projectId,
        projectCreated: ref.projectCreated,
        duplicated: ref.duplicated,
        result: {
          vulnReceived: vulnSummary.received,
          vulnCreated: vulnSummary.created,
          vulnUpdated: vulnSummary.updated + vulnSummary.resurfaced,
          vulnSkipped: vulnSummary.skipped,
          sampleReceived: sampleSummary.received,
          sampleCreated: sampleSummary.created,
          sampleDuplicated: sampleSummary.duplicated,
          positiveCount: sampleSummary.positiveCount,
          negativeCount: sampleSummary.negativeCount,
        },
      };
    });

    if (body.duplicated) ok(res, body, '扫描批次已存在，已按幂等追加数据');
    else created(res, body);
  }),
);

/** 契约里声明的单条报文上限，暴露给扫描侧自检用 */
ingestRouter.get(
  '/limits',
  asyncHandler((_req, res) => {
    ok(res, {
      maxBodyBytes: LIMITS.MAX_BODY_BYTES,
      maxBatchItems: LIMITS.MAX_BATCH_ITEMS,
      maxSnippetBytes: LIMITS.MAX_SNIPPET_BYTES,
      apiVersion: 'v1',
    });
  }),
);
