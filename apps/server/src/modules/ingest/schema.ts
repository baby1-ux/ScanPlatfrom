import { z } from 'zod';
import { REPO_TYPES, SAMPLE_LABELS, SCAN_STATUSES, SEVERITIES, TRIGGER_TYPES } from '@vuln/shared';

/**
 * 上报接口入参校验 —— 对应 docs/02-API接口文档.md 第 5 章。
 * 这里的规则就是给扫描侧看的契约，错误信息会原样返回，方便对方定位字段。
 */

const optionalText = (max: number) =>
  z
    .string()
    .max(max, `长度不能超过 ${max} 字符`)
    .optional()
    .nullable()
    .transform((v): string | undefined => (v === null || v === undefined || v === '' ? undefined : v));

const optionalNullableText = (max: number) =>
  z
    .string()
    .max(max)
    .optional()
    .nullable()
    .transform((v) => (v === null || v === undefined || v === '' ? null : v));

export const scanObjectSchema = z.object({
  repoType: z.enum(REPO_TYPES, { errorMap: () => ({ message: 'repoType 必须是 github/gitlab/gitee/bitbucket/other 之一' }) }),
  repoUrl: z.string().min(1, 'repoUrl 不能为空').max(512),
  repoFullName: optionalText(255),
  projectName: optionalText(128),
  branch: optionalText(128),
  commitId: optionalText(64),
  commitMessage: optionalText(512),
  commitAuthor: optionalText(64),
  commitTime: optionalNullableText(64),
});

export const scannerSchema = z
  .object({
    name: optionalText(64),
    version: optionalText(32),
  })
  .optional();

export const createScanSchema = z.object({
  scanNo: z
    .string()
    .min(1, 'scanNo 不能为空')
    .max(128)
    .regex(/^[A-Za-z0-9._:-]+$/, 'scanNo 只允许字母、数字、点、下划线、冒号、连字符，请勿包含 / 或空格'),
  scanner: scannerSchema,
  triggerType: z.enum(TRIGGER_TYPES).optional(),
  scan: scanObjectSchema,
  startedAt: optionalNullableText(64),
  totalFiles: z.coerce.number().int().min(0).optional(),
});

export const vulnerabilityItemSchema = z.object({
  externalVulnId: optionalText(64),
  ruleId: z.string().min(1, '缺少必填字段 ruleId').max(128),
  ruleName: optionalText(255),
  title: z.string().min(1, '缺少必填字段 title').max(512),
  severity: z.enum(SEVERITIES, {
    errorMap: () => ({ message: '必须是 critical/high/medium/low/info 之一' }),
  }),
  category: optionalText(64),
  cwe: optionalText(32),
  cve: optionalText(64),
  language: optionalText(32),
  filePath: z.string().min(1, '缺少必填字段 filePath').max(512),
  lineStart: z.coerce.number().int().min(1).optional().nullable(),
  lineEnd: z.coerce.number().int().min(1).optional().nullable(),
  codeSnippet: optionalText(200_000),
  description: optionalText(20_000),
  suggestion: optionalText(20_000),
  confidence: z.coerce.number().min(0).max(1).optional().nullable(),
});

export const vulnerabilitiesBodySchema = z.object({
  vulnerabilities: z.array(z.unknown()).min(1, 'vulnerabilities 不能为空'),
});

export const sampleItemSchema = z.object({
  externalSampleId: optionalText(64),
  label: z.enum(SAMPLE_LABELS, {
    errorMap: () => ({ message: 'label 必须是 positive / negative 之一' }),
  }),
  filePath: z.string().min(1, '缺少必填字段 filePath').max(512),
  language: optionalText(32),
  lineStart: z.coerce.number().int().min(1).optional().nullable(),
  lineEnd: z.coerce.number().int().min(1).optional().nullable(),
  snippet: optionalText(200_000),
  snippetHash: z
    .string()
    .regex(/^[a-f0-9]{64}$/i, 'snippetHash 必须是 64 位十六进制 sha256')
    .optional()
    .nullable(),
  fileHash: z
    .string()
    .regex(/^[a-f0-9]{64}$/i, 'fileHash 必须是 64 位十六进制 sha256')
    .optional()
    .nullable(),
  externalVulnId: optionalText(64),
});

export const samplesBodySchema = z.object({
  samples: z.array(z.unknown()).min(1, 'samples 不能为空'),
});

export const completeScanSchema = z.object({
  status: z.enum(['success', 'failed', 'partial'] as const, {
    errorMap: () => ({ message: 'status 必须是 success / failed / partial 之一' }),
  }),
  finishedAt: optionalNullableText(64),
  totalFiles: z.coerce.number().int().min(0).optional(),
  scannedFiles: z.coerce.number().int().min(0).optional(),
  errorMessage: optionalNullableText(1024),
});

export const fullReportSchema = z.object({
  scanNo: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9._:-]+$/, 'scanNo 请勿包含 / 或空格'),
  scanner: scannerSchema,
  triggerType: z.enum(TRIGGER_TYPES).optional(),
  scan: scanObjectSchema,
  startedAt: optionalNullableText(64),
  finishedAt: optionalNullableText(64),
  status: z.enum(SCAN_STATUSES).optional(),
  totalFiles: z.coerce.number().int().min(0).optional(),
  scannedFiles: z.coerce.number().int().min(0).optional(),
  vulnerabilities: z.array(z.unknown()).optional().default([]),
  samples: z.array(z.unknown()).optional().default([]),
});

export type CreateScanInput = z.infer<typeof createScanSchema>;
export type FullReportInput = z.infer<typeof fullReportSchema>;
