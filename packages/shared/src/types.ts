/**
 * 前后端共享类型 —— 与 docs/02-API接口文档.md 第 2.3 节「核心对象」及第 6~8 章响应结构对齐。
 */
import type {
  RepoType,
  Role,
  SampleLabel,
  ScanStatus,
  Severity,
  TriggerType,
  VulnStatus,
  Permission,
} from './constants.js';

// ------------------------------------------------------------ 统一响应
export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  data: T;
  traceId?: string;
}

export interface Pagination {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface Paged<T> {
  list: T[];
  pagination: Pagination;
}

export interface FieldError {
  field: string;
  message: string;
}

// ---------------------------------------------------------------- Auth
export interface UserInfo {
  id: number;
  username: string;
  displayName: string | null;
  email: string | null;
  role: Role;
  status: number;
  lastLoginAt: string | null;
  createdAt?: string;
  permissions?: Permission[];
}

export interface LoginResult {
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  user: UserInfo;
}

// -------------------------------------------------------------- Project
export interface ProjectStats {
  scanCount: number;
  vulnTotal: number;
  vulnOpen: number;
  vulnCritical: number;
  vulnHigh: number;
}

export interface Project {
  id: number;
  name: string;
  repoType: RepoType;
  repoUrl: string;
  repoFullName: string | null;
  defaultBranch: string | null;
  owner: string | null;
  description: string | null;
  status: number;
  stats?: ProjectStats;
  lastScanAt?: string | null;
  createdAt: string;
  updatedAt?: string;
}

export interface ProjectDetail extends Project {
  severityDistribution?: Array<{ severity: Severity; count: number }>;
  recentScans?: ScanTask[];
}

// ----------------------------------------------------------------- Scan
export interface ScanTask {
  id: number;
  scanNo: string;
  project: { id: number; name: string; repoType: RepoType } | null;
  scanner: { name: string | null; version: string | null };
  triggerType: TriggerType;
  branch: string | null;
  commitId: string | null;
  commitMessage: string | null;
  commitAuthor: string | null;
  commitTime: string | null;
  status: ScanStatus;
  totalFiles: number;
  scannedFiles: number;
  vulnCount: number;
  sampleCount: number;
  positiveCount: number;
  negativeCount: number;
  durationMs: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

export interface ScanTaskDetail extends ScanTask {
  errorMessage: string | null;
  vulnSummary: Record<Severity, number>;
  topRules: Array<{ ruleId: string; ruleName: string | null; count: number }>;
}

// ---------------------------------------------------------- Vulnerability
export interface VulnerabilityListItem {
  id: number;
  vulnNo: string;
  title: string;
  severity: Severity;
  status: VulnStatus;
  category: string | null;
  cwe: string | null;
  cve: string | null;
  language: string | null;
  ruleId: string | null;
  ruleName: string | null;
  project: { id: number; name: string; repoType: RepoType; repoUrl: string } | null;
  filePath: string;
  lineStart: number | null;
  lineEnd: number | null;
  assignee: { id: number; username: string; displayName: string | null } | null;
  confidence: number | null;
  firstFoundAt: string;
  lastFoundAt: string;
  occurrenceCount: number;
  createdAt: string;
}

export interface VulnEvent {
  id: number;
  action: 'created' | 'status_changed' | 'assigned' | 'commented' | 'resurfaced' | string;
  fromValue: string | null;
  toValue: string | null;
  operatorName: string | null;
  comment: string | null;
  createdAt: string;
}

export interface VulnerabilityDetail extends Omit<VulnerabilityListItem, 'project'> {
  fingerprint: string;
  description: string | null;
  suggestion: string | null;
  remark: string | null;
  project: Project | null;
  location: {
    filePath: string;
    lineStart: number | null;
    lineEnd: number | null;
    codeSnippet: string | null;
    codeSnippetOffset: number | null;
  };
  latestScan: {
    scanId: number;
    scanNo: string;
    branch: string | null;
    commitId: string | null;
    commitAuthor: string | null;
    commitTime: string | null;
    status: ScanStatus;
  } | null;
  samples: Array<{ id: number; label: SampleLabel; filePath: string; snippet: string | null }>;
  fixedAt: string | null;
  events: VulnEvent[];
}

export interface VulnListQuery {
  page?: number;
  pageSize?: number;
  projectId?: number | number[];
  repoType?: RepoType;
  severity?: Severity | Severity[];
  status?: VulnStatus | VulnStatus[];
  ruleId?: string;
  category?: string;
  cwe?: string;
  language?: string;
  filePath?: string;
  keyword?: string;
  assignee?: number;
  branch?: string;
  startTime?: string;
  endTime?: string;
  sortBy?: 'lastFoundAt' | 'severity' | 'firstFoundAt' | 'status' | 'projectId';
  sortOrder?: 'asc' | 'desc';
}

export interface VulnListResult extends Paged<VulnerabilityListItem> {
  summary: Record<Severity, number>;
}

// ---------------------------------------------------------------- Sample
export interface SampleListItem {
  id: number;
  label: SampleLabel;
  projectId: number;
  projectName?: string | null;
  scanNo: string | null;
  filePath: string;
  language: string | null;
  lineStart: number | null;
  lineEnd: number | null;
  snippetPreview: string | null;
  snippetSize: number;
  vulnId: number | null;
  ruleId: string | null;
  createdAt: string;
}

export interface SampleListResult extends Paged<SampleListItem> {
  summary: { positive: number; negative: number };
}

export interface SampleStats {
  total: number;
  positive: number;
  negative: number;
  positiveRatio: number;
  byLanguage: Array<{ language: string | null; positive: number; negative: number }>;
  byRule: Array<{ ruleId: string; ruleName: string | null; count: number }>;
}

// ----------------------------------------------------------------- Stats
export interface StatsOverview {
  vulnTotal: number;
  vulnOpen: number;
  vulnCritical: number;
  vulnHigh: number;
  newInPeriod: number;
  fixedInPeriod: number;
  projectCount: number;
  scanCount: number;
  sampleCount: number;
  avgFixHours: number | null;
}

export interface TrendPoint {
  date: string;
  newCount: number;
  fixedCount: number;
  openCount: number;
}

export interface SeverityBucket {
  severity: Severity;
  count: number;
  openCount: number;
  fixedCount: number;
}

export interface TopRule {
  ruleId: string;
  ruleName: string | null;
  category: string | null;
  count: number;
  criticalCount: number;
}

export interface TopProject {
  projectId: number;
  name: string;
  repoType: RepoType;
  vulnTotal: number;
  vulnOpen: number;
  criticalCount: number;
  highCount: number;
}

// -------------------------------------------------------------- ApiKey
export interface ApiKeyItem {
  id: number;
  name: string;
  keyPrefix: string;
  maskedKey: string;
  scopes: string[];
  repoScope: string[] | null;
  status: number;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}

export interface ApiKeyCreated extends ApiKeyItem {
  /** 明文只在创建时返回一次 */
  apiKey: string;
}

// ----------------------------------------------------------------- ML
export type MlMode = 'auto' | 'detection' | 'classification';

export interface MlDetectRequest {
  code: string;
  filePath?: string;
  language?: string;
  /** auto = 检测 + 分类都跑 */
  mode?: MlMode;
  threshold?: number;
}

export interface MlDetectResult {
  /** 是否由真实模型产出；false 表示模型服务不可用，走了降级 */
  modelServed: boolean;
  degraded: boolean;
  degradedReason: string | null;
  modelName: string;
  /**
   * 逐任务的来源说明。
   * mode=auto 时只要有一个任务降级整体就是 degraded，但另一个任务可能是真实模型算的；
   * 用这个字段区分，避免把「真模型判定的漏洞」误当成 mock 结果。
   */
  tasks?: Partial<
    Record<
      'detection' | 'classification',
      { modelServed: boolean; degraded: boolean; modelName: string; reason: string | null }
    >
  >;
  latencyMs: number;
  verdict: 'vulnerable' | 'safe' | null;
  vulnerableProbability: number | null;
  safeProbability: number | null;
  threshold: number;
  predictedCwe: string | null;
  predictedCweName: string | null;
  cweConfidence: number | null;
  topCwe: Array<{ cwe: string; name: string | null; probability: number }>;
}

export interface MlServiceStatus {
  online: boolean;
  url: string;
  fallbackMode: string;
  modelName: string | null;
  checkpoint: string | null;
  devices: string[] | null;
  detail: string | null;
  checkedAt: string;
}

export interface MlAnalyzeResponse {
  scan: {
    scanId: number;
    scanNo: string;
    projectId: number;
    vulnCreated: number;
    vulnUpdated: number;
    vulnSkipped: number;
    positiveSamples: number;
    negativeSamples: number;
  };
  result: MlDetectResult;
}

// ------------------------------------------------------------- Ingest
export interface ScanObjectPayload {
  repoType: RepoType;
  repoUrl: string;
  repoFullName?: string;
  projectName?: string;
  branch?: string;
  commitId?: string;
  commitMessage?: string;
  commitAuthor?: string;
  commitTime?: string;
}

export interface VulnerabilityItemPayload {
  externalVulnId?: string;
  ruleId: string;
  ruleName?: string;
  title: string;
  severity: Severity;
  category?: string;
  cwe?: string;
  cve?: string;
  language?: string;
  filePath: string;
  lineStart?: number;
  lineEnd?: number;
  codeSnippet?: string;
  description?: string;
  suggestion?: string;
  confidence?: number;
}

export interface SampleItemPayload {
  externalSampleId?: string;
  label: SampleLabel;
  filePath: string;
  language?: string;
  lineStart?: number;
  lineEnd?: number;
  snippet?: string;
  snippetHash?: string;
  fileHash?: string;
  externalVulnId?: string;
}

export interface IngestScanCreatePayload {
  scanNo: string;
  scanner?: { name?: string; version?: string };
  triggerType?: TriggerType;
  scan: ScanObjectPayload;
  startedAt?: string;
  totalFiles?: number;
}
