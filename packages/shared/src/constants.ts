/**
 * 枚举与常量 —— 与 docs/02-API接口文档.md 第 2 章「数据字典」严格对齐。
 * 前后端共用，避免枚举漂移。
 */

// ---------------------------------------------------------------- severity
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_META: Record<Severity, { label: string; color: string; order: number }> = {
  critical: { label: '严重', color: '#cf1322', order: 0 },
  high: { label: '高危', color: '#fa541c', order: 1 },
  medium: { label: '中危', color: '#faad14', order: 2 },
  low: { label: '低危', color: '#1677ff', order: 3 },
  info: { label: '提示', color: '#8c8c8c', order: 4 },
};

// ------------------------------------------------------------- vulnStatus
export const VULN_STATUSES = [
  'open',
  'confirmed',
  'fixing',
  'fixed',
  'ignored',
  'false_positive',
] as const;
export type VulnStatus = (typeof VULN_STATUSES)[number];

export const VULN_STATUS_META: Record<
  VulnStatus,
  { label: string; color: string; isTerminal: boolean; countsAsOpen: boolean }
> = {
  open: { label: '待处理', color: 'red', isTerminal: false, countsAsOpen: true },
  confirmed: { label: '已确认', color: 'orange', isTerminal: false, countsAsOpen: true },
  fixing: { label: '修复中', color: 'blue', isTerminal: false, countsAsOpen: true },
  fixed: { label: '已修复', color: 'green', isTerminal: true, countsAsOpen: false },
  ignored: { label: '已忽略', color: 'default', isTerminal: true, countsAsOpen: false },
  false_positive: { label: '误报', color: 'purple', isTerminal: true, countsAsOpen: false },
};

// --------------------------------------------------------------- repoType
export const REPO_TYPES = ['github', 'gitlab', 'gitee', 'bitbucket', 'other'] as const;
export type RepoType = (typeof REPO_TYPES)[number];
export const REPO_TYPE_META: Record<RepoType, { label: string; color: string }> = {
  github: { label: 'GitHub', color: 'default' },
  gitlab: { label: 'GitLab', color: 'volcano' },
  gitee: { label: 'Gitee', color: 'red' },
  bitbucket: { label: 'Bitbucket', color: 'blue' },
  other: { label: '其他', color: 'default' },
};

// ------------------------------------------------------------ triggerType
export const TRIGGER_TYPES = ['push', 'merge_request', 'manual', 'schedule', 'webhook'] as const;
export type TriggerType = (typeof TRIGGER_TYPES)[number];
export const TRIGGER_TYPE_META: Record<TriggerType, { label: string }> = {
  push: { label: 'Push' },
  merge_request: { label: 'MR/PR' },
  manual: { label: '手动' },
  schedule: { label: '定时' },
  webhook: { label: 'Webhook' },
};

// ------------------------------------------------------------- scanStatus
export const SCAN_STATUSES = ['running', 'success', 'failed', 'partial'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];
export const SCAN_STATUS_META: Record<ScanStatus, { label: string; color: string }> = {
  running: { label: '扫描中', color: 'processing' },
  success: { label: '成功', color: 'success' },
  failed: { label: '失败', color: 'error' },
  partial: { label: '部分成功', color: 'warning' },
};

// ------------------------------------------------------------- sampleLabel
export const SAMPLE_LABELS = ['positive', 'negative'] as const;
export type SampleLabel = (typeof SAMPLE_LABELS)[number];
export const SAMPLE_LABEL_META: Record<SampleLabel, { label: string; color: string }> = {
  positive: { label: '正样本（有漏洞）', color: 'red' },
  negative: { label: '负样本（无漏洞）', color: 'green' },
};

// ------------------------------------------------------------------ roles
export const ROLES = ['admin', 'auditor', 'viewer'] as const;
export type Role = (typeof ROLES)[number];
export const ROLE_META: Record<Role, { label: string }> = {
  admin: { label: '平台管理员' },
  auditor: { label: '安全审计员' },
  viewer: { label: '只读用户' },
};

// ------------------------------------------------------------ permissions
export const PERMISSIONS = [
  'vuln:read',
  'vuln:write',
  'sample:read',
  'project:read',
  'project:write',
  'scan:read',
  'export',
  'user:manage',
  'apikey:manage',
  'ml:invoke',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  admin: [...PERMISSIONS],
  auditor: [
    'vuln:read',
    'vuln:write',
    'sample:read',
    'project:read',
    'project:write',
    'scan:read',
    'export',
    'ml:invoke',
  ],
  viewer: ['vuln:read', 'sample:read', 'project:read', 'scan:read', 'export'],
};

// ------------------------------------------------------------- 错误码全表
export const ERROR_CODES = {
  OK: 0,
  PARAM_INVALID: 40001,
  OLD_PASSWORD_WRONG: 40002,
  PASSWORD_TOO_WEAK: 40003,
  SCAN_STATE_NOT_ALLOWED: 40004,
  UNAUTHORIZED: 40100,
  API_KEY_INVALID: 40101,
  API_KEY_EXPIRED: 40102,
  API_KEY_REPO_DENIED: 40103,
  FORBIDDEN: 40300,
  ACCOUNT_DISABLED: 40301,
  NOT_FOUND: 40400,
  CONFLICT: 40900,
  PAYLOAD_TOO_LARGE: 41300,
  RATE_LIMITED: 42900,
  LOGIN_RATE_LIMITED: 42902,
  INTERNAL_ERROR: 50000,
  DB_ERROR: 50001,
  SERVICE_UNAVAILABLE: 50300,
} as const;
export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

export const ERROR_MESSAGES: Record<number, string> = {
  [ERROR_CODES.OK]: 'success',
  [ERROR_CODES.PARAM_INVALID]: '参数校验失败',
  [ERROR_CODES.OLD_PASSWORD_WRONG]: '旧密码不正确',
  [ERROR_CODES.PASSWORD_TOO_WEAK]: '新密码强度不足',
  [ERROR_CODES.SCAN_STATE_NOT_ALLOWED]: '批次状态不允许该操作',
  [ERROR_CODES.UNAUTHORIZED]: '未登录或 Token 无效/过期',
  [ERROR_CODES.API_KEY_INVALID]: 'API Key 无效或已被吊销',
  [ERROR_CODES.API_KEY_EXPIRED]: 'API Key 已过期',
  [ERROR_CODES.API_KEY_REPO_DENIED]: 'API Key 无权访问该仓库',
  [ERROR_CODES.FORBIDDEN]: '无权限',
  [ERROR_CODES.ACCOUNT_DISABLED]: '账号已被禁用',
  [ERROR_CODES.NOT_FOUND]: '资源不存在',
  [ERROR_CODES.CONFLICT]: '资源冲突',
  [ERROR_CODES.PAYLOAD_TOO_LARGE]: '请求体过大，请使用分片上报接口',
  [ERROR_CODES.RATE_LIMITED]: '请求过于频繁',
  [ERROR_CODES.LOGIN_RATE_LIMITED]: '登录尝试过于频繁',
  [ERROR_CODES.INTERNAL_ERROR]: '服务器内部错误',
  [ERROR_CODES.DB_ERROR]: '数据库错误',
  [ERROR_CODES.SERVICE_UNAVAILABLE]: '服务暂不可用（维护中）',
};

// ------------------------------------------------------------------ 限制
export const LIMITS = {
  /** 单批数组元素上限 */
  MAX_BATCH_ITEMS: 500,
  /** 请求体上限（gzip 前） */
  MAX_BODY_BYTES: 5 * 1024 * 1024,
  /** 单条代码片段上限 64KB */
  MAX_SNIPPET_BYTES: 64 * 1024,
  /** 列表默认/最大分页 */
  DEFAULT_PAGE_SIZE: 20,
  MAX_PAGE_SIZE: 200,
  /** 导出上限 */
  MAX_EXPORT_ROWS: 50000,
  /** 登录频率：10 次/分钟 */
  LOGIN_RATE_LIMIT: 10,
} as const;

export const ROUTES = {
  login: '/login',
  dashboard: '/dashboard',
  vulnerabilities: '/vulnerabilities',
  vulnerabilityDetail: (id: number | string) => `/vulnerabilities/${id}`,
  projects: '/projects',
  scans: '/scans',
  scanDetail: (scanNo: string) => `/scans/${encodeURIComponent(scanNo)}`,
  samples: '/samples',
  model: '/model',
  settings: '/settings',
} as const;
